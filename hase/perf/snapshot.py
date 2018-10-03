from __future__ import absolute_import, division, print_function

import ctypes as ct
import mmap
import fcntl
import os
from typing import List, Generator, Any, Optional, Iterator, Dict

from .cpuid import CPUID
from ..mmap import MMap
from .consts import (
    Libc,
    AttrFlags,
    SampleFlags,
    PerfRecord,
    Ioctls,
    EventStructs,
    perf_event_header,
    perf_event_attr,
    perf_event_mmap_page,
    PERF_FLAG_FD_CLOEXEC,
    PERF_TYPE_SOFTWARE,
    SYS_perf_event_open,
    PERF_COUNT_SW_DUMMY,
    CAP_USER_TIME_ZERO,
)

event_structs = EventStructs(SampleFlags.PERF_SAMPLE_MASK)


EVENTS = {
    PerfRecord.PERF_RECORD_MMAP: event_structs.mmap_event,
    PerfRecord.PERF_RECORD_LOST: event_structs.lost_event,
    PerfRecord.PERF_RECORD_COMM: event_structs.comm_event,
    PerfRecord.PERF_RECORD_EXIT: event_structs.exit_event,
    PerfRecord.PERF_RECORD_THROTTLE: event_structs.throttle_event,
    PerfRecord.PERF_RECORD_UNTHROTTLE: event_structs.unthrottle_event,
    PerfRecord.PERF_RECORD_FORK: event_structs.fork_event,
    PerfRecord.PERF_RECORD_MMAP2: event_structs.mmap2_event,
    PerfRecord.PERF_RECORD_AUX: event_structs.aux_event,
    PerfRecord.PERF_RECORD_ITRACE_START: event_structs.itrace_start_event,
    PerfRecord.PERF_RECORD_LOST_SAMPLES: event_structs.lost_samples_event,
    PerfRecord.PERF_RECORD_SWITCH: event_structs.record_switch_event,
    PerfRecord.PERF_RECORD_SWITCH_CPU_WIDE: event_structs.record_switch_cpu_wide_event,
}  # yapf: disable


def cpus_online():
    # type: () -> List[int]

    # Accepted parameters:
    # 0  - core 0
    # 0,1,2,3  - cores 0,1,2,3
    # 0-12,13-15,18,19

    with open("/sys/devices/system/cpu/online") as f:
        cores = f.read().strip()

    result = set()
    sequences = cores.split(',')
    for seq in sequences:
        if '-' not in seq:
            if not seq.isdigit():
                raise ValueError('%s is not digital' % seq)
            result.add(int(seq))
        else:
            core_range = seq.split('-')
            if len(core_range) != 2 or not core_range[0].isdigit() \
                    or not core_range[1].isdigit():
                raise ValueError('Core Range Error')
            result.update(range(int(core_range[0]), int(core_range[1]) + 1))
    return list(result)


def intel_pt_type():
    # type: () -> int
    with open("/sys/bus/event_source/devices/intel_pt/type") as f:
        return int(f.read())


class PMU(object):
    def __init__(self, perf_attr, cpu, pid):
        # type: (perf_event_attr, int, int) -> None
        self.fd = Libc.syscall(SYS_perf_event_open, ct.byref(perf_attr), pid,
                               cpu, -1, PERF_FLAG_FD_CLOEXEC)
        assert self.fd != -1
        fcntl.fcntl(self.fd, fcntl.F_SETFL, os.O_RDONLY | os.O_NONBLOCK)

    def __enter__(self):
        # type: () -> PMU
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def _ioctl(self, cmd, arg):
        # type: (int, Any) -> int
        res = Libc.ioctl(self.fd, cmd, arg)
        assert res == 0
        return res

    def set_output(self, pmu):
        # type: (PMU) -> int
        return self._ioctl(Ioctls.PERF_EVENT_IOC_SET_OUTPUT, pmu.fd)

    def pause(self):
        # type: () -> int
        return self._ioctl(Ioctls.PERF_EVENT_IOC_PAUSE_OUTPUT, 1)

    def disable(self):
        # type: () -> int
        return self._ioctl(Ioctls.PERF_EVENT_IOC_DISABLE, 0)

    def enable(self):
        # type: () -> int
        return self._ioctl(Ioctls.PERF_EVENT_IOC_ENABLE, 0)

    def close(self):
        # type: () -> None
        os.close(self.fd)

    def event_id(self):
        # type: () -> int
        id = ct.c_ulong()
        self._ioctl(Ioctls.PERF_EVENT_IOC_ID, ct.byref(id))
        return id.value


def open_pt_event(cpu, pid):
    # type: (int, int) -> PMU
    attr = perf_event_attr()
    attr.size = ct.sizeof(attr)
    attr.type = intel_pt_type()
    # FIXME: find out how config works,
    # currenty copied from strace output
    attr.config = 0x300e601
    attr.sample_type = SampleFlags.PERF_SAMPLE_MASK
    attr.sample_period = 1
    attr.clockid = 1
    attr.flags = AttrFlags.DISABLED | \
        AttrFlags.EXCLUDE_KERNEL | \
        AttrFlags.EXCLUDE_HV | \
        AttrFlags.SAMPLE_ID_ALL | \
        AttrFlags.WRITE_BACKWARD

    return PMU(attr, cpu, pid)


def open_dummy_event(cpu, pid):
    # type: (int, int) -> PMU
    attr = perf_event_attr()
    attr.size = ct.sizeof(attr)
    attr.type = PERF_TYPE_SOFTWARE
    attr.config = PERF_COUNT_SW_DUMMY
    attr.sample_type = SampleFlags.PERF_SAMPLE_MASK
    attr.sample_period = 1
    attr.clockid = 1

    attr.flags = AttrFlags.EXCLUDE_KERNEL | \
        AttrFlags.EXCLUDE_HV | \
        AttrFlags.SAMPLE_ID_ALL | \
        AttrFlags.CONTEXT_SWITCH | \
        AttrFlags.WRITE_BACKWARD

    #attr.flags = AttrFlags.EXCLUDE_KERNEL | \
    #    AttrFlags.EXCLUDE_HV | \
    #    AttrFlags.SAMPLE_ID_ALL | \
    #    AttrFlags.MMAP | \
    #    AttrFlags.COMM | \
    #    AttrFlags.TASK | \
    #    AttrFlags.MMAP2 | \
    #    AttrFlags.COMM_EXEC | \
    #    AttrFlags.CONTEXT_SWITCH | \
    #    AttrFlags.WRITE_BACKWARD

    return PMU(attr, cpu, pid)


class TscConversion(object):
    def __init__(self, time_mult, time_shift, time_zero):
        # type: (int, int, int) -> None
        self.time_mult = time_mult
        self.time_shift = time_shift
        self.time_zero = time_zero

class CpuId(object):
    def __init__(self, family, model, stepping, cpuid_0x15_eax,
                 cpuid_0x15_ebx):
        # type: (int, int, int, int, int) -> None
        self.family = family
        self.model = model
        self.stepping = stepping
        self.cpuid_0x15_eax = cpuid_0x15_eax
        self.cpuid_0x15_ebx = cpuid_0x15_ebx


class MmapHeader(object):
    def __init__(self, addr, data_size):
        # type: (int, int) -> None
        self._header = perf_event_mmap_page.from_address(addr)
        self.data_addr = addr + self._header.data_offset
        self.data_size = data_size

    # From kernel commit 9ecda41acb971ebd07c8fb35faf24005c0baea12 introducing
    # overwritable ring buffer:
    #
    # Following figure demonstrates the state of the overwritable ring buffer
    # when 'write_backward' is set before overwriting:
    #
    #        head
    #         |
    #         V
    #     +---+------+----------+-------+------+
    #     |   |D....D|C........C|B.....B|A....A|
    #     +---+------+----------+-------+------+
    #
    # and after overwriting:
    #                                      head
    #                                       |
    #                                       V
    #     +---+------+----------+-------+---+--+
    #     |..E|D....D|C........C|B.....B|A..|E.|
    #     +---+------+----------+-------+---+--+
    #
    # In each situation, 'head' points to the beginning of the newest record.
    # From this record, tooling can iterate over the full ring buffer and fetch
    # records one by one.
    def events(self):
        # type: () -> Iterator[ct.Structure]
        data_head = self._header.data_head
        events = []  # type: List[ct.Structure]

        data_size = self.data_size
        offset = data_head + data_size

        first = True

        while True:
            begin = self.data_addr + offset % data_size
            ev = perf_event_header.from_address(begin)
            if ev.size == 0:
                break
            end = self.data_addr + (offset + ev.size) % data_size

            if first:
                first_begin = begin
                first_end = end
            elif begin <= first_begin and end >= first_end:
                break

            buf = bytearray(ev.size)
            c_buf = (ct.c_byte * ev.size).from_buffer(buf)
            if end < begin:
                # event wraps around into ring buffer start
                length = self.data_addr + data_size - begin
                ct.memmove(c_buf, begin, length)
                ct.memmove(
                    ct.addressof(c_buf) + length, self.data_addr,
                    ev.size - length)
            else:
                ct.memmove(c_buf, begin, ct.sizeof(c_buf))
            struct_factory = EVENTS.get(ev.type)
            if struct_factory is None:
                raise Exception("unexpeced perf_event type: %d" % ev.type)
            struct = struct_factory(ev.size).from_buffer(buf)
            assert ct.sizeof(struct) == ev.size
            events.append(struct)
            first = False
            offset += ev.size
        return reversed(events)

    def tsc_conversion(self):
        # type: () -> TscConversion
        i = 0
        while True:
            seq = self._header.lock
            conversion = TscConversion(self._header.time_mult,
                                       self._header.time_shift,
                                       self._header.time_zero)

            cap_user_time_zero = self._header.capabilities & 1 << CAP_USER_TIME_ZERO
            if self._header.lock == seq and (seq & 1) == 0:
                assert cap_user_time_zero != 0
                return conversion
            i += 1
            if i > 10000:
                raise Exception("failed to get perf_event_mmap_page lock")

    @property
    def aux_offset(self):
        # type: () -> int
        return self._header.aux_offset

    @property
    def aux_size(self):
        # type: () -> int
        return self._header.aux_size

    @aux_size.setter
    def aux_size(self, size):
        # type: (int) -> None
        self._header.aux_offset = self._header.data_offset + self._header.data_size
        self._header.aux_size = size

    def advance(self):
        # type: () -> None
        self._header.data_tail = self._header.data_head


class BackwardRingbuffer(object):
    def __init__(self, cpu, pid=-1):
        # type: (int, int) -> None
        """
        Implements ring buffer described here: https://lwn.net/Articles/688338/
        """
        # data and aux area must be a multiply of two
        self.pmu = open_dummy_event(cpu, pid)
        header_size = Libc.PAGESIZE
        data_size = (2**9) * Libc.PAGESIZE  # == 2097152

        self.buf = MMap(self.pmu.fd, header_size + data_size, mmap.PROT_READ,
                        mmap.MAP_SHARED)

        self.header = MmapHeader(self.buf.addr, data_size)

    def stop(self):
        # type: () -> None
        self.pmu.pause()

    def close(self):
        # type: () -> None
        if self.buf:
            self.buf.close()
        self.pmu.close()

    def events(self):
        # type: () -> Iterator[ct.Structure]
        return self.header.events()

    def tsc_conversion(self):
        # type: () -> TscConversion
        return self.header.tsc_conversion()


class AuxRingbuffer(object):
    def __init__(self, cpu, pid=-1):
        # type: (int, int) -> None
        # data area must be a multiply of two
        data_size = (2**9) * Libc.PAGESIZE  # == 2097152
        self.pmu = open_pt_event(cpu, pid)
        header_size = Libc.PAGESIZE

        self.buf = MMap(self.pmu.fd, header_size + data_size,
                        mmap.PROT_READ | mmap.PROT_WRITE, mmap.MAP_SHARED)

        self.header = MmapHeader(self.buf.addr, data_size)

        # aux area must be a multiply of two
        self.header.aux_size = Libc.PAGESIZE * (2**14)  # == 67108864
        self.aux_buf = MMap(
            self.pmu.fd,
            self.header.aux_size,
            mmap.PROT_READ,
            mmap.MAP_SHARED,
            offset=self.header.aux_offset)

        self.pmu.enable()

    def mark_as_read(self):
        # type: () -> None
        self.header.advance()

    def close(self):
        # type: () -> None
        if self.aux_buf:
            self.aux_buf.close()

        if self.buf:
            self.buf.close()

        self.pmu.close()

    def stop(self):
        # type: () -> None
        self.pmu.disable()

    def events(self):
        # type: () -> Iterator[ct.Structure]
        return self.header.events()


class PerfEvents(object):
    def __init__(self, tsc_conversion):
        self.tsc_conversion = tsc_conversion


class Cpu(object):
    def __init__(self, idx, event_buffer, pt_buffer):
        # type: (int, BackwardRingbuffer, AuxRingbuffer) -> None
        self.idx = idx
        self.event_buffer = event_buffer
        self.pt_buffer = pt_buffer

        self._itrace_start_event = None # type: Optional[ct.Structure]

    def events(self):
        # type: () -> Iterator[ct.Structure]
        return self.event_buffer.events()

    def itrace_start_event(self):
        # type: () -> ct.Structure
        assert self._itrace_start_event is not None
        return self._itrace_start_event

    def traces(self):
        # type: () -> Generator[bytearray, None, None]
        seen = {}  # type: Dict[int, int]
        for ev in self.pt_buffer.events():
            if ev.type == PerfRecord.PERF_RECORD_ITRACE_START:
                self._itrace_start_event = ev

            if ev.type != PerfRecord.PERF_RECORD_AUX:
                continue
            aux_begin = self.pt_buffer.aux_buf.addr
            aux_end = self.pt_buffer.aux_buf.addr + self.pt_buffer.aux_buf.size
            if aux_begin in seen:
                assert seen[aux_begin] == aux_end
                continue
            else:
                seen[aux_begin] = aux_end

            begin = aux_begin + ev.aux_offset
            end = begin + ev.aux_size

            buf = bytearray(ev.aux_size)
            c_buf = (ct.c_byte * ev.aux_size).from_buffer(buf)
            # trace wraps around in aux ring buffer
            if end > aux_end:
                length = aux_end - begin
                ct.memmove(c_buf, begin, length)
                ct.memmove(
                    ct.addressof(c_buf) + length, aux_begin,
                    ev.aux_size - length)
            else:
                ct.memmove(c_buf, aux_begin, ct.sizeof(c_buf))

            yield buf

    def stop(self):
        # type: () -> None
        self.pt_buffer.stop()

        self.event_buffer.stop()

    def close(self):
        # type: () -> None
        self.pt_buffer.close()
        self.event_buffer.close()


class Snapshot(object):
    def __init__(self, pid=-1):
        # type: (int) -> None
        self.stopped = False
        self.cpus = []  # type: List[Cpu]

        try:
            self.start(pid)
        except Exception:
            self.close()
            raise

    def start(self, pid):
        # type: (int) -> None
        assert not self.stopped
        event_buffers = []  # type: List[BackwardRingbuffer]
        pt_buffers = []  # type: List[AuxRingbuffer]

        cpu_idx = cpus_online()
        for idx in cpu_idx:
            event_buffers.append(BackwardRingbuffer(idx, pid))

        # gather dummy events before pt events
        for idx in cpu_idx:
            pt_buffers.append(AuxRingbuffer(idx, pid))

        for idx in cpu_idx:
            self.cpus.append(Cpu(idx, event_buffers[idx], pt_buffers[idx]))

    def __enter__(self):
        # type: () -> Snapshot
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def stop(self):
        # type: () -> None
        for cpu in self.cpus:
            cpu.stop()
        self.stopped = True

    def tsc_conversion(self):
        # type: () -> TscConversion
        return self.cpus[0].event_buffer.tsc_conversion()

    def cpuid(self):
        # type: () -> CpuId
        cpuid = CPUID()
        eax, _, _, _ = cpuid(0x1)
        family = (eax >> 8) & 0xf
        if family == 0xf:
            family += (eax >> 20) & 0xf
        model = (eax >> 4) & 0xf
        if family == 0x6 or family == 0xf:
            model += (eax >> 12) & 0xf0
        stepping = (eax >> 0) & 0xf
        cpuid_0x15_eax, cpuid_0x15_ebx, _, _ = cpuid(0x15)

        return CpuId(family, model, stepping, cpuid_0x15_eax, cpuid_0x15_ebx)

    def sample_type(self):
        # type: () -> int
        return SampleFlags.PERF_SAMPLE_MASK

    def close(self):
        # type: () -> None
        for cpu in self.cpus:
            cpu.close()