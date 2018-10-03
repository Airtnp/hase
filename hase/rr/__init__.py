from __future__ import absolute_import, division, print_function

import subprocess
import logging
from pygdbmi.gdbcontroller import GdbController
from ..path import APP_ROOT


def rr_record(binary_path, *args):
    proc = subprocess.Popen(
        [
            'rr',
            'replay',
            binary_path,
        ] + args,
    )
    proc.wait()
    if proc.stdout:
        lines = proc.stdout.readline().strip()
        print(lines)


class RRController(object):
    def __init__(self, binary_path, fulltrace):
        self.binary_path = binary_path
        self.fulltrace = fulltrace
        self.rr = GdbController(
            gdb_args=[binary_path],
            rr=True,
        )
        self.current_index = 0
        self.clear_output()

    def eval_expression(self, expr):
        # type: (str) -> None
        res = self.rr.write(
            "-data-evaluate-expression %s" % expr, timeout_sec=99999)
        print(res)

    def write_request(self, req, get_resp=True, **kwargs):
        timeout_sec = kwargs.pop('timeout_sec', 10)
        kwargs['read_response'] = False
        self.rr.write(req, timeout_sec=timeout_sec, **kwargs)
        resp = []
        while True:
            try:
                resp += self.rr.get_gdb_response()
            except:
                break
        return resp

    def count_occurence(self, idx):
        """Count # of addr -> target in trace"""
        event = self.fulltrace[idx]
        addr = event.addr
        cnt = 0
        step = 1 if idx > self.current_index else -1
        for i in range(self.current_index, idx, step):
            e = self.fulltrace[i]
            ne = self.fulltrace[i + 1]
            if e.addr == addr:
                cnt += 1
            # NOTE: not dealing with rep here
            if e.ip <= addr < ne.addr:
                cnt += 1
        return cnt

    def run_until(self, idx):
        event = self.fulltrace[idx]
        addr = event.addr
        n = self.count_occurence(idx)
        cont_ins = 'c' if idx > self.current_index else 'reverse-cont'
        self.write_request('b *{}'.format(hex(addr)), get_resp=False, timeout_sec=10)
        self.write_request('{}'.format(cont_ins), get_resp=False, timeout_sec=10)
        if n != 0:
            self.write_request('{} {}'.format(cont_ins, n), get_resp=False, timeout_sec=10)
        self.write_request('clear *{}'.format(hex(addr)), get_resp=False, timeout_sec=10)
        self.current_index = idx

        self.clear_output()

    def convert(self, num):
        if num.startswith('0x'):
            return int(num, 16)
        else:
            return int(num, 10)

    def read_memory(self, addr, size):
        resp = self.write_request('x/{}b {}'.format(size, hex(addr)))
        loc = {}
        for i, r in enumerate(resp):
            if r['payload'].startswith('(rr)') and ':\t' in r['payload']:
                addr_descs = resp[i:]
                for desc in addr_descs:
                    payload = desc['payload']
                    if payload.startswith('0x'):
                        addr = payload.split(':\t')[0].split(' ')[0]
                        addr = self.convert(addr)
                        start_idx = payload.index(':\t') + 2
                        values = payload[start_idx:].split('\t')
                        for j in range(len(values)):
                            loc[addr + j] = self.convert(values[j])
                break
        return loc

    def read_reg(self):
        resp = self.write_request('info reg')
        reg_names = [
            'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
            'rbp', 'rsp', 'r8', 'r9', 'r10',
            'r11', 'r12', 'r13', 'r14', 'r15',
            'rip', 'eflags', 'cs', 'ss', 'ds', 'es',
            'fs', 'gs', 'fs_base', 'gs_base'
        ]
        print(resp)
        reg_dict = {}
        for i, r, in enumerate(resp):
            if r['payload'].startswith('(rr) rax'):
                reg_descs = resp[i:]
                reg_descs[0]['payload'] = reg_descs[0]['payload'][5:]
                for desc in reg_descs:
                    payload = desc['payload']
                    reg_name = payload.split(' ')[0]
                    if reg_name in reg_names:
                        if reg_name != 'eflags':
                            if payload.endswith('>'):
                                value = payload.split(' ')[-2].split('\t')[1]
                            else:
                                value = payload.split(' ')[-1].split('\t')[1]
                            reg_dict[reg_name] = self.convert(value)
                break
        print(reg_dict)
        return reg_dict

    def clear_output(self):
        for _ in range(10):
            try:
                self.rr.get_gdb_response(timeout_sec=3, raise_error_on_timeout=False)
            except UnicodeDecodeError:
                pass
