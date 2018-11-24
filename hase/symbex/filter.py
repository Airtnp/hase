from __future__ import absolute_import, division, print_function

import logging
from bisect import bisect
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from angr import Project, SimProcedure
from angr.analyses.cfg import CFGFast

from ..pt.events import Instruction
from .hook import unsupported_symbols, common_prefix, common_suffix

if False:  # for mypy
    from .tracer import CoredumpGDB

l = logging.getLogger(__name__)


class FakeSymbol:
    def __init__(self, name: str, addr: int) -> None:
        self.name = name
        self.rebased_addr = addr

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, FakeSymbol):
            return False
        return self.name == other.name and self.rebased_addr == other.rebased_addr

    def __hash__(self) -> int:
        return hash((self.name, self.rebased_addr))

    def __repr__(self) -> str:
        # () -> str
        return "FakeSymbol '{}' at {}".format(self.name, hex(self.rebased_addr))


class FilterBase:
    def __init__(
        self,
        project: Project,
        trace: List[Instruction],
        hooked_symbol: Dict[str, SimProcedure],
        gdb: "CoredumpGDB",
        omitted_section: List[List[int]],
    ) -> None:

        assert cfg.kb is not None

        self.project = project
        self.main_cfg = self.project.analyses.CFGFast(show_progressbar=True)
        self.main_object = project.loader.main_object
        self.trace = trace
        self.hooked_symbol = hooked_symbol
        self.gdb = gdb
        self.new_trace: List[Instruction] = []
        self.omitted_section = omitted_section
        self.hooked_symname = list(self.hooked_symbol.keys())
        self.hooked_addon : List[str] = []

        self.analyze_unsupported()

        self.syms: Dict[Any, List[int]] = {}
        self.syms_dict: Dict[Any, Dict[int, Any]] = {}
        for lib in self.project.loader.all_elf_objects:
            self.syms_dict[lib] = lib.symbols_by_addr.copy()
            self.syms[lib] = list(self.syms_dict[lib].keys())
            self.syms[lib].sort()

    def add_hook_omit_symbol(self, fname, name):
        try:
            r = self.gdb.get_func_range(fname)
            self.omitted_section.append(r)
            func = self.hooked_symbol[name]
            project.hook(r[0], func(), length=r[1])
        except Exception:
            print("Unable to fetch {} range by gdb".format(fname))
        self.hooked_addon.append(fname)

    def analyze_unsupported(self) -> None:
        for l in unsupported_symbols:
            try:
                r = self.gdb.get_func_range(l[0])
            except Exception:
                print("Unable to fetch {} range by gdb".format(l[0]))
                r = [0, 0]
            self.omitted_section.append(r)

    def test_plt_vdso(self, addr: int) -> bool:
        # NOTE: .plt or .plt.got
        section = self.project.loader.find_section_containing(addr)
        if section:
            return section.name.startswith(".plt")
        else:
            # NOTE: unrecognizable section, regard as vDSO
            return True

    def test_ld(self, addr: int) -> bool:
        o = self.project.loader.find_object_containing(addr)
        return o == self.project.loader.linux_loader_object

    def test_omit(self, addr: int) -> bool:
        for sec in self.omitted_section:
            if sec[0] <= addr < sec[0] + sec[1]:
                return True
        return False

    def test_hook_name(self, fname: str) -> bool:
        if name in self.hooked_addon:
            return True
        for name in self.hooked_symname:
            if fname == name:
                return True
            for prefix in common_prefix:
                if common_prefix + name in fname:
                    self.add_hook_omit_symbol(fname)
                    return True
            for suffix in common_suffix:
                if name + common_suffix in fname:
                    self.add_hook_omit_symbol(fname)
                    return True
        return False

    def solve_name_plt(self, addr: int) -> str:
        for lib in self.project.loader.all_elf_objects:
            if addr in lib.reverse_plt.keys():
                return lib.reverse_plt[addr]
        return ""

    # FIXME return type should be a union of the actual type and FakeSymbol
    def find_function(self, addr: int) -> Optional[FakeSymbol]:
        for lib, symx in self.syms.items():
            if lib.contains_addr(addr):
                # NOTE: angr cannot solve plt symbol name
                if self.test_plt_vdso(addr):
                    name = self.solve_name_plt(addr)
                    if name:
                        sym = FakeSymbol(name, addr)
                        return sym
                idx = bisect(symx, addr) - 1
                entry = symx[idx]
                return self.syms_dict[lib][entry]
        return None

    def test_function_entry(self, addr: int) -> Tuple[bool, str]:
        sym = self.find_function(addr)
        if sym and sym.rebased_addr == addr:
            symname = sym.name
            return True, symname
        return False, ""


class FilterTrace(FilterBase):
    def __init__(
        self,
        project: Project,
        trace: List[Instruction],
        hooked_symbol: Dict[str, SimProcedure],
        gdb: "CoredumpGDB",
        omitted_section: List[List[int]],
        static_link: bool,
    ) -> None:
        super().__init__(project, cfg, trace, hooked_symbol, gdb)

        self.trace_idx: List[int] = []
        self.hook_target: Dict[int, int] = {}
        self.static_link = static_link
        self.analyze_trace()

    def analyze_trace(self) -> None:
        # NOTE: assume the hooked function should have return
        self.new_trace = []
        self.call_parent: defaultdict = defaultdict(lambda: None)
        hooked_parent = None
        is_current_hooked = False
        hook_idx = 0
        first_meet = False
        plt_sym = None
        previous_instr = None
        for (idx, instruction) in enumerate(self.trace):
            if idx > 0:
                previous_instr = self.trace[idx - 1]

            present = True
            if (
                self.test_plt_vdso(instruction.ip)
                or self.test_ld(instruction.ip)
                or self.test_omit(instruction.ip)
            ):
                present = False
            # NOTE: if already in hooked function, leaving to parent
            # FIXME: gcc optimization will lead to main->func1->(set rbp)func2->main
            # A better solution is to record callstack,
            # which means we need to get jumpkind of every address,
            # but I cannot find it now. large recursive_level could slow down filter a lot
            # Or find scope outside hooked_libs
            if is_current_hooked:
                if present:
                    sym = self.find_function(instruction.ip)
                    recursive_level = 4
                    if sym == hooked_parent:
                        is_current_hooked = False
                        l.warning(" ->(back) " + sym.name)
                        hooked_parent = None
                        present = True
                        self.hook_target[hook_idx] = instruction.ip
                    else:
                        present = False
                        cur_func = hooked_parent
                        for _ in range(recursive_level):
                            parent = self.call_parent[cur_func]
                            if parent:
                                if sym == parent:
                                    is_current_hooked = False
                                    hooked_parent = None
                                    self.call_parent[cur_func] = None
                                    self.hook_target[hook_idx] = instruction.ip
                                    l.warning(" ->(back) " + sym.name)
                                    break
                                else:
                                    cur_func = parent
                            else:
                                break
                # At least when we get back to main object, it should be unhooked
                # NOTE: that doesn't work for static compiled object
                if not self.static_link:
                    if (
                        is_current_hooked
                        and not self.test_plt_vdso(instruction.ip)
                        and not self.test_ld(instruction.ip)
                        and self.project.loader.find_object_containing(instruction.ip)
                        == self.main_object
                    ):
                        is_current_hooked = False
                        hooked_parent = None
                        self.hook_target[hook_idx] = instruction.ip
                        l.warning(" ->(back) main_object")

            else:
                flg, fname = self.test_function_entry(instruction.ip)
                if flg and previous_instr is not None:
                    # NOTE: function entry, testing is hooked
                    sym = self.find_function(instruction.ip)
                    parent = self.find_function(previous_instr.ip)
                    # NOTE: plt -> dso -> libc
                    if self.test_plt_vdso(instruction.ip):
                        plt_sym = sym
                        self.call_parent[plt_sym] = parent
                    if self.test_ld(previous_instr.ip) and not self.test_ld(
                        instruction.ip
                    ):
                        self.call_parent[parent] = plt_sym
                    self.call_parent[sym] = parent
                    if self.test_hook_name(fname) and not self.test_ld(instruction.ip):
                        assert parent is not None and sym is not None
                        l.warning(parent.name + " ->(hook) " + sym.name)
                        is_current_hooked = True
                        first_meet = False
                        hooked_parent = parent
                        hook_idx = idx + self.start_idx
                else:
                    if self.test_omit(instruction.ip):
                        is_current_hooked = True
                        first_meet = False
                        assert previous_instr is not None
                        hooked_parent = self.find_function(previous_instr.ip)
                        hook_idx = idx + self.start_idx
            flg, fname = self.test_function_entry(instruction.ip)
            if (
                is_current_hooked
                and not first_meet
                and not self.test_plt_vdso(instruction.ip)
                and not self.test_ld(instruction.ip)
                and not self.test_omit(instruction.ip)
            ):
                present = True
                first_meet = True
                l.warning("entry: " + fname + " " + hex(instruction.ip))
            if present:
                self.new_trace.append(instruction)
                self.trace_idx.append(idx + self.start_idx)

    def filtered_trace(
        self, update: bool = False
    ) -> Tuple[List[Instruction], List[int], Dict[int, int]]:
        if self.new_trace and not update:
            return self.new_trace, self.trace_idx, self.hook_target
        self.analyze_trace()
        return self.new_trace, self.trace_idx, self.hook_target
