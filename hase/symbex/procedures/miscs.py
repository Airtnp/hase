from angr.sim_type import SimTypeInt, SimTypeString, SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength
from angr import SimProcedure
from angr.procedures import SIM_PROCEDURES


# TODO: getlogin, getpwuid


class setlocale(SimProcedure):
    def run(self, category, locale):
        self.argument_types = {
            0: SimTypeInt(32, True),
            1: self.ty_ptr(SimTypeString())
        }
        self.return_type = self.ty_ptr(SimTypeString())
        # FIXME: just symbolic maxlen string
        max_str_len = self.state.libc.max_str_len
        malloc = SIM_PROCEDURES['libc']['malloc']
        str_addr = self.inline_call(malloc, max_str_len).ret_expr
        return self.state.se.If(
            self.state.se.BoolS("setlocale_flag"),
            str_addr,
            self.state.se.BVV(0, self.state.arch.bits)
        )


'''
# NOTE: getenv relies on __environ and modifies rbp
   0x00007ffff7a46786 <+22>:	mov    r13,rax
   0x00007ffff7a46789 <+25>:	mov    rax,QWORD PTR [rip+0x38a728]        # 0x7ffff7dd0eb8
   0x00007ffff7a46790 <+32>:	mov    rbp,QWORD PTR [rax]
   0x00007ffff7a46793 <+35>:	test   rbp,rbp
   0x00007ffff7a46796 <+38>:	je     0x7ffff7a46848 <__GI_getenv+216>
which we cannot repair on unsat path.
'''
class getenv(SimProcedure):
    def run(self, name):
        max_str_len = self.state.libc.max_str_len
        malloc = SIM_PROCEDURES['libc']['malloc']
        str_addr = self.inline_call(malloc, max_str_len).ret_expr
        return self.state.se.If(
            self.state.se.BoolS("getenv_flag"),
            str_addr,
            self.state.se.BVV(0, self.state.arch.bits)
        )


# FIXME: do real things
# NOTE: angr sigaction does nothing now
class sigaction(SimProcedure):
    def run(self, signum, act, oact):
        return self.state.se.BVV(0, self.state.arch.bits)


# FIXME: do real things
class atexit(SimProcedure):
    def run(self, func_ptr):
        return self.state.se.BVV(0, self.state.arch.bits)


class __cxa_atexit(SimProcedure):
    def run(self, func_ptr, arg, dso_handle):
        return self.state.se.BVV(0, self.state.arch.bits)


class gethostid(SimProcedure):
    def run(self):
        return self.state.se.BVS('hostid', self.state.arch.bits)


class sethostid(SimProcedure):
    def run(self, hostid):
        self.state.hostid = hostid
        return self.state.se.BVV(0, 32)


class gettext(SimProcedure):
    def run(self, msgid):
        malloc = SIM_PROCEDURES['libc']['malloc']
        str_addr = self.inline_call(malloc, self.state.libc.max_str_len).ret_expr
        return self.state.se.If(
            self.state.se.BoolS('gettext'),
            str_addr,
            msgid
        )


class dgettext(SimProcedure):
    def run(self, domain, msgid):
        return self.inline_call(gettext, msgid).ret_expr


class dcgettext(SimProcedure):
    def run(self, domain, msgid, category):
        return self.inline_call(gettext, msgid).ret_expr