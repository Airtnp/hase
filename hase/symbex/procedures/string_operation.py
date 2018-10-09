from __future__ import absolute_import, division, print_function

import claripy
from angr import SimProcedure
from angr.errors import SimProcedureError
from angr.procedures import SIM_PROCEDURES
from angr.sim_type import (SimTypeArray, SimTypeChar, SimTypeFd, SimTypeInt,
                           SimTypeLength, SimTypeString)


class atof(SimProcedure):
    def run(self, ptr):
        return self.state.solver.FPS("atof", self.state.solver.fp.FSORT_DOUBLE)


class strtof(SimProcedure):
    def run(self, nptr, endptr):
        return self.state.solver.FPS("strtof", self.state.solver.fp.FSORT_FLOAT)


class strtof_l(SimProcedure):
    def run(self, nptr, endptr, locale):
        return self.state.solver.FPS("strtof_l", self.state.solver.fp.FSORT_FLOAT)


class strtod(SimProcedure):
    def run(self, nptr, endptr):
        return self.state.solver.FPS("strtod", self.state.solver.fp.FSORT_DOUBLE)


class strtod_l(SimProcedure):
    def run(self, nptr, endptr, locale):
        return self.state.solver.FPS("strtod_l", self.state.solver.fp.FSORT_DOUBLE)


# FIXME: no long double in claripy.fp now
class strtold(SimProcedure):
    def run(self, nptr, endptr):
        return self.state.solver.FPS("strtold", self.state.solver.fp.FSORT_DOUBLE)


class strtold_l(SimProcedure):
    def run(self, nptr, endptr, locale):
        return self.state.solver.FPS("strtold_l", self.state.solver.fp.FSORT_DOUBLE)


class strspn(SimProcedure):
    def run(self, str1, str2):
        return self.state.solver.Unconstrained(
            "strspn", self.state.arch.bits, uninitialized=False
        )


class strcspn(SimProcedure):
    def run(self, str1, str2):
        return self.state.solver.Unconstrained(
            "strspn", self.state.arch.bits, uninitialized=False
        )
