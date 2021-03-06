from __future__ import absolute_import, division, print_function

import sys
import os
import tempfile
import resource
# TODO python3
from pipes import quote
from typing import Optional, IO, Any
import logging

from .coredump_handler import RECV_MESSAGE, EXTRA_CORE_DUMP_PARAMETER
from ..path import which

l = logging.getLogger(__name__)

HANDLER_PATH = "/proc/sys/kernel/core_pattern"

COREDUMP_FILTER_PATH = "/proc/self/coredump_filter"

# core(5) on coredump filter
# bit 0  Dump anonymous private mappings.
# bit 1  Dump anonymous shared mappings.
# bit 2  Dump file-backed private mappings.
# bit 3  Dump file-backed shared mappings.
# bit 4 (since Linux 2.6.24)
#        Dump ELF headers.
# bit 5 (since Linux 2.6.28)
#        Dump private huge pages.
# bit 6 (since Linux 2.6.28)
#        Dump shared huge pages.
# bit 7 (since Linux 4.4)
#        Dump private DAX pages.
# bit 8 (since Linux 4.4)
#        Dump shared DAX pages.


class Coredump(object):
    def __init__(self, core_file, fifo_path):
        # type: (str, str) -> None
        self.core_file = core_file
        self.fifo_path = fifo_path
        self.fifo_file = None  # type: Optional[IO[Any]]

    def get(self):
        # type: () -> str
        l.info("wait for fifo %s", self.fifo_path)
        self.fifo_file = open(self.fifo_path)
        msg = self.fifo_file.read(len(RECV_MESSAGE))
        assert msg == RECV_MESSAGE, "got '%s' from fifo, expected: '%s'" % (
            msg, RECV_MESSAGE)
        return self.core_file

    def remove(self):
        # type: () -> None
        os.unlink(self.core_file)
        if self.fifo_file is not None:
            self.fifo_file.close()
        os.unlink(self.fifo_path)


class Handler(object):
    def __init__(self,
                 perf_pid,
                 core_file,
                 fifo_path,
                 manifest_path,
                 log_path="/tmp/coredump.log"):
        # type: (int, str, str, str, str) -> None
        self.previous_pattern = None
        self.old_core_rlimit = None
        self.handler_script = None
        self.core_file = core_file
        self.fifo_path = fifo_path
        self.manifest_path = manifest_path
        self.log_path = log_path
        os.mkfifo(fifo_path)

        self.perf_pid = perf_pid

    def __enter__(self):
        # () -> Coredump

        kill_command = which("kill")
        assert kill_command is not None

        self.handler_script = tempfile.NamedTemporaryFile(
            prefix="core_handler", delete=False)
        os.chmod(self.handler_script.name, 0o755)
        assert len(self.handler_script.name) < 128

        script_template = """#!/bin/sh
exec 1>>{log_path}
exec 2>&1

{kill} -SIGUSR2 "{perf_pid}" "{hase_pid}"
{kill} -SIGTERM "{perf_pid}"

export PYTHONPATH={pythonpath}

exec {python} -m hase.record.coredump_handler {fifo_path} {core_file} {manifest_path} "$@"
"""

        script_content = script_template.format(
            kill=kill_command,
            perf_pid=self.perf_pid,
            hase_pid=os.getpid(),
            python=quote(sys.executable),
            pythonpath=":".join(sys.path),
            fifo_path=quote(self.fifo_path),
            core_file=quote(self.core_file),
            log_path=quote(self.log_path),
            manifest_path=quote(self.manifest_path))

        self.handler_script.write(script_content)
        self.handler_script.close()

        inf = resource.RLIM_INFINITY
        self.old_core_rlimit = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (inf, inf))

        with open(HANDLER_PATH, "rb+") as f,\
                open(COREDUMP_FILTER_PATH, "w+") as filter_file:
            self.previous_pattern = f.read()
            f.seek(0)
            extra_args = " ".join(EXTRA_CORE_DUMP_PARAMETER.values())
            f.write('|{} {}'.format(self.handler_script.name, extra_args))

            # just dump everything into core dumps and worry later
            filter_file.write("0xff\n")
            filter_file.flush()

            return Coredump(self.core_file, self.fifo_path)

    def __exit__(self, type, value, traceback):
        with open(HANDLER_PATH, "w") as f:
            f.write(self.previous_pattern)
        if self.old_core_rlimit is not None:
            resource.setrlimit(resource.RLIMIT_CORE, self.old_core_rlimit)
        if self.handler_script is not None:
            os.unlink(self.handler_script.name)
