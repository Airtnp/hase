from __future__ import absolute_import, division, print_function

import sys
import shutil
import errno
import json

from collections import OrderedDict, defaultdict

RECV_MESSAGE = "GOT COREDUMP"

try:
    from typing import List, Any, IO, DefaultDict, Dict
except ImportError:
    pass

EXTRA_CORE_DUMP_PARAMETER = OrderedDict([
    ("executable", "%E"),  # path of executable
    ("uid", "%u"),  # user id
    ("gid", "%g"),  # group id
    ("containerized_tid", "%i"),  # thread id in process's PID namespace
    ("global_tid", "%I"),  # thread id in global PID namespace
    ("containerized_pid", "%p"),  # process id in process's PID namespace
    ("global_pid", "%P"),  # process id in global PID namespace
    ("signal", "%s"),  # signal causing dump
    ("time", "%t"),  # time of core dump
])


def process_coredump(os_args, core_file, manifest_file):
    # type: (List[str], IO[Any], IO[Any]) -> None
    shutil.copyfileobj(sys.stdin, core_file)

    metadata = defaultdict(dict)  # type: DefaultDict[str, Any]
    for name, arg in zip(EXTRA_CORE_DUMP_PARAMETER.keys(), os_args):
        metadata["coredump"][name] = arg

    pid = int(metadata["coredump"]["global_pid"])

    json.dump(metadata, manifest_file, indent=4, sort_keys=True)


def main(args):
    # type: (List[str]) -> None
    nargs = 1  # argv[0]
    nargs += len(EXTRA_CORE_DUMP_PARAMETER)
    nargs += 3  # arguments from our self
    msg = "Expected %d arguments, got %d: %s" % (nargs, len(sys.argv),
                                                 sys.argv)
    assert len(sys.argv) == nargs, msg

    fifo_path = args[1]
    core_dump_path = args[2]
    manifest_path = args[3]

    write_response = True
    try:
        with open(core_dump_path, "wbx") as core_file, \
                open(manifest_path, "wbx") as manifest_file:
            process_coredump(args[4:], core_file, manifest_file)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise
        # a second exception was thrown while we are still busy collecting the
        # current one, ignore this one
        print(
            "%s already exists, this means another coredump was generated while we are processing the first one!",
            file=sys.stderr)
        write_response = False
    finally:
        if write_response:
            with open(fifo_path, "w") as f:
                f.write(RECV_MESSAGE)


if __name__ == "__main__":
    print(sys.argv)
    main(sys.argv)