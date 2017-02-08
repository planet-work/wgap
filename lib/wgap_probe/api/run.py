""" Implement the cmd1 command.

"""
from __future__ import absolute_import

import os
import pwd
from time import sleep
from ..core import logger
from ..core import config
from bcc import BPF
import json

UID_CACHE = {}
INTERVAL = 1


def get_username(uid):
    if uid in UID_CACHE:
        return UID_CACHE[uid]
    p = pwd.getpwuid(uid)
    UID_CACHE[uid] = p.pw_name
    return p.pw_name


def send_output(data):
    json.dumps(data)


def main(**kwargs):
    """ Execute the command.

    """
    # Using kwargs to provide a generic interface across all commands.
    logger.debug("executing run command")
    bpf_text = ''
    src_path = os.path.dirname(__file__)
    f = open(src_path + '/bpf_probe.c')
    bpf_text = ''.join(f.readlines())
    f.close()

    bpf_text = bpf_text.replace('TGID_FILTER', '0')
    bpf_text = bpf_text.replace('TYPE_FILTER', '!S_ISREG(mode)')

    if 'gid_min' in config.filter:
        gid_min = config.filter.gid_min
        bpf_text = bpf_text.replace('GID_FILTER', 'gid < %i' % gid_min)
    else:
        bpf_text = bpf_text.replace('GID_FILTER', '0')

    if 'uid_min' in config.filter:
        uid_min = config.filter.uid_min
        bpf_text = bpf_text.replace('UID_FILTER', 'uid < %i' % uid_min)
    else:
        bpf_text = bpf_text.replace('UID_FILTER', '0')

    b = BPF(text=bpf_text)

    if 'file_read' in config.input:
        b.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")
    if 'file_write' in config.input:
        b.attach_kprobe(event="__vfs_write", fn_name="trace_write_entry")

    return 0

    exiting = 0
    while 1:
        try:
            sleep(INTERVAL)
        except KeyboardInterrupt:
            exiting = 1

        counts = b.get_table("counts")

        for k, v in reversed(sorted(counts.items(),
                                    key=lambda counts: counts[1].rbytes)):
            name = k.name
            if name in config.filter.exclude_files:
                continue
            k.user = get_username(k.uid)
            print("%s %s" % (k.user, k.name))
            if k.user not in ['planet-work']:
                continue
            print(
              "%-6d %-16s %-6d %-6d %-7d %-7d %1s %s" % (
                  k.pid, k.user,
                  v.reads, v.writes, v.rbytes / 1024, v.wbytes / 1024, k.type,
                  name)
            )

        if exiting:
            print("Detaching...")
            exit()

    return 0
