""" Implement the cmd1 command.

"""
from __future__ import absolute_import

import os
import pwd
from time import sleep
from ..core import logger
from ..core import config
from bcc import BPF
# import json
import pprint
# import yaml

UID_CACHE = {}
INTERVAL = 1


class Event:
    def __init__(self):
        d = self.__dict__
        d['pid'] = 0
        d['uid'] = 0
        d['gid'] = 0
        d['username'] = ''
        d['groupname'] = ''
        d['filename'] = ''
        d['progname'] = ''
        d['event'] = ''
        d['path'] = ''
        d['local_port'] = ''
        d['remote_port'] = ''
        d['remote_ip'] = ''


def get_username(uid):
    if uid in UID_CACHE:
        return UID_CACHE[uid]
    p = pwd.getpwuid(uid)
    UID_CACHE[uid] = p.pw_name
    return p.pw_name


def send_output(data):
    print("~"*100)
    # j = json.dumps(data.__dict__)
    if 'console' in config.output:
        pprint.pprint(data.__dict__)


def create_bpf_probe():
    """ Generates BPF C source code from template and configuration

    """
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
    return bpf_text


def main(**kwargs):
    """ Execute the command.

    """
    # Using kwargs to provide a generic interface across all commands.
    logger.debug("Execution run command")

    logger.debug("Generates BPF probe")
    bpf_text = create_bpf_probe()
    b = BPF(text=bpf_text)

    # Attach probe to configured entries
    logger.debug("Attach probe to %s" % ','.join(config.input))
    if 'file_read' in config.input:
        b.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")
    if 'file_write' in config.input:
        b.attach_kprobe(event="__vfs_write", fn_name="trace_write_entry")

    exiting = 0
    # Main loop
    logger.debug("Starting main loop every %i seconds" % INTERVAL)
    while 1:
        try:
            sleep(INTERVAL)
        except KeyboardInterrupt:
            exiting = 1

        counts = b.get_table("counts")

        continue
        for k, v in reversed(sorted(counts.items(),
                                    key=lambda counts: counts[1].rbytes)):
            evt = Event()
            name = k.name
            if name in config.filter.exclude_files:
                continue
            k.user = get_username(k.uid)
            if k.user in config.filter.exclude_users:
                continue
            evt.pid = int(k.pid)
            evt.username = k.user
            evt.type = k.type
            evt.filename = k.name.decode('utf-8')
            evt.uid = int(k.uid)
            evt.progname = k.comm.decode('utf-8')
            # evt.gid = k.gid
            send_output(evt)

        if exiting:
            print("Detaching...")
            exit()

    return 0
