""" Implement the cmd1 command.

"""
from __future__ import absolute_import

import os
from os.path import basename
import pwd
import platform
from subprocess import Popen, PIPE
# from time import sleep
import ctypes as ct
from ..core import logger
from ..core import config
from bcc import BPF
import fnmatch
# import json
import pprint
# import yaml

UID_CACHE = {}

TASK_COMM_LEN = 16    # linux/sched.h
NAME_MAX = 255        # linux/limits.h


class Event:
    def __init__(self):
        d = self.__dict__
        d['pid'] = 0
        d['uid'] = 0
        d['gid'] = 0
        d['username'] = ''
        d['groupname'] = ''
        d['file_name'] = ''
        d['file_inodenum'] = 0
        d['file_parentdir'] = ''
        d['progname'] = ''
        d['event'] = ''
        d['path'] = ''
        d['local_port'] = ''
        d['remote_port'] = ''
        d['remote_ip'] = ''


def get_username(uid):
    if uid in UID_CACHE:
        return UID_CACHE[uid]
    try:
        p = pwd.getpwuid(uid)
        UID_CACHE[uid] = p.pw_name
    except KeyError:
        UID_CACHE[uid] = '????'
    return UID_CACHE[uid]


def send_output(data):
    # j = json.dumps(data.__dict__)
    # print("%s %s/%s" % (data.username, data.file_parentdir, data.file_name))
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


class Data(ct.Structure):
    _fields_ = [
        ("id", ct.c_ulonglong),
        ("ts", ct.c_ulonglong),
        ("ret", ct.c_int),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("fname", ct.c_char * NAME_MAX),
        ("uid", ct.c_uint)
    ]

initial_ts = 0


# process event
def process_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    global initial_ts

    # if event.ret >= 0:
    #     fd_s = event.ret
    #     err = 0
    # else:
    #     fd_s = -1
    #     err = - event.ret

    if not initial_ts:
        initial_ts = event.ts

    evt = Event()
    evt.file_name = event.fname
    if basename(evt.file_name) in config.filter.exclude_files:
        return None
    evt.username = get_username(event.uid)

    for excl in config.filter.exclude_paths:
        if fnmatch.fnmatch(evt.file_parentdir, excl):
            return None

    evt.progname = event.comm.decode('utf-8')
    send_output(evt)


def main(**kwargs):
    """ Execute the command.

    """
    # Using kwargs to provide a generic interface across all commands.
    logger.debug("Execution run command")

    logger.debug("Check for kernel headers")
    kernel_v = platform.uname().release
    header_check = '/lib/modules/%s/build/include/linux/bpf.h' % kernel_v
    if not os.path.exists(header_check):
        logger.warning("No Kernel neaders found for %s" % kernel_v)
        pkgs = ['linux-headers-%s' % kernel_v, 'linux-image-%s' % kernel_v]
        if config.autoinstall_headers:
            logger.info("Installing packages ...")
            p = Popen(['apt-get', 'update'], stdout=PIPE)
            os.waitpid(p.pid, 0)
            p = Popen(['apt-get', 'install', '-y', pkgs[0], pkgs[1]])
            os.waitpid(p.pid, 0)

        else:
            logger.error("Please run  apt-get install -y %s" % ' '.join(pkgs))

    logger.debug("Generates BPF probe")
    bpf_text = create_bpf_probe()
    b = BPF(text=bpf_text)

    # Attach probe to configured entries
    logger.debug("Attach probe to %s" % ','.join(config.input))
    if 'file_read' in config.input:
        logger.debug("Attaching __sys_open")
        b.attach_kprobe(event="sys_open", fn_name="trace_sys_open_entry")
        b.attach_kretprobe(event="sys_open", fn_name="trace_sys_open_return")
    #
    # if 'file_read' in config.input:
    #    logger.debug("Attaching __vfs_read")
    #     b.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")
    # if 'file_write' in config.input:
    #     logger.debug("Attaching __vfs_write")
    #     b.attach_kprobe(event="__vfs_write", fn_name="trace_write_entry")

    # Main loop
    logger.debug("Starting main loop every %i seconds" % config.poll_interval)
    b["events"].open_perf_buffer(process_event)
    while 1:
        b.kprobe_poll()
    return 0
