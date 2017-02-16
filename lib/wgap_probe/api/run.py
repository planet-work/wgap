""" Implement the cmd1 command.

"""
from __future__ import absolute_import

import os
import pwd
import platform
from subprocess import Popen, PIPE
from time import sleep
from ..core import logger
from ..core import config
from bcc import BPF
# import json
import pprint
# import yaml

UID_CACHE = {}


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
    p = pwd.getpwuid(uid)
    UID_CACHE[uid] = p.pw_name
    return p.pw_name


def send_output(data):
    print("~"*80)
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
        logger.debug("Attaching __vfs_read")
        b.attach_kprobe(event="__vfs_read", fn_name="trace_read_entry")
    if 'file_write' in config.input:
        logger.debug("Attaching __vfs_write")
        b.attach_kprobe(event="__vfs_write", fn_name="trace_write_entry")

    # Main loop
    logger.debug("Starting main loop every %i seconds" % config.poll_interval)
    exiting = 0
    while 1:
        try:
            sleep(config.poll_interval)
        except KeyboardInterrupt:
            exiting = 1

        counts = b.get_table("fileops")

        print(dir(counts))
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
            evt.type = '%1s' % k.type.decode('utf-8')
            evt.file_name = k.name.decode('utf-8')
            parents = [k.parent1.decode('utf-8'),
                       k.parent2.decode('utf-8'),
                       k.parent3.decode('utf-8'),
                       k.parent4.decode('utf-8')]
            parents = list(filter(None, parents))
            parents.reverse()
            evt.file_parentdir = '/'.join(parents).replace('//', '/')
            evt.file_inodenum = int(k.inode)
            evt.uid = int(k.uid)
            evt.progname = k.comm.decode('utf-8')
            # evt.gid = k.gid
            send_output(evt)

            # 1 event for DEBUG
            logger.error("TEST MODE STOPPING!")
            exiting = 1

        if exiting:
            logger.debug("Detaching...")
            exit()

    return 0
