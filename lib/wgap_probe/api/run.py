""" Implement the cmd1 command.

"""
from __future__ import absolute_import

import sys
import os
from pwd import getpwuid
import platform
from time import gmtime, mktime
from subprocess import Popen, PIPE
# from time import sleep
import ctypes as ct
from ..core import logger
from ..core import config
from bcc import BPF
import fnmatch
import json
import pprint
# import yaml
import http.client
import socket
import netaddr

UID_CACHE = {}

TASK_COMM_LEN = 16    # linux/sched.h
NAME_MAX = 255        # linux/limits.h
HOSTNAME = socket.gethostname()


class Event:
    def __init__(self):
        d = self.__dict__
        d['hostname'] = HOSTNAME
        d['timestamp'] = mktime(gmtime())
        d['pid'] = 0
        d['uid'] = 0
        d['gid'] = 0
        d['username'] = ''
        d['groupname'] = ''
        d['filename'] = ''
        d['progname'] = ''
        d['event'] = ''
        d['path'] = ''
        d['protocol'] = ''
        d['local_port'] = ''
        d['remote_port'] = ''
        d['remote_ip'] = ''


def get_username(uid):
    if uid in UID_CACHE:
        return UID_CACHE[uid]
    try:
        p = getpwuid(uid)
        UID_CACHE[uid] = p.pw_name
    except KeyError:
        UID_CACHE[uid] = '????'
    return UID_CACHE[uid]


def send_output(data):
    if True:
        pprint.pprint(data.__dict__)

    if 'console' in config.output:
        print("%s %s %s %s[%i]" % (
                            data.event,
                            data.username,
                            data.filename,
                            data.progname,
                            data.pid))

    if 'collector' in config.output:
        params = json.dumps(data.__dict__)
        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}
        address = config.output.collector.address.split(':')[0]
        port = int(config.output.collector.address.split(':')[1])
        conn = http.client.HTTPConnection(address, int(port))
        try:
            conn.request("POST", "", params, headers)
        except:
            logger.error("Cannot sent event to collector:%s" %
                         sys.exc_info()[0])


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
        bpf_text = bpf_text.replace('UID_FILTER',
                                    'uid < %i || uid == 65534' % uid_min)
    else:
        bpf_text = bpf_text.replace('UID_FILTER', '0')

    if 'exclude_ports' in config.filter:
        dports = config.filter.exclude_ports
        p_if = ' && '.join(['dport == %d' % socket.ntohs(dport)
                            for dport in dports])
        bpf_text = bpf_text.replace('PORT_FILTER', p_if)
    else:
        bpf_text = bpf_text.replace('PORT_FILTER', '0')

    if 'file_read' in config.input and 'file_write' not in config.input:
        bpf_text = bpf_text.replace('MODE_FILTER', "val.mode != 'R'")
    elif 'file_write' in config.input and 'file_read' not in config.input:
        bpf_text = bpf_text.replace('MODE_FILTER', "val.mode != 'W'")
    else:
        bpf_text = bpf_text.replace('MODE_FILTER', '0')

    return bpf_text


class Data(ct.Structure):
    _fields_ = [
        ("id", ct.c_ulonglong),
        ("ts_us", ct.c_ulonglong),
        ("ret", ct.c_int),
        ("pid", ct.c_uint),
        ("uid", ct.c_uint),
        ("gid", ct.c_uint),
        ("mode", ct.c_char),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("data1", ct.c_char * NAME_MAX),
        ("proto", ct.c_ulonglong),
        ("laddr", ct.c_ulonglong * 2),
        ("raddr", ct.c_ulonglong * 2),
        ("lport", ct.c_ulonglong),
        ("rport", ct.c_ulonglong),

    ]


initial_ts = 0


# process event
def process_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents
    global initial_ts

    if not initial_ts:
        initial_ts = event.ts_us

    evt = Event()

    mode = event.mode.decode('ascii')
    if mode == 'R':
        evt.event = 'file_read'
    elif mode == 'W':
        evt.event = 'file_write'
    elif mode == 'E':
        evt.event = 'execve'
    elif mode == 'L':
        evt.event = 'inet_listen'
    elif mode == 'C':
        evt.event = 'tcp_connect'
    elif mode == 'U':
        evt.event = 'udp'

    evt.uid = event.uid
    # evt.gid = event.gid
    evt.pid = event.pid
    evt.progname = event.comm.decode('utf-8')
    evt.username = get_username(event.uid)
    evt.timestamp = event.ts_us

    if mode in ['R', 'W']:
        evt.filename = event.data1.decode('utf-8')
        if config.filter.include_files:
            keep = False
            for ext in config.filter.include_files:
                if fnmatch.fnmatch(evt.filename, ext):
                    keep = True
            if not keep:
                return None

        for excl in config.filter.exclude_files:
            if fnmatch.fnmatch(evt.filename, excl):
                return None
    elif mode == 'E':
        evt.filename = event.data1.decode('utf-8')
    elif mode in ['L', 'C']:
        proto_family = event.proto & 0xff
        proto_type = event.proto >> 16 & 0xff

        if proto_family == socket.SOCK_STREAM:
            protocol = "TCP"
        elif proto_family == socket.SOCK_DGRAM:
            protocol = "UDP"
        else:
            protocol = "UNK"
        laddress = ""
        raddress = ""
        if proto_type == socket.AF_INET:
            protocol += "v4"
            laddress = netaddr.IPAddress(event.laddr[0])
            raddress = netaddr.IPAddress(event.raddr[0])
        elif proto_type == socket.AF_INET6:
            laddress = netaddr.IPAddress(event.laddr[0] << 64 | event.laddr[1],
                                         version=6)
            raddress = netaddr.IPAddress(event.raddr[0] << 64 | event.raddr[1],
                                         version=6)
            protocol += "v5"
        evt.local_port = event.lport
        evt.remote_port = event.rport
        evt.local_ip = '%s' % laddress
        evt.remote_ip = '%s' % raddress
        evt.protocol = protocol

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
    if 'file_read' in config.input or 'file_write' in config.input:
        logger.debug("Attaching __sys_open")
        b.attach_kprobe(event="sys_open", fn_name="trace_sys_open_entry")
        b.attach_kretprobe(event="sys_open", fn_name="trace_sys_open_return")
    if 'execve' in config.input:
        logger.debug("Attaching __sys_execve")
        b.attach_kprobe(event="sys_execve", fn_name="trace_sys_execve")
    if 'tcp_connect' in config.input:
        logger.debug("Attaching __tcp_connect")
        b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
        b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
        b.attach_kretprobe(event="tcp_v4_connect",
                           fn_name="trace_connect_v4_return")
        b.attach_kretprobe(event="tcp_v6_connect",
                           fn_name="trace_connect_v6_return")

    if 'inet_listen' in config.input:
        logger.debug("Attaching __inet_listen")
        b.attach_kprobe(event="inet_listen", fn_name="trace_inet_listen")

    # Main loop
    logger.debug("Starting main loop every %i seconds" % config.poll_interval)
    b["events"].open_perf_buffer(process_event)
    while 1:
        b.kprobe_poll()
    return 0
