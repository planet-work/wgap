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
from struct import pack
import datetime
import ctypes as ct
from ..core import logger
from ..core import config
from bcc import BPF
import fnmatch
import json
# import pprint
# import yaml
import http.client
from socket import SOCK_STREAM, SOCK_DGRAM, AF_INET, AF_INET6, inet_ntop, \
    gethostname, ntohs
import netaddr

UID_CACHE = {}
TASK_COMM_LEN = 16    # linux/sched.h
NAME_MAX = 255        # linux/limits.h
HOSTNAME = gethostname()
TENANT_ID = ''
TENANT = ''

try:
    TENANT = os.getenv('TENANT')
except KeyError:
    TENANT = ''

has_heka = False
try:
    from ..heka import Message, INFO, HekaConnection
    has_heka = True
except ImportError:
    logger.error("Cannot import heka python lib")
    pass

heka_conn = None


class Event:
    def __init__(self):
        d = self.__dict__
        d['event'] = ''
        d['hostname'] = HOSTNAME
        d['tenant'] = TENANT
        d['timestamp'] = mktime(gmtime())
        d['pid'] = 0
        d['uid'] = 0
        d['user'] = ''
        d['message'] = ''
        d['fields'] = {}


def get_user(uid):
    if uid in UID_CACHE:
        return UID_CACHE[uid]
    try:
        p = getpwuid(uid)
        UID_CACHE[uid] = p.pw_name
    except KeyError:
        UID_CACHE[uid] = '????'
    return UID_CACHE[uid]


class DateTimeEncoder(json.JSONEncoder):
    """JSON serializer for objects not serializable by default json code"""
    def default(self, o):
        if isinstance(o, datetime.datetime):
            return o.isoformat()
        return json.JSONEncoder.default(self, o)


def send_output(data):
    if 'console' in config.output:
        print('%s %s' % (data.timestamp.isoformat(), data.message))

    if 'heka' in config.output and has_heka:
        address = config.output.heka.address.split(':')[0]
        port = int(config.output.heka.address.split(':')[1])
        # if not heka_conn:
        heka_conn = HekaConnection('%s:%i' % (address, port))

        fields = {
            'message': data.message,
            'event': data.event,
            'tenant': data.tenant,
            'appname': data.appname,
            'user': data.user,
            'uid': data.uid,
            'pid': data.pid,
            'timestamp': data.timestamp.isoformat()       # ISO 8601 UTC
        }
        for f in data.fields.keys():
            fields[f] = data.fields[f]

        ts_us = float(data.timestamp.strftime('%s.%f'))
        ts_ns = int(ts_us*1e9)
        msg = Message(
            logger='wgap',
            type='probe_event',
            hostname=data.hostname,
            timestamp=ts_ns,
            severity=INFO,
            fields=fields
        )
        heka_conn.send_message(msg)

    if 'collector' in config.output and data.event == 'file_write':
        data.timestamp = data.timestamp.isoformat()
        params = json.dumps(data.__dict__, cls=DateTimeEncoder)
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
        p_if = ' && '.join(['dport == %d' % ntohs(dport)
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
    evt.appname = event.comm.decode('utf-8')
    evt.user = get_user(event.uid)
    # evt.timestamp = time.mktime(time.gmtime())
    evt.timestamp = datetime.datetime.now(datetime.timezone.utc)

    evt.message = '%s@%s %s[%i] %s: ' % (evt.user,
                                         evt.tenant,
                                         evt.appname,
                                         evt.pid,
                                         evt.event)

    if mode in ['R', 'W']:
        evt.fields['filename'] = event.data1.decode('utf-8')
        if config.filter.include_files:
            keep = False
            for ext in config.filter.include_files:
                if fnmatch.fnmatch(evt.fields['filename'], ext):
                    keep = True
            if not keep:
                return None

        for excl in config.filter.exclude_files:
            if fnmatch.fnmatch(evt.fields['filename'], excl):
                return None
        evt.message += evt.fields['filename']
    elif mode == 'E':
        evt.fields['filename'] = event.data1.decode('utf-8')
        if evt.fields['filename'] in [' ', ''] or evt.fields['filename'] in \
                config.filter.exclude_progs:
            return None
        evt.message += evt.fields['filename']
    elif mode in ['L', 'C']:
        print("PROTO: %i" % event.proto)
        proto_family = event.proto & 0xff
        proto_type = event.proto >> 16 & 0xff
        # print("Proto: " + repr(event.proto))
        # print("ProtoT=%i" % proto_type)
        # print("ProtoF=%i" % proto_family)
        # print("lAddr0: " + repr(event.laddr[0]))
        # print("rAddr0: " + repr(event.raddr[0]))

        if proto_family == SOCK_STREAM:
            protocol = "TCP"
        elif proto_family == SOCK_DGRAM:
            protocol = "UDP"
        else:
            protocol = "UNK"
        laddress = ""
        raddress = ""
        # TODO IPv6 support
        if proto_type == AF_INET or True:
            protocol += "v4"
            laddress = inet_ntop(AF_INET, pack("I", event.laddr[0]))
            raddress = inet_ntop(AF_INET, pack("I", event.raddr[0]))
        elif proto_type == AF_INET6:
            laddress = netaddr.IPAddress(event.laddr[0] << 64 | event.laddr[1],
                                         version=6)
            raddress = netaddr.IPAddress(event.raddr[0] << 64 | event.raddr[1],
                                         version=6)
            protocol += "v5"
        evt.fields['localPort'] = event.lport
        evt.fields['remotePort'] = event.rport
        evt.fields['localAddr'] = '%s' % laddress
        evt.fields['remoteAddr'] = '%s' % raddress
        evt.fields['protocol'] = protocol

        evt.message += '[%s]:%i' % (evt.fields['localAddr'],
                                    evt.fields['localPort'])
        if mode == 'C':
            evt.message += ' > [%s]:%i (%s)' % (evt.fields['remoteAddr'],
                                                evt.fields['remotePort'],
                                                evt.fields['protocol'])

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
