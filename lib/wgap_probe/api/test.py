""" Implement the cmd2 command.

"""
from __future__ import absolute_import
import sys
import os

from ..core import logger


def main(**kwargs):
    """ Execute the command.

    """
    # Using kwargs to provide a generic interface across all commands.
    logger.debug("executing test command")
    try:
        from bcc import BPF
    except ImportError:
        logger.error("Unable to import bcc, please install python-bcc")
        sys.exit(1)
    if os.getuid() != 0:
        logger.error("Need super-user privileges to run")
        sys.exit(1)
    logger.warning("Compiling program ...")
    text = """int kprobe__sys_clone(void *ctx) {
                  bpf_trace_printk("Hello, World!\\n");
                  return 0; \
             }
    """
    b = BPF(text=text)
    logger.warning("Running, wait for a 'clone' ")
    (prog, pid, counter, foo, time, msg) = b.trace_fields()
    print("OK: pid=%i, prog=%s, msg=%s" % (pid, prog, msg))
    return 0
