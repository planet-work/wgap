=============================
WGAP : Webserver Gets a Probe
=============================

**Auditing probe for webservers**

This tool is based on IoVisor/bcc and need a Linux 4.6+ kernel, headers.

The probe runs on webservers and sends events to a collector daemon ( hindsight <https://github.com/mozilla-services/hindsight>) or hekad <https://github.com/mozilla-services/heka> for example).



Minimum Requirements
====================

* Linux 4.6+
* Kernels image and headers (``linux-image-`` and ``linux-headers-``)
* Libbcc and python-bcc from https://github.com/iovisor/bcc
* Python 3.4


Optional Requirements
=====================

..  _py.test: http://pytest.org
..  _Sphinx: http://sphinx-doc.org

* `py.test`_ 2.7 (for running the test suite)
* `Sphinx`_ 1.3 (for generating documentation)


Events
======

The probes listens events from uid > 1000 (normal users):

* file write operations : ``__sys_open``
* TCP connect (80, 443, 25)  : ``__tcp_v4_connect``
* UDP packets sent (Dos) :
* Server socket listen: ``__inet_listen``
* Command execution : ``__sys_execve``


Event message format
====================

- timestamp : nanosecond
- event : FILE_WRITE, FILE_READ, TCP_CONN, UDP_PKT, SOCK_LISTEN, EXEC
- host : hostname
- uid
- gid
- pid
- namespace
- process_name
- cwd : current working directory of the process
- fields :
    - src_addr / dst_addr / src_port / dst_port
    - filename, filepath
    - ...



Basic Setup
===========

Install for the current user:

..  code-block::

    $ python setup.py install --user


Run the application:

..  code-block::

    $ python -m wgap --help


Run the test suite:

..  code-block::
   
    $ py.test test/


Build documentation:

..  code-block::

    $ cd doc && make html
    
    
Deploy the application in a self-contained `Virtualenv`_ environment:

..  _Virtualenv: https://virtualenv.readthedocs.org

..  code-block::

    $ python deploy.py /path/to/apps
    $ cd /path/to/apps/ && wgap/bin/cli --help
