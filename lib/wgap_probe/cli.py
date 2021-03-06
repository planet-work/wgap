""" Implementation of the command line interface.

"""
from __future__ import absolute_import

from argparse import ArgumentParser

from . import __version__
from .api import run
from .api import test
from .core import config
from .core import logger


__all__ = "main",


def _cmdline(argv=None):
    """ Parse command line arguments.

    """
    parser = ArgumentParser()
    parser.add_argument(
        "-c", "--config", action="append",
        help="config file [/etc/wgap-probe/config.yml]")
    parser.add_argument(
        "-v", "--version", action="version",
        version="wgap {:s}".format(__version__.__version__),
        help="print version and exit"
    )
    # parser.add_argument(
    #         "-d", "--debug", default="DEBUG",
    #        help="logger debug level [DEBUG]")
    parser.add_argument(
        "-w", "--warn", default="WARNING",
        help="logger warning level [WARNING]")
    subparsers = parser.add_subparsers(title="commands")
    run_parser = subparsers.add_parser("run")
    run_parser.set_defaults(command=run)
    test_parser = subparsers.add_parser("test")
    test_parser.set_defaults(command=test)
    args = parser.parse_args(argv)
    if not args.config:
        # Don't specify this as an argument default or else it will always be
        # included in the list.
        args.config = ["/etc/wgap-probe/config.yml"]
    # if not args.command:
    #     args.command = 'run'
    return args


def main(argv=None):
    """ Execute the application CLI.

    Arguments are taken from sys.argv by default.

    """
    args = _cmdline(argv)
    logger.start(args.warn)
    logger.info("starting execution")
    config.load(args.config)
    try:
        logger.setLevel(config.loglevel)
    except KeyError:
        pass
    args.command(**vars(args))
    logger.info("successful completion")
    return 0


# Make the module executable.

if __name__ == "__main__":
    try:
        status = main()
    except:
        logger.critical("shutting down due to fatal error")
        raise  # print stack trace
    else:
        raise SystemExit(status)
