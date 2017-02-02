""" Application commands common to all interfaces.

"""
from .run import main as run
from .test import main as test


__all__ = "run", "test"
