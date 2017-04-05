"""
Severity levels. Adapted from RFC 5424 and Heka documentation.

"""

# Severity levels as defined in RFC 5424.
EMERGENCY = 0
ALERT = 1
CRITICAL = 2
ERROR = 3
WARNING = 4
NOTICE = 5
INFORMATIONAL = 6
DEBUG = 7


# Aliases for convinience.
EMERG = PANIC = EMERGENCY
CRIT = CRITICAL
ERR = ERROR
WARN = WARNING
INFO = INFORMATIONAL
