# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
from __future__ import division

from ipaddress import ip_address

from six import PY2, text_type


def is_ip_address(hostname):
    try:
        ip_address(text_type(hostname))
    except ValueError:
        return False

    return True


def days_to_seconds(days):
    return int(days * 24 * 60 * 60)


def seconds_to_days(seconds):
    return seconds / 60 / 60 / 24


if PY2:
    from contextlib import closing as _closing

    def closing(sock):
        return _closing(sock)


else:

    def closing(sock):
        return sock
