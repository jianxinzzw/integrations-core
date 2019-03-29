# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import pytest

from datadog_checks.tls import TLSCheck
from datadog_checks.tls.utils import days_to_seconds

from .utils import download_cert, temp_binary


@pytest.fixture(scope='session', autouse=True)
def dd_environment():
    yield {'host': 'https://www.google.com'}


@pytest.fixture
def local_not_found():
    instance = {'local_cert_path': 'not_found.pem'}
    yield TLSCheck('tls', {}, [instance])


@pytest.fixture(scope='session')
def local_ok():
    with download_cert('ok.pem', 'https://www.google.com') as cert:
        instance = {'local_cert_path': cert}

        yield TLSCheck('tls', {}, [instance])


@pytest.fixture(scope='session')
def local_ok_der():
    with download_cert('ok.crt', 'https://www.google.com', raw=True) as cert:
        instance = {'local_cert_path': cert}

        yield TLSCheck('tls', {}, [instance])


@pytest.fixture(scope='session')
def local_hostname():
    instance = {'server_hostname': 'www.google.com'}

    with download_cert('ok.pem', instance['server_hostname']) as cert:
        instance['local_cert_path'] = cert

        yield TLSCheck('tls', {}, [instance])


@pytest.fixture(scope='session')
def local_hostname_mismatch():
    with download_cert('mismatch.pem', 'www.bing.com') as cert:
        instance = {'local_cert_path': cert, 'server_hostname': 'www.google.com'}

        yield TLSCheck('tls', {}, [instance])


@pytest.fixture(scope='session')
def local_cert_bad():
    with temp_binary(b'junk') as f:
        instance = {'local_cert_path': f}

        yield TLSCheck('tls', {}, [instance])


@pytest.fixture(scope='session')
def local_cert_expired():
    with download_cert('expired.pem', 'https://expired.badssl.com') as cert:
        instance = {'local_cert_path': cert}

        yield TLSCheck('tls', {}, [instance])


@pytest.fixture(scope='session')
def local_cert_critical_days():
    with download_cert('critical.pem', 'https://www.google.com') as cert:
        instance = {'local_cert_path': cert, 'days_critical': 1000}

        yield TLSCheck('tls', {}, [instance])


@pytest.fixture(scope='session')
def local_cert_critical_seconds():
    with download_cert('critical.pem', 'https://www.google.com') as cert:
        instance = {'local_cert_path': cert, 'days_critical': -1, 'seconds_critical': days_to_seconds(1000)}

        yield TLSCheck('tls', {}, [instance])


@pytest.fixture(scope='session')
def local_cert_warning_days():
    with download_cert('warning.pem', 'https://www.google.com') as cert:
        instance = {'local_cert_path': cert, 'days_warning': 1000}

        yield TLSCheck('tls', {}, [instance])


@pytest.fixture(scope='session')
def local_cert_warning_seconds():
    with download_cert('warning.pem', 'https://www.google.com') as cert:
        instance = {'local_cert_path': cert, 'days_warning': -1, 'seconds_warning': days_to_seconds(1000)}

        yield TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_ok():
    instance = {'host': 'https://www.google.com'}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_ok_ip():
    instance = {'host': '1.1.1.1'}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_ok_udp():
    instance = {'host': '1.1.1.1', 'transport': 'udp'}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_no_resolve():
    instance = {'host': 'https://this.does.not.exist.foo'}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_no_connect():
    instance = {'host': 'localhost', 'port': 56789}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_no_connect_port_in_host():
    instance = {'host': 'localhost:56789'}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_hostname_mismatch():
    instance = {'host': 'https://wrong.host.badssl.com'}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_cert_expired():
    instance = {'host': 'https://expired.badssl.com'}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_cert_critical_days():
    instance = {'host': 'https://www.google.com', 'days_critical': 1000}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_cert_critical_seconds():
    instance = {'host': 'https://www.google.com', 'days_critical': -1, 'seconds_critical': days_to_seconds(1000)}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_cert_warning_days():
    instance = {'host': 'https://www.google.com', 'days_warning': 1000}
    return TLSCheck('tls', {}, [instance])


@pytest.fixture
def remote_cert_warning_seconds():
    instance = {'host': 'https://www.google.com', 'days_warning': -1, 'seconds_warning': days_to_seconds(1000)}
    return TLSCheck('tls', {}, [instance])
