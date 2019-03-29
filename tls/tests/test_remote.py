# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import mock
from six import PY2


def test_ok(aggregator, remote_ok):
    remote_ok.check(None)

    aggregator.assert_service_check(
        remote_ok.SERVICE_CHECK_CAN_CONNECT, status=remote_ok.OK, tags=remote_ok._tags, count=1
    )
    aggregator.assert_service_check(
        remote_ok.SERVICE_CHECK_VALIDATION, status=remote_ok.OK, tags=remote_ok._tags, count=1
    )
    aggregator.assert_service_check(
        remote_ok.SERVICE_CHECK_EXPIRATION, status=remote_ok.OK, tags=remote_ok._tags, count=1
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_ok_ip(aggregator, remote_ok_ip):
    remote_ok_ip.check(None)

    aggregator.assert_service_check(
        remote_ok_ip.SERVICE_CHECK_CAN_CONNECT, status=remote_ok_ip.OK, tags=remote_ok_ip._tags, count=1
    )
    aggregator.assert_service_check(
        remote_ok_ip.SERVICE_CHECK_VALIDATION, status=remote_ok_ip.OK, tags=remote_ok_ip._tags, count=1
    )
    aggregator.assert_service_check(
        remote_ok_ip.SERVICE_CHECK_EXPIRATION, status=remote_ok_ip.OK, tags=remote_ok_ip._tags, count=1
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_ok_udp(aggregator, remote_ok_udp):
    remote_ok_udp.check(None)

    aggregator.assert_service_check(
        remote_ok_udp.SERVICE_CHECK_CAN_CONNECT, status=remote_ok_udp.OK, tags=remote_ok_udp._tags, count=1
    )
    aggregator.assert_service_check(
        remote_ok_udp.SERVICE_CHECK_VALIDATION, status=remote_ok_udp.OK, tags=remote_ok_udp._tags, count=1
    )
    aggregator.assert_service_check(
        remote_ok_udp.SERVICE_CHECK_EXPIRATION, status=remote_ok_udp.OK, tags=remote_ok_udp._tags, count=1
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_no_resolve(aggregator, remote_no_resolve):
    remote_no_resolve.check(None)

    aggregator.assert_service_check(
        remote_no_resolve.SERVICE_CHECK_CAN_CONNECT,
        status=remote_no_resolve.CRITICAL,
        tags=remote_no_resolve._tags,
        count=1,
    )
    aggregator.assert_service_check(remote_no_resolve.SERVICE_CHECK_VALIDATION, count=0)
    aggregator.assert_service_check(remote_no_resolve.SERVICE_CHECK_EXPIRATION, count=0)

    message = 'Unable to resolve host, check your DNS'
    assert message in aggregator.service_checks(remote_no_resolve.SERVICE_CHECK_CAN_CONNECT)[0].message

    aggregator.assert_all_metrics_covered()


def test_no_connect(aggregator, remote_no_connect):
    remote_no_connect.check(None)

    aggregator.assert_service_check(
        remote_no_connect.SERVICE_CHECK_CAN_CONNECT,
        status=remote_no_connect.CRITICAL,
        tags=remote_no_connect._tags,
        count=1,
    )
    aggregator.assert_service_check(remote_no_connect.SERVICE_CHECK_VALIDATION, count=0)
    aggregator.assert_service_check(remote_no_connect.SERVICE_CHECK_EXPIRATION, count=0)

    message = 'Unable to resolve host, check your DNS'
    assert message not in aggregator.service_checks(remote_no_connect.SERVICE_CHECK_CAN_CONNECT)[0].message

    aggregator.assert_all_metrics_covered()


def test_no_connect_port_in_host(aggregator, remote_no_connect_port_in_host):
    remote_no_connect_port_in_host.check(None)

    aggregator.assert_service_check(
        remote_no_connect_port_in_host.SERVICE_CHECK_CAN_CONNECT,
        status=remote_no_connect_port_in_host.CRITICAL,
        tags=remote_no_connect_port_in_host._tags,
        count=1,
    )
    aggregator.assert_service_check(remote_no_connect_port_in_host.SERVICE_CHECK_VALIDATION, count=0)
    aggregator.assert_service_check(remote_no_connect_port_in_host.SERVICE_CHECK_EXPIRATION, count=0)

    message = 'Unable to resolve host, check your DNS'
    assert message not in aggregator.service_checks(remote_no_connect_port_in_host.SERVICE_CHECK_CAN_CONNECT)[0].message

    aggregator.assert_all_metrics_covered()


def test_no_connect_ipv6(aggregator, remote_no_connect):
    with mock.patch('socket.getaddrinfo', return_value=()):
        remote_no_connect.check(None)

    aggregator.assert_service_check(
        remote_no_connect.SERVICE_CHECK_CAN_CONNECT,
        status=remote_no_connect.CRITICAL,
        tags=remote_no_connect._tags,
        message='No valid addresses found, try checking your IPv6 connectivity',
        count=1,
    )
    aggregator.assert_service_check(remote_no_connect.SERVICE_CHECK_VALIDATION, count=0)
    aggregator.assert_service_check(remote_no_connect.SERVICE_CHECK_EXPIRATION, count=0)

    aggregator.assert_all_metrics_covered()


def test_hostname_mismatch(aggregator, remote_hostname_mismatch):
    remote_hostname_mismatch.check(None)

    aggregator.assert_service_check(
        remote_hostname_mismatch.SERVICE_CHECK_CAN_CONNECT,
        status=remote_hostname_mismatch.OK,
        tags=remote_hostname_mismatch._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_hostname_mismatch.SERVICE_CHECK_VALIDATION,
        status=remote_hostname_mismatch.CRITICAL,
        tags=remote_hostname_mismatch._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_hostname_mismatch.SERVICE_CHECK_EXPIRATION,
        status=remote_hostname_mismatch.OK,
        tags=remote_hostname_mismatch._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_cert_expired(aggregator, remote_cert_expired):
    remote_cert_expired.check(None)

    aggregator.assert_service_check(
        remote_cert_expired.SERVICE_CHECK_CAN_CONNECT,
        status=remote_cert_expired.OK,
        tags=remote_cert_expired._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_cert_expired.SERVICE_CHECK_VALIDATION,
        status=remote_cert_expired.CRITICAL,
        tags=remote_cert_expired._tags,
        count=1,
    )
    if PY2:
        aggregator.assert_service_check(remote_cert_expired.SERVICE_CHECK_EXPIRATION, count=0)
    else:
        aggregator.assert_service_check(
            remote_cert_expired.SERVICE_CHECK_EXPIRATION,
            status=remote_cert_expired.CRITICAL,
            tags=remote_cert_expired._tags,
            message='Certificate has expired',
            count=1,
        )

    aggregator.assert_all_metrics_covered()


def test_cert_critical_days(aggregator, remote_cert_critical_days):
    remote_cert_critical_days.check(None)

    aggregator.assert_service_check(
        remote_cert_critical_days.SERVICE_CHECK_CAN_CONNECT,
        status=remote_cert_critical_days.OK,
        tags=remote_cert_critical_days._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_cert_critical_days.SERVICE_CHECK_VALIDATION,
        status=remote_cert_critical_days.OK,
        tags=remote_cert_critical_days._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_cert_critical_days.SERVICE_CHECK_EXPIRATION,
        status=remote_cert_critical_days.CRITICAL,
        tags=remote_cert_critical_days._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_cert_critical_seconds(aggregator, remote_cert_critical_seconds):
    remote_cert_critical_seconds.check(None)

    aggregator.assert_service_check(
        remote_cert_critical_seconds.SERVICE_CHECK_CAN_CONNECT,
        status=remote_cert_critical_seconds.OK,
        tags=remote_cert_critical_seconds._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_cert_critical_seconds.SERVICE_CHECK_VALIDATION,
        status=remote_cert_critical_seconds.OK,
        tags=remote_cert_critical_seconds._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_cert_critical_seconds.SERVICE_CHECK_EXPIRATION,
        status=remote_cert_critical_seconds.CRITICAL,
        tags=remote_cert_critical_seconds._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_cert_warning_days(aggregator, remote_cert_warning_days):
    remote_cert_warning_days.check(None)

    aggregator.assert_service_check(
        remote_cert_warning_days.SERVICE_CHECK_CAN_CONNECT,
        status=remote_cert_warning_days.OK,
        tags=remote_cert_warning_days._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_cert_warning_days.SERVICE_CHECK_VALIDATION,
        status=remote_cert_warning_days.OK,
        tags=remote_cert_warning_days._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_cert_warning_days.SERVICE_CHECK_EXPIRATION,
        status=remote_cert_warning_days.WARNING,
        tags=remote_cert_warning_days._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_cert_warning_seconds(aggregator, remote_cert_warning_seconds):
    remote_cert_warning_seconds.check(None)

    aggregator.assert_service_check(
        remote_cert_warning_seconds.SERVICE_CHECK_CAN_CONNECT,
        status=remote_cert_warning_seconds.OK,
        tags=remote_cert_warning_seconds._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_cert_warning_seconds.SERVICE_CHECK_VALIDATION,
        status=remote_cert_warning_seconds.OK,
        tags=remote_cert_warning_seconds._tags,
        count=1,
    )
    aggregator.assert_service_check(
        remote_cert_warning_seconds.SERVICE_CHECK_EXPIRATION,
        status=remote_cert_warning_seconds.WARNING,
        tags=remote_cert_warning_seconds._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()
