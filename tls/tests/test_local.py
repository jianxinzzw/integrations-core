# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)


def test_not_found(aggregator, local_not_found):
    local_not_found.check(None)

    aggregator.assert_service_check(local_not_found.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(
        local_not_found.SERVICE_CHECK_VALIDATION, status=local_not_found.CRITICAL, tags=local_not_found._tags, count=1
    )
    aggregator.assert_service_check(local_not_found.SERVICE_CHECK_EXPIRATION, count=0)

    aggregator.assert_all_metrics_covered()


def test_ok(aggregator, local_ok):
    local_ok.check(None)

    aggregator.assert_service_check(local_ok.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(local_ok.SERVICE_CHECK_VALIDATION, status=local_ok.OK, tags=local_ok._tags, count=1)
    aggregator.assert_service_check(local_ok.SERVICE_CHECK_EXPIRATION, status=local_ok.OK, tags=local_ok._tags, count=1)

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_ok_der(aggregator, local_ok_der):
    local_ok_der.check(None)

    aggregator.assert_service_check(local_ok_der.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(
        local_ok_der.SERVICE_CHECK_VALIDATION, status=local_ok_der.OK, tags=local_ok_der._tags, count=1
    )
    aggregator.assert_service_check(
        local_ok_der.SERVICE_CHECK_EXPIRATION, status=local_ok_der.OK, tags=local_ok_der._tags, count=1
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_hostname(aggregator, local_hostname):
    local_hostname.check(None)

    aggregator.assert_service_check(local_hostname.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(
        local_hostname.SERVICE_CHECK_VALIDATION, status=local_hostname.OK, tags=local_hostname._tags, count=1
    )
    aggregator.assert_service_check(
        local_hostname.SERVICE_CHECK_EXPIRATION, status=local_hostname.OK, tags=local_hostname._tags, count=1
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_hostname_mismatch(aggregator, local_hostname_mismatch):
    local_hostname_mismatch.check(None)

    aggregator.assert_service_check(local_hostname_mismatch.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(
        local_hostname_mismatch.SERVICE_CHECK_VALIDATION,
        status=local_hostname_mismatch.CRITICAL,
        tags=local_hostname_mismatch._tags,
        count=1,
    )
    aggregator.assert_service_check(
        local_hostname_mismatch.SERVICE_CHECK_EXPIRATION,
        status=local_hostname_mismatch.OK,
        tags=local_hostname_mismatch._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_cert_bad(aggregator, local_cert_bad):
    local_cert_bad.check(None)

    aggregator.assert_service_check(local_cert_bad.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(
        local_cert_bad.SERVICE_CHECK_VALIDATION, status=local_cert_bad.CRITICAL, tags=local_cert_bad._tags, count=1
    )
    aggregator.assert_service_check(local_cert_bad.SERVICE_CHECK_EXPIRATION, count=0)

    aggregator.assert_all_metrics_covered()


def test_cert_expired(aggregator, local_cert_expired):
    local_cert_expired.check(None)

    aggregator.assert_service_check(local_cert_expired.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(
        local_cert_expired.SERVICE_CHECK_VALIDATION,
        status=local_cert_expired.OK,
        tags=local_cert_expired._tags,
        count=1,
    )
    aggregator.assert_service_check(
        local_cert_expired.SERVICE_CHECK_EXPIRATION,
        status=local_cert_expired.CRITICAL,
        tags=local_cert_expired._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_cert_critical_days(aggregator, local_cert_critical_days):
    local_cert_critical_days.check(None)

    aggregator.assert_service_check(local_cert_critical_days.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(
        local_cert_critical_days.SERVICE_CHECK_VALIDATION,
        status=local_cert_critical_days.OK,
        tags=local_cert_critical_days._tags,
        count=1,
    )
    aggregator.assert_service_check(
        local_cert_critical_days.SERVICE_CHECK_EXPIRATION,
        status=local_cert_critical_days.CRITICAL,
        tags=local_cert_critical_days._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_cert_critical_seconds(aggregator, local_cert_critical_seconds):
    local_cert_critical_seconds.check(None)

    aggregator.assert_service_check(local_cert_critical_seconds.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(
        local_cert_critical_seconds.SERVICE_CHECK_VALIDATION,
        status=local_cert_critical_seconds.OK,
        tags=local_cert_critical_seconds._tags,
        count=1,
    )
    aggregator.assert_service_check(
        local_cert_critical_seconds.SERVICE_CHECK_EXPIRATION,
        status=local_cert_critical_seconds.CRITICAL,
        tags=local_cert_critical_seconds._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_cert_warning_days(aggregator, local_cert_warning_days):
    local_cert_warning_days.check(None)

    aggregator.assert_service_check(local_cert_warning_days.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(
        local_cert_warning_days.SERVICE_CHECK_VALIDATION,
        status=local_cert_warning_days.OK,
        tags=local_cert_warning_days._tags,
        count=1,
    )
    aggregator.assert_service_check(
        local_cert_warning_days.SERVICE_CHECK_EXPIRATION,
        status=local_cert_warning_days.WARNING,
        tags=local_cert_warning_days._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()


def test_cert_warning_seconds(aggregator, local_cert_warning_seconds):
    local_cert_warning_seconds.check(None)

    aggregator.assert_service_check(local_cert_warning_seconds.SERVICE_CHECK_CAN_CONNECT, count=0)
    aggregator.assert_service_check(
        local_cert_warning_seconds.SERVICE_CHECK_VALIDATION,
        status=local_cert_warning_seconds.OK,
        tags=local_cert_warning_seconds._tags,
        count=1,
    )
    aggregator.assert_service_check(
        local_cert_warning_seconds.SERVICE_CHECK_EXPIRATION,
        status=local_cert_warning_seconds.WARNING,
        tags=local_cert_warning_seconds._tags,
        count=1,
    )

    aggregator.assert_metric('tls.days_left', count=1)
    aggregator.assert_metric('tls.seconds_left', count=1)
    aggregator.assert_all_metrics_covered()
