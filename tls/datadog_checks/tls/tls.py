# (C) Datadog, Inc. 2019
# All rights reserved
# Licensed under a 3-clause BSD style license (see LICENSE)
import socket
import ssl
from datetime import datetime
from os.path import expanduser, isdir

import service_identity
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate
from six import text_type
from six.moves.urllib.parse import urlparse

from datadog_checks.base import AgentCheck, is_affirmative

from .utils import closing, days_to_seconds, is_ip_address, seconds_to_days


class TLSCheck(AgentCheck):
    SERVICE_CHECK_CAN_CONNECT = 'tls.can_connect'
    SERVICE_CHECK_VALIDATION = 'tls.cert_valid'
    SERVICE_CHECK_EXPIRATION = 'tls.cert_expiration'

    DEFAULT_EXPIRE_DAYS_WARNING = 14
    DEFAULT_EXPIRE_DAYS_CRITICAL = 7
    DEFAULT_EXPIRE_SECONDS_WARNING = days_to_seconds(DEFAULT_EXPIRE_DAYS_WARNING)
    DEFAULT_EXPIRE_SECONDS_CRITICAL = days_to_seconds(DEFAULT_EXPIRE_DAYS_CRITICAL)

    def __init__(self, name, init_config, instances):
        super(TLSCheck, self).__init__(name, init_config, instances)

        self._name = self.instance.get('name')
        self._local_cert_path = self.instance.get('local_cert_path', '')
        self._timeout = float(self.instance.get('timeout', 10))

        host = self.instance.get('host', '')
        parsed_uri = urlparse(host)

        # Handle IP addresses, see: https://bugs.python.org/issue754016
        if not parsed_uri.hostname:
            parsed_uri = urlparse('//{}'.format(host))

        self._host = parsed_uri.hostname

        # TODO: Support (implement) UDP
        # https://chris-wood.github.io/2016/05/06/OpenSSL-DTLS.html
        transport = self.instance.get('transport', 'tcp').lower()
        if transport == 'udp':
            # SOCK_DGRAM
            self._sock_type = socket.SOCK_STREAM
            # Default to 4433 (no standard port, but it's what OpenSSL uses)
            self._port = int(self.instance.get('port', parsed_uri.port or 443))
        else:
            self._sock_type = socket.SOCK_STREAM
            self._port = int(self.instance.get('port', parsed_uri.port or 443))

        # https://en.wikipedia.org/wiki/Server_Name_Indication
        self._server_hostname = self.instance.get('server_hostname', self._host)
        self._validate_hostname = is_affirmative(self.instance.get('validate_hostname', True))
        if is_ip_address(self._server_hostname):
            self._hostname_validation = (service_identity.cryptography.verify_certificate_ip_address, 'IP address')
        else:
            self._hostname_validation = (service_identity.cryptography.verify_certificate_hostname, 'hostname')

        self._cert = self.instance.get('cert')
        if self._cert:
            self._cert = expanduser(self._cert)

        self._private_key = self.instance.get('private_key')
        if self._private_key:
            self._private_key = expanduser(self._private_key)

        self._cafile = None
        self._capath = None
        ca_cert = self.instance.get('ca_cert')
        if ca_cert:
            ca_cert = expanduser(ca_cert)
            if isdir(ca_cert):
                self._capath = ca_cert
            else:
                self._cafile = ca_cert

        # Thresholds expressed in seconds take precedence over those expressed in days
        self._seconds_warning = (
            int(self.instance.get('seconds_warning', 0))
            or days_to_seconds(float(self.instance.get('days_warning', 0)))
            or self.DEFAULT_EXPIRE_SECONDS_WARNING
        )
        self._seconds_critical = (
            int(self.instance.get('seconds_critical', 0))
            or days_to_seconds(float(self.instance.get('days_critical', 0)))
            or self.DEFAULT_EXPIRE_SECONDS_CRITICAL
        )

        self._tags = self.instance.get('tags', [])
        if self._name:
            self._tags.append('name:{}'.format(self._name))

        # Decide the method of collection for this instance
        if self._local_cert_path:
            self.check = self.check_local
            if self._validate_hostname and self._server_hostname:
                self._tags.append('server_hostname:{}'.format(self._server_hostname))
        else:
            self.check = self.check_remote
            self._tags.append('server_hostname:{}'.format(self._server_hostname))
            self._tags.append('host:{}'.format(self._host))
            self._tags.append('port:{}'.format(self._port))

        # Cache lazily
        self._tls_context = None

    @property
    def tls_context(self):
        if self._tls_context is None:
            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext
            # https://docs.python.org/3/library/ssl.html#ssl.PROTOCOL_TLS
            self._tls_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS)

            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.verify_mode
            self._tls_context.verify_mode = ssl.CERT_REQUIRED

            # Run our own validation later on if need be
            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname
            self._tls_context.check_hostname = False

            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_verify_locations
            if self._cafile or self._capath:  # no cov
                self._tls_context.load_verify_locations(self._cafile, self._capath, None)

            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_default_certs
            else:
                self._tls_context.load_default_certs(ssl.Purpose.SERVER_AUTH)

            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_cert_chain
            if self._cert:  # no cov
                self._tls_context.load_cert_chain(self._cert, keyfile=self._private_key)

        return self._tls_context

    def check_remote(self, instance):
        try:
            sock = self.create_connection()
        except Exception as e:
            self.service_check(self.SERVICE_CHECK_CAN_CONNECT, self.CRITICAL, tags=self._tags, message=str(e))
            return
        else:
            self.service_check(self.SERVICE_CHECK_CAN_CONNECT, self.OK, tags=self._tags)

        with closing(sock):
            try:
                with closing(self.tls_context.wrap_socket(sock, server_hostname=self._server_hostname)) as secure_sock:
                    der_cert = secure_sock.getpeercert(binary_form=True)
                    # protocol_version = secure_sock.version()
            except Exception as e:
                message = str(e)
                self.service_check(self.SERVICE_CHECK_VALIDATION, self.CRITICAL, tags=self._tags, message=str(message))

                # There's no sane way to tell it to not validate expiration
                # This only works on Python 3.7+
                if 'expired' in message:
                    self.service_check(
                        self.SERVICE_CHECK_EXPIRATION, self.CRITICAL, tags=self._tags, message='Certificate has expired'
                    )

                return

        try:
            cert = load_der_x509_certificate(der_cert, default_backend())
        except Exception as e:
            self.service_check(
                self.SERVICE_CHECK_VALIDATION,
                self.CRITICAL,
                tags=self._tags,
                message='Unable to parse the certificate: {}'.format(e),
            )
            return

        self.validate_certificate(cert)
        self.check_age(cert)

    def check_local(self, instance):
        try:
            with open(self._local_cert_path, 'rb') as f:
                cert = f.read()
        except Exception as e:
            self.service_check(
                self.SERVICE_CHECK_VALIDATION,
                self.CRITICAL,
                tags=self._tags,
                message='Unable to open the certificate: {}'.format(e),
            )
            return

        if self._local_cert_path.endswith(('.cer', '.crt', '.der')):
            loader = load_der_x509_certificate
        else:
            loader = load_pem_x509_certificate

        try:
            cert = loader(cert, default_backend())
        except Exception as e:
            self.service_check(
                self.SERVICE_CHECK_VALIDATION,
                self.CRITICAL,
                tags=self._tags,
                message='Unable to parse the certificate: {}'.format(e),
            )
            return

        self.validate_certificate(cert)
        self.check_age(cert)

    def validate_certificate(self, cert):
        if self._validate_hostname and self._server_hostname:
            validator, host_type = self._hostname_validation

            try:
                validator(cert, text_type(self._server_hostname))
            except service_identity.VerificationError:
                self.service_check(
                    self.SERVICE_CHECK_VALIDATION,
                    self.CRITICAL,
                    tags=self._tags,
                    message='The {} on the certificate does not match the given host'.format(host_type),
                )
                return
            except service_identity.CertificateError as e:  # no cov
                self.service_check(
                    self.SERVICE_CHECK_VALIDATION,
                    self.CRITICAL,
                    tags=self._tags,
                    message='The certificate contains invalid/unexpected data: {}'.format(e),
                )
                return

        self.service_check(self.SERVICE_CHECK_VALIDATION, self.OK, tags=self._tags)

    def check_age(self, cert):
        delta = cert.not_valid_after - datetime.utcnow()
        seconds_left = delta.total_seconds()
        days_left = seconds_to_days(seconds_left)

        self.gauge('tls.days_left', days_left, tags=self._tags)
        self.gauge('tls.seconds_left', seconds_left, tags=self._tags)

        if seconds_left <= 0:
            self.service_check(
                self.SERVICE_CHECK_EXPIRATION, self.CRITICAL, tags=self._tags, message='Certificate has expired'
            )
        elif seconds_left < self._seconds_critical:
            self.service_check(
                self.SERVICE_CHECK_EXPIRATION,
                self.CRITICAL,
                tags=self._tags,
                message='Certificate will expire in only {} days'.format(days_left),
            )
        elif seconds_left < self._seconds_warning:
            self.service_check(
                self.SERVICE_CHECK_EXPIRATION,
                self.WARNING,
                tags=self._tags,
                message='Certificate will expire in {} days'.format(days_left),
            )
        else:
            self.service_check(self.SERVICE_CHECK_EXPIRATION, self.OK, tags=self._tags)

    def create_connection(self):
        """See: https://github.com/python/cpython/blob/40ee9a3640d702bce127e9877c82a99ce817f0d1/Lib/socket.py#L691"""
        err = None
        try:
            for res in socket.getaddrinfo(self._host, self._port, 0, self._sock_type):
                af, socktype, proto, canonname, sa = res
                sock = None
                try:
                    sock = socket.socket(af, socktype, proto)
                    sock.settimeout(self._timeout)
                    sock.connect(sa)
                    # Break explicitly a reference cycle
                    err = None
                    return sock

                except socket.error as _:
                    err = _
                    if sock is not None:
                        sock.close()

            if err is not None:
                raise err
            else:
                raise socket.error('No valid addresses found, try checking your IPv6 connectivity')
        except socket.gaierror as e:
            err_code, message = e.args
            if err_code == socket.EAI_NODATA or err_code == socket.EAI_NONAME:
                raise socket.error('Unable to resolve host, check your DNS: {}'.format(message))

            raise
