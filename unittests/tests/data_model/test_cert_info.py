#!/usr/bin/python3
"""
this file implements unittests for the data model
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2018 Lukas Reiter

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
__version__ = 0.1

from datetime import datetime
from OpenSSL import crypto
from database.config import DomainConfig
from database.model import CertType
from database.model import CertInfo
from database.model import HostName
from database.model import DomainName
from unittests.tests.core import BaseDataModelTestCase


class TestCertInfo(BaseDataModelTestCase):
    """
    Test data model for CipherSuite
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, CertInfo)
        self._domain_config = DomainConfig()
        self._stackexchange_pem = """-----BEGIN CERTIFICATE-----
MIIG9DCCBdygAwIBAgISAwlZX3toja8spIxSXHTKF+FyMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMDEyMDMxNDAwNTJaFw0yMTAzMDMxNDAwNTJaMB4xHDAaBgNVBAMM
Eyouc3RhY2tleGNoYW5nZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCv/JcuNRZQmB5/e6vDoud+eNc/tp3Eu65I4NgLVQ28oX8ORtdpJD10pw1g
oArHnf1j9jLFZbe6B5sWZq990rNnjKOra5YksxFMYmCC0HgoPmqBnz43mrEKgBrj
JIuVCrOqVWEtia1oc2uIQSkawgIuGf5I+unQA+vspp1H9DaE70/tBtd0kpy6m5KZ
0PsibrjWGrW5leTB5q7w0e0l6Bh73hJnsfI5oKlQDx8uIJ9GThrFAfk+Xx4iZUwz
b2XJLg3RpPqqFmgBEIo9HC1Gxphn9NZbnvi1J1adFA4nfQh7uElt4dh6A3uwmWln
riPZ8Mt0T539tYl+x6j6Z6QyCRB1AgMBAAGjggQWMIIEEjAOBgNVHQ8BAf8EBAMC
BaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAw
HQYDVR0OBBYEFKyYhPGAVlTGYHx0ErZRgwSRyek+MB8GA1UdIwQYMBaAFBQusxe3
WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0
cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5j
ci5vcmcvMIIB5AYDVR0RBIIB2zCCAdeCDyouYXNrdWJ1bnR1LmNvbYISKi5ibG9n
b3ZlcmZsb3cuY29tghIqLm1hdGhvdmVyZmxvdy5uZXSCGCoubWV0YS5zdGFja2V4
Y2hhbmdlLmNvbYIYKi5tZXRhLnN0YWNrb3ZlcmZsb3cuY29tghEqLnNlcnZlcmZh
dWx0LmNvbYINKi5zc3RhdGljLm5ldIITKi5zdGFja2V4Y2hhbmdlLmNvbYITKi5z
dGFja292ZXJmbG93LmNvbYIVKi5zdGFja292ZXJmbG93LmVtYWlsgg8qLnN1cGVy
dXNlci5jb22CDWFza3VidW50dS5jb22CEGJsb2dvdmVyZmxvdy5jb22CEG1hdGhv
dmVyZmxvdy5uZXSCFG9wZW5pZC5zdGFja2F1dGguY29tgg9zZXJ2ZXJmYXVsdC5j
b22CC3NzdGF0aWMubmV0gg1zdGFja2FwcHMuY29tgg1zdGFja2F1dGguY29tghFz
dGFja2V4Y2hhbmdlLmNvbYISc3RhY2tvdmVyZmxvdy5ibG9nghFzdGFja292ZXJm
bG93LmNvbYITc3RhY2tvdmVyZmxvdy5lbWFpbIIRc3RhY2tzbmlwcGV0cy5uZXSC
DXN1cGVydXNlci5jb20wTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMB
AQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggEE
BgorBgEEAdZ5AgQCBIH1BIHyAPAAdwBc3EOS/uarRUSxXprUVuYQN/vV+kfcoXOU
sl7m9scOygAAAXYpHsnaAAAEAwBIMEYCIQD2BYPFaoNHxpuR7dpGPx90b2t2OFv1
oEELbqYiBWo4tAIhAKT8/8UQ6po+ONKkl4u9/hXrV424SewLQjyKuc656f/6AHUA
fT7y+I//iFVoJMLAyp5SiXkrxQ54CX8uapdomX4i8NcAAAF2KR7JpAAABAMARjBE
AiBk58dzHIsANdFi9Y305G6X1N1kGQVbZjrhIt4oQQooOAIgCi0yANzZULHUlKfF
WlNDSfKXHImI6W5vyF7XpkWt+HIwDQYJKoZIhvcNAQELBQADggEBAExNEHaf0ATu
kmLPA/FGKOi97vEieZv5QiKg2idsESsSc5XUcXjzHuz2ws+IYInd6gz6s3aua7c0
iCjwbkBuledtntKgvhBxB7ax4wcxt0vKY4yhcTifG+XpsdC2rjtIXO/Uckpn14tx
cUo4SsVqXLtxQu4qQ2DS3QGlyAwLPlPS46XkUP/ztd4D3WcyokUW72+2NMdtpgZq
NzteVkfQ5xb2akdrm2lN7/S2GBFPFzPGLUEwm0nxEPlF08kk3BWKlXfIWnCdHkrW
9mPoMo048BH4cVTwMDTR177IMxJY4p0uqsNMoPvTpvNIqbIl5bv3uABROg0Y8yLq
4CZZLJFwyL0=
-----END CERTIFICATE-----"""

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            self._test_unique_constraint(session,
                                         service=service,
                                         cert_type=CertType.identity,
                                         pem=self._google_pem[0])
            self._test_unique_constraint(session,
                                         company=company,
                                         cert_type=CertType.identity,
                                         pem=self._google_pem[0])
            self._test_unique_constraint(session,
                                         host_name=host_name,
                                         cert_type=CertType.identity,
                                         pem=self._google_pem[0])

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            # Missing cert_type
            self._test_not_null_constraint(session,
                                           service=service,
                                           cert_type=None,
                                           pem=self._google_pem[0])
            self._test_not_null_constraint(session,
                                           company=company,
                                           cert_type=None,
                                           pem=self._google_pem[0])
            self._test_not_null_constraint(session,
                                           host_name=host_name,
                                           cert_type=None,
                                           pem=self._google_pem[0])

    def test_check_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            # Misses service, host_name and company
            self._test_check_constraint(session,
                                        cert_type=CertType.identity,
                                        pem=self._google_pem[0])
            self._test_check_constraint(session,
                                        service=service,
                                        company=company,
                                        cert_type=CertType.identity,
                                        pem=self._google_pem[0])
            self._test_check_constraint(session,
                                        service=service,
                                        host_name=host_name,
                                        cert_type=CertType.identity,
                                        pem=self._google_pem[0])
            self._test_check_constraint(session,
                                        host_name=host_name,
                                        company=company,
                                        cert_type=CertType.identity,
                                        pem=self._google_pem[0])
            self._test_check_constraint(session,
                                        service=service,
                                        host_name=host_name,
                                        company=company,
                                        cert_type=CertType.identity,
                                        pem=self._google_pem[0])

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            self._test_success(session,
                               service=service,
                               cert_type=CertType.identity,
                               pem=self._google_pem[0])
            self._test_success(session,
                               company=company,
                               cert_type=CertType.identity,
                               pem=self._google_pem[0])
            self._test_success(session,
                               host_name=host_name,
                               cert_type=CertType.identity,
                               pem=self._google_pem[0])

    def test_certificate_attributes(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            self._test_success(session,
                               service=service,
                               cert_type=CertType.identity,
                               pem=self._google_pem[0])
        with self._engine.session_scope() as session:
            result = session.query(CertInfo).first()
            extensions = result.extensions_dict
            self.assertEqual(2, result.version)
            self.assertEqual("fa:6b:ba:90:4c:26:1d:f2:12:54:f6:7d:cc:de:65:db", result.serial_number)
            self.assertEqual("sha256WithRSAEncryption", result.signature_algorithm)
            self.assertEqual("C=US, O=Google Trust Services LLC, CN=GTS CA 1C3", result.issuer)
            self.assertListEqual(["GTS CA 1C3"], result.issuer_common_names)
            self.assertEqual("GTS CA 1C3", result.issuer_common_names_str)
            self.assertEqual(datetime(2022, 9, 12, 8, 19, 33), result.valid_from)
            self.assertEqual('2022-09-12', result.valid_from_str)
            self.assertEqual(datetime(2022, 12, 5, 8, 19, 32), result.valid_until)
            self.assertEqual('2022-12-05', result.valid_until_str)
            self.assertEqual(83, result.validity_period_days)
            self.assertEqual("CN=www.google.com", result.subject)
            self.assertListEqual(["www.google.com"], result.subject_common_names)
            self.assertEqual("www.google.com", result.subject_common_names_str)
            self.assertListEqual(["www.google.com"], result.subject_alt_names)
            self.assertEqual("www.google.com", result.subject_alt_names_str)
            self.assertListEqual(["www.google.com"], result.all_names)
            self.assertListEqual([], result.organizations)
            self.assertEqual("", result.organizations_str)
            self.assertListEqual([], result.email_addresses)
            self.assertEqual("", result.email_addresses_str)
            self.assertListEqual(["http://ocsp.pki.goog/gts1c3"], result.ocsp_servers)
            self.assertEqual("http://ocsp.pki.goog/gts1c3", result.ocsp_servers_str)
            self.assertListEqual(["http://crls.pki.goog/gts1c3/zdATt0Ex_Fk.crl"], result.crl_distribution_points)
            self.assertEqual("http://crls.pki.goog/gts1c3/zdATt0Ex_Fk.crl", result.crl_distribution_points_str)
            self.assertEqual(256, result.public_key_size)
            self.assertEqual("secp256r1", result.public_key_name)
            self.assertIsNone(result.exponent)
            self.assertListEqual(["keyUsage", "basicConstraints"], result.critical_extensions)
            self.assertEqual("keyUsage, basicConstraints", result.critical_extensions_str)
            self.assertFalse(result.is_self_signed())
            self.assertTrue(result.has_recommended_duration())
            self.assertEqual("Digital Signature", str(extensions["keyUsage"]))
            self.assertEqual("TLS Web Server Authentication", str(extensions["extendedKeyUsage"]))

    def test_verify(self):
        certs = []
        config = DomainConfig()
        i = 0
        for item in self._google_pem:
            if i == 0:
                cert_type = CertType.identity
            elif i == 1:
                cert_type = CertType.intermediate
            elif i == 2:
                cert_type = CertType.root
            else:
                raise NotImplementedError("case not implemented")
            certs.append(CertInfo(pem=item, cert_type=cert_type))
            i += 1
        # Verification is successful
        certs[0].verify(x509_store=self._domain_config.x509_store, chain=certs)
        # Verification is unsuccessful
        with self.assertRaises(crypto.X509StoreContextError) as ex:
            self._domain_config.x509_store.set_time(datetime(2019, 1, 1))
            certs[0].verify(x509_store=self._domain_config.x509_store, chain=certs)
            self.assertEqual("certificate is not yet valid", str(ex))

    def test_method_matches_host_name(self):
        google_cert = CertInfo(pem=self._google_pem[0], cert_type=CertType.identity)
        stackexchange_cert = CertInfo(pem=self._stackexchange_pem, cert_type=CertType.identity)
        # Google certificates: www.google.com
        self.assertTrue(google_cert.matches_host_name(HostName(name="www", domain_name=DomainName(name="google.com"))))
        self.assertFalse(google_cert.matches_host_name(HostName(name=None, domain_name=DomainName(name="google.com"))))
        # Stack Exchange certrificate: *.stackexchange.com
        self.assertTrue(stackexchange_cert.matches_host_name(HostName(name="www",
                                                                      domain_name=DomainName(name="stackexchange.com"))))
        self.assertTrue(stackexchange_cert.matches_host_name(HostName(name=None,
                                                                      domain_name=DomainName(name="stackexchange.com"))))

    def test_method_matches_host_names(self):
        google_cert = CertInfo(pem=self._google_pem[0], cert_type=CertType.identity)
        stackexchange_cert = CertInfo(pem=self._stackexchange_pem, cert_type=CertType.identity)
        domain_name = DomainName(name="stackexchange.com")
        host_names = [HostName(name="www", domain_name=domain_name),
                      HostName(name="ftp", domain_name=domain_name),
                      HostName(name="ssh", domain_name=domain_name),
                      HostName(name=None, domain_name=domain_name)]
        self.assertTrue(stackexchange_cert.matches_host_names(host_names))
        domain_name = DomainName(name="test.com")
        host_names = [HostName(name="www", domain_name=domain_name),
                      HostName(name="ftp", domain_name=domain_name),
                      HostName(name="ssh", domain_name=domain_name),
                      HostName(name=None, domain_name=domain_name)]
        self.assertFalse(stackexchange_cert.matches_host_names(host_names))
        host_names.append(HostName(name=None, domain_name=domain_name))
        domain_name = DomainName(name="google.com")
        host_names = [HostName(name="www", domain_name=domain_name)]
        self.assertTrue(google_cert.matches_host_names(host_names))
        host_names = [HostName(name="ftp", domain_name=domain_name),
                      HostName(name="ssh", domain_name=domain_name),
                      HostName(name=None, domain_name=domain_name)]
        self.assertFalse(google_cert.matches_host_names(host_names))
        domain_name = DomainName(name="test.com")
        host_names = [HostName(name="www", domain_name=domain_name),
                      HostName(name="ftp", domain_name=domain_name),
                      HostName(name="ssh", domain_name=domain_name),
                      HostName(name=None, domain_name=domain_name)]
        self.assertFalse(google_cert.matches_host_names(host_names))
