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
from database.model import CertType
from database.model import CertInfo
from database.model import HostName
from database.model import DomainName
from database.model import HashAlgorithm
from database.model import AsymmetricAlgorithm
from unittests.tests.core import BaseDataModelTestCase


class TestCertInfo(BaseDataModelTestCase):
    """
    Test data model for CipherSuite
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, CertInfo)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            self._test_unique_constraint(session,
                                         service=service,
                                         serial_number=1,
                                         common_name="www.test.com",
                                         issuer_name="www.test.com",
                                         signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                         signature_bits=2048,
                                         hash_algorithm=HashAlgorithm.sha1,
                                         cert_type=CertType.root,
                                         valid_from=datetime.now(),
                                         valid_until=datetime.now(),
                                         extension_info={})
            self._test_unique_constraint(session,
                                         company=company,
                                         serial_number=1,
                                         common_name="www.test.com",
                                         issuer_name="www.test.com",
                                         signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                         signature_bits=2048,
                                         hash_algorithm=HashAlgorithm.sha1,
                                         cert_type=CertType.root,
                                         valid_from=datetime.now(),
                                         valid_until=datetime.now(),
                                         extension_info={})
            self._test_unique_constraint(session,
                                         host_name=host_name,
                                         serial_number=1,
                                         common_name="www.test.com",
                                         issuer_name="www.test.com",
                                         signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                         signature_bits=2048,
                                         hash_algorithm=HashAlgorithm.sha1,
                                         cert_type=CertType.root,
                                         valid_from=datetime.now(),
                                         valid_until=datetime.now(),
                                         extension_info={})

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            self._test_not_null_constraint(session,
                                           service=service,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           company=company,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           host_name=host_name,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           valid_from=datetime.now(),
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_until=datetime.now(),
                                           extension_info={})
            self._test_not_null_constraint(session,
                                           service=service,
                                           serial_number=1,
                                           common_name="www.test.com",
                                           issuer_name="www.test.com",
                                           signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                           signature_bits=2048,
                                           hash_algorithm=HashAlgorithm.sha1,
                                           cert_type=CertType.root,
                                           valid_from=datetime.now(),
                                           extension_info={})

    def test_check_constraint(self):

        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            self._test_check_constraint(session,
                                        serial_number=1,
                                        common_name="www.test.com",
                                        issuer_name="www.test.com",
                                        signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                        signature_bits=2048,
                                        hash_algorithm=HashAlgorithm.sha1,
                                        cert_type=CertType.root,
                                        valid_from=datetime.now(),
                                        valid_until=datetime.now(),
                                        extension_info={})
            self._test_check_constraint(session,
                                        service=service,
                                        company=company,
                                        serial_number=1,
                                        common_name="www.test.com",
                                        issuer_name="www.test.com",
                                        signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                        signature_bits=2048,
                                        hash_algorithm=HashAlgorithm.sha1,
                                        cert_type=CertType.root,
                                        valid_from=datetime.now(),
                                        valid_until=datetime.now(),
                                        extension_info={})
            self._test_check_constraint(session,
                                        service=service,
                                        host_name=host_name,
                                        serial_number=1,
                                        common_name="www.test.com",
                                        issuer_name="www.test.com",
                                        signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                        signature_bits=2048,
                                        hash_algorithm=HashAlgorithm.sha1,
                                        cert_type=CertType.root,
                                        valid_from=datetime.now(),
                                        valid_until=datetime.now(),
                                        extension_info={})
            self._test_check_constraint(session,
                                        host_name=host_name,
                                        company=company,
                                        serial_number=1,
                                        common_name="www.test.com",
                                        issuer_name="www.test.com",
                                        signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                        signature_bits=2048,
                                        hash_algorithm=HashAlgorithm.sha1,
                                        cert_type=CertType.root,
                                        valid_from=datetime.now(),
                                        valid_until=datetime.now(),
                                        extension_info={})
            self._test_check_constraint(session,
                                        service=service,
                                        host_name=host_name,
                                        company=company,
                                        serial_number=1,
                                        common_name="www.test.com",
                                        issuer_name="www.test.com",
                                        signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                                        signature_bits=2048,
                                        hash_algorithm=HashAlgorithm.sha1,
                                        cert_type=CertType.root,
                                        valid_from=datetime.now(),
                                        valid_until=datetime.now(),
                                        extension_info={})

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            service = self.create_service(session=session)
            company = self.create_company(session=session)
            host_name = self.create_hostname(session=session)
            self._test_success(session,
                               service=service,
                               serial_number=1,
                               common_name="www.test.com",
                               issuer_name="www.test.com",
                               signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                               signature_bits=2048,
                               hash_algorithm=HashAlgorithm.sha1,
                               cert_type=CertType.root,
                               valid_from=datetime.now(),
                               valid_until=datetime.now(),
                               extension_info={})
            self._test_success(session,
                               company=company,
                               serial_number=1,
                               common_name="www.test.com",
                               issuer_name="www.test.com",
                               signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                               signature_bits=2048,
                               hash_algorithm=HashAlgorithm.sha1,
                               cert_type=CertType.root,
                               valid_from=datetime.now(),
                               valid_until=datetime.now(),
                               extension_info={})
            self._test_success(session,
                               host_name=host_name,
                               serial_number=1,
                               common_name="www.test.com",
                               issuer_name="www.test.com",
                               signature_asym_algorithm=AsymmetricAlgorithm.rsa,
                               signature_bits=2048,
                               hash_algorithm=HashAlgorithm.sha1,
                               cert_type=CertType.root,
                               valid_from=datetime.now(),
                               valid_until=datetime.now(),
                               extension_info={})

    def test_method_matches_host_name(self):
        cert = CertInfo()
        cert.common_name = "www.test.com"
        self.assertTrue(cert.matches_host_name(HostName(name="www", domain_name=DomainName(name="test.com"))))
        self.assertFalse(cert.matches_host_name(HostName(name=None, domain_name=DomainName(name="test.com"))))
        cert = CertInfo()
        cert.common_name = "*.test.com"
        self.assertTrue(cert.matches_host_name(HostName(name="www", domain_name=DomainName(name="test.com"))))
        self.assertFalse(cert.matches_host_name(HostName(name=None, domain_name=DomainName(name="test.com"))))
        cert = CertInfo()
        cert.subject_alt_names = ["www.test.com"]
        self.assertTrue(cert.matches_host_name(HostName(name="www", domain_name=DomainName(name="test.com"))))
        self.assertFalse(cert.matches_host_name(HostName(name=None, domain_name=DomainName(name="test.com"))))
        cert = CertInfo()
        cert.subject_alt_names = ["*.test.com"]
        self.assertTrue(cert.matches_host_name(HostName(name="www", domain_name=DomainName(name="test.com"))))
        self.assertFalse(cert.matches_host_name(HostName(name=None, domain_name=DomainName(name="test.com"))))

    def test_method_matches_host_names(self):
        cert = CertInfo()
        cert.common_name = "*.test.com"
        domain_name = DomainName(name="test.com")
        host_names = [HostName(name="www", domain_name=domain_name),
                      HostName(name="ftp", domain_name=domain_name),
                      HostName(name="ssh", domain_name=domain_name)]
        self.assertTrue(cert.matches_host_names(host_names))
        host_names.append(HostName(name=None, domain_name=domain_name))
        self.assertFalse(cert.matches_host_names(host_names))
        cert = CertInfo()
        cert.subject_alt_names = ["*.test.com"]
        host_names = [HostName(name="www", domain_name=domain_name),
                      HostName(name="ftp", domain_name=domain_name),
                      HostName(name="ssh", domain_name=domain_name)]
        self.assertTrue(cert.matches_host_names(host_names))
        host_names.append(HostName(name=None, domain_name=domain_name))
        self.assertFalse(cert.matches_host_names(host_names))
        cert = CertInfo()
        cert.common_name = "www.test.com"
        host_names = [HostName(name="www", domain_name=domain_name),
                      HostName(name="ftp", domain_name=domain_name),
                      HostName(name="ssh", domain_name=domain_name),
                      HostName(name=None, domain_name=domain_name)]
        cert.subject_alt_names = ["ftp.test.com", "ssh.test.com", "test.com"]
        self.assertTrue(cert.matches_host_names(host_names))
        cert = CertInfo()
        cert.common_name = "test.com"
        cert.subject_alt_names = ["*.test.com"]
        self.assertTrue(cert.matches_host_names(host_names))
        host_names.append(HostName(name="www", domain_name=DomainName(name="test1.com")))
        self.assertFalse(cert.matches_host_names(host_names))
        cert = CertInfo()
        cert.common_name = "*.test.com"
        cert.subject_alt_names = ["test.com"]
        host_names = [HostName(name="www", domain_name=domain_name),
                      HostName(name="ftp", domain_name=domain_name),
                      HostName(name="ssh", domain_name=domain_name),
                      HostName(name=None, domain_name=domain_name)]
        self.assertTrue(cert.matches_host_names(host_names))
        host_names.append(HostName(name="www", domain_name=DomainName(name="test1.com")))
        self.assertFalse(cert.matches_host_names(host_names))
