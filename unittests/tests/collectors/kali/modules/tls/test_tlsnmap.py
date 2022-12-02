#!/usr/bin/python3
"""
this file implements all unittests for collector tlsnmap
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

import os
import tempfile
from database.model import CollectorType
from database.model import TlsInfo
from database.model import ScopeType
from database.model import TlsVersion
from typing import List
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.scan.core import BaseNmapCollectorTestCase
from collectors.os.modules.tls.tlsnmap import CollectorClass as TlsNmapCollector


# | ssl-enum-ciphers:
# |   TLSv1.0:
# |     ciphers:
# |       TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A
# |       TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A
# |       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A
# |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A
# |       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
# |       TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A
# |       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
# |     compressors:
# |       NULL
# |     cipher preference: server
# |     warnings:
# |       64-bit block cipher 3DES vulnerable to SWEET32 attack
# |   TLSv1.1:
# |     ciphers:
# |       TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A
# |       TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A
# |       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A
# |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A
# |       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
# |       TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A
# |       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
# |     compressors:
# |       NULL
# |     cipher preference: server
# |     warnings:
# |       64-bit block cipher 3DES vulnerable to SWEET32 attack
# |   TLSv1.2:
# |     ciphers:
# |       TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A
# |       TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
# |       TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A
# |       TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
# |       TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
# |       TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A
# |       TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
# |       TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A
# |       TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
# |       TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
# |       TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C
# |       TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A
# |       TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa 2048) - A
# |       TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A
# |       TLS_RSA_WITH_AES_256_GCM_SHA384 (rsa 2048) - A
# |     compressors:
# |       NULL
# |     cipher preference: client
# |     warnings:
# |       64-bit block cipher 3DES vulnerable to SWEET32 attack
# |   TLSv1.3:
# |     ciphers:
# |       TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A
# |       TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A
# |       TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A
# |     cipher preference: client
# |_  least strength: C

class BaseTlsNmapCollectorTestCase(BaseNmapCollectorTestCase):
    """
    This class implements all unittests for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="tlsnmap",
                         collector_class=TlsNmapCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return []

    @staticmethod
    def get_command_xml_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return []

    def test_verify_results(self):
        """
        This method checks whether the collector correctly verifies the command output
        :return:
        """
        self.init_db(load_cipher_suites=True)
        with tempfile.TemporaryDirectory() as temp_dir:
            test_suite = CollectorProducerTestSuite(engine=self._engine,
                                                    arguments={"workspace": self._workspaces[0],
                                                               "output_dir": temp_dir})
            with self._engine.session_scope() as session:
                source = self.create_source(session, source_str=self._collector_name)
                command = self.create_command(session=session,
                                              workspace_str=self._workspaces[0],
                                              command=["nmap", '-p', '443', '192.168.1.1'],
                                              collector_name_str="tlsnmap",
                                              collector_name_type=CollectorType.host_service,
                                              service_port=443,
                                              scope=ScopeType.all)
                with open(os.path.join(os.path.dirname(__file__), "nmap.xml"), "r") as file:
                    command.xml_output = file.read()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            # TlsInfo
            tls_info = session.query(TlsInfo).all()
            results = [item.version_str for item in tls_info]
            results.sort()
            expected_results = ["TLSv1.0",
                                "TLSv1.1",
                                "TLSv1.2",
                                "TLSv1.3"]
            expected_results.sort()
            self.assertListEqual(expected_results, results)
            # Test SSLv2
            result = session.query(TlsInfo).filter_by(version=TlsVersion.ssl2).one_or_none()
            self.assertIsNone(result)
            # Test SSLv3
            result = session.query(TlsInfo).filter_by(version=TlsVersion.ssl3).one_or_none()
            self.assertIsNone(result)
            # Test TLSv1.0
            result = session.query(TlsInfo).filter_by(version=TlsVersion.tls10).one()
            expected_result = ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519)",
                               "TLS_RSA_WITH_AES_128_CBC_SHA (rsa2048)",
                               "TLS_RSA_WITH_AES_256_CBC_SHA (rsa2048)",
                               "TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa2048)"]
            expected_result.sort()
            result = ["{} ({})".format(item.cipher_suite.iana_name,
                                       item.kex_algorithm_details.name) for item in result.cipher_suite_mappings]
            result.sort()
            self.assertListEqual(expected_result, result)
            # Test TLSv1.1
            result = session.query(TlsInfo).filter_by(version=TlsVersion.tls11).one()
            expected_result = ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519)",
                               "TLS_RSA_WITH_AES_128_CBC_SHA (rsa2048)",
                               "TLS_RSA_WITH_AES_256_CBC_SHA (rsa2048)",
                               "TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa2048)"]
            expected_result.sort()
            result = ["{} ({})".format(item.cipher_suite.iana_name,
                                       item.kex_algorithm_details.name) for item in result.cipher_suite_mappings]
            result.sort()
            self.assertListEqual(expected_result, result)
            # Test TLSv1.2
            result = session.query(TlsInfo).filter_by(version=TlsVersion.tls12).one()
            expected_result = ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519)",
                               "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519)",
                               "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519)",
                               "TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa2048)",
                               "TLS_RSA_WITH_AES_128_CBC_SHA (rsa2048)",
                               "TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa2048)",
                               "TLS_RSA_WITH_AES_256_CBC_SHA (rsa2048)",
                               "TLS_RSA_WITH_AES_256_GCM_SHA384 (rsa2048)"]
            expected_result.sort()
            result = ["{} ({})".format(item.cipher_suite.iana_name,
                                       item.kex_algorithm_details.name) for item in result.cipher_suite_mappings]
            result.sort()
            self.assertListEqual(expected_result, result)
            # Test TLSv1.3
            result = session.query(TlsInfo).filter_by(version=TlsVersion.tls13).one()
            expected_result = ["TLS_AKE_WITH_AES_128_GCM_SHA256 (ecdh_x25519)",
                               "TLS_AKE_WITH_AES_256_GCM_SHA384 (ecdh_x25519)",
                               "TLS_AKE_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519)"]
            expected_result.sort()
            result = [item.iana_name for item in result.cipher_suites]
            result.sort()
