#!/usr/bin/python3
"""
this file implements all unittests for collector sslyze
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
import json
from database.model import CollectorType
from database.model import TlsInfo
from database.model import CertInfo
from database.model import TlsInfoCipherSuiteMapping
from database.model import CipherSuite
from database.model import ScopeType
from database.model import TlsVersion
from database.model import KeyExchangeAlgorithm
from typing import List
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.scan.core import BaseNmapCollectorTestCase
from collectors.os.modules.tls.sslyze import CollectorClass as SslyzeCollector


# * TLS 1.0 Cipher Suites:
#     Attempted to connect using 80 cipher suites.
#
#     The server accepted the following 5 cipher suites:
#        TLS_RSA_WITH_AES_256_CBC_SHA                      256
#        TLS_RSA_WITH_AES_128_CBC_SHA                      128
#        TLS_RSA_WITH_3DES_EDE_CBC_SHA                     168
#        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                256       ECDH: prime256v1 (256 bits)
#        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                128       ECDH: prime256v1 (256 bits)
#
#     The group of cipher suites supported by the server has the following properties:
#       Forward Secrecy                    OK - Supported
#       Legacy RC4 Algorithm               OK - Not Supported
#
#
# * TLS 1.1 Cipher Suites:
#     Attempted to connect using 80 cipher suites.
#
#     The server accepted the following 5 cipher suites:
#        TLS_RSA_WITH_AES_256_CBC_SHA                      256
#        TLS_RSA_WITH_AES_128_CBC_SHA                      128
#        TLS_RSA_WITH_3DES_EDE_CBC_SHA                     168
#        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                256       ECDH: prime256v1 (256 bits)
#        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                128       ECDH: prime256v1 (256 bits)
#
#     The group of cipher suites supported by the server has the following properties:
#       Forward Secrecy                    OK - Supported
#       Legacy RC4 Algorithm               OK - Not Supported
#
#
# * TLS 1.2 Cipher Suites:
#     Attempted to connect using 156 cipher suites.
#
#     The server accepted the following 11 cipher suites:
#        TLS_RSA_WITH_AES_256_GCM_SHA384                   256
#        TLS_RSA_WITH_AES_256_CBC_SHA                      256
#        TLS_RSA_WITH_AES_128_GCM_SHA256                   128
#        TLS_RSA_WITH_AES_128_CBC_SHA                      128
#        TLS_RSA_WITH_3DES_EDE_CBC_SHA                     168
#        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256       256       ECDH: X25519 (253 bits)
#        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384             256       ECDH: prime256v1 (256 bits)
#        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                256       ECDH: prime256v1 (256 bits)
#        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256             128       ECDH: prime256v1 (256 bits)
#        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                128       ECDH: prime256v1 (256 bits)
#        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256     256       ECDH: X25519 (253 bits)
#
#     The group of cipher suites supported by the server has the following properties:
#       Forward Secrecy                    OK - Supported
#       Legacy RC4 Algorithm               OK - Not Supported
#
#
# * TLS 1.3 Cipher Suites:
#     Attempted to connect using 5 cipher suites.
#
#     The server accepted the following 3 cipher suites:
#        TLS_CHACHA20_POLY1305_SHA256                      256       ECDH: X25519 (253 bits)
#        TLS_AES_256_GCM_SHA384                            256       ECDH: X25519 (253 bits)
#        TLS_AES_128_GCM_SHA256                            128       ECDH: X25519 (253 bits)


class SslyzeCollectorTestCase(BaseNmapCollectorTestCase):
    """
    This class implements all unittests for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="sslyze",
                         collector_class=SslyzeCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return []

    @staticmethod
    def get_command_json_outputs() -> List[str]:
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
                                              command=["sslyze", 'www.google.com'],
                                              collector_name_str="sslyze",
                                              collector_name_type=CollectorType.host_service,
                                              service_port=443,
                                              scope=ScopeType.all)
                with open(os.path.join(os.path.dirname(__file__), "sslyze.json"), "r") as file:
                    json_text = file.read()
                    json_object = json.loads(json_text)
                command.json_output.append(json_object)
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            # CertInfo
            results = session.query(CertInfo).all()
            self.assertEqual(4, len(results))
            # TlsInfo
            results = session.query(TlsInfo).all()
            results = [item.version_str for item in results]
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
            expected_result = ["TLS_RSA_WITH_AES_256_CBC_SHA",
                               "TLS_RSA_WITH_AES_128_CBC_SHA",
                               "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                               "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"]
            expected_result.sort()
            result = [item.iana_name for item in result.cipher_suites]
            result.sort()
            self.assertListEqual(expected_result, result)
            # Test TLSv1.1
            result = session.query(TlsInfo).filter_by(version=TlsVersion.tls11).one()
            result = [item.iana_name for item in result.cipher_suites]
            result.sort()
            self.assertListEqual(expected_result, result)
            # Test TLSv1.2
            result = session.query(TlsInfo).filter_by(version=TlsVersion.tls12).one()
            expected_result = ["TLS_RSA_WITH_AES_256_GCM_SHA384",
                               "TLS_RSA_WITH_AES_256_CBC_SHA",
                               "TLS_RSA_WITH_AES_128_GCM_SHA256",
                               "TLS_RSA_WITH_AES_128_CBC_SHA",
                               "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                               "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                               "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                               "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                               "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                               "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"]
            expected_result.sort()
            result = [item.iana_name for item in result.cipher_suites]
            result.sort()
            self.assertListEqual(expected_result, result)
            # Test TLSv1.3
            result = session.query(TlsInfo).filter_by(version=TlsVersion.tls13).one()
            expected_result = ["TLS_CHACHA20_POLY1305_SHA256",
                               "TLS_AES_256_GCM_SHA384",
                               "TLS_AES_128_GCM_SHA256"]
            expected_result.sort()
            result = [item.iana_name for item in result.cipher_suites]
            result.sort()
            self.assertListEqual(expected_result, result)
            # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256       256       ECDH: X25519 (253 bits)
            result = session.query(TlsInfoCipherSuiteMapping) \
                .join((TlsInfo, TlsInfoCipherSuiteMapping.tls_info)) \
                .join((CipherSuite, TlsInfoCipherSuiteMapping.cipher_suite)) \
                .filter(TlsInfo.version == TlsVersion.tls12,
                        CipherSuite.iana_name == "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256").one()
            # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384             256       ECDH: prime256v1 (256 bits)
            result = session.query(TlsInfoCipherSuiteMapping) \
                .join((TlsInfo, TlsInfoCipherSuiteMapping.tls_info)) \
                .join((CipherSuite, TlsInfoCipherSuiteMapping.cipher_suite)) \
                .filter(TlsInfo.version == TlsVersion.tls12,
                        CipherSuite.iana_name == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384").one()
            self.assertEqual(KeyExchangeAlgorithm.p_256, result.kex_algorithm_details)
            # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA                256       ECDH: prime256v1 (256 bits)
            result = session.query(TlsInfoCipherSuiteMapping) \
                .join((TlsInfo, TlsInfoCipherSuiteMapping.tls_info)) \
                .join((CipherSuite, TlsInfoCipherSuiteMapping.cipher_suite)) \
                .filter(TlsInfo.version == TlsVersion.tls12,
                        CipherSuite.iana_name == "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA").one()
            self.assertEqual(KeyExchangeAlgorithm.p_256, result.kex_algorithm_details)
            # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256             128       ECDH: prime256v1 (256 bits)
            result = session.query(TlsInfoCipherSuiteMapping) \
                .join((TlsInfo, TlsInfoCipherSuiteMapping.tls_info)) \
                .join((CipherSuite, TlsInfoCipherSuiteMapping.cipher_suite)) \
                .filter(TlsInfo.version == TlsVersion.tls12,
                        CipherSuite.iana_name == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256").one()
            self.assertEqual(KeyExchangeAlgorithm.p_256, result.kex_algorithm_details)
            # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA                128       ECDH: prime256v1 (256 bits)
            result = session.query(TlsInfoCipherSuiteMapping) \
                .join((TlsInfo, TlsInfoCipherSuiteMapping.tls_info)) \
                .join((CipherSuite, TlsInfoCipherSuiteMapping.cipher_suite)) \
                .filter(TlsInfo.version == TlsVersion.tls12,
                        CipherSuite.iana_name == "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA").one()
            self.assertEqual(KeyExchangeAlgorithm.p_256, result.kex_algorithm_details)
            # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256                256       ECDH: X25519 (253 bits)
            result = session.query(TlsInfoCipherSuiteMapping) \
                .join((TlsInfo, TlsInfoCipherSuiteMapping.tls_info)) \
                .join((CipherSuite, TlsInfoCipherSuiteMapping.cipher_suite)) \
                .filter(TlsInfo.version == TlsVersion.tls12,
                        CipherSuite.iana_name == "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256").one()
            self.assertEqual(KeyExchangeAlgorithm.ecdh_x25519, result.kex_algorithm_details)
