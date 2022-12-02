#!/usr/bin/python3
"""
this file implements all unittests for collector sslscan
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
from database.model import HostName
from database.model import CertInfo
from database.model import TlsVersion
from database.model import ScopeType
from database.model import CipherSuite
from database.model import TlsInfoCipherSuiteMapping
from database.model import KeyExchangeAlgorithm
from typing import List
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.scan.core import BaseNmapCollectorTestCase
from collectors.os.modules.tls.sslscan import CollectorClass as SslscanCollector


#   Supported Server Cipher(s):
# Preferred TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
# Accepted  TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve 25519 DHE 253
# Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253
# Preferred TLSv1.2  256 bits  ECDHE-ECDSA-CHACHA20-POLY1305 Curve 25519 DHE 253
# Accepted  TLSv1.2  128 bits  ECDHE-ECDSA-AES128-GCM-SHA256 Curve 25519 DHE 253
# Accepted  TLSv1.2  256 bits  ECDHE-ECDSA-AES256-GCM-SHA384 Curve 25519 DHE 253
# Accepted  TLSv1.2  128 bits  ECDHE-ECDSA-AES128-SHA        Curve 25519 DHE 253
# Accepted  TLSv1.2  256 bits  ECDHE-ECDSA-AES256-SHA        Curve 25519 DHE 253
# Accepted  TLSv1.2  256 bits  ECDHE-RSA-CHACHA20-POLY1305   Curve 25519 DHE 253
# Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve 25519 DHE 253
# Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-GCM-SHA384   Curve 25519 DHE 253
# Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-SHA          Curve 25519 DHE 253
# Accepted  TLSv1.2  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
# Accepted  TLSv1.2  128 bits  AES128-GCM-SHA256
# Accepted  TLSv1.2  256 bits  AES256-GCM-SHA384
# Accepted  TLSv1.2  128 bits  AES128-SHA
# Accepted  TLSv1.2  256 bits  AES256-SHA
# Accepted  TLSv1.2  112 bits  DES-CBC3-SHA
# Preferred TLSv1.1  128 bits  ECDHE-ECDSA-AES128-SHA        Curve 25519 DHE 253
# Accepted  TLSv1.1  256 bits  ECDHE-ECDSA-AES256-SHA        Curve 25519 DHE 253
# Accepted  TLSv1.1  128 bits  ECDHE-RSA-AES128-SHA          Curve 25519 DHE 253
# Accepted  TLSv1.1  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
# Accepted  TLSv1.1  128 bits  AES128-SHA
# Accepted  TLSv1.1  256 bits  AES256-SHA
# Accepted  TLSv1.1  112 bits  DES-CBC3-SHA
# Preferred TLSv1.0  128 bits  ECDHE-ECDSA-AES128-SHA        Curve 25519 DHE 253
# Accepted  TLSv1.0  256 bits  ECDHE-ECDSA-AES256-SHA        Curve 25519 DHE 253
# Accepted  TLSv1.0  128 bits  ECDHE-RSA-AES128-SHA          Curve 25519 DHE 253
# Accepted  TLSv1.0  256 bits  ECDHE-RSA-AES256-SHA          Curve 25519 DHE 253
# Accepted  TLSv1.0  128 bits  AES128-SHA
# Accepted  TLSv1.0  256 bits  AES256-SHA
# Accepted  TLSv1.0  112 bits  DES-CBC3-SHA
#
#   Server Key Exchange Group(s):
# TLSv1.3  128 bits  secp256r1 (NIST P-256)
# TLSv1.3  128 bits  x25519
# TLSv1.2  128 bits  secp256r1 (NIST P-256)
# TLSv1.2  128 bits  x25519


class SslscanCollectorTestCase(BaseNmapCollectorTestCase):
    """
    This class implements all unittests for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="sslscan",
                         collector_class=SslscanCollector)

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
                                              command=["sslscan", 'www.google.com'],
                                              collector_name_str="sslscan",
                                              collector_name_type=CollectorType.host_service,
                                              service_port=443,
                                              scope=ScopeType.all)
                with open(os.path.join(os.path.dirname(__file__), "sslscan.xml"), "r") as file:
                    command.xml_output = file.read()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            # CertInfo
            results = session.query(CertInfo).one()
            self.assertEqual("www.google.com", results.subject_common_names_str)
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
            expected_result = ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519)",
                               "TLS_RSA_WITH_AES_128_CBC_SHA (None)",
                               "TLS_RSA_WITH_AES_256_CBC_SHA (None)",
                               "TLS_RSA_WITH_3DES_EDE_CBC_SHA (None)"]
            expected_result.sort()
            result = ["{} ({})".format(item.cipher_suite.iana_name,
                                       item.kex_algorithm_details.name if item.kex_algorithm_details else "None")
                      for item in result.cipher_suite_mappings]
            result.sort()
            self.assertListEqual(expected_result, result)
            # Test TLSv1.1
            result = session.query(TlsInfo).filter_by(version=TlsVersion.tls11).one()
            expected_result = ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519)",
                               "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519)",
                               "TLS_RSA_WITH_AES_128_CBC_SHA (None)",
                               "TLS_RSA_WITH_AES_256_CBC_SHA (None)",
                               "TLS_RSA_WITH_3DES_EDE_CBC_SHA (None)"]
            expected_result.sort()
            result = ["{} ({})".format(item.cipher_suite.iana_name,
                                       item.kex_algorithm_details.name if item.kex_algorithm_details else "None")
                      for item in result.cipher_suite_mappings]
            result.sort()
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
                               "TLS_RSA_WITH_3DES_EDE_CBC_SHA (None)",
                               "TLS_RSA_WITH_AES_128_CBC_SHA (None)",
                               "TLS_RSA_WITH_AES_128_GCM_SHA256 (None)",
                               "TLS_RSA_WITH_AES_256_CBC_SHA (None)",
                               "TLS_RSA_WITH_AES_256_GCM_SHA384 (None)"]
            expected_result.sort()
            result = ["{} ({})".format(item.cipher_suite.iana_name,
                                       item.kex_algorithm_details.name if item.kex_algorithm_details else "None")
                      for item in result.cipher_suite_mappings]
            result.sort()
            self.assertListEqual(expected_result, result)
            # Test TLSv1.3
            result = session.query(TlsInfo).filter_by(version=TlsVersion.tls13).one()
            expected_result = ["TLS_AES_128_GCM_SHA256 (ecdh_x25519)",
                               "TLS_AES_256_GCM_SHA384 (ecdh_x25519)",
                               "TLS_CHACHA20_POLY1305_SHA256 (ecdh_x25519)"]
            expected_result.sort()
            result = ["{} ({})".format(item.cipher_suite.iana_name,
                                       item.kex_algorithm_details.name if item.kex_algorithm_details else "None")
                      for item in result.cipher_suite_mappings]
            result.sort()
            self.assertListEqual(expected_result, result)
