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

import tempfile
from database.model import CollectorType
from database.model import TlsInfo
from database.model import CipherSuite
from database.model import TlsInfoCipherSuiteMapping
from database.model import ScopeType
from database.model import TlsVersion
from database.model import KeyExchangeAlgorithm
from typing import List
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.scan.core import BaseNmapCollectorTestCase
from collectors.os.modules.tls.tlsnmap import CollectorClass as TlsNmapCollector


# PORT    STATE SERVICE
# 443/tcp open  https
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
        return ["""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.91 scan initiated Wed Sep 15 21:10:08 2021 as: nmap -p 443 -sS -&#45;script ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed,sslv2,ssl-known-key 192.168.1.1 -->
<nmaprun scanner="nmap" args="nmap -p 443 -sS -&#45;script ssl-enum-ciphers,ssl-dh-params,ssl-heartbleed,sslv2,ssl-known-key 192.168.1.1" start="1631733008" startstr="Wed Sep 15 21:10:08 2021" version="7.91" xmloutputversion="1.05">
<scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
<verbose level="0"/>
<debugging level="0"/>
<hosthint><status state="up" reason="unknown-response" reason_ttl="0"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostnames />
</hosthint>
<host starttime="1631733008" endtime="1631733009"><status state="up" reason="echo-reply" reason_ttl="109"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostnames />
<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack" reason_ttl="51"/><service name="http" product="Apache httpd" version="2.4.39" extrainfo="(Win64) OpenSSL/1.1.1b PHP/7.3.4" tunnel="ssl" method="probed" conf="10"><cpe>cpe:/a:apache:http_server:2.4.39</cpe></service><script id="http-server-header" output="Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4"><elem>Apache/2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4</elem></script><script id="ssl-enum-ciphers" output="&#xa;  TLSv1.0: &#xa;    ciphers: &#xa;      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A&#xa;      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A&#xa;      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C&#xa;    compressors: &#xa;      NULL&#xa;    cipher preference: server&#xa;    warnings: &#xa;      64-bit block cipher 3DES vulnerable to SWEET32 attack&#xa;  TLSv1.1: &#xa;    ciphers: &#xa;      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A&#xa;      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A&#xa;      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C&#xa;    compressors: &#xa;      NULL&#xa;    cipher preference: server&#xa;    warnings: &#xa;      64-bit block cipher 3DES vulnerable to SWEET32 attack&#xa;  TLSv1.2: &#xa;    ciphers: &#xa;      TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A&#xa;      TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A&#xa;      TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (ecdh_x25519) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ecdh_x25519) - A&#xa;      TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (ecdh_x25519) - A&#xa;      TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (ecdh_x25519) - A&#xa;      TLS_RSA_WITH_3DES_EDE_CBC_SHA (rsa 2048) - C&#xa;      TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - A&#xa;      TLS_RSA_WITH_AES_128_GCM_SHA256 (rsa 2048) - A&#xa;      TLS_RSA_WITH_AES_256_CBC_SHA (rsa 2048) - A&#xa;      TLS_RSA_WITH_AES_256_GCM_SHA384 (rsa 2048) - A&#xa;    compressors: &#xa;      NULL&#xa;    cipher preference: client&#xa;    warnings: &#xa;      64-bit block cipher 3DES vulnerable to SWEET32 attack&#xa;  least strength: C"><table key="TLSv1.0">
<table key="ciphers">
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
<table>
<elem key="strength">C</elem>
<elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
</table>
<table key="compressors">
<elem>NULL</elem>
</table>
<elem key="cipher preference">server</elem>
<table key="warnings">
<elem>64-bit block cipher 3DES vulnerable to SWEET32 attack</elem>
</table>
</table>
<table key="TLSv1.1">
<table key="ciphers">
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
<table>
<elem key="strength">C</elem>
<elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
</table>
<table key="compressors">
<elem>NULL</elem>
</table>
<elem key="cipher preference">server</elem>
<table key="warnings">
<elem>64-bit block cipher 3DES vulnerable to SWEET32 attack</elem>
</table>
</table>
<table key="TLSv1.2">
<table key="ciphers">
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256</elem>
<elem key="kex_info">ecdh_x25519</elem>
</table>
<table>
<elem key="strength">C</elem>
<elem key="name">TLS_RSA_WITH_3DES_EDE_CBC_SHA</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_RSA_WITH_AES_128_CBC_SHA</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_RSA_WITH_AES_128_GCM_SHA256</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_RSA_WITH_AES_256_CBC_SHA</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
<table>
<elem key="strength">A</elem>
<elem key="name">TLS_RSA_WITH_AES_256_GCM_SHA384</elem>
<elem key="kex_info">rsa 2048</elem>
</table>
</table>
<table key="compressors">
<elem>NULL</elem>
</table>
<elem key="cipher preference">client</elem>
<table key="warnings">
<elem>64-bit block cipher 3DES vulnerable to SWEET32 attack</elem>
</table>
</table>
<elem key="least strength">C</elem>
</script></port>
</ports>
<times srtt="3697" rttvar="3774" to="100000"/>
</host>
<runstats><finished time="1631733009" timestr="Wed Sep 15 21:10:09 2021" summary="Nmap done at Wed Sep 15 21:10:09 2021; 1 IP address (1 host up) scanned in 1.06 seconds" elapsed="1.06" exit="success"/><hosts up="1" down="0" total="1"/>
</runstats>
</nmaprun>"""]

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
                command.xml_output = self.get_command_xml_outputs()[0]
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
            expected_results = ["TLSv1.0", "TLSv1.1", "TLSv1.2"]
            expected_results.sort()
            self.assertListEqual(expected_results, results)
            self.assertEqual("Apache httpd", tls_info[0].service.nmap_product)
            self.assertEqual("2.4.39", tls_info[0].service.nmap_version)
            self.assertEqual("Apache httpd 2.4.39 (Win64) OpenSSL/1.1.1b PHP/7.3.4",
                             tls_info[0].service.nmap_product_version)
            # TlsInfo
            results = session.query(TlsInfo).all()
            results = [item.version_str for item in results]
            results.sort()
            expected_results = ["TLSv1.0",
                                "TLSv1.1",
                                "TLSv1.2"]
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
            expected_result = ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                               "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                               "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                               "TLS_RSA_WITH_AES_128_CBC_SHA",
                               "TLS_RSA_WITH_AES_256_CBC_SHA",
                               "TLS_RSA_WITH_3DES_EDE_CBC_SHA"]
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
            expected_result = ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
                               "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                               "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
                               "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                               "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                               "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
                               "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                               "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
                               "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                               "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
                               "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                               "TLS_RSA_WITH_AES_128_CBC_SHA",
                               "TLS_RSA_WITH_AES_128_GCM_SHA256",
                               "TLS_RSA_WITH_AES_256_CBC_SHA",
                               "TLS_RSA_WITH_AES_256_GCM_SHA384"]
            expected_result.sort()
            result = [item.iana_name for item in result.cipher_suites]
            result.sort()
            self.assertListEqual(expected_result, result)
            # Test TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (ecdh_x25519)
            result = session.query(TlsInfoCipherSuiteMapping) \
                .join((TlsInfo, TlsInfoCipherSuiteMapping.tls_info)) \
                .join((CipherSuite, TlsInfoCipherSuiteMapping.cipher_suite)) \
                .filter(TlsInfo.version == TlsVersion.tls12,
                        CipherSuite.iana_name == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256").one()
            self.assertEqual(KeyExchangeAlgorithm.ecdh_x25519, result.kex_algorithm_details)
            # Test TLS_RSA_WITH_3DES_EDE_CBC_SHA
            result = session.query(TlsInfoCipherSuiteMapping) \
                .join((TlsInfo, TlsInfoCipherSuiteMapping.tls_info)) \
                .join((CipherSuite, TlsInfoCipherSuiteMapping.cipher_suite)) \
                .filter(TlsInfo.version == TlsVersion.tls12,
                        CipherSuite.iana_name == "TLS_RSA_WITH_3DES_EDE_CBC_SHA").one()
            self.assertEqual(KeyExchangeAlgorithm.rsa2048, result.kex_algorithm_details)
