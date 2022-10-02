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
        return ["""<?xml version="1.0" encoding="UTF-8"?>
<document title="SSLScan Results" version="2.0.10-static" web="http://github.com/rbsec/sslscan">
 <ssltest host="www.google.com" sniname="www.google.com" port="443">
  <protocol type="ssl" version="2" enabled="0" />
  <protocol type="ssl" version="3" enabled="0" />
  <protocol type="tls" version="1.0" enabled="1" />
  <protocol type="tls" version="1.1" enabled="1" />
  <protocol type="tls" version="1.2" enabled="1" />
  <protocol type="tls" version="1.3" enabled="1" />
  <fallback supported="1" />
  <renegotiation supported="1" secure="1" />
  <compression supported="0" />
  <heartbleed sslversion="TLSv1.3" vulnerable="0" />
  <heartbleed sslversion="TLSv1.2" vulnerable="0" />
  <heartbleed sslversion="TLSv1.1" vulnerable="0" />
  <heartbleed sslversion="TLSv1.0" vulnerable="0" />
  <cipher status="preferred" sslversion="TLSv1.3" bits="128" cipher="TLS_AES_128_GCM_SHA256" id="0x1301" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.3" bits="256" cipher="TLS_AES_256_GCM_SHA384" id="0x1302" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.3" bits="256" cipher="TLS_CHACHA20_POLY1305_SHA256" id="0x1303" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="preferred" sslversion="TLSv1.2" bits="256" cipher="ECDHE-ECDSA-CHACHA20-POLY1305" id="0xCCA9" strength="strong" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="ECDHE-ECDSA-AES128-GCM-SHA256" id="0xC02B" strength="strong" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="ECDHE-ECDSA-AES256-GCM-SHA384" id="0xC02C" strength="strong" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="ECDHE-ECDSA-AES128-SHA" id="0xC009" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="ECDHE-ECDSA-AES256-SHA" id="0xC00A" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-CHACHA20-POLY1305" id="0xCCA8" strength="strong" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="ECDHE-RSA-AES128-GCM-SHA256" id="0xC02F" strength="strong" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-AES256-GCM-SHA384" id="0xC030" strength="strong" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="ECDHE-RSA-AES128-SHA" id="0xC013" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-AES256-SHA" id="0xC014" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="AES128-GCM-SHA256" id="0x009C" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="AES256-GCM-SHA384" id="0x009D" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="AES128-SHA" id="0x002F" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="AES256-SHA" id="0x0035" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="112" cipher="DES-CBC3-SHA" id="0x000A" strength="medium" />
  <cipher status="preferred" sslversion="TLSv1.1" bits="128" cipher="ECDHE-ECDSA-AES128-SHA" id="0xC009" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.1" bits="256" cipher="ECDHE-ECDSA-AES256-SHA" id="0xC00A" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.1" bits="128" cipher="ECDHE-RSA-AES128-SHA" id="0xC013" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.1" bits="256" cipher="ECDHE-RSA-AES256-SHA" id="0xC014" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.1" bits="128" cipher="AES128-SHA" id="0x002F" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.1" bits="256" cipher="AES256-SHA" id="0x0035" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.1" bits="112" cipher="DES-CBC3-SHA" id="0x000A" strength="medium" />
  <cipher status="preferred" sslversion="TLSv1.0" bits="128" cipher="ECDHE-ECDSA-AES128-SHA" id="0xC009" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="256" cipher="ECDHE-ECDSA-AES256-SHA" id="0xC00A" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="128" cipher="ECDHE-RSA-AES128-SHA" id="0xC013" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="256" cipher="ECDHE-RSA-AES256-SHA" id="0xC014" strength="acceptable" curve="25519" ecdhebits="253" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="128" cipher="AES128-SHA" id="0x002F" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="256" cipher="AES256-SHA" id="0x0035" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="112" cipher="DES-CBC3-SHA" id="0x000A" strength="medium" />
  <group sslversion="TLSv1.3" bits="128" name="secp256r1 (NIST P-256)" id="0x0017" />
  <group sslversion="TLSv1.3" bits="128" name="x25519" id="0x001d" />
  <group sslversion="TLSv1.2" bits="128" name="secp256r1 (NIST P-256)" id="0x0017" />
  <group sslversion="TLSv1.2" bits="128" name="x25519" id="0x001d" />
 <certificates>
  <certificate type="full">
   <certificate-blob>
-----BEGIN CERTIFICATE-----
MIIEhzCCA2+gAwIBAgIQBzqkk7k/YrYKAAAAAPuB6DANBgkqhkiG9w0BAQsFADBG
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM
QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMTA4MjMwNDAzNDRaFw0yMTExMTUw
NDAzNDNaMBkxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEtAzrBmnqksqM0fypfchLIYZCi1ZLifdynZglgoP0mlMEZVDs
MLFVPucGmBTIORvWhfKzIyUNGHIn9r5+dnaiM6OCAmcwggJjMA4GA1UdDwEB/wQE
AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
BBQZDN5lrOyr62P9JMXMbT/M8BdMCzAfBgNVHSMEGDAWgBSKdH+vhc3ulc09nNDi
RhTzcTUdJzBqBggrBgEFBQcBAQReMFwwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3Nw
LnBraS5nb29nL2d0czFjMzAxBggrBgEFBQcwAoYlaHR0cDovL3BraS5nb29nL3Jl
cG8vY2VydHMvZ3RzMWMzLmRlcjAZBgNVHREEEjAQgg53d3cuZ29vZ2xlLmNvbTAh
BgNVHSAEGjAYMAgGBmeBDAECATAMBgorBgEEAdZ5AgUDMDwGA1UdHwQ1MDMwMaAv
oC2GK2h0dHA6Ly9jcmxzLnBraS5nb29nL2d0czFjMy9RT3ZKME4xc1QyQS5jcmww
ggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdwB9PvL4j/+IVWgkwsDKnlKJeSvFDngJ
fy5ql2iZfiLw1wAAAXtxZKTzAAAEAwBIMEYCIQCAct1r7Lt0HrHLsxtDwveb3Ny+
MNX0PcF6RzPQ0aijeAIhAKca0H/O2Kgf80/KNTdldTd0PyppJ7ouFy8imDdL19uJ
AHUAXNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDsoAAAF7cWSlqAAABAMA
RjBEAiBR0gYJZg2FwaK3FHCALReafzSlj7T5UCh3nHZbDxG8vAIgLTD31R9xCyrG
UlK1Thw76H0di2ziYXCh/AEiLpLn90gwDQYJKoZIhvcNAQELBQADggEBANMroXvs
YknyxdElXC2xbNWo6OSAEjof9EQmIBYDqWiToqO17Omois1qA6bF3bdqBZRaXIwl
Ut5jqmEBIEmt27e1nVDkOrY7/xhglz0BBn65pBlLGQmwl6/xSicGG0i1+SDJzB+7
b8po3s8G7BQ9tZq6uBhPXuiupfxr1co7FFo4v0GWtjTHC15/2upSfvlUu7OU2n2q
su+jEUMo1fJqaF6rioEKhWJHv1ZqPQf59CFxM8uq1reusoqY0bM7VMymJlrgnIMJ
AJC06U3ArWErYVyjuqkfbm6TDbqjy3TSGUwvmkQT6sODJMz8gEXAn9R4lNtg62Ci
rMOU4YMvqw/caKo=
-----END CERTIFICATE-----
   </certificate-blob>
   <version>2</version>
   <serial>07:3a:a4:93:b9:3f:62:b6:0a:00:00:00:00:fb:81:e8</serial>
   <signature-algorithm>    Signature Algorithm: sha256WithRSAEncryption
</signature-algorithm>
   <issuer><![CDATA[/C=US/O=Google Trust Services LLC/CN=GTS CA 1C3]]></issuer>
   <not-valid-before>Aug 23 04:03:44 2021 GMT</not-valid-before>
   <not-valid-after>Nov 15 04:03:43 2021 GMT</not-valid-after>
   <subject><![CDATA[/CN=www.google.com]]></subject>
   <pk-algorithm>NULL</pk-algorithm>
   <pk error="false" type="EC">
    Public-Key: (256 bit)
    pub:
        04:b4:0c:eb:06:69:ea:92:ca:8c:d1:fc:a9:7d:c8:
        4b:21:86:42:8b:56:4b:89:f7:72:9d:98:25:82:83:
        f4:9a:53:04:65:50:ec:30:b1:55:3e:e7:06:98:14:
        c8:39:1b:d6:85:f2:b3:23:25:0d:18:72:27:f6:be:
        7e:76:76:a2:33
    ASN1 OID: prime256v1
    NIST CURVE: P-256
   </pk>
   <X509v3-Extensions>
    <extension name="X509v3 Key Usage" level="critical"><![CDATA[Digital Signature]]></extension>
    <extension name="X509v3 Extended Key Usage"><![CDATA[TLS Web Server Authentication]]></extension>
    <extension name="X509v3 Basic Constraints" level="critical"><![CDATA[CA:FALSE]]></extension>
    <extension name="X509v3 Subject Key Identifier"><![CDATA[19:0C:DE:65:AC:EC:AB:EB:63:FD:24:C5:CC:6D:3F:CC:F0:17:4C:0B]]></extension>
    <extension name="X509v3 Authority Key Identifier"><![CDATA[keyid:8A:74:7F:AF:85:CD:EE:95:CD:3D:9C:D0:E2:46:14:F3:71:35:1D:27
]]></extension>
    <extension name="Authority Information Access"><![CDATA[OCSP - URI:http://ocsp.pki.goog/gts1c3
CA Issuers - URI:http://pki.goog/repo/certs/gts1c3.der
]]></extension>
    <extension name="X509v3 Subject Alternative Name"><![CDATA[DNS:www.google.com]]></extension>
    <extension name="X509v3 Certificate Policies"><![CDATA[Policy: 2.23.140.1.2.1
Policy: 1.3.6.1.4.1.11129.2.5.3
]]></extension>
    <extension name="X509v3 CRL Distribution Points"><![CDATA[
Full Name:
  URI:http://crls.pki.goog/gts1c3/QOvJ0N1sT2A.crl
]]></extension>
    <extension name="CT Precertificate SCTs"><![CDATA[Signed Certificate Timestamp:
    Version   : v1 (0x0)
    Log ID    : 7D:3E:F2:F8:8F:FF:88:55:68:24:C2:C0:CA:9E:52:89:
                79:2B:C5:0E:78:09:7F:2E:6A:97:68:99:7E:22:F0:D7
    Timestamp : Aug 23 05:03:46.419 2021 GMT
    Extensions: none
    Signature : ecdsa-with-SHA256
                30:46:02:21:00:80:72:DD:6B:EC:BB:74:1E:B1:CB:B3:
                1B:43:C2:F7:9B:DC:DC:BE:30:D5:F4:3D:C1:7A:47:33:
                D0:D1:A8:A3:78:02:21:00:A7:1A:D0:7F:CE:D8:A8:1F:
                F3:4F:CA:35:37:65:75:37:74:3F:2A:69:27:BA:2E:17:
                2F:22:98:37:4B:D7:DB:89
Signed Certificate Timestamp:
    Version   : v1 (0x0)
    Log ID    : 5C:DC:43:92:FE:E6:AB:45:44:B1:5E:9A:D4:56:E6:10:
                37:FB:D5:FA:47:DC:A1:73:94:B2:5E:E6:F6:C7:0E:CA
    Timestamp : Aug 23 05:03:46.600 2021 GMT
    Extensions: none
    Signature : ecdsa-with-SHA256
                30:44:02:20:51:D2:06:09:66:0D:85:C1:A2:B7:14:70:
                80:2D:17:9A:7F:34:A5:8F:B4:F9:50:28:77:9C:76:5B:
                0F:11:BC:BC:02:20:2D:30:F7:D5:1F:71:0B:2A:C6:52:
                52:B5:4E:1C:3B:E8:7D:1D:8B:6C:E2:61:70:A1:FC:01:
                22:2E:92:E7:F7:48]]></extension>
   </X509v3-Extensions>
  </certificate>
  <certificate type="short">
   <signature-algorithm>sha256WithRSAEncryption</signature-algorithm>
   <pk error="false" type="EC" curve_name="prime256v1" bits="128" />
   <subject><![CDATA[www.google.com]]></subject>
   <altnames><![CDATA[DNS:www.google.com]]></altnames>
   <issuer><![CDATA[GTS CA 1C3]]></issuer>
   <self-signed>false</self-signed>
   <not-valid-before>Aug 23 04:03:44 2021 GMT</not-valid-before>
   <not-valid-after>Nov 15 04:03:43 2021 GMT</not-valid-after>
   <expired>false</expired>
  </certificate>
 </certificates>
 </ssltest>
</document>"""]

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
                command.xml_output = self.get_command_xml_outputs()[0]
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
            # Test TLSv1.3
            result = session.query(TlsInfo).filter_by(version=TlsVersion.tls13).one()
            expected_result = ["TLS_AES_128_GCM_SHA256",
                               "TLS_AES_256_GCM_SHA384",
                               "TLS_CHACHA20_POLY1305_SHA256"]
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
            self.assertIsNone(result.kex_algorithm_details)
