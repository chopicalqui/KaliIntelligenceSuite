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
from database.model import CertInfo
from database.model import TlsInfoCipherSuiteMapping
from database.model import ScopeType
from typing import List
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.scan.core import BaseNmapCollectorTestCase
from collectors.os.modules.tls.sslscan import CollectorClass as SslscanCollector


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
<document title="SSLScan Results" version="1.11.13-static" web="http://github.com/rbsec/sslscan">
 <ssltest host="www.google.com" sniname="www.google.com" port="443">
  <fallback supported="1" />
  <renegotiation supported="1" secure="1" />
  <compression supported="0" />
  <heartbleed sslversion="TLSv1.2" vulnerable="0" />
  <heartbleed sslversion="TLSv1.1" vulnerable="0" />
  <heartbleed sslversion="TLSv1.0" vulnerable="0" />
  <cipher status="preferred" sslversion="TLSv1.2" bits="128" cipher="ECDHE-RSA-AES128-GCM-SHA256" id="0xC02F" curve="P-256" ecdhebits="256" strength="strong" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-AES256-GCM-SHA384" id="0xC030" curve="P-256" ecdhebits="256" strength="strong" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="ECDHE-RSA-AES128-SHA" id="0xC013" curve="P-256" ecdhebits="256" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="ECDHE-RSA-AES256-SHA" id="0xC014" curve="P-256" ecdhebits="256" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="AES128-GCM-SHA256" id="0x9C" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="AES256-GCM-SHA384" id="0x9D" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="128" cipher="AES128-SHA" id="0x2F" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="256" cipher="AES256-SHA" id="0x35" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.2" bits="112" cipher="DES-CBC3-SHA" id="0xA" strength="medium" />
  <cipher status="preferred" sslversion="TLSv1.1" bits="128" cipher="ECDHE-RSA-AES128-SHA" id="0xC013" curve="P-256" ecdhebits="256" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.1" bits="256" cipher="ECDHE-RSA-AES256-SHA" id="0xC014" curve="P-256" ecdhebits="256" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.1" bits="128" cipher="AES128-SHA" id="0x2F" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.1" bits="256" cipher="AES256-SHA" id="0x35" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.1" bits="112" cipher="DES-CBC3-SHA" id="0xA" strength="medium" />
  <cipher status="preferred" sslversion="TLSv1.0" bits="128" cipher="ECDHE-RSA-AES128-SHA" id="0xC013" curve="P-256" ecdhebits="256" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="256" cipher="ECDHE-RSA-AES256-SHA" id="0xC014" curve="P-256" ecdhebits="256" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="128" cipher="AES128-SHA" id="0x2F" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="256" cipher="AES256-SHA" id="0x35" strength="acceptable" />
  <cipher status="accepted" sslversion="TLSv1.0" bits="112" cipher="DES-CBC3-SHA" id="0xA" strength="medium" />
  <certificate>
   <certificate-blob>
-----BEGIN CERTIFICATE-----
MIIFiTCCBHGgAwIBAgIRAKj4thVDQxK2BQAAAAA8NKYwDQYJKoZIhvcNAQELBQAw
QjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET
MBEGA1UEAxMKR1RTIENBIDFPMTAeFw0xOTEyMDMxNDQ5MjZaFw0yMDAyMjUxNDQ5
MjZaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRcwFQYDVQQDEw53
d3cuZ29vZ2xlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAO36
tsAv/tMgd2dinrPjFxZ6DOoyqOwmStpYcotUQsghup/MeQFFXzOaHoqckM8AlVHw
pMa950VlRAPfQEBEvPOYEV6Tx2u9EnS0wkeVB4XCZz59ouRNjO3g05vhk0mns6ap
G9mS0LGR6YsLyiXLY0DopDfmS1NmSR6y+buca5+JUdhr3DaTVMnoXwRBQRM77fET
4ut0sKLTLWc+y0rcLg2+5rfL0Q5yjRJij/fmeqzY0kAwO++dTM061iODXd/d/DPv
2puPDJulaJ5Cse3JpNLcV8xFVPuH3GlxKCx2pHluux44eI1tnPMCBb6aWX9Je00t
u/8vveiHBxJAHNhsPpkCAwEAAaOCAlIwggJOMA4GA1UdDwEB/wQEAwIFoDATBgNV
HSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSbs3/h/Rb2
EYn6AVVF2dOiukykpDAfBgNVHSMEGDAWgBSY0fhuEOvPm+xgnxiQG6DrfQn9KzBk
BggrBgEFBQcBAQRYMFYwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnBraS5nb29n
L2d0czFvMTArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nL2dzcjIvR1RTMU8x
LmNydDAZBgNVHREEEjAQgg53d3cuZ29vZ2xlLmNvbTAhBgNVHSAEGjAYMAgGBmeB
DAECAjAMBgorBgEEAdZ5AgUDMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwu
cGtpLmdvb2cvR1RTMU8xLmNybDCCAQIGCisGAQQB1nkCBAIEgfMEgfAA7gB1ALIe
BcyLos2KIE6HZvkruYolIGdr2vpw57JJUy3vi5BeAAABbsxzumEAAAQDAEYwRAIg
Su7oB9Porkhn9N15k0Dvse9hfWebbejbZ9KkF2wzeiwCIB1sUMYSufXjU1PGipbT
qdsB3zrrJNTWyx2qcltESJ1FAHUAXqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1
loFxRVgAAAFuzHO6iQAABAMARjBEAiAR4P2K+GqSRqtlH+MRo4ow4EOHHFlYpIDi
y+eyJbz+PQIgDqPqvMoCCXLokU9IfOYRIIm1NBaLVayBIGMMQXjCIyEwDQYJKoZI
hvcNAQELBQADggEBACOaCeoNX9rqlOyXEwscdMiXZCJgZbvmFNp/ufhRvnvqvV+O
zksGyEyL9JFi4skU/IyLa9mLntCG+zvbf3T8UHVCRUH8iRHGyHlT1Td9OP/5TssM
uGAY0/AMWh1BjPnmXhndVqlHrjAfxz/8nVE+zmDoU3OkQI9pWKRm5BBEo7kk0+hc
Tqavqoayz+OI9whz2FE8HBDfZczf2wDL19el8I3H8+X0C1AKx5E3lt0Rpx2IqvU/
coqxWEuA6n4y43hnmyRyl997VisI79Slbhhh9B3NHRfVjhAVqMXFgIYhZ+iEh2zn
L/U56Npzl72GzKQqwCV2t3itSpaUPGrhsz8nqN0=
-----END CERTIFICATE-----
   </certificate-blob>
   <version>2</version>
   <serial>a8:f8:b6:15:43:43:12:b6:05:00:00:00:00:3c:34:a6</serial>
   <signature-algorithm>sha256WithRSAEncryption</signature-algorithm>
   <issuer><![CDATA[/C=US/O=Google Trust Services/CN=GTS CA 1O1]]></issuer>
   <not-valid-before>Dec  3 14:49:26 2019 GMT</not-valid-before>
   <not-valid-after>Feb 25 14:49:26 2020 GMT</not-valid-after>
   <subject><![CDATA[/C=US/ST=California/L=Mountain View/O=Google LLC/CN=www.google.com]]></subject>
   <pk-algorithm>rsaEncryption</pk-algorithm>
   <pk error="false" type="RSA" bits="2048">
    Public-Key: (2048 bit)
    Modulus:
        00:ed:fa:b6:c0:2f:fe:d3:20:77:67:62:9e:b3:e3:
        17:16:7a:0c:ea:32:a8:ec:26:4a:da:58:72:8b:54:
        42:c8:21:ba:9f:cc:79:01:45:5f:33:9a:1e:8a:9c:
        90:cf:00:95:51:f0:a4:c6:bd:e7:45:65:44:03:df:
        40:40:44:bc:f3:98:11:5e:93:c7:6b:bd:12:74:b4:
        c2:47:95:07:85:c2:67:3e:7d:a2:e4:4d:8c:ed:e0:
        d3:9b:e1:93:49:a7:b3:a6:a9:1b:d9:92:d0:b1:91:
        e9:8b:0b:ca:25:cb:63:40:e8:a4:37:e6:4b:53:66:
        49:1e:b2:f9:bb:9c:6b:9f:89:51:d8:6b:dc:36:93:
        54:c9:e8:5f:04:41:41:13:3b:ed:f1:13:e2:eb:74:
        b0:a2:d3:2d:67:3e:cb:4a:dc:2e:0d:be:e6:b7:cb:
        d1:0e:72:8d:12:62:8f:f7:e6:7a:ac:d8:d2:40:30:
        3b:ef:9d:4c:cd:3a:d6:23:83:5d:df:dd:fc:33:ef:
        da:9b:8f:0c:9b:a5:68:9e:42:b1:ed:c9:a4:d2:dc:
        57:cc:45:54:fb:87:dc:69:71:28:2c:76:a4:79:6e:
        bb:1e:38:78:8d:6d:9c:f3:02:05:be:9a:59:7f:49:
        7b:4d:2d:bb:ff:2f:bd:e8:87:07:12:40:1c:d8:6c:
        3e:99
    Exponent: 65537 (0x10001)
   </pk>
   <X509v3-Extensions>
    <extension name="X509v3 Key Usage" level="critical"><![CDATA[Digital Signature, Key Encipherment]]></extension>
    <extension name="X509v3 Extended Key Usage"><![CDATA[TLS Web Server Authentication]]></extension>
    <extension name="X509v3 Basic Constraints" level="critical"><![CDATA[CA:FALSE]]></extension>
    <extension name="X509v3 Subject Key Identifier"><![CDATA[9B:B3:7F:E1:FD:16:F6:11:89:FA:01:55:45:D9:D3:A2:BA:4C:A4:A4]]></extension>
    <extension name="X509v3 Authority Key Identifier"><![CDATA[keyid:98:D1:F8:6E:10:EB:CF:9B:EC:60:9F:18:90:1B:A0:EB:7D:09:FD:2B
]]></extension>
    <extension name="Authority Information Access"><![CDATA[OCSP - URI:http://ocsp.pki.goog/gts1o1
CA Issuers - URI:http://pki.goog/gsr2/GTS1O1.crt
]]></extension>
    <extension name="X509v3 Subject Alternative Name"><![CDATA[DNS:www.google.com]]></extension>
    <extension name="X509v3 Certificate Policies"><![CDATA[Policy: 2.23.140.1.2.2
Policy: 1.3.6.1.4.1.11129.2.5.3
]]></extension>
    <extension name="X509v3 CRL Distribution Points"><![CDATA[
Full Name:
  URI:http://crl.pki.goog/GTS1O1.crl
]]></extension>
    <extension name="CT Precertificate SCTs"><![CDATA[Signed Certificate Timestamp:
    Version   : v1(0)
    Log ID    : B2:1E:05:CC:8B:A2:CD:8A:20:4E:87:66:F9:2B:B9:8A:
                25:20:67:6B:DA:FA:70:E7:B2:49:53:2D:EF:8B:90:5E
    Timestamp : Dec  3 15:49:26.753 2019 GMT
    Extensions: none
    Signature : ecdsa-with-SHA256
                30:44:02:20:4A:EE:E8:07:D3:E8:AE:48:67:F4:DD:79:
                93:40:EF:B1:EF:61:7D:67:9B:6D:E8:DB:67:D2:A4:17:
                6C:33:7A:2C:02:20:1D:6C:50:C6:12:B9:F5:E3:53:53:
                C6:8A:96:D3:A9:DB:01:DF:3A:EB:24:D4:D6:CB:1D:AA:
                72:5B:44:48:9D:45
Signed Certificate Timestamp:
    Version   : v1(0)
    Log ID    : 5E:A7:73:F9:DF:56:C0:E7:B5:36:48:7D:D0:49:E0:32:
                7A:91:9A:0C:84:A1:12:12:84:18:75:96:81:71:45:58
    Timestamp : Dec  3 15:49:26.793 2019 GMT
    Extensions: none
    Signature : ecdsa-with-SHA256
                30:44:02:20:11:E0:FD:8A:F8:6A:92:46:AB:65:1F:E3:
                11:A3:8A:30:E0:43:87:1C:59:58:A4:80:E2:CB:E7:B2:
                25:BC:FE:3D:02:20:0E:A3:EA:BC:CA:02:09:72:E8:91:
                4F:48:7C:E6:11:20:89:B5:34:16:8B:55:AC:81:20:63:
                0C:41:78:C2:23:21]]></extension>
   </X509v3-Extensions>
  </certificate>
  <certificate>
   <signature-algorithm>sha256WithRSAEncryption</signature-algorithm>
   <pk error="false" type="RSA" bits="2048" />
   <subject><![CDATA[www.google.com]]></subject>
   <altnames><![CDATA[DNS:www.google.com]]></altnames>
   <issuer><![CDATA[GTS CA 1O1]]></issuer>
   <self-signed>false</self-signed>
   <not-valid-before>Dec  3 14:49:26 2019 GMT</not-valid-before>
   <not-valid-after>Feb 25 14:49:26 2020 GMT</not-valid-after>
   <expired>false</expired>
  </certificate>
 </ssltest>
</document>
"""]

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
            self.assertEqual("www.google.com", results.common_name)
            # TlsInfo
            results = session.query(TlsInfo).all()
            results = [item.version_str for item in results]
            results.sort()
            expected_results = ["TLSv1.0",
                                "TLSv1.1",
                                "TLSv1.2"]
            expected_results.sort()
            self.assertListEqual(expected_results, results)
            # TlsInfoCipherSuiteMapping
            results = session.query(TlsInfoCipherSuiteMapping).count()
            self.assertEqual(19, results)
