#!/usr/bin/python3
"""
this file implements all unittests for collector censyshost
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
from typing import List
from typing import Dict
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.core import BaseKaliCollectorTestCase
from collectors.os.modules.osint.censyshost import CollectorClass as CensysHostCollector
from database.model import CollectorType
from database.model import HostName
from database.model import DomainName
from database.model import Host
from database.model import Path
from database.model import Service
from database.model import PathType
from database.model import ScopeType
from database.model import ProtocolType
from database.model import ServiceState
from database.model import AdditionalInfo


class BaseShodanHostCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="censyshost",
                         collector_class=CensysHostCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return []

    @staticmethod
    def get_command_json_outputs() -> List[Dict[str, str]]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        json_objects = {'ip': '172.217.168.68', 'services': [{'_decoded': 'http', '_encoding': {'banner': 'DISPLAY_UTF8', 'banner_hex': 'DISPLAY_HEX'}, 'banner': 'HTTP/1.1 301 Moved Permanently\r\nLocation: http://www.google.com/\r\nContent-Type: text/html; charset=UTF-8\r\nDate:  <REDACTED>\nExpires: Thu, 24 Nov 2022 07:58:06 GMT\r\nCache-Control: public, max-age=2592000\r\nServer: gws\r\nContent-Length: 219\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\n', 'banner_hashes': ['sha256:79edd4d175a52e48c24d2c9912740570fba795b16fe59c7cb938e7cea5b9fb00'], 'banner_hex': '485454502f312e3120333031204d6f766564205065726d616e656e746c790d0a4c6f636174696f6e3a20687474703a2f2f7777772e676f6f676c652e636f6d2f0d0a436f6e74656e742d547970653a20746578742f68746d6c3b20636861727365743d5554462d380d0a446174653a20203c52454441435445443e0a457870697265733a205468752c203234204e6f7620323032322030373a35383a303620474d540d0a43616368652d436f6e74726f6c3a207075626c69632c206d61782d6167653d323539323030300d0a5365727665723a206777730d0a436f6e74656e742d4c656e6774683a203231390d0a582d5853532d50726f74656374696f6e3a20300d0a582d4672616d652d4f7074696f6e733a2053414d454f524947494e0d0a', 'extended_service_name': 'HTTP', 'http': {'request': {'method': 'GET', 'uri': 'http://172.217.168.68/', 'headers': {'User_Agent': ['Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)'], '_encoding': {'User_Agent': 'DISPLAY_UTF8', 'Accept': 'DISPLAY_UTF8'}, 'Accept': ['*/*']}}, 'response': {'protocol': 'HTTP/1.1', 'status_code': 301, 'status_reason': 'Moved Permanently', 'headers': {'Date': ['<REDACTED>'], '_encoding': {'Date': 'DISPLAY_UTF8', 'Content_Type': 'DISPLAY_UTF8', 'Cache_Control': 'DISPLAY_UTF8', 'Location': 'DISPLAY_UTF8', 'X_Xss_Protection': 'DISPLAY_UTF8', 'X_Frame_Options': 'DISPLAY_UTF8', 'Expires': 'DISPLAY_UTF8', 'Content_Length': 'DISPLAY_UTF8', 'Server': 'DISPLAY_UTF8'}, 'Content_Type': ['text/html; charset=UTF-8'], 'Cache_Control': ['public, max-age=2592000'], 'Location': ['http://www.google.com/'], 'X_Xss_Protection': ['0'], 'X_Frame_Options': ['SAMEORIGIN'], 'Expires': ['Thu, 24 Nov 2022 07:58:06 GMT'], 'Content_Length': ['219'], 'Server': ['gws']}, '_encoding': {'html_tags': 'DISPLAY_UTF8', 'body': 'DISPLAY_UTF8', 'body_hash': 'DISPLAY_UTF8', 'html_title': 'DISPLAY_UTF8'}, 'html_tags': ['<TITLE>301 Moved</TITLE>', '<meta http-equiv="content-type" content="text/html;charset=utf-8">'], 'body_size': 219, 'body': '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n', 'body_hashes': ['sha256:2178eedd5723a6ac22e94ec59bdcd99229c87f3623753f5e199678242f0e90de', 'sha1:c79f5572f672361bc097676cb5da9d4aa956c8b9'], 'body_hash': 'sha1:c79f5572f672361bc097676cb5da9d4aa956c8b9', 'html_title': '301 Moved'}, 'supports_http2': False}, 'observed_at': '2022-10-25T07:58:06.815301960Z', 'perspective_id': 'PERSPECTIVE_ORANGE', 'port': 80, 'service_name': 'HTTP', 'software': [{'uniform_resource_identifier': 'cpe:2.3:a:google:web_server:*:*:*:*:*:*:*:*', 'part': 'a', 'vendor': 'Google', 'product': 'Google Web Services', 'other': {'family': 'Google Web Server'}, 'source': 'OSI_APPLICATION_LAYER'}], 'source_ip': '167.94.145.60', 'transport_protocol': 'TCP', 'truncated': False}, {'_decoded': 'http', '_encoding': {'banner': 'DISPLAY_UTF8', 'certificate': 'DISPLAY_HEX', 'banner_hex': 'DISPLAY_HEX'}, 'banner': 'HTTP/1.1 301 Moved Permanently\r\nLocation: http://www.google.com/\r\nContent-Type: text/html; charset=UTF-8\r\nDate:  <REDACTED>\nExpires: Thu, 24 Nov 2022 12:52:58 GMT\r\nCache-Control: public, max-age=2592000\r\nServer: gws\r\nContent-Length: 219\r\nX-XSS-Protection: 0\r\nX-Frame-Options: SAMEORIGIN\r\nAlt-Svc: h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"\r\n', 'banner_hashes': ['sha256:1de663b84386b9681c50866a31710737799efcf0b5309c5c3ffccc3639ff0344'], 'banner_hex': '485454502f312e3120333031204d6f766564205065726d616e656e746c790d0a4c6f636174696f6e3a20687474703a2f2f7777772e676f6f676c652e636f6d2f0d0a436f6e74656e742d547970653a20746578742f68746d6c3b20636861727365743d5554462d380d0a446174653a20203c52454441435445443e0a457870697265733a205468752c203234204e6f7620323032322031323a35323a353820474d540d0a43616368652d436f6e74726f6c3a207075626c69632c206d61782d6167653d323539323030300d0a5365727665723a206777730d0a436f6e74656e742d4c656e6774683a203231390d0a582d5853532d50726f74656374696f6e3a20300d0a582d4672616d652d4f7074696f6e733a2053414d454f524947494e0d0a416c742d5376633a2068333d223a343433223b206d613d323539323030302c68332d32393d223a343433223b206d613d323539323030302c68332d513035303d223a343433223b206d613d323539323030302c68332d513034363d223a343433223b206d613d323539323030302c68332d513034333d223a343433223b206d613d323539323030302c717569633d223a343433223b206d613d323539323030303b20763d2234362c3433220d0a', 'certificate': 'd5129635a050f63dd607ffa9271eefaab597c0975809765dad253973fc554d25', 'extended_service_name': 'HTTPS', 'http': {'request': {'method': 'GET', 'uri': 'https://172.217.168.68/', 'headers': {'User_Agent': ['Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)'], '_encoding': {'User_Agent': 'DISPLAY_UTF8', 'Accept': 'DISPLAY_UTF8'}, 'Accept': ['*/*']}}, 'response': {'protocol': 'HTTP/1.1', 'status_code': 301, 'status_reason': 'Moved Permanently', 'headers': {'Expires': ['Thu, 24 Nov 2022 12:52:58 GMT'], '_encoding': {'Expires': 'DISPLAY_UTF8', 'X_Frame_Options': 'DISPLAY_UTF8', 'X_Xss_Protection': 'DISPLAY_UTF8', 'Cache_Control': 'DISPLAY_UTF8', 'Location': 'DISPLAY_UTF8', 'Content_Type': 'DISPLAY_UTF8', 'Content_Length': 'DISPLAY_UTF8', 'Server': 'DISPLAY_UTF8', 'Alt_Svc': 'DISPLAY_UTF8', 'Date': 'DISPLAY_UTF8'}, 'X_Frame_Options': ['SAMEORIGIN'], 'X_Xss_Protection': ['0'], 'Cache_Control': ['public, max-age=2592000'], 'Location': ['http://www.google.com/'], 'Content_Type': ['text/html; charset=UTF-8'], 'Content_Length': ['219'], 'Server': ['gws'], 'Alt_Svc': ['h3=":443"; ma=2592000,h3-29=":443"; ma=2592000,h3-Q050=":443"; ma=2592000,h3-Q046=":443"; ma=2592000,h3-Q043=":443"; ma=2592000,quic=":443"; ma=2592000; v="46,43"'], 'Date': ['<REDACTED>']}, '_encoding': {'html_tags': 'DISPLAY_UTF8', 'body': 'DISPLAY_UTF8', 'body_hash': 'DISPLAY_UTF8', 'html_title': 'DISPLAY_UTF8'}, 'html_tags': ['<TITLE>301 Moved</TITLE>', '<meta http-equiv="content-type" content="text/html;charset=utf-8">'], 'body_size': 219, 'body': '<HTML><HEAD><meta http-equiv="content-type" content="text/html;charset=utf-8">\n<TITLE>301 Moved</TITLE></HEAD><BODY>\n<H1>301 Moved</H1>\nThe document has moved\n<A HREF="http://www.google.com/">here</A>.\r\n</BODY></HTML>\r\n', 'body_hashes': ['sha256:2178eedd5723a6ac22e94ec59bdcd99229c87f3623753f5e199678242f0e90de', 'sha1:c79f5572f672361bc097676cb5da9d4aa956c8b9'], 'body_hash': 'sha1:c79f5572f672361bc097676cb5da9d4aa956c8b9', 'html_title': '301 Moved'}, 'supports_http2': True}, 'jarm': {'_encoding': {'fingerprint': 'DISPLAY_HEX', 'cipher_and_version_fingerprint': 'DISPLAY_HEX', 'tls_extensions_sha256': 'DISPLAY_HEX'}, 'fingerprint': '29d3fd00029d29d21c42d43d00041df48f145f65c66577d0b01ecea881c1ba', 'cipher_and_version_fingerprint': '29d3fd00029d29d21c42d43d00041d', 'tls_extensions_sha256': 'f48f145f65c66577d0b01ecea881c1ba', 'observed_at': '2022-10-12T09:49:28.789637064Z'}, 'observed_at': '2022-10-25T12:52:57.829150529Z', 'perspective_id': 'PERSPECTIVE_NTT', 'port': 443, 'service_name': 'HTTP', 'software': [{'uniform_resource_identifier': 'cpe:2.3:a:google:web_server:*:*:*:*:*:*:*:*', 'part': 'a', 'vendor': 'Google', 'product': 'Google Web Services', 'other': {'family': 'Google Web Server'}, 'source': 'OSI_APPLICATION_LAYER'}], 'source_ip': '167.248.133.46', 'tls': {'version_selected': 'TLSv1_3', 'cipher_selected': 'TLS_CHACHA20_POLY1305_SHA256', 'certificates': {'_encoding': {'leaf_fp_sha_256': 'DISPLAY_HEX'}, 'leaf_fp_sha_256': 'd5129635a050f63dd607ffa9271eefaab597c0975809765dad253973fc554d25', 'leaf_data': {'names': ['invalid2.invalid'], 'subject_dn': 'OU=No SNI provided\\; please fix your client., CN=invalid2.invalid', 'issuer_dn': 'OU=No SNI provided\\; please fix your client., CN=invalid2.invalid', 'pubkey_bit_size': 2048, 'pubkey_algorithm': 'RSA', 'tbs_fingerprint': 'dfbe5de1c7e753f5720adb802f94ffba09aa8f8a03c2cba407ad717db05679d4', 'fingerprint': 'd5129635a050f63dd607ffa9271eefaab597c0975809765dad253973fc554d25', 'issuer': {'common_name': ['invalid2.invalid'], 'organizational_unit': ['No SNI provided; please fix your client.']}, 'subject': {'common_name': ['invalid2.invalid'], 'organizational_unit': ['No SNI provided; please fix your client.']}, 'public_key': {'key_algorithm': 'RSA', 'rsa': {'_encoding': {'modulus': 'DISPLAY_BASE64', 'exponent': 'DISPLAY_BASE64'}, 'modulus': 'zWJP5cMThJgMBeTvRKKl7N6ZcZAbKDVAtNBNnRhIgSitXxCzKtt9rp2RHkLn76oZjdNO25EPp+QgMiWU/rkkB00Y18Oahw5fi8s+K9dRv6i+gSOiv2jlIeW/S0hOswUUDH0JXFkEPKILzpl5ML7wdp5kt93vHxa7HswOtAxEz2WtxMdezm/3CgO3sls20wl3W03iI+kCt7HyvhGy2aRPLhJfeABpQr0Uku3q6mtomy2cgFawekN/X/aH8KknX799MPcuWutM2q88mtUEBsuZmy2nsjK9J7/yhhCRDzOV/yY8c5+l/u/rWuwwkZ2lgzGp4xBBfhXdr6+m9kmwWCUm9Q==', 'exponent': 'AAEAAQ==', 'length': 256}, 'fingerprint': '8f88b8730004845fc114a6e4aa2f16656babe1b32faf6fc46e8bccd24bb514d7'}, 'signature': {'self_signed': True, 'signature_algorithm': 'SHA256-RSA'}}}, '_encoding': {'ja3s': 'DISPLAY_HEX'}, 'ja3s': 'd75f9129bb5d05492a65ff78e081bcb2'}, 'transport_protocol': 'TCP', 'truncated': False}], 'location': {'continent': 'North America', 'country': 'United States', 'country_code': 'US', 'postal_code': '', 'timezone': 'America/Chicago', 'coordinates': {'latitude': 37.751, 'longitude': -97.822}, 'registered_country': 'United States', 'registered_country_code': 'US'}, 'location_updated_at': '2022-10-23T08:04:19.528527Z', 'autonomous_system': {'asn': 15169, 'description': 'GOOGLE', 'bgp_prefix': '172.217.0.0/16', 'name': 'GOOGLE', 'country_code': 'US'}, 'autonomous_system_updated_at': '2022-10-19T19:29:30.769476Z', 'dns': {'names': ['zrh04s15-in-f4.1e100.net'], 'records': {'zrh04s15-in-f4.1e100.net': {'record_type': 'A', 'resolved_at': '2022-10-08T15:40:45.640623137Z'}}, 'reverse_dns': {'names': ['zrh04s15-in-f4.1e100.net'], 'resolved_at': '2022-10-18T06:55:55.258166472Z'}}, 'last_updated_at': '2022-10-25T13:03:47.345Z'}
        return [json_objects]

    def test_verify_results(self):
        """
        This method checks whether the collector correctly verifies the command output
        :return:
        """
        self.init_db()
        with tempfile.TemporaryDirectory() as temp_dir:
            test_suite = CollectorProducerTestSuite(engine=self._engine,
                                                    arguments={"workspace": self._workspaces[0],
                                                               "output_dir": temp_dir})
            with self._engine.session_scope() as session:
                source = self.create_source(session, source_str=self._collector_name)
                command = self.create_command(session=session,
                                              workspace_str=self._workspaces[0],
                                              ipv4_address="172.217.168.68",
                                              command=["kisimport", "google.com"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.domain,
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command.json_output = self.get_command_json_outputs()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            result = session.query(Host).count()
            self.assertEqual(1, result)
            result = session.query(Service).count()
            self.assertEqual(3, result)
            result = session.query(Path).count()
            self.assertEqual(3, result)
            result = session.query(DomainName).count()
            self.assertEqual(2, result)
            result = session.query(HostName).count()
            self.assertEqual(4, result)
            result = session.query(AdditionalInfo).count()
            self.assertEqual(4, result)
            # Port 80
            result = session.query(Service) \
                .join(Host) \
                .filter(Host.address == "172.217.168.68",
                        Service.port == 80,
                        Service.protocol == ProtocolType.tcp,
                        Service.nmap_service_name == "http",
                        Service.state == ServiceState.Open).one()
            self.assertEqual(1, len(result.paths))
            self.assertEqual("/", result.paths[0].name)
            self.assertEqual(301, result.paths[0].return_code)
            self.assertEqual(PathType.http, result.paths[0].type)
            self.assertIsNone(result.paths[0].size_bytes)
            # Port 443
            result = session.query(Service) \
                .join(Host) \
                .filter(Host.address == "172.217.168.68",
                        Service.port == 443,
                        Service.protocol == ProtocolType.tcp,
                        Service.nmap_service_name == "http",
                        Service.state == ServiceState.Open).one()
            self.assertEqual(1, len(result.paths))
            self.assertEqual("/", result.paths[0].name)
            self.assertEqual(301, result.paths[0].return_code)
            self.assertEqual(PathType.http, result.paths[0].type)
            self.assertIsNone(result.paths[0].size_bytes)
            result = session.query(DomainName).count()
            self.assertEqual(2, result)
            session.query(HostName) \
                .join(DomainName) \
                .filter(DomainName.name == "google.com", HostName.name.is_(None)).one()
            session.query(HostName) \
                .join(DomainName) \
                .filter(DomainName.name == "google.com", HostName.name == "www").one()
