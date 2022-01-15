#!/usr/bin/python3
"""
this file implements all unittests for collector shodanhost
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
import json
from typing import List
from typing import Dict
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.collectors.kali.modules.core import BaseKaliCollectorTestCase
from collectors.os.modules.osint.shodanhost import CollectorClass as ShodanHostCollector
from database.model import Credentials
from database.model import CollectorType
from database.model import HostName
from database.model import Company
from database.model import Host
from database.model import Path
from database.model import File
from database.model import FileType
from database.model import AdditionalInfo
from database.model import Service
from database.model import ScopeType


class BaseShodanHostCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="shodanhost",
                         collector_class=ShodanHostCollector)

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
        json_objects = json.loads("""{
    "hostnames": [
        "openvpn.unittest.com",
        "www.unittest.com"
    ],
    "data": [
        {
            "transport": "udp",
            "port": 1194,
            "hostnames": [
                "openvpn.unittest.com"
            ],
            "domains": [
                "unittest.com"
            ],
            "os": null,
            "ip_str": "127.0.0.1"
        },
        {
            "hostnames": [
                "web.unittest.com"
            ],
            "vulns": {
                "CVE-2014-0117": {
                    "verified": false,
                    "cvss": "4.3",
                    "summary": "The mod_proxy module in the Apache HTTP Server 2.4.x before 2.4.10, when a reverse proxy is enabled, allows remote attackers to cause a denial of service (child-process crash) via a crafted HTTP Connection header."
                },
                "CVE-2016-0736": {
                    "verified": false,
                    "cvss": "5.0",
                    "summary": "In Apache HTTP Server versions 2.4.0 to 2.4.23, mod_session_crypto was encrypting its data/cookie using the configured ciphers with possibly either CBC or ECB modes of operation (AES256-CBC by default), hence no selectable or builtin authenticated encryption. This made it vulnerable to padding oracle attacks, particularly with CBC."
                }
            },
            "port": 443,
            "transport": "tcp",
            "version": "2.4.6",
            "product": "Apache httpd",
            "cert": {
                "chain": [
                        "-----BEGIN CERTIFICATE-----\\nMIIFiTCCBHGgAwIBAgIRAOojQokwkAg5AgAAAABSqVUwDQYJKoZIhvcNAQELBQAw\\nQjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET\\nMBEGA1UEAxMKR1RTIENBIDFPMTAeFw0xOTEyMjAxMzEzNDNaFw0yMDAzMTMxMzEz\\nNDNaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH\\nEw1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRcwFQYDVQQDEw53\\nd3cuZ29vZ2xlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMdb\\nzkTc78UBXe8/rti2OxAGZQUQ1WnilkCSqRuMn/gmc1jeiIDeZCWFurFin9+RBB/K\\nib5xQx2iZ1ifcV+DOvDT16LEa887TehETAADpBnTJmVi0Z6GXjQQ9pyLrv+1PDYI\\n3z9Slkw3ZGVeMUE31etonDRB9lPN9skF09s1LvitIi4XdPXgaTNCBEWNMs1Tlv8H\\n1+UlaQiamriyTii4pptXv+KKsunDC//OEv1pm0cZnEeop8USMHermBzYkaFXC3ae\\n2hvV7Bj7w8c6PqHcTQ+e7xhoKoIzFVtneNoEyQL1h9QGtPdTofs/sidgd//Wo7sB\\n0JV1zq2EtSsKlp/N+U0CAwEAAaOCAlIwggJOMA4GA1UdDwEB/wQEAwIFoDATBgNV\\nHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBQiK5HMzk32\\nvjkQNky4VkFcyt/kQTAfBgNVHSMEGDAWgBSY0fhuEOvPm+xgnxiQG6DrfQn9KzBk\\nBggrBgEFBQcBAQRYMFYwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnBraS5nb29n\\nL2d0czFvMTArBggrBgEFBQcwAoYfaHR0cDovL3BraS5nb29nL2dzcjIvR1RTMU8x\\nLmNydDAZBgNVHREEEjAQgg53d3cuZ29vZ2xlLmNvbTAhBgNVHSAEGjAYMAgGBmeB\\nDAECAjAMBgorBgEEAdZ5AgUDMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwu\\ncGtpLmdvb2cvR1RTMU8xLmNybDCCAQIGCisGAQQB1nkCBAIEgfMEgfAA7gB1ALIe\\nBcyLos2KIE6HZvkruYolIGdr2vpw57JJUy3vi5BeAAABbyOoMvgAAAQDAEYwRAIg\\nBa8Zw9vk29aITM7udOH9zPzytfh5vjTxz2JPuNQuF6gCIEcduOoMHCV9s3G9uEwV\\nKXwfjtYwYvVlfKlCMW4ilFujAHUAXqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1\\nloFxRVgAAAFvI6gzIgAABAMARjBEAiBRslW536auv4WHgspy1wNvLEwS2VH66MMV\\nMJUcgN6IvwIgepYRaAuSuiJeAla6KuAnPCeJvXlscWTnFbm85DIEaegwDQYJKoZI\\nhvcNAQELBQADggEBAKqExHCpU6rjr/XMezkzy+fp76TST2l39vqIJKDdkQPe8V0I\\nafWgkc/T3z4bZx/4plzW+iAvk4KTyvDWNbv2xh3njAB6FoJyZkf9/H6zahLSaS4z\\nqiI3axO3rSD6AW6G5u5cKIN8IaJzLc6CgW+NkxMulOM//u008jZIvp6qGwVfeMlc\\n1kDocDf8imLam7yM4BQKvOPb5w7e+SgKO6qxRkhFsL18xgh7HZk8F1fvFFhGyuYQ\\nWL0jORJvjomn/uMxiU9UFlAiVtsY0zmyuVIEp2rDpdfaG8AnVV4BLnR6Ey8TpHzR\\nw1b3ocoOJi0is55pSMwU8L9RE7cz9MP9krrb7zU=\\n-----END CERTIFICATE-----\\n",
                        "-----BEGIN CERTIFICATE-----\\nMIIESjCCAzKgAwIBAgINAeO0mqGNiqmBJWlQuDANBgkqhkiG9w0BAQsFADBMMSAw\\nHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFs\\nU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAwNDJaFw0yMTEy\\nMTUwMDAwNDJaMEIxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3Qg\\nU2VydmljZXMxEzARBgNVBAMTCkdUUyBDQSAxTzEwggEiMA0GCSqGSIb3DQEBAQUA\\nA4IBDwAwggEKAoIBAQDQGM9F1IvN05zkQO9+tN1pIRvJzzyOTHW5DzEZhD2ePCnv\\nUA0Qk28FgICfKqC9EksC4T2fWBYk/jCfC3R3VZMdS/dN4ZKCEPZRrAzDsiKUDzRr\\nmBBJ5wudgzndIMYcLe/RGGFl5yODIKgjEv/SJH/UL+dEaltN11BmsK+eQmMF++Ac\\nxGNhr59qM/9il71I2dN8FGfcddwuaej4bXhp0LcQBbjxMcI7JP0aM3T4I+DsaxmK\\nFsbjzaTNC9uzpFlgOIg7rR25xoynUxv8vNmkq7zdPGHXkxWY7oG9j+JkRyBABk7X\\nrJfoucBZEqFJJSPk7XA0LKW0Y3z5oz2D0c1tJKwHAgMBAAGjggEzMIIBLzAOBgNV\\nHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1Ud\\nEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJjR+G4Q68+b7GCfGJAboOt9Cf0rMB8G\\nA1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYuMDUGCCsGAQUFBwEBBCkwJzAl\\nBggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdvb2cvZ3NyMjAyBgNVHR8EKzAp\\nMCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dzcjIvZ3NyMi5jcmwwPwYDVR0g\\nBDgwNjA0BgZngQwBAgIwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9wa2kuZ29vZy9y\\nZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAGoA+Nnn78y6pRjd9XlQWNa7H\\nTgiZ/r3RNGkmUmYHPQq6Scti9PEajvwRT2iWTHQr02fesqOqBY2ETUwgZQ+lltoN\\nFvhsO9tvBCOIazpswWC9aJ9xju4tWDQH8NVU6YZZ/XteDSGU9YzJqPjY8q3MDxrz\\nmqepBCf5o8mw/wJ4a2G6xzUr6Fb6T8McDO22PLRL6u3M4Tzs3A2M1j6bykJYi8wW\\nIRdAvKLWZu/axBVbzYmqmwkm5zLSDW5nIAJbELCQCZwMH56t2Dvqofxs6BBcCFIZ\\nUSpxu6x6td0V7SvJCCosirSmIatj/9dSSVDQibet8q/7UK4v4ZUN80atnZz1yg==\\n-----END CERTIFICATE-----\\n"
                    ]
            },
            "http": {
               "product": "Apache httpd",
               "title": "Start page",
               "robots": "User-agent: Fasterfox\\r\\nDisallow: /secret\\r\\nUser-agent: *\\r\\nDisallow:\\r\\n",
               "location": "/en/start",
               "server": "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.2.17"
            },
            "ssl": {
                "cert": {
                    "subject": {
                        "CN": "web1.unittest.com",
                        "O": "Test Company"
                    }
                },
                "chain": [
                    "-----BEGIN CERTIFICATE-----\\nMIIEvjCCA6agAwIBAgIQLi/6Fx6+6KICAAAAAECl1jANBgkqhkiG9w0BAQsFADBC\\nMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVR29vZ2xlIFRydXN0IFNlcnZpY2VzMRMw\\nEQYDVQQDEwpHVFMgQ0EgMU8xMB4XDTE5MDgxMzE2MjAyNVoXDTE5MTExMTE2MjAy\\nNVowaDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcT\\nDU1vdW50YWluIFZpZXcxEzARBgNVBAoTCkdvb2dsZSBMTEMxFzAVBgNVBAMTDnd3\\ndy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErDSfErsJHyjZ\\nwkccquFwr0sCUwPX7TrMBRY5P4u1mXVm7QRabPXQebHrdom7ZM+hwHu7eHXjrKNO\\nHQ/zwmp1uqOCAlMwggJPMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEF\\nBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkwLyGwlGyeq7XqFjXFJIU5GVe\\nSTAfBgNVHSMEGDAWgBSY0fhuEOvPm+xgnxiQG6DrfQn9KzBkBggrBgEFBQcBAQRY\\nMFYwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3NwLnBraS5nb29nL2d0czFvMTArBggr\\nBgEFBQcwAoYfaHR0cDovL3BraS5nb29nL2dzcjIvR1RTMU8xLmNydDAZBgNVHREE\\nEjAQgg53d3cuZ29vZ2xlLmNvbTAhBgNVHSAEGjAYMAgGBmeBDAECAjAMBgorBgEE\\nAdZ5AgUDMC8GA1UdHwQoMCYwJKAioCCGHmh0dHA6Ly9jcmwucGtpLmdvb2cvR1RT\\nMU8xLmNybDCCAQMGCisGAQQB1nkCBAIEgfQEgfEA7wB2AGPy283oO8wszwtyhCdX\\nazOkjWF3j711pjixx2hUS9iNAAABbIv+x7oAAAQDAEcwRQIgdVGP/bUKdYykhLh9\\n9zUUYxteaPGfppx9r/yknsVTjI8CIQDTHVM8i98rp8gk9mX5kKEON/TDtc9i+XfO\\n9qckKSRvwQB1AHR+2oMxrTMQkSGcziVPQnDCv/1eQiAIxjc1eeYQe8xWAAABbIv+\\nx8MAAAQDAEYwRAIgG9hbzgW+Yp8spYgkBAWNNZ381bYjN6TfpcxhM0GsOhgCIDMn\\nNTVxPC0Umgh9gRtFmM5pvjX71Sd/59iNR4jFtLjOMA0GCSqGSIb3DQEBCwUAA4IB\\nAQCTzUJExrNYCuRGRTXXqaHefaRdc1n30HZBUgUFTH3WqOBdbd0L1r1Vc2uYq7xO\\nfA95tKjflgXW74fwSZ6UZeQa0X0jBbtJs2aykCeh9PqQtGqlmVfOVUVhxtD0qSUG\\nGy9HoX2V/mPC+rOMZfaCzvSqd5yUz7TxwlMFH8GlAxd0s2Gqyq2OdWFMfpfZpvyD\\nAEJG3VFzPWAH5jCPLD8hX/J/xPCsA/sdt6vBlFPvSXqoAgYaUkrkQ7SZv/pkQ0Cn\\n3GZL+Ofa0btisJ4XLOP5YWW1f+oERZ3JqwIgXdpzFfCvVIpunGwCbb3mxd7/2DZ6\\n4PnmK3SOQ3dsM8QLcoBa3ASe\\n-----END CERTIFICATE-----"
                ]
            }
        },
        {
            "transport": "tcp",
            "product": "Microsoft ftpd",
            "port": 21,
            "ftp": {
                "anonymous": true
            },
            "hostnames": [
                "web.unittest.com"
            ]
        }
    ],
    "ip_str": "127.0.0.1",
    "os": null,
    "ports": [
        1194,
        443,
        21
    ]
}""")
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
                                              command=["kisimport", "unittest2.com"],
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
            # Check credentials
            session.query(Credentials).filter_by(username="anonymous").one()
            # Check Company
            session.query(Company).filter_by(name="google llc").one()
            # Check Host
            session.query(Host).filter_by(address="127.0.0.1").one()
            # Check File
            session.query(File).filter_by(type=FileType.certificate).one()
            # Check Path
            results = session.query(Path).filter_by().all()
            results = [item.name for item in results]
            results.sort()
            paths = ["/", "/", "/en/start", "/secret"]
            self.assertListEqual(paths, results)
            # Check HostName
            results = session.query(HostName).filter_by().all()
            results = [item.full_name for item in results]
            results.sort()
            hosts = ["google.com",
                     "www.google.com",
                     "unittest.com",
                     "openvpn.unittest.com",
                     "www.unittest.com",
                     "web.unittest.com"]
            hosts.sort()
            self.assertListEqual(hosts, results)
            # Check AdditionalInfo
            results = session.query(AdditionalInfo).filter_by().all()
            results = [item.name for item in results]
            results.sort()
            additional_info = ["HTTP title", "HTTP server", "CVEs"]
            additional_info.sort()
            self.assertListEqual(additional_info, results)
            # Check service
            results = session.query(Service).filter_by().all()
            results = ["{}/{}".format(service.protocol_str, service.port) for service in results]
            results.sort()
            service = ["tcp/80", "tcp/443", "tcp/21", "udp/1194"]
            service.sort()
            self.assertListEqual(service, results)
