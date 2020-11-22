#!/usr/bin/python3
"""
this file implements all unittests for collector certopenssl
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
from typing import List
from unittests.tests.collectors.kali.modules.dns.core import BaseKaliDnsCollectorTestCase
from collectors.os.modules.tls.certopenssl import CollectorClass as CertOpensslCollector
from unittests.tests.collectors.core import CollectorProducerTestSuite
from database.model import CollectorType
from database.model import File
from database.model import HostName
from database.model import Company
from database.model import ScopeType


class CertOpensslCollectorTestCase(BaseKaliDnsCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="certopenssl",
                         collector_class=CertOpensslCollector,
                         **kwargs)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return """i:C = US, O = Google Trust Services, CN = GTS CA 1O1
-----BEGIN CERTIFICATE-----
MIIEwTCCA6mgAwIBAgIRAMwUs1jGAqBZAgAAAABSqVYwDQYJKoZIhvcNAQELBQAw
QjELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFUdvb2dsZSBUcnVzdCBTZXJ2aWNlczET
MBEGA1UEAxMKR1RTIENBIDFPMTAeFw0xOTEyMjAxMzEzNDRaFw0yMDAzMTMxMzEz
NDRaMGgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQH
Ew1Nb3VudGFpbiBWaWV3MRMwEQYDVQQKEwpHb29nbGUgTExDMRcwFQYDVQQDEw53
d3cuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLkvPK6BjgCj
y3mZGWveosUHfMzrbGdRmX4IQ+c5e+kVstzMDIZYx8yBWbyDfvv5wz/8b0Udq5Wa
rM1W0i8xXJ6jggJVMIICUTAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUZ+Jr7Q8eQTO3Bq4X1LXo0iqO
tckwHwYDVR0jBBgwFoAUmNH4bhDrz5vsYJ8YkBug630J/SswZAYIKwYBBQUHAQEE
WDBWMCcGCCsGAQUFBzABhhtodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHMxbzEwKwYI
KwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZy9nc3IyL0dUUzFPMS5jcnQwGQYDVR0R
BBIwEIIOd3d3Lmdvb2dsZS5jb20wIQYDVR0gBBowGDAIBgZngQwBAgIwDAYKKwYB
BAHWeQIFAzAvBgNVHR8EKDAmMCSgIqAghh5odHRwOi8vY3JsLnBraS5nb29nL0dU
UzFPMS5jcmwwggEFBgorBgEEAdZ5AgQCBIH2BIHzAPEAdwCyHgXMi6LNiiBOh2b5
K7mKJSBna9r6cOeySVMt74uQXgAAAW8jqDd8AAAEAwBIMEYCIQD06hLX9HU4SjY/
xQf5Ti1NRJT0RiFOvl3b4CAPR/W/vQIhANdI4Rd4aO7qrzTaI35IlNbkB94vxLTV
sRcDgO3j2fGDAHYAXqdz+d9WwOe1Nkh90EngMnqRmgyEoRIShBh1loFxRVgAAAFv
I6g3pAAABAMARzBFAiB6haH5CwtT6y85R0Xx/Rq608nhe/n9L2lea+0nZwC8DgIh
AMZrrLk5bFSpYPX1eEIklvQbO7X9Y/swowHUWeH9pGDHMA0GCSqGSIb3DQEBCwUA
A4IBAQCuWbHkpVjSCAVKh0bxuNIiT6g9DbyP59ZzNDzpExNqQW5/SGZSn4hMvSDb
7EuwXFWdPYSCkvAarSTgPuCztWCR+cRSqTZJaIQw8MTpuXx+90iXsH64qeokZe/X
83IMAf61jtUdXX+zuBAMxDINrVNAOtOTdUiFPkhlnd1MoHuMmSIxXtRutZZnwnxW
A6A8naTGkDMSQ9YkRzaXOoabxGwGmAYkEUQXdkPF29Dl5eyMFtZD4zny24t/rKJx
EjKD7c4lU7ppWt32hx/8FyQgrdz/1431mnYVYBvfPRctYLJWwrygde4qkrg+HhJu
rBC/7orShrqw9/LyviJ2zewPA74H
-----END CERTIFICATE-----
1 s:C = US, O = Google Trust Services, CN = GTS CA 1O1
i:OU = GlobalSign Root CA - R2, O = GlobalSign, CN = GlobalSign
-----BEGIN CERTIFICATE-----
MIIESjCCAzKgAwIBAgINAeO0mqGNiqmBJWlQuDANBgkqhkiG9w0BAQsFADBMMSAw
HgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFs
U2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjAeFw0xNzA2MTUwMDAwNDJaFw0yMTEy
MTUwMDAwNDJaMEIxCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVHb29nbGUgVHJ1c3Qg
U2VydmljZXMxEzARBgNVBAMTCkdUUyBDQSAxTzEwggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQDQGM9F1IvN05zkQO9+tN1pIRvJzzyOTHW5DzEZhD2ePCnv
UA0Qk28FgICfKqC9EksC4T2fWBYk/jCfC3R3VZMdS/dN4ZKCEPZRrAzDsiKUDzRr
mBBJ5wudgzndIMYcLe/RGGFl5yODIKgjEv/SJH/UL+dEaltN11BmsK+eQmMF++Ac
xGNhr59qM/9il71I2dN8FGfcddwuaej4bXhp0LcQBbjxMcI7JP0aM3T4I+DsaxmK
FsbjzaTNC9uzpFlgOIg7rR25xoynUxv8vNmkq7zdPGHXkxWY7oG9j+JkRyBABk7X
rJfoucBZEqFJJSPk7XA0LKW0Y3z5oz2D0c1tJKwHAgMBAAGjggEzMIIBLzAOBgNV
HQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMBIGA1Ud
EwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFJjR+G4Q68+b7GCfGJAboOt9Cf0rMB8G
A1UdIwQYMBaAFJviB1dnHB7AagbeWbSaLd/cGYYuMDUGCCsGAQUFBwEBBCkwJzAl
BggrBgEFBQcwAYYZaHR0cDovL29jc3AucGtpLmdvb2cvZ3NyMjAyBgNVHR8EKzAp
MCegJaAjhiFodHRwOi8vY3JsLnBraS5nb29nL2dzcjIvZ3NyMi5jcmwwPwYDVR0g
BDgwNjA0BgZngQwBAgIwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly9wa2kuZ29vZy9y
ZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAGoA+Nnn78y6pRjd9XlQWNa7H
TgiZ/r3RNGkmUmYHPQq6Scti9PEajvwRT2iWTHQr02fesqOqBY2ETUwgZQ+lltoN
FvhsO9tvBCOIazpswWC9aJ9xju4tWDQH8NVU6YZZ/XteDSGU9YzJqPjY8q3MDxrz
mqepBCf5o8mw/wJ4a2G6xzUr6Fb6T8McDO22PLRL6u3M4Tzs3A2M1j6bykJYi8wW
IRdAvKLWZu/axBVbzYmqmwkm5zLSDW5nIAJbELCQCZwMH56t2Dvqofxs6BBcCFIZ
USpxu6x6td0V7SvJCCosirSmIatj/9dSSVDQibet8q/7UK4v4ZUN80atnZz1yg==
-----END CERTIFICATE-----
---
Server certificate""".split(os.linesep)

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
                                              command=["openssl", "unittest.com"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.service,
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command.stdout_output = self.get_command_text_outputs()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            result = session.query(File).all()
            self.assertEqual(2, len(result))
            session.query(Company).filter_by(name="google llc").one()
            result = [item.full_name for item in session.query(HostName).all()]
            result.sort()
            expected_result = ["google.com", "www.google.com"]
            expected_result.sort()
            self.assertListEqual(expected_result, result)
