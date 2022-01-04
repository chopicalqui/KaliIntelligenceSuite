#!/usr/bin/python3
"""
this file implements all unittests for collector dnshost
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
from collectors.os.modules.dns.dnsaxfrservice import CollectorClass as DnsaxfrCollector
from unittests.tests.collectors.core import CollectorProducerTestSuite
from database.model import CollectorType
from database.model import DnsResourceRecordType
from database.model import ScopeType


class BaseDnsTakeOverCollectorTestCase(BaseKaliDnsCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="dnsaxfr",
                         collector_class=DnsaxfrCollector,
                         **kwargs)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return """Trying "megacorpone.com"
Using domain server:
Name: 51.222.39.63
Address: 51.222.39.63#53
Aliases:

;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61338
;; flags: qr aa; QUERY: 1, ANSWER: 29, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;megacorpone.com.               IN      AXFR

;; ANSWER SECTION:
megacorpone.com.        300     IN      SOA     ns1.megacorpone.com. admin.megacorpone.com. 202102161 28800 7200 2419200 300
megacorpone.com.        300     IN      TXT     "google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA"
megacorpone.com.        300     IN      MX      50 mail.megacorpone.com.
megacorpone.com.        300     IN      NS      ns1.megacorpone.com.
test.megacorpone.com.   300     IN      CNAME   cname.megacorpone.com.
www2.megacorpone.com.   300     IN      A       149.56.244.87
www6.megacorpone.com.   300     IN      AAAA    2a00:1450:400a:802::2004
megacorpone.com.        300     IN      SOA     ns1.megacorpone.com. admin.megacorpone.com. 202102161 28800 7200 2419200 300

Received 723 bytes from 51.222.39.63#53 in 100 ms""".split(os.linesep)

    def _check_existence(self, session, host_name: str):
        self.assertIsNotNone(self.query_hostname(session=session,
                                                 workspace_str=self._workspaces[0],
                                                 host_name=host_name))

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
                                              command=["host", "-t", "axfr", "-p", "53", "megacorpone.com", "51.222.39.63"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.host_service,
                                              service_port=53,
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command.stdout_output = self.get_command_text_outputs()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            self._check_existence(session=session, host_name="megacorpone.com")
            self._check_existence(session=session, host_name="ns1.megacorpone.com")
            self._check_existence(session=session, host_name="admin.megacorpone.com")
            self._check_existence(session=session, host_name="mail.megacorpone.com")
            self._check_existence(session=session, host_name="test.megacorpone.com")
            self._check_existence(session=session, host_name="www2.megacorpone.com")
            self._check_existence(session=session, host_name="www6.megacorpone.com")
            host_name = self.query_hostname(session=session,
                                            workspace_str=self._workspaces[0],
                                            host_name="test.megacorpone.com")
            mapping = host_name.resolved_host_name_mappings[0]
            self.assertEqual("cname.megacorpone.com", mapping.resolved_host_name.full_name)
            host_name = self.query_hostname(session=session,
                                            workspace_str=self._workspaces[0],
                                            host_name="www2.megacorpone.com")
            hosts = host_name.get_host_host_name_mappings([DnsResourceRecordType.a])
            self.assertEqual("149.56.244.87", hosts[0].host.ipv4_address)
            host_name = self.query_hostname(session=session,
                                            workspace_str=self._workspaces[0],
                                            host_name="www6.megacorpone.com")
            hosts = host_name.get_host_host_name_mappings([DnsResourceRecordType.aaaa])
            self.assertEqual("2a00:1450:400a:802::2004", hosts[0].host.ipv6_address)
