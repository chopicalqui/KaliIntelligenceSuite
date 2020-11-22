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
from collectors.os.modules.dns.dnshost import CollectorClass as DnshostCollector
from unittests.tests.collectors.core import CollectorProducerTestSuite
from database.model import CollectorType
from database.model import HostName
from database.model import DomainName
from database.model import DnsResourceRecordType
from database.model import ScopeType


class BaseDnsTakeOverCollectorTestCase(BaseKaliDnsCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="dnshost",
                         collector_class=DnshostCollector,
                         **kwargs)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return """$ host www.starbucks.com
www.test.local is an alias for sites.test.local.edgekey.net.
sites.test.local.edgekey.net is an alias for e13595.a.akamaiedge.net.
e13595.a.akamaiedge.net has address 92.122.36.1
e13595.a.akamaiedge.net has IPv6 address 2a00:1450:400a:802::2004""".split(os.linesep)

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
                                              command=["dig", "www.test.local"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.domain,
                                              host_name_str="www.test.local",
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command.stdout_output = self.get_command_text_outputs()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            result = session.query(HostName) \
                .join(DomainName) \
                .filter(DomainName.name == "test.local", HostName.name == "www").one()
            cnames = result.canonical_name_records
            self.assertEqual(3, len(cnames))
            self.assertEqual("www.test.local", cnames[0].full_name)
            self.assertEqual("sites.test.local.edgekey.net", cnames[1].full_name)
            self.assertEqual("e13595.a.akamaiedge.net", cnames[2].full_name)
            self.assertEqual("92.122.36.1",
                             cnames[0].get_host_host_name_mappings(types=[DnsResourceRecordType.a])[0].host.ipv4_address)
            self.assertEqual("2a00:1450:400a:802::2004",
                             cnames[0].get_host_host_name_mappings(types=[DnsResourceRecordType.aaaa])[0].host.ipv6_address)
            self.assertEqual("92.122.36.1",
                             cnames[-1].get_host_host_name_mappings(types=[DnsResourceRecordType.a])[0].host.ipv4_address)
            self.assertEqual("2a00:1450:400a:802::2004",
                             cnames[-1].get_host_host_name_mappings(types=[DnsResourceRecordType.aaaa])[0].host.ipv6_address)
