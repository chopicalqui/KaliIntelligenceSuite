#!/usr/bin/python3
"""
this file implements all unittests for collector dnsspf
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
from collectors.os.modules.dns.dnsspf import CollectorClass as DnsSpfCollector
from unittests.tests.collectors.core import CollectorProducerTestSuite
from database.model import Host
from database.model import Network
from database.model import ScopeType
from database.model import CollectorType


class BaseDnsSpfCollectorTestCase(BaseKaliDnsCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="dnsspf",
                         collector_class=DnsSpfCollector,
                         **kwargs)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return """$ /usr/bin/dig +short -t TXT test.local
"v=spf1 mx include:mail.test.local include:smtp.test.local include:spf.protection.outlook.com a:mail.test1.local a:smtp.test1.local a:mail.test2.local/24 mx:mail.test3.local exists:mail.test4.local -all"
"v=spf1 ip4:192.168.0.0/16 ~all"
"v=spf1 ip4:192.168.0.1/16 ~all"
"v=spf1 ip4:192.168.0.2/32 ~all"
"v=spf1 ip4:192.168.0.3 ~all"
"v=spf1 ip6:fe80::/64 ~all"
"v=spf1 ip6:::1/96 ~all"
"v=spf1 ip6:::2/128 ~all"
"v=spf1 ip6:::3 ~all"
"v=spf1 ip6:1080::8:800:200C:417A/98 ~all"
""".split(os.linesep)

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
                                              command=["dig", "+short", "-t", "TXT", "test.local"],
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
        # Check database
        with self._engine.session_scope() as session:
            # Check domain names
            self._check_existence(session=session, host_name="test.local")
            self._check_existence(session=session, host_name="mail.test.local")
            self._check_existence(session=session, host_name="smtp.test.local")
            self._check_existence(session=session, host_name="test1.local")
            self._check_existence(session=session, host_name="mail.test1.local")
            self._check_existence(session=session, host_name="smtp.test1.local")
            self._check_existence(session=session, host_name="test2.local")
            self._check_existence(session=session, host_name="mail.test2.local")
            self._check_existence(session=session, host_name="test3.local")
            self._check_existence(session=session, host_name="mail.test3.local")
            self._check_existence(session=session, host_name="outlook.com")
            self._check_existence(session=session, host_name="spf.protection.outlook.com")
            # Check IP addresses
            self.assertIsNotNone(session.query(Host).filter_by(address="::1").one_or_none())
            self.assertIsNotNone(session.query(Host).filter_by(address="::2").one_or_none())
            self.assertIsNotNone(session.query(Host).filter_by(address="::3").one_or_none())
            self.assertIsNotNone(session.query(Host).filter_by(address="192.168.0.1").one_or_none())
            self.assertIsNotNone(session.query(Host).filter_by(address="192.168.0.2").one_or_none())
            self.assertIsNotNone(session.query(Host).filter_by(address="192.168.0.3").one_or_none())
            self.assertIsNotNone(session.query(Host).filter_by(address="1080::8:800:200C:417A").one_or_none())
            # Check IP networks
            self.assertIsNotNone(session.query(Network).filter_by(network="fe80::/64").one_or_none())
            self.assertIsNotNone(session.query(Network).filter_by(network="192.168.0.0/16").one_or_none())
