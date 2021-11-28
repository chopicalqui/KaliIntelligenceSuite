#!/usr/bin/python3
"""
this file implements all unittests for collector dnsgobuster
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
from collectors.os.modules.dns.dnsgobuster import CollectorClass as DnsGoBusterCollector
from unittests.tests.collectors.core import CollectorProducerTestSuite
from database.model import CollectorType
from database.model import HostName
from database.model import ScopeType


class BaseDnsGoBusterCollectorTestCase(BaseKaliDnsCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="dnsgobuster",
                         collector_class=DnsGoBusterCollector,
                         **kwargs)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return """$ gobuster dns -i -z -q --wildcard -t 10 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -d test.local
\rFound: www.test.local [127.0.0.1,127.0.0.2,127.0.0.3,127.0.0.4]
\rFound: dev.test.local [127.0.0.5]""".split(os.linesep)

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
                                              command=["gobuster", "dns", "test.local"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.domain,
                                              host_name_str="test.local",
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command.stdout_output = self.get_command_text_outputs()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            for host_name in session.query(HostName).all():
                if host_name.full_name == "www.test.local":
                    self.assertEqual(4, len(host_name.host_host_name_mappings))
                elif host_name.full_name == "dev.test.local":
                    self.assertEqual(1, len(host_name.host_host_name_mappings))
                    self.assertEqual("127.0.0.5", host_name.host_host_name_mappings[0].host.address)
                elif host_name.name is not None:
                    raise ValueError("this case should not happen.")
