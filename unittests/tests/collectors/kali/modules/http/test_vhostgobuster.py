#!/usr/bin/python3
"""
this file implements all unittests for collector httpgobuaster
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
from unittests.tests.collectors.kali.modules.http.core import BaseKaliHttpCollectorTestCase
from unittests.tests.collectors.core import CollectorProducerTestSuite
from collectors.os.modules.http.vhostgobuster import CollectorClass as VhostGobusterCollector
from database.model import Command
from database.model import CollectorType
from database.model import ScopeType
from database.model import DomainName
from database.model import HostName
from database.model import DnsResourceRecordType


class BaseHttpGobusterCollectorTestCase(BaseKaliHttpCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="vhostgobuster",
                         collector_class=VhostGobusterCollector)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return ["""===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          https://mysite.com
[+] Threads:      10
[+] Wordlist:     common-vhosts.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2019/06/21 08:36:00 Starting gobuster
===============================================================
Found: www.mysite.com
Found: piwik.mysite.com
Found: mail.mysite.com
===============================================================
2019/06/21 08:36:05 Finished
==============================================================="""]

    def test_for_invalid_arguments(self):
        """
        This method checks whether the collector creates a valid command for the installed version
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self._test_for_invalid_arguments(session=session,
                                             workspace_str=self._workspaces[0],
                                             expected_command_count=2)

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
                self.create_hostname(session=session,
                                     workspace_str=self._workspaces[0],
                                     host_name="www.mysite.com",
                                     scope=ScopeType.all)
                self.create_hostname(session=session,
                                     workspace_str=self._workspaces[0],
                                     host_name="piwik.mysite.com",
                                     scope=ScopeType.all)
                self.create_hostname(session=session,
                                     workspace_str=self._workspaces[0],
                                     host_name="mail.mysite.com",
                                     scope=ScopeType.all)
                source = self.create_source(session, source_str=self._collector_name)
                command = self.create_command(session=session,
                                              workspace_str=self._workspaces[0],
                                              command=["gobuster", "192.168.1.1"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.service,
                                              service_port=80,
                                              scope=ScopeType.all,
                                              stdout_output=self.get_command_text_outputs()[0],
                                              output_path=temp_dir)
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            results = session.query(Command).count()
            self.assertEqual(1, results)
            results = session.query(DomainName).all()
            self.assertEqual(1, len(results))
            results = session.query(HostName).all()
            self.assertEqual(4, len(results))
            host_names = [item.full_name for item in results]
            self.assertIn("www.mysite.com", host_names)
            self.assertIn("piwik.mysite.com", host_names)
            self.assertIn("mail.mysite.com", host_names)
            for item in results:
                if item.name is not None:
                    self.assertEqual(1, len(item.host_host_name_mappings))
                    self.assertEqual(DnsResourceRecordType.vhost, item.host_host_name_mappings[0].type)
                    self.assertEqual("192.168.1.1", item.host_host_name_mappings[0].host.address)
