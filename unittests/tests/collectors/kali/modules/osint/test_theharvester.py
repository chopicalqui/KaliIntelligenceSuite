#!/usr/bin/python3
"""
this file implements all unittests for collector theharvester
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
from collectors.os.modules.osint.theharvester import CollectorClass as TheHarvesterCollector
from database.model import Host
from database.model import Email
from database.model import HostName
from database.model import ScopeType
from database.model import CollectorType


class BaseBuiltWithCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="theharvester",
                         collector_class=TheHarvesterCollector)

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
    "asns": [
        "AS0000",
        "AS0001"
    ],
    "emails": [
        "test@test1.local",
        "test@test2.local"
    ],
    "hosts": [
        "www.test3.local:127.0.0.1",
        "www.test4.local"
    ],
    "interesting_urls": [
        "http://www.test5.local/login.html",
        "https://www.test6.local/admin.html"
    ],
    "ips": [
        "127.0.0.1",
        "127.0.0.2"
    ],
    "shodan": []
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
                                              command=["kisimport", "test.local"],
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
        expected_host_names = ["test1.local",
                               "test2.local",
                               "test3.local",
                               "www.test3.local",
                               "test4.local",
                               "www.test4.local",
                               "test5.local",
                               "www.test5.local",
                               "test6.local",
                               "www.test6.local"]
        expected_emails = ["test@test1.local", "test@test2.local"]
        expected_hosts = ["127.0.0.1", "127.0.0.2", "192.168.1.1"]
        expected_host_names.sort()
        expected_emails.sort()
        expected_hosts.sort()
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.get_workspace(session=session, name=self._workspaces[0])
            result = [item.full_name for item in session.query(HostName).all()]
            result.sort()
            self.assertListEqual(expected_host_names, result)
            result = [item.email_address for item in session.query(Email).all()]
            result.sort()
            self.assertListEqual(expected_emails, result)
            result = [item.address for item in session.query(Host).all()]
            result.sort()
            self.assertListEqual(expected_hosts, result)
            # Check http://www.test5.local/login.html
            result = self._domain_utils.get_host_name(session=session, workspace=workspace, host_name="www.test5.local")
            self.assertIsNotNone(result)
            self.assertEqual(1, len(result.services))
            self.assertEqual(80, result.services[0].port)
            self.assertIsNone(result.services[0].nmap_tunnel)
            self.assertEqual(2, len(result.services[0].paths))
            self.assertListEqual(["/", "/login.html"], [item.name for item in result.services[0].paths])
            # Check https://www.test6.local/admin.html
            result = self._domain_utils.get_host_name(session=session, workspace=workspace, host_name="www.test6.local")
            self.assertIsNotNone(result)
            self.assertEqual(1, len(result.services))
            self.assertEqual(443, result.services[0].port)
            self.assertEqual("ssl", result.services[0].nmap_tunnel)
            self.assertEqual(2, len(result.services[0].paths))
            self.assertEqual(["/", "/admin.html"], [item.name for item in result.services[0].paths])
