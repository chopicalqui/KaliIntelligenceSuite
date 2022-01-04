#!/usr/bin/python3
"""
this file implements all unittests for collector host.io
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
from collectors.os.modules.osint.hostio import CollectorClass as HostIoCollector
from database.model import Host
from database.model import Email
from database.model import Network
from database.model import HostName
from database.model import ScopeType
from database.model import CollectorType


class BaseBuiltWithCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="hostio",
                         collector_class=HostIoCollector)

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
    "domain": "test.local",
    "dns": {
        "domain": "test1.local",
        "a": [
            "127.0.0.1"
        ],
        "mx": [
            "10 smtp1.test1.local.",
            "10 mail5.test1.local.",
            "30 mail6.test1.local."
        ],
        "ns": [
            "ns1.test1.local.",
            "ns2.test1.local."
        ]
    },
    "ipinfo": {
        "127.0.0.2": {
            "asn": {
                "asn": "AS0000",
                "name": "Company LLC",
                "domain": "test2.local",
                "route": "127.0.0.0/20",
                "type": "business"
            }
        }
    },
    "related": {
        "ip": [
            {
                "value": "127.0.0.3"
            }
        ],
        "asn": [
            {
                "value": "AS0000"
            }
        ],
        "ns": [
            {
                "value": "test3.local"
            }
        ],
        "mx": [
            {
                "value": "test4.local"
            }
        ],
        "backlinks": [
            {
                "value": "test5.local"
            }
        ],
        "redirects": [
            {
                "value": "test6.local"
            }
        ],
        "email": [
            {
                "value": ["test@test12.local", "test1@test12.local"]
            }
        ]
    },
    "web": {
        "domain": "test7.local",
        "url": "https://www.test7.local:8443/login.html",
        "ip": "127.0.0.4",
        "links": [
            "test8.local",
            "test9.local"
        ],
        "redirect": [
            "www.test10.local",
            "www.test11.local"
        ],
        "email": "test@test13.local, test1@test13.local"
    }
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
                                              command=["kisimport", "027.ru"],
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
        expected_host_names = ["test.local",
                               "test1.local",
                               "smtp1.test1.local",
                               "mail5.test1.local",
                               "mail6.test1.local",
                               "ns1.test1.local",
                               "ns2.test1.local",
                               "test2.local",
                               "test3.local",
                               "test4.local",
                               "test5.local",
                               "test6.local",
                               "test7.local",
                               "www.test7.local",
                               "test8.local",
                               "test9.local",
                               "test10.local",
                               "www.test10.local",
                               "www.test11.local",
                               "test11.local",
                               "test12.local",
                               "test13.local"]
        expected_emails = ["test@test12.local", "test1@test12.local", "test@test13.local", "test1@test13.local"]
        expected_hosts = ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "192.168.1.1"]
        expected_networks = ["127.0.0.0/20"]
        expected_host_names.sort()
        expected_emails.sort()
        expected_hosts.sort()
        expected_networks.sort()
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
            result = [item.network for item in session.query(Network).all()]
            result.sort()
            self.assertListEqual(expected_networks, result)
            # Check https://www.test7.local:8443/login.html
            result = self._domain_utils.get_host_name(session=session, workspace=workspace, host_name="www.test7.local")
            self.assertIsNotNone(result)
            self.assertEqual(1, len(result.services))
            self.assertEqual(8443, result.services[0].port)
            self.assertEqual("ssl", result.services[0].nmap_tunnel)
            self.assertEqual(1, len(result.services[0].paths))
            self.assertEqual("/login.html", result.services[0].paths[0].name)
