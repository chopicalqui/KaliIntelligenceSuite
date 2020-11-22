#!/usr/bin/python3
"""
this file implements all unittests for collector builtwith
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
from collectors.os.modules.osint.builtwith import CollectorClass as BuiltWithCollector
from database.model import DomainName
from database.model import CollectorType
from database.model import Host
from database.model import ScopeType


class BaseBuiltWithCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="builtwith",
                         collector_class=BuiltWithCollector)

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
    "Relationships": [
        {
            "Domain": "unittest.com",
            "Identifiers": [
                {
                    "Type": "ip",
                    "Value": "192.168.10.1",
                    "First": 1345212000000,
                    "Last": 1565531237296,
                    "Matches": []
                },
                {
                    "Type": "google-analytics",
                    "Value": "1212341234",
                    "First": 1294059600000,
                    "Last": 1530438765239,
                    "Matches": [
                      {
                          "Domain": "unittest.ch",
                          "First": 1389790800000,
                          "Last": 1390827600000,
                          "Overlap": true
                      },
                      {
                          "Domain": "unittest.org",
                          "First": 1389790800000,
                          "Last": 1390827600000,
                          "Overlap": true
                      },
                      {
                          "Domain": "unittest.se",
                          "First": 1389790800000,
                          "Last": 1390222800000,
                          "Overlap": true
                      }
                    ]
                },
                {
                    "Type": "ip",
                    "Value": "host.www.localhost.com",
                    "First": 1507590000000,
                    "Last": 1519945200000,
                    "Matches": []
                },
                {
                    "Type": "google-tag-manager",
                    "Value": "ASDF3423",
                    "First": 1519858800000,
                    "Last": 1545920855764,
                    "Matches": [
                      {
                          "Domain": "unittest1.ch",
                          "First": 1389790800000,
                          "Last": 1390827600000,
                          "Overlap": true
                      },
                      {
                          "Domain": "unittest1.org",
                          "First": 1389790800000,
                          "Last": 1390827600000,
                          "Overlap": true
                      },
                      {
                          "Domain": "unittest1.se",
                          "First": 1389790800000,
                          "Last": 1390222800000,
                          "Overlap": true
                      }
                    ]
                }
            ]
        }
    ],
    "Errors": []
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
            results = session.query(DomainName).all()
            results = [item.name for item in results]
            results.sort()
            expected_results = ["unittest.ch",
                                "unittest.org",
                                "unittest.se",
                                "unittest1.ch",
                                "unittest1.org",
                                "unittest1.se"]
            expected_results.sort()
            self.assertListEqual(expected_results, results)
            results = session.query(Host).filter_by(address="192.168.10.1").one()
            self.assertEqual("192.168.10.1", results.ipv4_address)
