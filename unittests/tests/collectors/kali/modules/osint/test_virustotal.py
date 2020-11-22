#!/usr/bin/python3
"""
this file implements all unittests for collector virustotal
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
from collectors.os.modules.osint.virustotal import CollectorClass as VirustotalCollector
from database.model import HostName
from database.model import CollectorType
from database.model import ScopeType


class BaseBuiltWithCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="virustotal",
                         collector_class=VirustotalCollector)

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
    "undetected_referrer_samples": [
        {
            "date": "2018-03-04 16:38:06",
            "positives": 0,
            "total": 66,
            "sha256": "ce08cf22949b6b6fcd4e61854ce810a4f9ee04529340dd077fa354d759dc7a95"
        },
        {
            "positives": 0,
            "total": 53,
            "sha256": "b8f5db667431d02291eeec61cf9f0c3d7af00798d0c2d676fde0efb0cedb7741"
        }
    ],
    "whois_timestamp": 1520586501,
    "detected_downloaded_samples": [
        {
            "date": "2013-06-20 18:51:30",
            "positives": 2,
            "total": 46,
            "sha256": "cd8553d9b24574467f381d13c7e0e1eb1e58d677b9484bd05b9c690377813e54"
        }
    ],
    "detected_referrer_samples": [],
    "undetected_downloaded_samples": [
        {
            "date": "2018-01-14 22:34:24",
            "positives": 0,
            "total": 70,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
    ],
    "resolutions": [
        {
            "last_resolved": "2018-03-09 00:00:00",
            "ip_address": "185.53.177.31"
        },
        {
            "last_resolved": "2013-06-20 00:00:00",
            "ip_address": "90.156.201.97"
        }
    ],
    "subdomains": [
        "test.027.ru",
        "www.027.ru"
    ],
    "categories": [
        "parked",
        "uncategorized"
    ],
    "domain_siblings": [],
    "undetected_urls": [],
    "response_code": 1,
    "verbose_msg": "Domain found in dataset",
    "detected_urls": [
        {
            "url": "http://027.ru/",
            "positives": 2,
            "total": 67,
            "scan_date": "2018-04-01 15:51:22"
        },
        {
            "url": "http://027.ru/adobe/flash_install_v10x1.php",
            "positives": 5,
            "total": 67,
            "scan_date": "2018-03-26 09:22:43"
        },
        {
            "url": "http://027.ru/track.php",
            "positives": 4,
            "total": 66,
            "scan_date": "2018-01-14 22:39:41"
        },
        {
            "url": "http://027.ru/track.php?domain=027.ru&caf=1&toggle=answercheck",
            "positives": 2,
            "total": 66,
            "scan_date": "2018-01-09 22:19:43"
        },
        {
            "url": "https://027.ru/",
            "positives": 1,
            "total": 66,
            "scan_date": "2016-02-08 13:25:40"
        }
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
        with self._engine.session_scope() as session:
            results = [item.full_name for item in session.query(HostName).all()]
            results.sort()
            expected_results = ["027.ru",
                                "test.027.ru",
                                "www.027.ru"]
            expected_results.sort()
            self.assertListEqual(expected_results, results)
