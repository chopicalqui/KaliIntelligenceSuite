#!/usr/bin/python3
"""
this file implements all unittests for collector censysdomain
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
from collectors.os.modules.osint.censysdomain import CollectorClass as CensysDomainCollector
from database.model import DomainName
from database.model import CollectorType
from database.model import HostName
from database.model import Host
from database.model import Path
from database.model import AdditionalInfo
from database.model import Service
from database.model import ScopeType


class BaseShodanHostCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="censysdomain",
                         collector_class=CensysDomainCollector)

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
        json_objects = [{'parsed.names': ['autodiscover.icloud-google.com', 'cpanel.icloud-google.com', 'cpcalendars.icloud-google.com', 'cpcontacts.icloud-google.com', 'icloud-google.com', 'mail.icloud-google.com', 'webdisk.icloud-google.com', 'webmail.icloud-google.com', 'www.icloud-google.com']},
{'parsed.names': ['cpanel.myaccounts-google.com', 'cpcalendars.myaccounts-google.com', 'cpcontacts.myaccounts-google.com', 'mail.myaccounts-google.com', 'myaccounts-google.com', 'webdisk.myaccounts-google.com', 'webmail.myaccounts-google.com', 'www.myaccounts-google.com']},
{'parsed.names': ['accounts.validate-google.com', 'apis.validate-google.com', 'content.validate-google.com', 'myaccount.validate-google.com', 'play.validate-google.com', 'ssl.validate-google.com', 'www.validate-google.com', 'youtube.validate-google.com']},
{'parsed.names': ['accounts.validate-google.com', 'apis.validate-google.com', 'content.validate-google.com', 'myaccount.validate-google.com', 'play.validate-google.com', 'ssl.validate-google.com', 'www.validate-google.com', 'youtube.validate-google.com']},
{'parsed.names': ['autodiscover.icloud-google.com', 'cpanel.icloud-google.com', 'cpcalendars.icloud-google.com', 'cpcontacts.icloud-google.com', 'icloud-google.com', 'mail.icloud-google.com', 'webdisk.icloud-google.com', 'webmail.icloud-google.com', 'www.icloud-google.com']}]
        return json_objects

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
                                              command=["kisimport", "google.com"],
                                              host_name_str="google.com",
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
            expected_result = ["google.com",
                               "icloud-google.com",
                               "autodiscover.icloud-google.com",
                               "cpanel.icloud-google.com",
                               "cpcalendars.icloud-google.com",
                               "cpcontacts.icloud-google.com",
                               "mail.icloud-google.com",
                               "webdisk.icloud-google.com",
                               "webmail.icloud-google.com",
                               "www.icloud-google.com",
                               "myaccounts-google.com",
                               "cpanel.myaccounts-google.com",
                               "cpcalendars.myaccounts-google.com",
                               "cpcontacts.myaccounts-google.com",
                               "mail.myaccounts-google.com",
                               "webdisk.myaccounts-google.com",
                               "webmail.myaccounts-google.com",
                               "www.myaccounts-google.com",
                               "validate-google.com",
                               "accounts.validate-google.com",
                               "apis.validate-google.com",
                               "content.validate-google.com",
                               "myaccount.validate-google.com",
                               "play.validate-google.com",
                               "ssl.validate-google.com",
                               "www.validate-google.com",
                               "youtube.validate-google.com"]
            expected_result.sort()
            result = session.query(Host).count()
            self.assertEqual(0, result)
            result = session.query(Service).count()
            self.assertEqual(0, result)
            result = session.query(Path).count()
            self.assertEqual(0, result)
            result = session.query(DomainName).count()
            self.assertEqual(4, result)
            result = session.query(HostName).count()
            self.assertEqual(27, result)
            result = session.query(AdditionalInfo).count()
            self.assertEqual(0, result)
            result = session.query(HostName).all()
            result = [item.full_name for item in result]
            result.sort()
            self.assertListEqual(expected_result, result)
