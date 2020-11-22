#!/usr/bin/python3
"""
this file implements all unittests for collectors haveibeenpwned
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
from collectors.os.modules.osint.haveibeenbreach import CollectorClass as HaveibeenbreachCollector
from collectors.os.modules.osint.haveibeenpaste import CollectorClass as HaveibeenpasteCollector
from collectors.apis.haveibeenpwned import HaveIBeenPwnedPasteAcccount
from collectors.apis.haveibeenpwned import HaveIBeenPwnedBreachedAcccount
from database.model import AdditionalInfo
from database.model import CollectorType
from database.model import ScopeType


class HaveibeenbreachCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="haveibeenbreach",
                         collector_class=HaveibeenbreachCollector)

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
        json_objects = json.loads("""[
    {
        "Name": "Adobe",
        "Title": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "AddedDate": "2013-12-04T00:00Z",
        "ModifiedDate": "2013-12-04T00:00Z",
        "PwnCount": 152445165,
        "Description": "",
        "DataClasses": [
            "Email addresses",
            "Password hints",
            "Passwords",
            "Usernames"
        ],
        "IsVerified": true,
        "IsFabricated": false,
        "IsSensitive": false,
        "IsRetired": false,
        "IsSpamList": false,
        "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png"
    },
    {
        "Name": "BattlefieldHeroes",
        "Title": "Battlefield Heroes",
        "Domain": "battlefieldheroes.com",
        "BreachDate": "2011-06-26",
        "AddedDate": "2014-01-23T13:10Z",
        "ModifiedDate": "2014-01-23T13:10Z",
        "PwnCount": 530270,
        "Description": "",
        "DataClasses": [
            "Passwords",
            "Usernames"
        ],
        "IsVerified": true,
        "IsFabricated": false,
        "IsSensitive": false,
        "IsRetired": false,
        "IsSpamList": false,
        "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/BattlefieldHeroes.png"
    }
]""")
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
                                              command=["kisimport", "test@test.com"],
                                              email_str="test@test.com",
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.email,
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command_output = self.get_command_json_outputs()
                command.json_output.extend(command_output[0])
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            result = session.query(AdditionalInfo).filter_by(name=HaveIBeenPwnedBreachedAcccount.NAME).one()
            self.assertListEqual(["Adobe", "BattlefieldHeroes"], result.values)


class HaveibeenpasteCollectorTestCase(BaseKaliCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="haveibeenpaste",
                         collector_class=HaveibeenpasteCollector)

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
        json_objects = json.loads("""[
    {
        "Source": "Pastebin",
        "Id": "8Q0BvKD8",
        "Title": "syslog",
        "Date": "2014-03-04T19:14:54Z",
        "EmailCount": 139
    },
    {
        "Source": "Pastie",
        "Id": "7152479",
        "Date": "2013-03-28T16:51:10Z",
        "EmailCount": 30
    }
]""")
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
                                              command=["kisimport", "test@test.com"],
                                              email_str="test@test.com",
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.email,
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command_output = self.get_command_json_outputs()
                command.json_output.extend(command_output[0])
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            result = session.query(AdditionalInfo).filter_by(name=HaveIBeenPwnedPasteAcccount.NAME).one()
            self.assertListEqual(["Pastebin", "Pastie"], result.values)
