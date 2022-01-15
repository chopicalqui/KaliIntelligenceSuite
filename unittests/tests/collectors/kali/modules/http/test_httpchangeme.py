#!/usr/bin/python3
"""
this file implements all unittests for collector httpchangeme
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
from typing import Dict
from unittests.tests.collectors.kali.modules.http.core import BaseKaliHttpCollectorTestCase
from unittests.tests.collectors.core import CollectorProducerTestSuite
from collectors.os.modules.http.httpchangeme import CollectorClass as HttpChangemeCollector
from database.model import Command
from database.model import CollectorType
from database.model import Credentials
from database.model import Path
from database.model import ScopeType


class BaseHttpChangemeCollectorTestCase(BaseKaliHttpCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="httpchangeme",
                         collector_class=HttpChangemeCollector)

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
        return [{"results": [{"name": "Tomcat",
                              "username": "tomcat",
                              "password": "tomcat",
                              "target": "http://127.0.0.1:8080/manager/status",
                              "evidence": ""}]}]

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
                source = self.create_source(session, source_str=self._collector_name)
                command = self.create_command(session=session,
                                              workspace_str=self._workspaces[0],
                                              command=["changeme", "127.0.0.1"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.host_service,
                                              service_port=80,
                                              scope=ScopeType.all,
                                              output_path=temp_dir)
                command.json_output = self.get_command_json_outputs()
                test_suite.verify_results(session=session,
                                          arg_parse_module=self._arg_parse_module,
                                          command=command,
                                          source=source,
                                          report_item=self._report_item)
        with self._engine.session_scope() as session:
            results = session.query(Command).count()
            self.assertEqual(1, results)
            results = session.query(Credentials).count()
            self.assertEqual(1, results)
            results = session.query(Credentials).one()
            self.assertEqual("tomcat", results.username)
            self.assertEqual("tomcat", results.password)
            results = [item.name for item in session.query(Path).all()]
            self.assertListEqual(["/", "/manager/status"], results)
