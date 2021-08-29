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
from collectors.os.modules.http.httpkiterunner import CollectorClass as HttpKiterunner
from database.model import Command
from database.model import CollectorType
from database.model import Path
from database.model import ScopeType


class BaseHttpGobusterCollectorTestCase(BaseKaliHttpCollectorTestCase):
    """
    This class implements all unittestss for the given collector
    """
    def __init__(self, test_name: str, **kwargs):
        super().__init__(test_name,
                         collector_name="httpkiterunner",
                         collector_class=HttpKiterunner)

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return ["""[...]
GET     404 [    141,    6,  10] https://www.redacted.com/service 0cc39f88b974e7013240b118a0a1e847e9c77a39
GET     400 [   1644,   88,  14] https://www.redacted.com/chart 0cc39f7566cea0d21888e3fec6effeced2705889
GET     400 [   1644,   88,  14] https://www.redacted.com/chart 0cc39f8059eb4446edad16e48fb2a4adc3db3e88
GET     200 [ 183040, 4153, 236] https://www.redacted.com/ 0cc39f799603269e7e5d5e244ac049c94871a2bd
GET     200 [ 182955, 4153, 236] https://www.redacted.com/ 0cc39f79183f1622c5718cf989ed5cc013a87cfb
 100% |█████| (53033/53033, 1342 it/s)          
{"level":"info","results":5,"duration":39982.285811,"time":"2021-08-28T14:59:38Z","message":"scan complete"}"""]

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
                                              command=["kr", "www.redacted.com"],
                                              collector_name_str=self._collector_name,
                                              collector_name_type=CollectorType.host_service,
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
            results = [item.name for item in session.query(Path).all()]
            results.sort()
            self.assertListEqual(["/", "/chart", "/service"], results)
