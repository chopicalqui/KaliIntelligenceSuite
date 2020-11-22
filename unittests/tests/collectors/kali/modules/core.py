#!/usr/bin/python3
"""
this file implements core functionalities to test os collectors
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

import re
import tempfile
from unittests.tests.collectors.core import BaseCollectorTestCase
from unittests.tests.collectors.core import CollectorProducerTestSuite
from unittests.tests.core import BaseKisTestCase
from database.model import Command
from sqlalchemy.orm.session import Session
from typing import List
from collectors.os.collector import ArgParserModule


class BaseKaliCollectorTestCase(BaseCollectorTestCase):
    """
    This class represents the base class for all os collector tests
    """

    def __init__(self,
                 test_name: str,
                 collector_name: str = None,
                 collector_class: type = None):
        super().__init__(test_name)
        if collector_name and collector_class:
            self._arg_parse_module = ArgParserModule(collector_class=collector_class, arg_option=collector_name)
        else:
            self._arg_parse_module = None
        self._collector_class = collector_class
        self._collector_name = collector_name
        self._expected_command_values = None

    @staticmethod
    def get_command_text_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return []

    @staticmethod
    def get_command_json_outputs() -> List[str]:
        """
        This method returns example outputs of the respective collectors
        :return:
        """
        return []

    @staticmethod
    def create_test_data(test_case: BaseKisTestCase,
                         session: Session,
                         workspace_str: str) -> None:
        """
        This method creates test data in the database in order to be able to create commands
        :param test_case: The test case that provides all methods for creating test data
        :param session: The database session based on which the data is created in the database
        :param workspace_str: The workspace within which the data is created
        :return:
        """
        raise NotImplementedError("method not implemented")

    def _check_invalid_argument_command_output(self, output: List[str], regex: re.Pattern, command: str):
        """
        This method checks whether the given output contains an invalid argument
        """
        for line in output:
            match = regex.match(line)
            if match:
                if match.re.groups:
                    argument = match.group("argument")
                    self.fail("collector '{}' uses invalid argument '{}' for '{}'".format(self._arg_parse_module.name,
                                                                                          argument,
                                                                                          command))
                else:
                    self.fail("collector '{}' uses invalid argument for '{}'".format(self._arg_parse_module.name,
                                                                                     command))

    def _test_for_invalid_arguments(self,
                                    session: Session,
                                    workspace_str: str,
                                    expected_command_count: int):
        """
        This method is a helper for testing valid command arguments
        :return:
        """
        self.create_test_data(test_case=self,
                              session=session,
                              workspace_str=workspace_str)
        session.commit()
        with tempfile.TemporaryDirectory() as temp_dir:
            test_suite = CollectorProducerTestSuite(engine=self._engine,
                                                    arguments={"workspace": workspace_str,
                                                               "output_dir": temp_dir})
            test_suite.create_execute_commands([self._arg_parse_module])
        session.commit()
        result = session.query(Command).count()
        self.assertEqual(expected_command_count, result)
        regex_list = self._arg_parse_module.collector_class.get_invalid_argument_regex()
        for regex in regex_list:
            for command in session.query(Command).all():
                self._check_invalid_argument_command_output(command.stderr_output, regex, command.os_command[0])
                self._check_invalid_argument_command_output(command.stdout_output, regex, command.os_command[0])
