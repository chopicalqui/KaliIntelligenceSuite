#!/usr/bin/python3
"""
this file implements core functionalities for reporting unittests
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2022 Lukas Reiter

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

import argparse
from typing import List
from sqlalchemy.orm.session import Session
from database.report.core import ReportGenerator
from unittests.tests.core import KisCommandEnum
from unittests.tests.core import BaseTestKisCommand


class BaseReportTestCase(BaseTestKisCommand):
    """
    This class implements functionalities for testing the report
    """

    def __init__(self, **kwargs):
        super().__init__(command=KisCommandEnum.kisreport, **kwargs)
        # Setup arguments
        self._parser = ReportGenerator.get_report_argument_parser()
        sub_parser = ReportGenerator.add_sub_argument_parsers(self._parser)
        self._report_classes = ReportGenerator.add_argparser_arguments(sub_parser)
        self._generator = ReportGenerator(report_classes=self._report_classes)

    def _test_filter(self,
                     session: Session,
                     workspace_str: str,
                     argument_list: List[str],
                     item,
                     expected_result: bool):
        """
        This is a helper method for testing the filter methods
        :return:
        """
        if "--testing" not in argument_list:
            argument_list.insert(0, "--testing")
        args = self._parser.parse_args(argument_list)
        workspace = self.create_workspace(session, workspace=workspace_str)
        report = self._generator.create_report_instance(args=args, session=session, workspaces=[workspace])
        result = report._filter(item)
        self.assertEqual(expected_result, result)

    def _get_csv_report(self,
                    session: Session,
                    workspace_str: str,
                    argument_list: List[str]) -> List[List[str]]:
        result = None
        if "--testing" not in argument_list:
            argument_list.insert(0, "--testing")
            args = self._parser.parse_args(argument_list)
            workspace = self.create_workspace(session, workspace=workspace_str)
            report = self._generator.create_report_instance(args=args, session=session, workspaces=[workspace])
            result = report.get_csv()
        return result