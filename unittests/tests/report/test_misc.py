#!/usr/bin/python3
"""
this file implements general unittests for reporting.
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

import os
import tempfile
from collectors.core import DomainUtils
from database.report.core import ReportGenerator
from unittests.tests.report.core import BaseReportTestCase


class TestReportCreation(BaseReportTestCase):
    """
    Test collector report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name=test_name)

    def test_excel_creation(self):
        self.init_db(load_cipher_suites=True)
        # create database
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                self._populate_all_tables(session, workspace_str)
        # create report
        with tempfile.TemporaryDirectory() as temp_dir:
            excel_file = os.path.join(temp_dir, "excel.xlsx")
            self.execute(subcommand="excel", arguments="{} -w {} -r all".format(excel_file, " ".join(self._workspaces)))
            self.assertTrue(os.path.isfile(excel_file))

    def test_final_creation(self):
        self.init_db(load_cipher_suites=True)
        # create database
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                self._populate_all_tables(session, workspace_str)
        # create report
        with tempfile.TemporaryDirectory() as temp_dir:
            excel_file = os.path.join(temp_dir, "final.xlsx")
            self.execute(subcommand="final", arguments="{} -w {}".format(excel_file, " ".join(self._workspaces)))
            self.assertTrue(os.path.isfile(excel_file))

    def test_text_creation(self):
        self.init_db(load_cipher_suites=True)
        # create database
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                self._populate_all_tables(session, workspace_str)
        # create reports
        report_classes = ReportGenerator.add_argparser_arguments()
        workspaces = " ".join(self._workspaces)
        for module_name in report_classes.keys():
            if module_name in ["excel", "file"]:
                continue
            elif module_name not in ["additionalinfo", "breach", "cert", "tls", "cname", "credential", "file", "path", "vulnerability"]:
                if module_name == "service":
                    self.execute(subcommand=module_name, arguments="-w {} --text".format(workspaces))
                    self.execute(subcommand=module_name, arguments="-w {} -r domain --text".format(workspaces))
                    self.execute(subcommand=module_name, arguments="-w {} -r all --text".format(workspaces))
                else:
                    self.execute(subcommand=module_name, arguments="-w {} --text".format(workspaces))
            else:
                self.execute(subcommand=module_name,
                             arguments="-w {} --text".format(workspaces),
                             expected_return_code=2)

    def test_csv_creation(self):
        self.init_db(load_cipher_suites=True)
        # create database
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                self._populate_all_tables(session, workspace_str)
        # create reports
        report_classes = ReportGenerator.add_argparser_arguments()
        workspaces = " ".join(self._workspaces)
        for module_name in report_classes.keys():
            if module_name in ["excel", "final"]:
                continue
            else:
                self.execute(subcommand=module_name, arguments="-w {} --csv".format(workspaces))

    def _check_csv_report_columns(self, report, module_name):
        try:
            rows = report.get_csv()
            if len(rows) > 1:
                header_count = len(rows[0])
                for row in rows[1:]:
                    row_count = len(row)
                    if row_count != header_count:
                        self.fail("In report '{}' row count mismatch between "
                                  "header ({}) and content columns ({})".format(module_name,
                                                                                header_count,
                                                                                row_count))
                    self.assertEqual(header_count, row_count)
        except NotImplementedError:
            pass

    def test_csv_check_column_count(self):
        self.init_db(load_cipher_suites=True)
        # create database
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                self._populate_all_tables(session, workspace_str)
        # create reports
        with self._engine.session_scope() as session:
            workspaces = DomainUtils.get_workspaces(session=session)
            for module_name in self._report_classes.keys():
                if module_name != "service":
                    args = self._parser.parse_args([module_name, "--csv"])
                    report = self._generator.create_report_instance(args=args, session=session, workspaces=workspaces)
                    self._check_csv_report_columns(report, module_name)
            # Test service report
            module_name = "service"
            report = self._generator.create_report_instance(args=self._parser.parse_args([module_name, "--csv"]),
                                                            session=session,
                                                            workspaces=workspaces)
            self._check_csv_report_columns(report, module_name)
            report = self._generator.create_report_instance(args=self._parser.parse_args([module_name,
                                                                                          "--csv", "-r", "all"]),
                                                            session=session,
                                                            workspaces=workspaces)
            self._check_csv_report_columns(report, module_name)
            report = self._generator.create_report_instance(args=self._parser.parse_args([module_name,
                                                                                          "--csv",
                                                                                          "-r", "domain"]),
                                                            session=session,
                                                            workspaces=workspaces)
            self._check_csv_report_columns(report, module_name)
