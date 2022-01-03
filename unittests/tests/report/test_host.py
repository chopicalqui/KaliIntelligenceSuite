#!/usr/bin/python3
"""
this file implements unittests for reporting host information
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

from database.model import ScopeType
from unittests.tests.report.core import BaseReportTestCase


class TestHostReport(BaseReportTestCase):
    """
    Test host report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name=test_name)

    def create_data_for_filter_test(self) -> None:
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_network(session,
                                workspace_str=workspace,
                                network="192.168.0.0/24",
                                scope=ScopeType.all)
            self.create_network(session,
                                workspace_str=workspace,
                                network="192.168.10.0/24",
                                scope=ScopeType.exclude)
            self.create_host(session, workspace_str=workspace, address="192.168.0.1")
            self.create_host(session, workspace_str=workspace, address="192.168.0.2")
            self.create_host(session, workspace_str=workspace, address="192.168.10.1")
            self.create_host(session, workspace_str=workspace, address="192.168.10.2")
            workspace = self._workspaces[1]
            self.create_network(session,
                                workspace_str=workspace,
                                network="192.168.0.0/24",
                                scope=ScopeType.exclude)
            self.create_network(session,
                                workspace_str=workspace,
                                network="192.168.10.0/24",
                                scope=ScopeType.all)
            self.create_host(session, workspace_str=workspace, address="192.168.0.1")
            self.create_host(session, workspace_str=workspace, address="192.168.0.2")
            self.create_host(session, workspace_str=workspace, address="192.168.10.1")
            self.create_host(session, workspace_str=workspace, address="192.168.10.2")

    def test_filter_in_scope(self):
        """
        Unittests for _HostReportGenerator.filter
        :return:
        """
        self.init_db()
        self.create_data_for_filter_test()
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_host(session=session,
                                                   workspace_str=workspace,
                                                   ipv4_address="192.168.0.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_host(session=session,
                                                   workspace_str=workspace,
                                                   ipv4_address="192.168.10.1"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.100.1",
                                                    in_scope=False),
                              expected_result=False)

    def test_filter_include(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        self.create_data_for_filter_test()
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "+192.168.0.1"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "+192.168.0.0/24"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "+192.168.1.1"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "+192.168.1.0/24"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=False)

    def test_filter_exclude(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        self.create_data_for_filter_test()
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.0.1"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.0.0/24"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.0.1"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.0.1"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.1.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.0.0/24"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.1.1"),
                              expected_result=True)

    def test_filter_mixed(self):
        """
        Unittests for _HostNameReportGenerator.filter
        :return:
        """
        self.init_db()
        self.create_data_for_filter_test()
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "+192.168.0.1",
                                             "--scope", "within"],
                              item=self.query_host(session=session,
                                                    workspace_str=workspace,
                                                    ipv4_address="192.168.0.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.0.1",
                                             "--scope", "within"],
                              item=self.create_host(session=session,
                                                    workspace_str=workspace,
                                                    address="192.168.1.1",
                                                    in_scope=False),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["host", "-w", workspace, "--csv", "--filter", "192.168.1.0/24",
                                             "--scope", "within"],
                              item=self.query_host(session=session,
                                                   workspace_str=workspace,
                                                   ipv4_address="192.168.0.1"),
                              expected_result=True)
