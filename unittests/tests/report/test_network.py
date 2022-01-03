#!/usr/bin/python3
"""
this file implements unittests for reporting IPv4/IPv6 information.
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
from sqlalchemy.orm.session import Session
from unittests.tests.report.core import BaseReportTestCase


class TestIpv4NetworkReport(BaseReportTestCase):
    """
    Test IPv4 network report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name=test_name)

    def create_data_for_filter_test(self, session: Session) -> None:
        workspace = self._workspaces[0]
        self.create_network(session, workspace_str=workspace, network="192.168.0.0/24", scope=ScopeType.all)
        self.create_network(session,
                            workspace_str=workspace,
                            network="192.168.10.0/24",
                            scope=ScopeType.exclude)
        workspace = self._workspaces[1]
        self.create_network(session,
                            workspace_str=workspace,
                            network="192.168.0.0/24",
                            scope=ScopeType.exclude)
        self.create_network(session, workspace_str=workspace, network="192.168.10.0/24", scope=ScopeType.all)

    def test_filter_in_scope(self):
        """
        Unittests for _Ipv4NetworkReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.10.0/24"),
                              expected_result=False)

    def test_filter_include(self):
        """
        Unittests for _Ipv4NetworkReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--filter", "+192.168.0.0/24"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--filter", "+192.168.0.0/24"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.10.0/24"),
                              expected_result=False)

    def test_filter_exclude(self):
        """
        Unittests for _Ipv4NetworkReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--filter", "192.168.0.0/24"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv", "--filter", "192.168.10.0/24"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=True)

    def test_filter_mixed(self):
        """
        Unittests for _Ipv4NetworkReportGenerator.filter
        :return:
        """
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv",
                                             "--filter", "192.168.0.0/24", "--scope", "within"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv",
                                             "--filter", "+192.168.0.0/24", "--scope", "within"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["network", "-w", workspace, "--csv",
                                             "--filter", "192.168.0.0/24", "--scope", "within"],
                              item=self.query_ipv4network(session=session,
                                                          workspace_str=workspace,
                                                          ipv4_network="192.168.10.0/24"),
                              expected_result=False)
