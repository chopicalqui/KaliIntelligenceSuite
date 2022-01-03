#!/usr/bin/python3
"""
this file implements unittests for reporting collector information.
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


class TestCollectorReport(BaseReportTestCase):
    """
    Test collector report
    """

    def __init__(self, test_name):
        super().__init__(test_name=test_name)

    def create_ipv4_network_data(self, session: Session) -> None:
        workspace = self._workspaces[0]
        self.create_command(session,
                            workspace_str=workspace,
                            command=["nmap", "-sS", "192.168.0.0/24"],
                            collector_name_str="tcpnmap",
                            ipv4_network_str="192.168.0.0/24",
                            scope=ScopeType.all)
        self.create_command(session,
                            workspace_str=workspace,
                            command=["nmap", "-sU", "192.168.0.0/24"],
                            collector_name_str="udpnmap",
                            ipv4_network_str="192.168.0.0/24",
                            scope=ScopeType.all)
        self.create_command(session,
                            workspace_str=workspace,
                            command=["nmap", "-sS", "192.168.10.0/24"],
                            collector_name_str="tcpnmap",
                            ipv4_network_str="192.168.10.0/24",
                            scope=ScopeType.exclude)
        self.create_command(session,
                            workspace_str=workspace,
                            command=["nmap", "-sU", "192.168.10.0/24"],
                            collector_name_str="udpnmap",
                            ipv4_network_str="192.168.10.0/24",
                            scope=ScopeType.exclude)

    def create_data_for_filter_test(self, session: Session) -> None:
        self.create_ipv4_network_data(session)

    def test_filter_ipv4_network_in_scope(self):
        """
        Unittests for _CollectorReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.0.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.10.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.10.0/24"),
                              expected_result=False)

    def test_filter_ipv4_network_include_collector(self):
        """
        Unittests for _CollectorReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "-I", "tcpnmap"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.0.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "-X", "tcpnmap"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.0.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "-X", "tcpnmap"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sU", "192.168.0.0/24"],
                                                      collector_name="udpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)

    def test_filter_ipv4_network_exclude_collector(self):
        """
        Unittests for _CollectorReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "-X", "tcpnmap"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.0.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "-X", "tcpnmap"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sU", "192.168.0.0/24"],
                                                      collector_name="udpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)

    def test_filter_ipv4_network_include_network(self):
        """
        Unittests for _CollectorReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "--filter", "+192.168.0.0/24"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.0.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv", "--filter", "+192.168.0.0/24"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sS", "192.168.10.0/24"],
                                                      collector_name="tcpnmap",
                                                      ipv4_network="192.168.10.0/24"),
                              expected_result=False)

    def test_filter_ipv4_network_mixed(self):
        """
        Unittests for _CollectorReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv",
                                             "--filter", "+192.168.0.0/24", "-I", "tcpnmap", "--scope", "within"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sU", "192.168.0.0/24"],
                                                      collector_name="udpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=False)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["command", "-w", workspace, "--csv",
                                             "--filter", "+192.168.0.0/24", "-I", "udpnmap", "--scope", "within"],
                              item=self.query_command(session=session,
                                                      workspace_str=workspace,
                                                      command_str=["nmap", "-sU", "192.168.0.0/24"],
                                                      collector_name="udpnmap",
                                                      ipv4_network="192.168.0.0/24"),
                              expected_result=True)
