#!/usr/bin/python3
"""
this file implements unittests for reporting credential information.
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
from database.model import DnsResourceRecordType
from sqlalchemy.orm.session import Session
from unittests.tests.report.core import BaseReportTestCase


class TestCredentialReport(BaseReportTestCase):
    """
    Test credential report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name=test_name)

    def create_data_for_filter_test(self, session: Session) -> None:
        workspace = self._workspaces[0]
        self.create_network(session, workspace_str=workspace, network="192.168.0.0/24", scope=ScopeType.all)
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address="192.168.0.1"))
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address="192.168.0.10"))
        self.create_network(session,
                            workspace_str=workspace,
                            network="192.168.10.0/24",
                            scope=ScopeType.exclude)
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address="192.168.10.1"))
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address="192.168.10.10"))
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address=None,
                                                           host_name_str="www.test1.com",
                                                           scope=ScopeType.all))
        self.create_host_host_name_mapping(session,
                                           workspace_str=workspace,
                                           ipv4_address="192.168.0.1",
                                           host_name_str="www.test1.com",
                                           mapping_type=DnsResourceRecordType.a,
                                           source_str="dnshost")
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address=None,
                                                           host_name_str="ftp.test1.com",
                                                           scope=ScopeType.all))
        self.create_credential(session,
                               workspace_str=workspace,
                               username="testuser",
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address=None,
                                                           host_name_str="www.test2.com",
                                                           scope=ScopeType.exclude))
        self.create_credential(session,
                               workspace_str=workspace,
                               service=self.create_service(session,
                                                           workspace_str=workspace,
                                                           address=None,
                                                           host_name_str="ftp.test2.com",
                                                           scope=ScopeType.exclude))
        self.create_credential(session,
                               workspace_str=workspace,
                               email=self.create_email(session,
                                                       workspace_str=workspace,
                                                       email_address="user1@test1.com"))
        self.create_credential(session,
                               workspace_str=workspace,
                               email=self.create_email(session,
                                                       workspace_str=workspace,
                                                       email_address="user2@test1.com"))
        self.create_credential(session,
                               workspace_str=workspace,
                               email=self.create_email(session,
                                                       workspace_str=workspace,
                                                       email_address="user1@test2.com"))
        self.create_credential(session,
                               workspace_str=workspace,
                               email=self.create_email(session,
                                                       workspace_str=workspace,
                                                       email_address="user2@test2.com"))

    def test_filter_host_in_scope(self):
        """
        Unittests for _PathReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_credential(session=session,
                                                         workspace_str=workspace,
                                                         username="testuser",
                                                         ipv4_address="192.168.0.1"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_credential(session=session,
                                                         workspace_str=workspace,
                                                         username="testuser",
                                                         ipv4_address="192.168.10.1"),
                              expected_result=False)

    def test_filter_hostname_in_scope(self):
        """
        Unittests for _PathReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
        with self._engine.session_scope() as session:
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_credential(session=session,
                                                         workspace_str=workspace,
                                                         username="testuser",
                                                         host_name="www.test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_credential(session=session,
                                                         workspace_str=workspace,
                                                         username="testuser",
                                                         host_name="www.test2.com"),
                              expected_result=False)

    def test_filter_email_in_scope(self):
        """
        Unittests for _PathReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test1.com"),
                              expected_result=True)
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["credential", "-w", workspace, "--csv", "--scope", "within"],
                              item=self.query_email(session=session,
                                                    workspace_str=workspace,
                                                    email_address="user1@test2.com"),
                              expected_result=False)
