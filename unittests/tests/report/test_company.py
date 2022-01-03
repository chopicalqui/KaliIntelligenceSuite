#!/usr/bin/python3
"""
this file implements unittests for reporting company information
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


class TestCompanyReport(BaseReportTestCase):
    """
    Test email report
    """

    def __init__(self, test_name: str):
        super().__init__(test_name=test_name)

    def create_data_for_filter_test(self, session: Session) -> None:
        workspace_str = self._workspaces[0]
        workspace = self._domain_utils.add_workspace(session, workspace_str)
        excluded_network = self._ip_utils.add_network(session=session,
                                                      workspace=workspace,
                                                      network="192.168.1.0/24",
                                                      scope=ScopeType.exclude)
        included_network = self._ip_utils.add_network(session=session,
                                                      workspace=workspace,
                                                      network="192.168.10.0/24",
                                                      scope=ScopeType.all)
        excluded_domain = self._domain_utils.add_domain_name(session=session,
                                                             workspace=workspace,
                                                             item="www.excluded.com",
                                                             scope=ScopeType.exclude)
        included_domain = self._domain_utils.add_domain_name(session=session,
                                                             workspace=workspace,
                                                             item="www.excluded.com",
                                                             scope=ScopeType.all)
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Included Network LLC",
                                       in_scope=True,
                                       network=included_network)
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Excluded Network LLC",
                                       network=excluded_network)
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Included Domain LLC",
                                       in_scope=True,
                                       domain_name=included_domain)
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Excluded Domain LLC",
                                       domain_name=excluded_domain)
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Included All LLC",
                                       in_scope=True,
                                       domain_name=included_domain,
                                       network=included_network, )
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Excluded Domain LLC",
                                       domain_name=excluded_domain,
                                       network=excluded_network)

    def test_filter_within_scope_I(self):
        """
        Unittests for _CompanyReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["company",
                                             "-w", workspace,
                                             "--csv",
                                             "--scope", "within",
                                             "--filter", '+included all llc'],
                              item=self.query_company(session=session,
                                                      workspace_str=workspace,
                                                      name="included all llc"),
                              expected_result=True)

    def test_filter_within_scope_II(self):
        """
        Unittests for _CompanyReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["company",
                                             "-w", workspace,
                                             "--csv",
                                             "--scope", "within",
                                             "--filter", '+exclude network llc'],
                              item=self.query_company(session=session,
                                                      workspace_str=workspace,
                                                      name="excluded network llc"),
                              expected_result=False)

    def test_filter_outside_scope(self):
        """
        Unittests for _CompanyReportGenerator.filter
        :return:
        """
        self.init_db()
        with self._engine.session_scope() as session:
            self.create_data_for_filter_test(session)
            workspace = self._workspaces[0]
            self._test_filter(session=session,
                              workspace_str=workspace,
                              argument_list=["company",
                                             "-w", workspace,
                                             "--csv",
                                             "--scope", "outside",
                                             "--filter", '+included all llc'],
                              item=self.query_company(session=session,
                                                      workspace_str=workspace,
                                                      name="included all llc"),
                              expected_result=False)
