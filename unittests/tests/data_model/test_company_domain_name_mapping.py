#!/usr/bin/python3
"""
this file implements unittests for the data model
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

from database.model import HostName
from database.model import CompanyDomainNameMapping
from unittests.tests.core import BaseDataModelTestCase


class TestCompanyDomainNameMapping(BaseDataModelTestCase):
    """
    Test data model for CompanyDomainNameMapping
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, CompanyDomainNameMapping)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            domain_name = self.create_domain_name(session=session, workspace_str=self._workspaces[0])
            company = self.create_company(session=session, workspace_str=self._workspaces[0])
            self._test_unique_constraint(session, company=company, domain_name=domain_name)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            domain_name = self.create_domain_name(session=session, workspace_str=self._workspaces[0])
            company = self.create_company(session=session, workspace_str=self._workspaces[0])
            self._test_not_null_constraint(session)
            self._test_not_null_constraint(session, domain_name=domain_name)
            self._test_not_null_constraint(session, company=company)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            domain_name = self.create_domain_name(session=session, workspace_str=self._workspaces[0])
            company = self.create_company(session=session, workspace_str=self._workspaces[0])
            self._test_success(session, company=company, domain_name=domain_name, verified=True)
            mapping = session.query(CompanyDomainNameMapping).first()
            self.assertTrue(mapping.verified)

    def test_add_mapping_1(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session=session, workspace_str=self._workspaces[0])
            company = self.create_company(session=session, workspace_str=self._workspaces[0])
            self._domain_utils.add_company_domain_name_mapping(session=session,
                                                               company=company,
                                                               host_name=host_name,
                                                               verified=True)
        with self._engine.session_scope() as session:
            mapping = session.query(CompanyDomainNameMapping).first()
            self.assertTrue(mapping.verified)

    def test_add_mapping_2(self):
        self.init_db()
        with self._engine.session_scope() as session:
            domain_name = self.create_domain_name(session=session, workspace_str=self._workspaces[0])
            company = self.create_company(session=session, workspace_str=self._workspaces[0])
            self._domain_utils.add_company_domain_name_mapping(session=session,
                                                               company=company,
                                                               host_name=HostName(domain_name=domain_name),
                                                               verified=True)
        with self._engine.session_scope() as session:
            mapping = session.query(CompanyDomainNameMapping).first()
            self.assertTrue(mapping.verified)
