#!/usr/bin/python3
"""
this file implements unittests for the kismanage script
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
from database.model import ReportScopeType
from database.model import Company
from database.model import CompanyNetworkMapping
from database.model import CompanyDomainNameMapping
from unittests.tests.core import KisCommandEnum
from unittests.tests.core import BaseTestKisCommand


class TestCompany(BaseTestKisCommand):
    """
    This class implements checks for testing subcommand command
    """

    def __init__(self, test_name: str):
        super().__init__(command=KisCommandEnum.kismanage, test_name=test_name)

    def test_add_delete(self):
        """
        This unittest tests adding and deleting a company
        """
        source = " unittest "
        scope = ReportScopeType.within
        item = " Test LLC "
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new item to database
        self.execute(subcommand="company",
                     arguments="-w {ws} --scope {scope} -a \"{item}\" --source \"{source}\"".format(ws=self._workspace,
                                                                                                    scope=scope.name,
                                                                                                    item=item,
                                                                                                    source=source))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Company).filter_by(name=item.strip().lower()).one()
            self.assertTrue(result.in_scope) if scope == ReportScopeType.within else self.assertFalse(result.in_scope)
            self.assertListEqual([source.strip()], [item.name for item in result.sources])
        # Delete item from database
        self.execute(subcommand="company",
                     arguments="-w {ws} -d \"{item}\"".format(ws=self._workspace, item=item))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Company).count()
            self.assertEqual(0, result)

    def test_Add_Delete(self):
        """
        This unittest tests adding and deleting a company from file
        """
        source = "unittest"
        scope = ReportScopeType.outside
        items = ["Test1 LLC", "Test2 LLC"]
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Initialize file
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "companies.txt")
            with open(file_name, "w") as file:
                file.writelines([item + os.linesep for item in items])
            # Add new item to database
            self.execute(subcommand="company",
                         arguments="-w {ws} --scope {scope} -A \"{item}\" --source \"{source}\"".format(ws=self._workspace,
                                                                                                        scope=scope.name,
                                                                                                        item=file_name,
                                                                                                        source=source))
            # Check database
            with self._engine.session_scope() as session:
                for item in items:
                    result = session.query(Company).filter_by(name=item.lower()).one()
                    self.assertTrue(result.in_scope) if scope == ReportScopeType.within else self.assertFalse(result.in_scope)
                    self.assertEqual(item.lower(), result.name)
                    self.assertListEqual([source], [item.name for item in result.sources])
            # Add all in scope
            self.execute(subcommand="company",
                         arguments="-w {ws} --Scope {scope} \"{item}\"".format(ws=self._workspace,
                                                                               scope=ReportScopeType.within.name,
                                                                               item=file_name))
            # Check database
            with self._engine.session_scope() as session:
                for item in items:
                    result = session.query(Company).filter_by(name=item.lower()).one()
                    self.assertTrue(result.in_scope)
                    self.assertEqual(item.lower(), result.name)
                    self.assertListEqual([source], [item.name for item in result.sources])
            # Delete item from database
            self.execute(subcommand="company", arguments="-w {ws} -D \"{item}\"".format(ws=self._workspace,
                                                                                        item=file_name))
            # Check database
            with self._engine.session_scope() as session:
                result = session.query(Company).count()
                self.assertEqual(0, result)

    def test_add_network(self):
        item = "Test LLC "
        source = " unittest "
        network = "10.10.10.0/24 "
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {ws}".format(ws=self._workspace))
        self.execute(subcommand="network",
                     arguments="-w {ws} -a \"{nw}\"".format(ws=self._workspace, nw=network))
        # Add new item to database
        self.execute(subcommand="company",
                     arguments="-w {ws} --network \"{nw}\" -a \"{item}\" --source {src}".format(ws=self._workspace,
                                                                                                nw=network,
                                                                                                item=item,
                                                                                                src=source))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(CompanyNetworkMapping).one()
            self.assertEqual(network.strip().lower(), result.network.network)
            self.assertEqual(item.strip().lower(), result.company.name)
            self.assertFalse(result.verified)
            self.assertListEqual([source.strip()], [item.name for item in result.sources])
        # Set verified to true
        self.execute(subcommand="company",
                     arguments="-w {ws} --network \"{nw}\" -a \"{item}\" --verified".format(ws=self._workspace,
                                                                                            nw=network,
                                                                                            item=item))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(CompanyNetworkMapping).one()
            self.assertEqual(network.strip().lower(), result.network.network)
            self.assertEqual(item.strip().lower(), result.company.name)
            self.assertTrue(result.verified)
            self.assertListEqual([source.strip(), "user"], [item.name for item in result.sources])

    def test_add_domain(self):
        item = " Test LLC "
        source = "unittest"
        domain = " UNITTEST.local "
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {ws}".format(ws=self._workspace))
        self.execute(subcommand="domain",
                     arguments="-w {ws} -a \"{domain}\"".format(ws=self._workspace, domain=domain))
        # Add new item to database
        self.execute(subcommand="company",
                     arguments="-w {ws} --domain \"{domain}\" -a \"{item}\" --source \"{src}\"".format(ws=self._workspace,
                                                                                                       domain=domain,
                                                                                                       item=item,
                                                                                                       src=source))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(CompanyDomainNameMapping).one()
            self.assertEqual(domain.lower().strip(), result.domain_name.name)
            self.assertEqual(item.strip().lower(), result.company.name)
            self.assertFalse(result.verified)
            self.assertListEqual([source.strip()], [item.name for item in result.sources])
        # Set verified to true
        self.execute(subcommand="company",
                     arguments="-w {ws} --domain \"{domain}\" -a \"{item}\" --verified".format(ws=self._workspace,
                                                                                               domain=domain,
                                                                                               item=item,
                                                                                               src=source))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(CompanyDomainNameMapping).one()
            self.assertEqual(domain.lower().strip(), result.domain_name.name)
            self.assertEqual(item.strip().lower(), result.company.name)
            self.assertTrue(result.verified)
            self.assertListEqual([source.strip(), "user"], [item.name for item in result.sources])
