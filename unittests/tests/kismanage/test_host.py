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
from database.model import Host
from database.model import ScopeType
from unittests.tests.core import KisCommandEnum
from unittests.tests.core import BaseTestKisCommand


class TestHost(BaseTestKisCommand):
    """
    This class implements checks for testing subcommand host
    """

    def __init__(self, test_name: str):
        super().__init__(command=KisCommandEnum.kismanage, test_name=test_name)

    def test_add_delete(self):
        """
        This unittest tests adding a new network
        """
        source = "unittest"
        scope = ReportScopeType.within
        address = " 192.168.1.1 "
        network = "192.168.1.0/24 "
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new network and host
        self.execute(subcommand="network", arguments="-w {} --scope {} -a \"{}\"".format(self._workspace,
                                                                                         ScopeType.strict.name,
                                                                                         network))
        self.execute(subcommand="host", arguments="-w {} -a {} --source {} --scope \"{}\"".format(self._workspace,
                                                                                                  address,
                                                                                                  source,
                                                                                                  scope.name))
        # Test network, host and source creation
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address=address.strip().lower()).one()
            self.assertEqual(ScopeType.strict, result.ipv4_network.scope)
            self.assertTrue(result.in_scope)
            self.assertListEqual([source], [item.name for item in result.sources])
        # Delete network
        self.execute(subcommand="host", arguments="-w {} -d {} --source {} --scope {}".format(self._workspace,
                                                                                              address,
                                                                                              source,
                                                                                              scope.name))
        # Test network deletion
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address=address.strip().lower()).one_or_none()
            self.assertIsNone(result)

    def test_Add_Delete(self):
        """
        This unittest tests the initialization of a workspace
        """
        source = "unittest"
        scope = ReportScopeType.outside
        network = "192.168.1.0/24"
        addresses = ["192.168.1.1", "192.168.1.2"]
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Initialize file
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "hosts.txt")
            with open(file_name, "w") as file:
                file.writelines([item + os.linesep for item in addresses])
            # Add new network and host
            self.execute(subcommand="network", arguments="-w {} -a {} --source {} --scope {}".format(self._workspace,
                                                                                                     network,
                                                                                                     source,
                                                                                                     ScopeType.strict.name))
            self.execute(subcommand="host", arguments="-w {} -A {} --source {} --scope {}".format(self._workspace,
                                                                                                  file_name,
                                                                                                  source,
                                                                                                  scope.name))
            # Test network, host and source creation
            with self._engine.session_scope() as session:
                for address in addresses:
                    result = session.query(Host).filter_by(address=address).one()
                    self.assertEqual(ScopeType.strict, result.ipv4_network.scope)
                    self.assertFalse(result.in_scope)
                    self.assertListEqual([source], [item.name for item in result.sources])
            # Delete networks
            self.execute(subcommand="host", arguments="-w {} -D {} --source {} --scope {}".format(self._workspace,
                                                                                                  file_name,
                                                                                                  source,
                                                                                                  scope.name))
            # Test network deletion
            with self._engine.session_scope() as session:
                result = session.query(Host).count()
                self.assertEqual(0, result)

    def test_set_scope(self):
        """
        This unittest tests the initialization of a workspace
        """
        scope = ReportScopeType.outside
        network = "192.168.1.0/24"
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {ws}".format(ws=self._workspace))
        self.execute(subcommand="network", arguments="-w {ws} -s strict -a {nw}".format(ws=self._workspace,
                                                                                        nw=network))
        # Add new item to database
        self.execute(subcommand="host", arguments="-w {ws} -a 192.168.1.1".format(ws=self._workspace))
        self.execute(subcommand="host", arguments="-w {ws} -a 192.168.1.2 -s outside".format(ws=self._workspace))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertTrue(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.2").one()
            self.assertFalse(result.in_scope)
        # Update scopes
        self.execute(subcommand="host", arguments="-w {ws} -a 192.168.1.1 -s outside".format(ws=self._workspace))
        self.execute(subcommand="host", arguments="-w {ws} 192.168.1.2 -s within".format(ws=self._workspace))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address="192.168.1.1").one()
            self.assertFalse(result.in_scope)
            result = session.query(Host).filter_by(address="192.168.1.2").one()
            self.assertTrue(result.in_scope)