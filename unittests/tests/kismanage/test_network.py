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
from database.model import Network
from database.model import ScopeType
from unittests.tests.core import KisCommandEnum
from unittests.tests.core import BaseTestKisCommand


class TestNetwork(BaseTestKisCommand):
    """
    This class implements checks for testing subcommand network
    """

    def __init__(self, test_name: str):
        super().__init__(command=KisCommandEnum.kismanage, test_name=test_name)

    def test_add_delete(self):
        """
        This unittest tests adding and deleting a network.
        """
        source = "unittest"
        scope = ScopeType.exclude
        network = " 192.168.0.0/31 "
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new network
        self.execute(subcommand="network", arguments="-w {} -a \"{}\" --source {} -c --scope {}".format(self._workspace,
                                                                                                        network,
                                                                                                        source,
                                                                                                        scope.name))
        # Test network, host and source creation
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network=network.strip()).one()
            self.assertEqual(scope, result.scope)
            self.assertListEqual([source], [item.name for item in result.sources])
            self.assertEqual(2, len(result.hosts))
        # Delete network
        self.execute(subcommand="network", arguments="-w {} -d \"{}\" --source {} -c --scope {}".format(self._workspace,
                                                                                                        network,
                                                                                                        source,
                                                                                                        scope.name))
        # Test network deletion
        with self._engine.session_scope() as session:
            result = session.query(Network).count()
            self.assertEqual(0, result)

    def test_Add_Delete(self):
        """
        This unittest tests adding and deleting networks via a file.
        """
        source = "unittest"
        scope = ScopeType.exclude
        networks = ["192.168.0.0/31", "192.168.1.0/31"]
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Initialize file
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "networks.txt")
            with open(file_name, "w") as file:
                file.writelines([item + os.linesep for item in networks])
            # Add new networks
            self.execute(subcommand="network",
                         arguments="-w {} -A {} --source {} -c --scope {}".format(self._workspace,
                                                                                  file_name,
                                                                                  source,
                                                                                  scope.name))
            # Test networks, hosts, and source creation
            with self._engine.session_scope() as session:
                for network in networks:
                    result = session.query(Network).filter_by(network=network).one()
                    self.assertEqual(scope, result.scope)
                    self.assertListEqual([source], [item.name for item in result.sources])
                    self.assertEqual(2, len(result.hosts))
            # Delete networks
            self.execute(subcommand="network",
                         arguments="-w {} -D {}".format(self._workspace, file_name, source, scope.name))
            # Test network deletion
            with self._engine.session_scope() as session:
                result = session.query(Network).count()
                self.assertEqual(0, result)

    def test_add_implicit_in_scope(self):
        """
        This unittest tests adding a new in-scope network.
        """
        network = "192.168.0.0/31"
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new network
        self.execute(subcommand="network", arguments="-w {} -a {}".format(self._workspace, network))
        # Test network creation
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network=network).one()
            self.assertEqual(ScopeType.all, result.scope)

    def test_Add_implicit_in_scope(self):
        """
        This unittest tests adding new in-scope networks via a file.
        """
        networks = ["192.168.0.0/31", "192.168.1.0/31"]
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "networks.txt")
            with open(file_name, "w") as file:
                file.writelines([item + os.linesep for item in networks])
            # Add new network
            self.execute(subcommand="network", arguments="-w {} -A {}".format(self._workspace, file_name))
        # Test networks
        with self._engine.session_scope() as session:
            for network in networks:
                result = session.query(Network).filter_by(network=network).one()
                self.assertEqual(ScopeType.all, result.scope)

    def test_add_explicit_in_scope(self):
        """
        This unittest tests adding a new in-scope network.
        """
        scope = ScopeType.all
        network = "192.168.0.0/31"
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new network
        self.execute(subcommand="network", arguments="-w {} -a {} --scope {}".format(self._workspace,
                                                                                     network,
                                                                                     scope.name))
        # Test network creation
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network=network).one()
            self.assertEqual(scope, result.scope)

    def test_Add_explicit_in_scope(self):
        """
        This unittest tests adding new in-scope networks via a file.
        """
        scope = ScopeType.all
        networks = ["192.168.0.0/31", "192.168.1.0/31"]
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "networks.txt")
            with open(file_name, "w") as file:
                file.writelines([item + os.linesep for item in networks])
            # Add new network
            self.execute(subcommand="network", arguments="-w {} -A {} --scope {}".format(self._workspace,
                                                                                         file_name,
                                                                                         scope.name))
        # Test networks
        with self._engine.session_scope() as session:
            for network in networks:
                result = session.query(Network).filter_by(network=network).one()
                self.assertEqual(scope, result.scope)

    def test_add_explicit_out_of_scope(self):
        """
        This unittest tests adding a new in-scope network.
        """
        scope = ScopeType.exclude
        network = "192.168.0.0/31"
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new network
        self.execute(subcommand="network", arguments="-w {} -a {} --scope {}".format(self._workspace,
                                                                                     network,
                                                                                     scope.name))
        # Test network creation
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network=network).one()
            self.assertEqual(scope, result.scope)

    def test_Add_explicit_out_of_scope(self):
        """
        This unittest tests adding new in-scope networks via a file.
        """
        scope = ScopeType.exclude
        networks = ["192.168.0.0/31", "192.168.1.0/31"]
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "networks.txt")
            with open(file_name, "w") as file:
                file.writelines([item + os.linesep for item in networks])
            # Add new network
            self.execute(subcommand="network", arguments="-w {} -A {} --scope {}".format(self._workspace,
                                                                                         file_name,
                                                                                         scope.name))
        # Test networks
        with self._engine.session_scope() as session:
            for network in networks:
                result = session.query(Network).filter_by(network=network).one()
                self.assertEqual(scope, result.scope)
