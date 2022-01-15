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

from database.model import Host
from database.model import Network
from database.model import ScopeType
from database.model import Workspace
from unittests.tests.core import BaseKisTestCase
from unittests.tests.core import BaseDataModelTestCase


class TestHost(BaseDataModelTestCase):
    """
    Test data model for host
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, model=Host)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_unique_constraint(session, address="192.168.1.1", workspace=workspace)

    def test_not_null_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_not_null_constraint(session, address="192.168.1.1")
            self._test_not_null_constraint(session, workspace=workspace)

    def test_success(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self.create_workspace(session)
            self._test_success(session, workspace=workspace, address="192.168.1.1")


class HostScopingTestCases(BaseKisTestCase):
    """
    This class implements functionalities for testing the host scope
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def _check_data(self, workspace_str: str, ipv4_address: str, ipv4_network: str, in_scope: bool):
        with self._engine.session_scope() as session:
            result = session.query(Host).join(Workspace) \
                .filter(Host.address == ipv4_address, Workspace.name == workspace_str).one()
            self.assertEqual(ipv4_network, result.ipv4_network.network)
            self.assertEqual(in_scope, result.in_scope)

    def test_network_scope(self):
        self.init_db()
        # set up database
        i = 0
        with self._engine.session_scope() as session:
            for workspace_str in self._workspaces:
                scope = ScopeType.all if (i % 2) == 0 else ScopeType.exclude
                i = i + 1
                workspace = self._domain_utils.add_workspace(session, workspace_str)
                self._ip_utils.add_host(session=session,
                                        workspace=workspace,
                                        address="10.10.0.1",
                                        in_scope=scope == ScopeType.exclude)
                self._ip_utils.add_network(session=session,
                                           workspace=workspace,
                                           network="10.10.0.0/16",
                                           scope=scope)
        # check database setup
        with self._engine.session_scope() as session:
            session.query(Host).join(Network).filter(Host._in_scope,
                                                     Network.scope == ScopeType.all).one()
            session.query(Host).join(Network).filter(Host._in_scope == False,
                                                     Network.scope == ScopeType.exclude).one()
        # lets add a larger network, which is out of scope (this can happen with whois)
        # in this case all sub-networks which are in-scope remain in scope
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="10.0.0.0/8")
        # check database setup
        with self._engine.session_scope() as session:
            session.query(Host).join(Network).filter(Host._in_scope,
                                                     Network.network == "10.10.0.0/16",
                                                     Network.scope == ScopeType.all).one()
        # lets add a smaller network, which is out of scope but the larger network is in scope
        # in this case, the smaller out of scope network is automatically set in scope by DB trigger and the host must
        # be re-assigned to the smallest network in the database
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="10.10.0.0/24")
        # check database setup
        with self._engine.session_scope() as session:
            session.query(Host).join(Network).filter(Host._in_scope,
                                                     Network.network == "10.10.0.0/24",
                                                     Network.scope == ScopeType.all).one()

    def test_host_scope_strict(self):
        """
        check trigger: if network's scope is set to strict, then host scope is set to false
        """
        ipv4_address = "192.168.1.1"
        ipv4_network = "192.168.1.0/24"
        # set up database
        self.init_db()
        for workspace in self._workspaces:
            with self._engine.session_scope() as session:
                self.create_host(session=session,
                                 workspace_str=workspace,
                                 address=ipv4_address,
                                 in_scope=True)
            with self._engine.session_scope() as session:
                self.create_network(session=session,
                                    workspace_str=workspace,
                                    network=ipv4_network,
                                    scope=ScopeType.strict)
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=False)
        # update host
        with self._engine.session_scope() as session:
            result = session.query(Host).join(Workspace) \
                .filter(Host.address == ipv4_address, Workspace.name == self._workspaces[0]).one()
            result.in_scope = True
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=workspace == self._workspaces[0])
        # update network to scope all
        with self._engine.session_scope() as session:
            for workspace in self._workspaces:
                result = session.query(Network) \
                    .join(Workspace) \
                    .filter(Network.network == ipv4_network, Workspace.name == workspace).one()
                result.scope = ScopeType.all
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=True)
        # update network to scope exclude
        with self._engine.session_scope() as session:
            for workspace in self._workspaces:
                result = session.query(Network) \
                    .join(Workspace) \
                    .filter(Network.network == ipv4_network, Workspace.name == workspace).one()
                result.scope = ScopeType.exclude
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=False)

    def test_host_scope_all(self):
        """
        check trigger: if network's scope is set to all, then host scope is set to true
        """
        # set up database
        self.init_db()
        ipv4_address = "192.168.1.1"
        ipv4_network = "192.168.1.0/24"
        for workspace in self._workspaces:
            with self._engine.session_scope() as session:
                self.create_host(session=session,
                                 workspace_str=workspace,
                                 address=ipv4_address,
                                 in_scope=False)
            with self._engine.session_scope() as session:
                self.create_network(session=session,
                                    workspace_str=workspace,
                                    network=ipv4_network,
                                    scope=ScopeType.all)
            with self._engine.session_scope() as session:
                self.create_host(session=session,
                                 workspace_str=workspace,
                                 address="192.168.1.2",
                                 in_scope=False)
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=True)
            self._check_data(workspace_str=workspace,
                             ipv4_address="192.168.1.2",
                             ipv4_network=ipv4_network,
                             in_scope=True)
        # update host
        with self._engine.session_scope() as session:
            result = session.query(Host).join(Workspace) \
                .filter(Host.address == ipv4_address, Workspace.name == self._workspaces[0]).one()
            result.in_scope = False
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=True)
        # update network to scope strict
        with self._engine.session_scope() as session:
            for workspace in self._workspaces:
                result = session.query(Network) \
                    .join(Workspace) \
                    .filter(Network.network == ipv4_network, Workspace.name == workspace).one()
                result.scope = ScopeType.strict
        # check database
        for workspace in self._workspaces:
            self._check_data(workspace_str=workspace,
                             ipv4_address=ipv4_address,
                             ipv4_network=ipv4_network,
                             in_scope=True)

    def test_network_assignment(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_host(session=session,
                                    workspace=workspace,
                                    address="10.10.0.1")
            network_id = self._ip_utils.add_network(session=session,
                                                    workspace=workspace,
                                                    network="10.10.0.1",
                                                    scope=ScopeType.all).id
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="10.10.0.1").one()
            self.assertIsNotNone(host.ipv4_network_id)
            host_network_id = host.ipv4_network_id
            self.assertEquals(network_id, host_network_id)
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="10.10.0.0/29",
                                       scope=ScopeType.all)
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="10.10.0.1").one()
            self.assertIsNotNone(host.ipv4_network_id)
            host_network_id = host.ipv4_network_id
            self.assertEquals(network_id, host_network_id)

    def test_network_assignment2(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_host(session=session,
                                    workspace=workspace,
                                    address="10.10.0.1")
            network_id = self._ip_utils.add_network(session=session,
                                                    workspace=workspace,
                                                    network="10.10.0.1",
                                                    scope=ScopeType.all).id
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="10.10.0.0/29",
                                       scope=ScopeType.all)
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="10.10.0.1").one()
            self.assertIsNotNone(host.ipv4_network_id)
            host_network_id = host.ipv4_network_id
            self.assertEquals(network_id, host_network_id)

    def test_network_assignment3(self):
        self.init_db()
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            self._ip_utils.add_host(session=session,
                                    workspace=workspace,
                                    address="10.10.0.1")
            network_id = self._ip_utils.add_network(session=session,
                                                    workspace=workspace,
                                                    network="10.10.0.0/29",
                                                    scope=ScopeType.all).id
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="10.10.0.1").one()
            self.assertIsNotNone(host.ipv4_network_id)
            host_network_id = host.ipv4_network_id
            self.assertEquals(network_id, host_network_id)
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.add_workspace(session, self._workspaces[0])
            network_id = self._ip_utils.add_network(session=session,
                                                    workspace=workspace,
                                                    network="10.10.0.1",
                                                    scope=ScopeType.all).id
        with self._engine.session_scope() as session:
            host = session.query(Host).filter_by(address="10.10.0.1").one()
            self.assertIsNotNone(host.ipv4_network_id)
            host_network_id = host.ipv4_network_id
            self.assertEquals(network_id, host_network_id)