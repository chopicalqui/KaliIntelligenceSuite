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

from database.model import Command
from database.model import Workspace
from database.model import ScopeType
from database.model import CollectorType
from database.model import CommandStatus
from unittests.tests.core import BaseKisTestCase
from unittests.tests.core import BaseDataModelTestCase


class TestCommand(BaseDataModelTestCase):
    """
    Test data model for command
    """

    # todo: update for new collector
    def __init__(self, test_name: str):
        super().__init__(test_name, model=Command)

    def _test_check_constraint(self,
                               session,
                               ex_message: str = "this case has not been implemented",
                               **kwargs):
        try:
            result = self._model(**kwargs)
            session.add(result)
            session.commit()
        except Exception as ex:
            self.assertIn(ex_message, str(ex))
            session.rollback()
            return
        if ex_message:
            self.assertIsNone(result)

    def test_unique_constraint(self):
        self.init_db()
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            service_host = self.create_service(session, workspace_str=self._workspaces[0])
            service_host_name = self.create_service(session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name_str="www.test.com")
            host = self.create_host(session, workspace_str=self._workspaces[0])
            ipv4_network = self.create_network(session, workspace_str=self._workspaces[0])
            collector_name = self.create_collector_name(session)
            self._test_unique_constraint(session,
                                         os_command=["sleep", "10"],
                                         collector_name=collector_name,
                                         service=service_host)
            self._test_unique_constraint(session,
                                         os_command=["sleep", "10"],
                                         collector_name=collector_name,
                                         service=service_host_name)
            self._test_unique_constraint(session,
                                         os_command=["sleep", "10"],
                                         collector_name=collector_name,
                                         host=host)
            self._test_unique_constraint(session,
                                         os_command=["sleep", "10"],
                                         collector_name=collector_name,
                                         host_name=host_name)
            self._test_unique_constraint(session,
                                         os_command=["sleep", "10"],
                                         collector_name=collector_name,
                                         ipv4_network=ipv4_network)

    def test_not_null_constraint(self):
        self.init_db()
        # todo: update for new collector
        with self._engine.session_scope() as session:
            collector_name = self.create_collector_name(session)
            service = self.create_service(session)
            self._test_not_null_constraint(session, os_command=["sleep", "10"], collector_name=None, service=service)
            self._test_not_null_constraint(session, os_command=None, collector_name=collector_name, service=service)

    def test_check_constraint(self):
        self.init_db()
        # todo: update for new collector
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0], host_name="www.unittest.com")
            service_host = self.create_service(session, address="10.10.10.10", workspace_str=self._workspaces[0])
            service_host_name = self.create_service(session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name_str="www.test.com")
            host = self.create_host(session, address="10.10.10.11", workspace_str=self._workspaces[0])
            ipv4_network = self.create_network(session, workspace_str=self._workspaces[0])
            collector_name = self.create_collector_name(session)
            # This checks will all result in the database error "this case has not been implemented" raised by the
            # following database trigger: pre_command_changes
            self._test_check_constraint(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        workspace_id=host.workspace_id)
            self._test_check_constraint(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        service=service_host,
                                        ipv4_network=ipv4_network,
                                        ex_message=None)
            self._test_check_constraint(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        service=service_host_name,
                                        ipv4_network=ipv4_network,
                                        ex_message=None)
            self._test_check_constraint(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        host=host,
                                        ipv4_network=ipv4_network,
                                        ex_message=None)
            self._test_check_constraint(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        host_name=host_name,
                                        ipv4_network=ipv4_network,
                                        ex_message=None)

    def test_success_service_host(self):
        self.init_db()
        # todo: update for new collector
        with self._engine.session_scope() as session:
            service_host = self.create_service(session, workspace_str=self._workspaces[0])
            collector_name = self.create_collector_name(session)
            result = self._test_success(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        service=service_host)
            self.assertIsNotNone(service_host.host_id)
            self.assertIsNotNone(service_host.host)
            self.assertEqual(service_host.host_id, result.host_id)
            self.assertEqual(service_host.id, result.id)
            self.assertEqual(service_host.workspace.id, result.workspace.id)

    def test_success_service_host_name(self):
        self.init_db()
        # todo: update for new collector
        with self._engine.session_scope() as session:
            service_host_name = self.create_service(session,
                                                    workspace_str=self._workspaces[0],
                                                    host_name_str="www.test.com")
            collector_name = self.create_collector_name(session)
            result = self._test_success(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        service=service_host_name)
            self.assertIsNotNone(service_host_name.host_name_id)
            self.assertIsNotNone(service_host_name.host_name)
            self.assertEqual(service_host_name.host_name_id, result.host_name.id)
            self.assertEqual(service_host_name.id, result.id)
            self.assertEqual(service_host_name.host_name.domain_name.workspace.id, result.workspace_id)

    def test_success_host(self):
        self.init_db()
        # todo: update for new collector
        with self._engine.session_scope() as session:
            host = self.create_host(session, workspace_str=self._workspaces[0])
            collector_name = self.create_collector_name(session)
            result = self._test_success(session,
                                        os_command=["sleep", "11"],
                                        collector_name=collector_name,
                                        host=host)
            self.assertEqual(host.workspace.id, result.workspace_id)

    def test_success_host_name(self):
        self.init_db()
        # todo: update for new collector
        with self._engine.session_scope() as session:
            host_name = self.create_hostname(session, workspace_str=self._workspaces[0])
            collector_name = self.create_collector_name(session)
            result = self._test_success(session,
                                        os_command=["sleep", "11"],
                                        collector_name=collector_name,
                                        host_name=host_name)
            self.assertEqual(host_name.domain_name.workspace.id, result.workspace_id)

    def test_success_network(self):
        self.init_db()
        # todo: update for new collector
        with self._engine.session_scope() as session:
            network = self.create_network(session, workspace_str=self._workspaces[0])
            collector_name = self.create_collector_name(session)
            result = self._test_success(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        ipv4_network=network)
            self.assertEqual(network.workspace.id, result.workspace_id)

    def test_success_email(self):
        self.init_db()
        # todo: update for new collector
        with self._engine.session_scope() as session:
            collector_name = self.create_collector_name(session)
            email = self.create_email(session=session, workspace_str=self._workspaces[0], email_address="test@test.com")
            result = self._test_success(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        email=email)
            self.assertEqual(email.host_name.domain_name.workspace.id, result.workspace_id)

    def test_success_company(self):
        self.init_db()
        # todo: update for new collector
        with self._engine.session_scope() as session:
            collector_name = self.create_collector_name(session)
            company = self.create_company(session=session, workspace_str=self._workspaces[0],
                                          name_str="test llc")
            result = self._test_success(session,
                                        os_command=["sleep", "10"],
                                        collector_name=collector_name,
                                        company=company)
            self.assertEqual(company.workspace.id, result.workspace_id)


class TestIncompleteCommandDeletion(BaseKisTestCase):
    """
    Test Engine.delete_incomplete_commands
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)

    def test_command_deletion(self):
        self.init_db()
        # Setup the database
        with self._engine.session_scope() as session:
            for name in self._workspaces:
                command = self.create_command(session=session,
                                              workspace_str=name,
                                              command=["nikto", "https://192.168.1.1"],
                                              collector_name_str="nikto",
                                              collector_name_type=CollectorType.host_service,
                                              ipv4_address="192.168.1.1",
                                              service_port=80,
                                              scope=ScopeType.all)
                command.status = CommandStatus.completed
                command = self.create_command(session=session,
                                              workspace_str=name,
                                              command=["nikto", "https://192.168.1.3"],
                                              collector_name_str="nikto",
                                              collector_name_type=CollectorType.host_service,
                                              ipv4_address="192.168.1.2",
                                              service_port=80,
                                              scope=ScopeType.all)
                command.status = CommandStatus.collecting
                command = self.create_command(session=session,
                                              workspace_str=name,
                                              command=["nikto", "https://192.168.1.4"],
                                              collector_name_str="nikto",
                                              collector_name_type=CollectorType.host_service,
                                              ipv4_address="192.168.1.4",
                                              service_port=80,
                                              scope=ScopeType.all)
                command.status = CommandStatus.pending
                command = self.create_command(session=session,
                                              workspace_str=name,
                                              command=["nikto", "https://www.test.local"],
                                              collector_name_str="nikto",
                                              collector_name_type=CollectorType.host_service,
                                              host_name_str="www.test.local",
                                              service_port=80,
                                              scope=ScopeType.all)
                command.status = CommandStatus.pending
                command = self.create_command(session=session,
                                              workspace_str=name,
                                              command=["nikto", "https://www1.test.local"],
                                              collector_name_str="nikto",
                                              collector_name_type=CollectorType.host_service,
                                              host_name_str="www1.test.local",
                                              service_port=80,
                                              scope=ScopeType.all)
                command.status = CommandStatus.pending
        # Delete incomplete commands
        self._engine.delete_incomplete_commands(self._workspaces[0])
        # Check database
        with self._engine.session_scope() as session:
            workspace = session.query(Workspace.id).filter_by(name=self._workspaces[0]).one()
            command = session.query(Command).filter_by(workspace_id=workspace.id,
                                                       status=CommandStatus.completed).one()
            self.assertListEqual(["nikto", "https://192.168.1.1"], command.os_command)
            workspace = session.query(Workspace.id).filter_by(name=self._workspaces[1]).one()
            commands = session.query(Command).filter_by(workspace_id=workspace.id).count()
            self.assertEqual(5, commands)
