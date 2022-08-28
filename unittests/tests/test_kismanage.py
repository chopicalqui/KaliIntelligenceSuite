#!/usr/bin/python3
"""
this file implements unittests for the kismanage script
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2018 Lukas Reiter

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
import argparse
from database.model import ReportScopeType
from database.model import Workspace
from database.model import Network
from database.model import Host
from database.model import PathType
from database.model import DomainName
from database.model import HostName
from database.model import Email
from database.model import Path
from database.model import Company
from database.model import Service
from database.model import ScopeType
from database.model import ProtocolType
from database.model import ServiceState
from database.model import CredentialType
from database.utils import Setup
from database.utils import CloneType
from collectors.core import IpUtils
from database.config import BaseConfig
from kismanage import ManageDatabase
from unittests.tests.core import BaseKisTestCase
from unittests.tests.core import KisCommandEnum
from unittests.tests.core import BaseTestKisCommand
from typing import List


class TestSubcommandDatabase(BaseTestKisCommand):
    """
    This class implements checks for testing subcommand database
    """

    def __init__(self, test_name: str):
        super().__init__(command=KisCommandEnum.kismanage, test_name=test_name)

    def test_backup_restore(self):
        """
        This unittest tests creating and restoring a backup.
        """
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Backup and restore database
        if not BaseConfig.is_docker():
            with tempfile.TemporaryDirectory() as temp_dir:
                file_name = os.path.join(temp_dir, "backup.sql")
                self.execute(subcommand="database", arguments="--backup {}".format(file_name))
                self.execute(subcommand="database", arguments="--restore {}".format(file_name))
            # Test restore
            with self._engine.session_scope() as session:
                result = session.query(Workspace).filter_by(name=self._workspace).one()
                self.assertEqual(self._workspace, result.name)

    def test_setup_dbg(self):
        """
        This unittest tests the --setup-dbg argument.
        """
        if not BaseConfig.is_docker():
            self.execute(subcommand="database", arguments="--setup-dbg")

    def test_test(self):
        """
        This unittest tests the --test argument.
        """
        Setup(engine=self._engine,
              kis_scripts=ManageDatabase.KIS_SCRIPTS,
              kali_packages=ManageDatabase.KALI_PACKAGES,
              git_repositories=ManageDatabase.GIT_REPOSITORIES,
              debug=True).test(throw_exception=True)

    def test_version(self):
        """
        This unittest tests the --version argument.
        """
        self.execute(subcommand="database", arguments="--version")


class TestSubcommandWorkspace(BaseTestKisCommand):
    """
    This class implements checks for testing subcommand workspace
    """

    def __init__(self, test_name: str):
        super().__init__(command=KisCommandEnum.kismanage, test_name=test_name)

    def test_add_delete(self):
        """
        This unittest tests the creation and deletion of a workspace
        """
        # Setup database
        self.execute(subcommand="database", arguments="--drop --init")
        # Test workspace creation
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        with self._engine.session_scope() as session:
            result = session.query(Workspace).filter_by(name=self._workspace).one()
            self.assertEqual(self._workspace, result.name)
        # Test workspace deletion
        self.execute(subcommand="workspace", arguments="-d {}".format(self._workspace))
        with self._engine.session_scope() as session:
            result = session.query(Workspace).filter_by(name=self._workspace).one_or_none()
            self.assertIsNone(result)

    def test_list_workspaces(self):
        """
        run kismanage -l
        """
        # Setup database
        self.execute(subcommand="database", arguments="--drop --init")
        # Test workspace creation
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Setup database and workspace
        self.execute(arguments="-l")

    def test_clone_workspace_ignore(self):
        self.init_db()
        # Setup the database
        # todo: update if data model was updated
        with self._engine.session_scope() as session:
            workspace = self._ip_utils.add_workspace(session=session, name=self._workspaces[0])
            self._ip_utils.add_workspace(session=session, name=self._workspaces[1])
            # Add network
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="192.168.0.0/24",
                                       scope=ScopeType.ignore)
            # Add domain
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="test1.local",
                                               scope=ScopeType.ignore,
                                               verify=False)
            # Add company
            self._ip_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Test1 LLC",
                                       verify=False,
                                       in_scope=False)
        self._engine.clone_workspace(source_workspace_str=self._workspaces[0],
                                     destination_workspace_str=self._workspaces[1],
                                     clone_types=[item for item in CloneType])
        # Test the database
        with self._engine.session_scope() as session:
            # Test network 192.168.0.0/24
            network = session.query(Network) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[1]) \
                .filter(Network.network == "192.168.0.0/24").one_or_none()
            self.assertIsNone(network)
            # Test domain and host names
            # Test test1.local
            host_name = session.query(DomainName).join(Workspace).filter(Workspace.name == self._workspaces[1]).count()
            self.assertEqual(0, host_name)
            # Test companies
            company = self.query_company(session=session, workspace_str=self._workspaces[1], name="test1 llc")
            self.assertIsNotNone(company)
            self.assertFalse(company.in_scope)

    def test_clone_workspace_in_scope(self):
        self.init_db()
        # Setup the database
        # todo: update if data model was updated
        with self._engine.session_scope() as session:
            workspace = self._ip_utils.add_workspace(session=session, name=self._workspaces[0])
            self._ip_utils.add_workspace(session=session, name=self._workspaces[1])
            # Add network
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="192.168.0.0/24")
            # Add domain
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="test1.local",
                                               verify=False)
            # Add company
            self._ip_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Test1 LLC",
                                       verify=False,
                                       in_scope=False)
        self._engine.clone_workspace(source_workspace_str=self._workspaces[0],
                                     destination_workspace_str=self._workspaces[1],
                                     clone_types=[CloneType.network_is, CloneType.domain_name_is, CloneType.company_is])
        # Test the database
        with self._engine.session_scope() as session:
            # Test network 192.168.0.0/24
            network = session.query(Network) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[1]) \
                .filter(Network.network == "192.168.0.0/24").one_or_none()
            self.assertIsNone(network)
            # Test domain and host names
            # Test test1.local
            host_name = session.query(DomainName).join(Workspace).filter(Workspace.name == self._workspaces[1]).count()
            self.assertEqual(0, host_name)
            # Test companies
            company = self.query_company(session=session, workspace_str=self._workspaces[1], name="test1 llc")
            self.assertIsNone(company)

    def test_clone_workspace_exclude(self):
        self.init_db()
        # Setup the database
        # todo: update if data model was updated
        with self._engine.session_scope() as session:
            workspace = self._ip_utils.add_workspace(session=session, name=self._workspaces[0])
            self._ip_utils.add_workspace(session=session, name=self._workspaces[1])
            # Add network
            self._ip_utils.add_network(session=session,
                                       workspace=workspace,
                                       network="192.168.0.0/24")
            # Add domain
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="test1.local",
                                               verify=False)
            # Add company
            self._ip_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Test1 LLC",
                                       verify=False,
                                       in_scope=False)
        self._engine.clone_workspace(source_workspace_str=self._workspaces[0],
                                     destination_workspace_str=self._workspaces[1],
                                     clone_types=[CloneType.network_ofs, CloneType.domain_name_ofs, CloneType.company_ofs])
        # Test the database
        with self._engine.session_scope() as session:
            # Test network 192.168.0.0/24
            network = session.query(Network) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[1]) \
                .filter(Network.network == "192.168.0.0/24").one_or_none()
            self.assertIsNotNone(network)
            # Test domain and host names
            # Test test1.local
            host_name = session.query(DomainName).join(Workspace).filter(Workspace.name == self._workspaces[1]).count()
            self.assertEqual(1, host_name)
            # Test companies
            company = self.query_company(session=session, workspace_str=self._workspaces[1], name="test1 llc")
            self.assertIsNotNone(company)

    def test_clone_workspace_full(self):
        self.init_db()
        # Setup the database
        # todo: update if data model was updated
        with self._engine.session_scope() as session:
            workspace = self._ip_utils.add_workspace(session=session, name=self._workspaces[0])
            # Add sources
            source_company = self._ip_utils.add_source(session=session, name="company")
            source_network = self._ip_utils.add_source(session=session, name="network")
            source_mapping = self._ip_utils.add_source(session=session, name="mapping")
            source_host = self._ip_utils.add_source(session=session, name="host")
            source_service = self._ip_utils.add_source(session=session, name="service")
            source_host_name = self._ip_utils.add_source(session=session, name="host name")
            source_path = self._ip_utils.add_source(session=session, name="path")
            source_credential = self._ip_utils.add_source(session=session, name="credential")
            source_email = self._ip_utils.add_source(session=session, name="email")
            # Add company
            company1 = self._ip_utils.add_company(session=session,
                                                  workspace=workspace,
                                                  name="Test1 LLC",
                                                  source=source_company,
                                                  verify=False,
                                                  in_scope=True)
            self._ip_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Test2 LLC",
                                       source=source_company,
                                       verify=False,
                                       in_scope=True)
            self._ip_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Test3 LLC",
                                       source=source_company,
                                       verify=False,
                                       in_scope=False)
            # Add network
            network = self._ip_utils.add_network(session=session,
                                                 workspace=workspace,
                                                 network="192.168.0.0/24",
                                                 scope=ScopeType.all,
                                                 source=source_network)
            self._ip_utils.add_company_network_mapping(session=session,
                                                       company=company1,
                                                       network=network,
                                                       verified=True,
                                                       source=source_mapping)
            network = self._ip_utils.add_network(session=session,
                                                 workspace=workspace,
                                                 network="192.168.1.0/24",
                                                 scope=ScopeType.all,
                                                 source=source_network)
            self._ip_utils.add_company_network_mapping(session=session,
                                                       company=company1,
                                                       network=network,
                                                       verified=False,
                                                       source=source_mapping)
            network = self._ip_utils.add_network(session=session,
                                                 workspace=workspace,
                                                 network="192.168.2.0/24",
                                                 scope=ScopeType.strict,
                                                 source=source_network)
            self._ip_utils.add_company_network_mapping(session=session,
                                                       company=company1,
                                                       network=network,
                                                       verified=True,
                                                       source=source_mapping)
            # Add hosts and services
            host1 = self._ip_utils.add_host(session=session,
                                            workspace=workspace,
                                            address="192.168.0.1",
                                            source=source_host)
            self._ip_utils.add_service(session=session,
                                       host=host1,
                                       protocol_type=ProtocolType.tcp,
                                       port=21,
                                       nmap_service_name="ftp",
                                       state=ServiceState.Open,
                                       source=source_service)
            self._ip_utils.add_service(session=session,
                                       host=host1,
                                       protocol_type=ProtocolType.tcp,
                                       port=445,
                                       nmap_service_name="smb",
                                       state=ServiceState.Open,
                                       source=source_service)
            host2 = self._ip_utils.add_host(session=session,
                                            workspace=workspace,
                                            address="192.168.1.1",
                                            source=source_host)
            service = self._ip_utils.add_service(session=session,
                                                 host=host2,
                                                 protocol_type=ProtocolType.tcp,
                                                 port=80,
                                                 nmap_service_name="http",
                                                 state=ServiceState.Open,
                                                 source=source_service)
            # Add path
            self._ip_utils.add_url_path(session=session,
                                        service=service,
                                        url_path="/test?a=b",
                                        size_bytes=185,
                                        status_code=200,
                                        source=source_path)
            # Add credential
            self._ip_utils.add_credential(session=session,
                                          service=service,
                                          password="Password123",
                                          credential_type=CredentialType.cleartext,
                                          username="test",
                                          domain="test",
                                          source=source_credential)
            self._ip_utils.add_service(session=session,
                                       host=host2,
                                       protocol_type=ProtocolType.tcp,
                                       port=443,
                                       nmap_tunnel="ssl",
                                       nmap_service_name="https",
                                       state=ServiceState.Open,
                                       source=source_service)
            host3 = self._ip_utils.add_host(session=session,
                                            workspace=workspace,
                                            address="192.168.2.1",
                                            source=source_host)
            self._ip_utils.add_service(session=session,
                                       host=host3,
                                       protocol_type=ProtocolType.tcp,
                                       port=8443,
                                       nmap_tunnel="ssl",
                                       nmap_service_name="https",
                                       state=ServiceState.Open,
                                       source=source_service)
            self._ip_utils.add_host(session=session,
                                    workspace=workspace,
                                    address="192.168.3.1",
                                    source=source_host)
            # Add domain and host names
            host_name = self._domain_utils.add_domain_name(session=session,
                                                           workspace=workspace,
                                                           item="test1.local",
                                                           source=source_host_name,
                                                           scope=ScopeType.all,
                                                           verify=False)
            # Add company for domain name
            self._ip_utils.add_company_domain_name_mapping(session=session,
                                                           company=company1,
                                                           host_name=host_name,
                                                           verified=True,
                                                           source=source_mapping)
            # Add email address
            email = Email(address="email", host_name=host_name)
            session.add(email)
            email.sources.append(source_email)
            # Add credentials
            self._ip_utils.add_credential(session=session,
                                          email=email,
                                          password="Password123",
                                          credential_type=CredentialType.cleartext,
                                          source=source_credential)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="www.test1.local",
                                               source=source_host_name,
                                               scope=ScopeType.all,
                                               verify=False)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="ftp.test1.local",
                                               source=source_host_name,
                                               scope=ScopeType.all,
                                               verify=False)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace,
                                               item="ftp.test2.local",
                                               source=source_host_name,
                                               scope=ScopeType.exclude,
                                               verify=False)
            self._ip_utils.add_workspace(session=session, name=self._workspaces[1])
        self._engine.clone_workspace(source_workspace_str=self._workspaces[0],
                                     destination_workspace_str=self._workspaces[1],
                                     clone_types=[CloneType.network_is,
                                                  CloneType.host_is,
                                                  CloneType.service,
                                                  CloneType.domain_name_is,
                                                  CloneType.host_name_is,
                                                  CloneType.company_is,
                                                  CloneType.email,
                                                  CloneType.path,
                                                  CloneType.credential])
        # Test the database
        with self._engine.session_scope() as session:
            # Test network 192.168.0.0/24
            network = session.query(Network) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[1]) \
                .filter(Network.network =="192.168.0.0/24").one()
            self.assertEqual(ScopeType.all, network.scope)
            self.assertEqual("network", network.sources_str)
            self.assertEqual(1, len(network.companies))
            self.assertEqual("test1 llc", network.company_network_mappings[0].company.name)
            self.assertTrue(network.company_network_mappings[0].verified)
            self.assertEqual("company", network.company_network_mappings[0].company.sources_str)
            self.assertEqual("mapping", network.company_network_mappings[0].sources_str)
            # Test network 192.168.1.0/24
            network = session.query(Network) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[1]) \
                .filter(Network.network =="192.168.1.0/24").one()
            self.assertEqual(ScopeType.all, network.scope)
            self.assertEqual("network", network.sources_str)
            self.assertEqual(1, len(network.companies))
            self.assertEqual("test1 llc", network.company_network_mappings[0].company.name)
            self.assertFalse(network.company_network_mappings[0].verified)
            self.assertEqual("company", network.company_network_mappings[0].company.sources_str)
            self.assertEqual("mapping", network.company_network_mappings[0].sources_str)
            # Test network 192.168.2.0/24
            network = session.query(Network) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[1]) \
                .filter(Network.network =="192.168.2.0/24").one_or_none()
            self.assertIsNone(network)
            # Test host 192.168.0.1
            host = session.query(Host) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[1]) \
                .filter(Host.address =="192.168.0.1").one()
            self.assertIsNotNone(host.ipv4_network)
            self.assertEqual("192.168.0.0/24", host.ipv4_network.network)
            self.assertTrue(host.in_scope)
            self.assertEqual("host", host.sources_str)
            # Test host 192.168.1.1
            host = session.query(Host) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[1]) \
                .filter(Host.address =="192.168.1.1").one()
            self.assertEqual("192.168.1.0/24", host.ipv4_network.network)
            self.assertTrue(host.in_scope)
            self.assertEqual("host", host.sources_str)
            # Test host 192.168.2.1
            host = session.query(Host) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[1]) \
                .filter(Host.address =="192.168.2.1").one_or_none()
            self.assertIsNone(host)
            # Test services
            for service in session.query(Service) \
                .join(Host) \
                .join(Workspace) \
                .filter(Workspace.name == self._workspaces[1]).all():
                self.assertEqual(ProtocolType.tcp, service.protocol)
                self.assertEqual(ServiceState.Open, service.state)
                self.assertEqual("service", service.sources_str)
                self.assertNotEqual(8443, service.port)
                if service.port == 21:
                    self.assertEqual("ftp", service.nmap_service_name)
                    self.assertEqual("192.168.0.1", service.host.address)
                    self.assertEqual(0, len(service.paths))
                    self.assertEqual(0, len(service.credentials))
                elif service.port == 445:
                    self.assertEqual("smb", service.nmap_service_name)
                    self.assertEqual("192.168.0.1", service.host.address)
                    self.assertEqual(0, len(service.paths))
                    self.assertEqual(0, len(service.credentials))
                elif service.port == 80:
                    self.assertEqual("http", service.nmap_service_name)
                    self.assertEqual("192.168.1.1", service.host.address)
                    # Test path
                    path = session.query(Path).filter_by(service_id=service.id).filter_by(return_code=200).one()
                    self.assertEqual(2, len(service.paths))
                    self.assertEqual("/test", path.name)
                    self.assertEqual(200, path.return_code)
                    self.assertEqual(185, path.size_bytes)
                    self.assertEqual(PathType.http, path.type)
                    self.assertEqual("path", path.sources_str)
                    # Test query
                    self.assertEqual(1, len(path.queries))
                    self.assertEqual("a=b", path.queries[0].query)
                    # Test credential
                    self.assertEqual(1, len(service.credentials))
                    self.assertEqual("test", service.credentials[0].username)
                    self.assertEqual("test", service.credentials[0].domain)
                    self.assertEqual("Password123", service.credentials[0].password)
                    self.assertEqual(CredentialType.cleartext, service.credentials[0].type)
                    self.assertEqual("credential", service.credentials[0].sources_str)
                elif service.port == 443:
                    self.assertEqual("https", service.nmap_service_name)
                    self.assertEqual("ssl", service.nmap_tunnel)
                    self.assertEqual("192.168.1.1", service.host.address)
                    self.assertEqual(1, len(service.paths))
                    self.assertEqual(0, len(service.credentials))
                else:
                    raise NotImplementedError("case not implemented")
            # Test domain and host names
            # Test test1.local
            host_name = self.query_hostname(session=session,
                                            workspace_str=self._workspaces[1],
                                            host_name="test1.local")
            self.assertEqual(self._workspaces[1], host_name.domain_name.workspace.name)
            self.assertEqual("test1.local", host_name.domain_name.name)
            self.assertEqual(ScopeType.all, host_name.domain_name.scope)
            self.assertEqual("host name", host_name.sources_str)
            self.assertIsNone(host_name.name)
            self.assertTrue(host_name.in_scope)
            # Test domain's companies
            self.assertEqual(1, len(host_name.companies))
            self.assertEqual("test1 llc", host_name.domain_name.company_domain_name_mappings[0].company.name)
            self.assertTrue(host_name.domain_name.company_domain_name_mappings[0].verified)
            self.assertEqual("company", host_name.domain_name.company_domain_name_mappings[0].company.sources_str)
            self.assertEqual("mapping", host_name.domain_name.company_domain_name_mappings[0].sources_str)
            # Test domain's emails
            self.assertEqual(1, len(host_name.emails))
            self.assertEqual("email", host_name.emails[0].address)
            self.assertEqual("email", host_name.emails[0].sources_str)
            # Test email's credentials
            self.assertEqual(1, len(host_name.emails[0].credentials))
            self.assertEqual("Password123", host_name.emails[0].credentials[0].password)
            self.assertEqual(CredentialType.cleartext, host_name.emails[0].credentials[0].type)
            self.assertEqual("credential", host_name.emails[0].credentials[0].sources_str)
            # Test www.test1.local
            host_name = self.query_hostname(session=session,
                                            workspace_str=self._workspaces[1],
                                            host_name="www.test1.local")
            self.assertEqual(self._workspaces[1], host_name.domain_name.workspace.name)
            self.assertEqual("test1.local", host_name.domain_name.name)
            self.assertEqual(ScopeType.all, host_name.domain_name.scope)
            self.assertEqual("host name", host_name.sources_str)
            self.assertEqual("www", host_name.name)
            self.assertTrue(host_name.in_scope)
            # Test domain's companies
            self.assertEqual(1, len(host_name.companies))
            # Test domain's emails
            self.assertEqual(0, len(host_name.emails))
            # Test ftp.test1.local
            host_name = self.query_hostname(session=session,
                                            workspace_str=self._workspaces[1],
                                            host_name="ftp.test1.local")
            self.assertEqual(self._workspaces[1], host_name.domain_name.workspace.name)
            self.assertEqual("test1.local", host_name.domain_name.name)
            self.assertEqual(ScopeType.all, host_name.domain_name.scope)
            self.assertEqual("host name", host_name.sources_str)
            self.assertEqual("ftp", host_name.name)
            self.assertTrue(host_name.in_scope)
            # Test domain's companies
            self.assertEqual(1, len(host_name.companies))
            # Test domain's emails
            self.assertEqual(0, len(host_name.emails))
            # Test ftp.test2.local
            host_name = self.query_hostname(session=session,
                                            workspace_str=self._workspaces[1],
                                            host_name="ftp.test2.local")
            self.assertIsNone(host_name)
            # Test companies
            company = self.query_company(session=session, workspace_str=self._workspaces[1], name="test2 llc")
            self.assertIsNotNone(company)
            self.assertTrue(company.in_scope)
            self.assertEqual("company", company.sources_str)
            company = self.query_company(session=session, workspace_str=self._workspaces[1], name="test3 llc")
            self.assertIsNone(company)


class TestSubcommandNetwork(BaseTestKisCommand):
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
        network = "192.168.0.0/31"
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new network
        self.execute(subcommand="network", arguments="-w {} -a {} --source {} -c --scope {}".format(self._workspace,
                                                                                                    network,
                                                                                                    source,
                                                                                                    scope.name))
        # Test network, host and source creation
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network=network).one()
            self.assertEqual(network, result.network)
            self.assertEqual(scope, result.scope)
            self.assertListEqual([source], [item.name for item in result.sources])
            self.assertEqual(2, len(result.hosts))
        # Delete network
        self.execute(subcommand="network", arguments="-w {} -d {} --source {} -c --scope {}".format(self._workspace,
                                                                                                    network,
                                                                                                    source,
                                                                                                    scope.name))
        # Test network deletion
        with self._engine.session_scope() as session:
            result = session.query(Network).filter_by(network=network).one_or_none()
            self.assertIsNone(result)

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
            self.execute(subcommand="network", arguments="-w {} -A {} --source {} -c --scope {}".format(self._workspace,
                                                                                                        file_name,
                                                                                                        source,
                                                                                                        scope.name))
            # Test networks, hosts, and source creation
            with self._engine.session_scope() as session:
                for network in networks:
                    result = session.query(Network).filter_by(network=network).one()
                    self.assertEqual(network, result.network)
                    self.assertEqual(scope, result.scope)
                    self.assertListEqual([source], [item.name for item in result.sources])
                    self.assertEqual(2, len(result.hosts))
            # Delete networks
            self.execute(subcommand="network", arguments="-w {} -D {} --source {} -c --scope {}".format(self._workspace,
                                                                                                        file_name,
                                                                                                        source,
                                                                                                        scope.name))
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
            self.assertEqual(network, result.network)
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
                self.assertEqual(network, result.network)
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
            self.assertEqual(network, result.network)
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
                self.assertEqual(network, result.network)
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
            self.assertEqual(network, result.network)
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
                self.assertEqual(network, result.network)
                self.assertEqual(scope, result.scope)


class TestSubcommandHost(BaseTestKisCommand):
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
        address = "192.168.1.1"
        network = "192.168.1.0/24"
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new network and host
        self.execute(subcommand="network", arguments="-w {} --scope {} -a {}".format(self._workspace,
                                                                                     ScopeType.strict.name,
                                                                                     network))
        self.execute(subcommand="host", arguments="-w {} -a {} --source {} --scope {}".format(self._workspace,
                                                                                              address,
                                                                                              source,
                                                                                              scope.name))
        # Test network, host and source creation
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address=address).one()
            self.assertEqual(ScopeType.strict, result.ipv4_network.scope)
            self.assertEqual(address, result.address)
            self.assertTrue(result.in_scope)
            self.assertListEqual([source], [item.name for item in result.sources])
        # Delete network
        self.execute(subcommand="host", arguments="-w {} -d {} --source {} --scope {}".format(self._workspace,
                                                                                              address,
                                                                                              source,
                                                                                              scope.name))
        # Test network deletion
        with self._engine.session_scope() as session:
            result = session.query(Host).filter_by(address=address).one_or_none()
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
                # Test networks, hosts, and source creation
                with self._engine.session_scope() as session:
                    for address in addresses:
                        result = session.query(Host).filter_by(address=address).one()
                        self.assertEqual(ScopeType.strict, result.ipv4_network.scope)
                        self.assertEqual(address, result.address)
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


# TODO: Refactor the code below
class BaseKismanageTestCase(BaseKisTestCase):
    """
    This class implements functionalities for testing kismanage
    """

    def __init__(self, test_name: str):
        super().__init__(test_name)
        parser = argparse.ArgumentParser(description=None)
        parser.add_argument("--debug",
                            action="store_true",
                            help="prints extra information to log file")
        parser.add_argument("-l", "--list", action='store_true', help="list existing workspaces")
        sub_parser = parser.add_subparsers(help='list of available database modules', dest="module")
        parser_kiscollect = sub_parser.add_parser('kiscollect', help='contains functionality used by kiscollect')
        parser_scan = sub_parser.add_parser('scan', help='allows importing scan results from filesystem')
        parser_database = sub_parser.add_parser('database', help='allows setting up and managing the database')
        parser_workspace = sub_parser.add_parser('workspace', help='allows managing workspaces')
        parser_network = sub_parser.add_parser('network', help='allows managing networks')
        parser_host = sub_parser.add_parser('host', help='allows managing hosts')
        parser_service = sub_parser.add_parser('service', help='allows managing services')
        parser_domain = sub_parser.add_parser('domain', help='allows managing second-level domains')
        parser_host_name = sub_parser.add_parser('hostname',
                                                 help='allows managing host names (sub-domains of second-level'
                                                      'domains')
        parser_email = sub_parser.add_parser('email', help='allows managing emails')
        parser_company = sub_parser.add_parser('company', help='allows managing companies')
        # setup workspace parser
        parser_workspace.add_argument('WORKSPACE', type=str)
        parser_workspace_group = parser_workspace.add_mutually_exclusive_group(required=True)
        parser_workspace_group.add_argument('-a', '--add',
                                            action="store_true",
                                            help="create the given workspace WORKSPACE in KIS database")
        parser_workspace_group.add_argument('-d', '--delete',
                                            action="store_true",
                                            help="delete the given workspace WORKSPACE together with all associated "
                                                 "information from KIS database (use with caution)")
        # setup database parser
        parser_database.add_argument('-a', '--add',
                                     action="store_true",
                                     help="create the given workspace WORKSPACE in KIS database")
        parser_database.add_argument("--init",
                                     help="creates tables, views, functions, and triggers for the KIS database",
                                     action="store_true")
        parser_database.add_argument("--drop",
                                     help="drops tables, views, functions, and triggers in the KIS database",
                                     action="store_true")
        parser_database.add_argument("--backup", metavar="FILE", type=str, help="writes database backup to FILE")
        parser_database.add_argument("--restore", metavar="FILE", type=str, help="restores database backup from FILE")
        parser_database.add_argument("--setup",
                                     action="store_true",
                                     help="run initial setup for KIS")
        parser_database.add_argument("--setup-dbg",
                                     action="store_true",
                                     help="like --setup but just prints commands for initial setup for KIS")
        parser_database.add_argument("--test",
                                     action="store_true",
                                     help="test the existing KIS setup")
        # setup network parser
        parser_network.add_argument('NETWORK', type=str, nargs="+")
        parser_network.add_argument("-w", "--workspace",
                                    metavar="WORKSPACE",
                                    help="use the given workspace",
                                    required=True,
                                    type=str)
        parser_network_group = parser_network.add_mutually_exclusive_group()
        parser_network_group.add_argument('-a', '--add',
                                          action="store_true",
                                          help="create the given network NETWORK in workspace WORKSPACE")
        parser_network_group.add_argument('-A', '--Add',
                                          action="store_true",
                                          help="read the given networks (one per line) from file NETWORK and add them to "
                                               "workspace WORKSPACE")
        parser_network_group.add_argument('-d', '--delete',
                                          action="store_true",
                                          help="delete the given networks NETWORK together with all associated host "
                                               "information in workspace WORKSPACE (use with caution)")
        parser_network_group.add_argument('-D', '--Delete',
                                          action="store_true",
                                          help="read the given networks (one per line) from file NETWORK and delete them "
                                               "from workspace WORKSPACE. Note that only the given NETWORK but no "
                                               "associated host information is deleted")
        parser_network.add_argument('-s', '--scope', choices=[item.name for item in ScopeType],
                                    type=str,
                                    help="set only the given networks in scope and exclude all IP addresses (option "
                                         "explicit). set the given networks including all IP addresses in scope (option "
                                         "all). exclude the given networks including all IP addresses from scope. set "
                                         "only those IP addresses (option vhost) in scope to which an in-scope host "
                                         "name resolves to. note that KIS only actively collects information from "
                                         "in-scope hosts and networks",
                                    default=ScopeType.all.name)
        parser_network.add_argument('-S', '--Scope', choices=[item.name for item in ScopeType],
                                    type=str,
                                    help="like argument --scope but read the networks (one per line) from file"
                                         "NETWORK")
        parser_network.add_argument('-c', '--create-hosts',
                                    action="store_true",
                                    help="add the given networks NETWORK to workspace WORKSPACE and add all IP "
                                         "addresses of these networks to hosts table")
        parser_network.add_argument("--source", metavar="SOURCE", type=str,
                                    help="specify the source of the networks to be added")
        # setup host parser
        parser_host.add_argument('IP', type=str, nargs="+")
        parser_host.add_argument("-w", "--workspace",
                                 metavar="WORKSPACE",
                                 help="use the given workspace",
                                 required=True,
                                 type=str)
        parser_host_group = parser_host.add_mutually_exclusive_group()
        parser_host_group.add_argument('-a', '--add',
                                       action="store_true",
                                       help="create the given host with IP address IP in workspace WORKSPACE")
        parser_host_group.add_argument('-A', '--Add',
                                       action="store_true",
                                       help="read the given IP addresses (one per line) from file IP and add them to "
                                            "workspace WORKSPACE")
        parser_host_group.add_argument('-d', '--delete',
                                       action="store_true",
                                       help="delete the given host with address IP together with all associated host "
                                            "information in workspace WORKSPACE (use with caution)")
        parser_host_group.add_argument('-D', '--Delete',
                                       action="store_true",
                                       help="read the given IP addresses (one per line) from file IP and delete them "
                                            "together with all associated host information from workspace WORKSPACE")
        parser_host.add_argument('-s', '--scope', choices=[item.name for item in ReportScopeType],
                                 help="set the given hosts IP in or out of scope. note that KIS only "
                                      "actively collects information from in-scope hosts and networks ",
                                 default=ReportScopeType.within.name)
        parser_host_group.add_argument("--source", metavar="SOURCE", type=str,
                                       help="specify the source of the hosts to be added")
        # setup domain parser
        parser_domain.add_argument('DOMAIN', type=str, nargs="+")
        parser_domain.add_argument("-w", "--workspace",
                                   metavar="WORKSPACE",
                                   help="use the given workspace",
                                   required=True,
                                   type=str)
        parser_domain_group = parser_domain.add_mutually_exclusive_group()
        parser_domain_group.add_argument('-a', '--add',
                                         action="store_true",
                                         help="create the given second-level domain DOMAIN in workspace WORKSPACE")
        parser_domain_group.add_argument('-A', '--Add',
                                         action="store_true",
                                         help="read the given second-level domain (one per line) from file DOMAIN and "
                                              "add them to workspace WORKSPACE")
        parser_domain_group.add_argument('-d', '--delete',
                                         action="store_true",
                                         help="delete the given second-level domain DOMAIN together with all associated "
                                              "host names and email addresses from workspace WORKSPACE (use with caution)")
        parser_domain_group.add_argument('-D', '--Delete',
                                         action="store_true",
                                         help="read the given second-level domain (one per line) from file DOMAIN and "
                                              "delete them together with all associated host names and emails from "
                                              "workspace WORKSPACE")
        parser_domain.add_argument('-s', '--scope', choices=[item.name for item in ScopeType],
                                   type=str,
                                   help="set only the given domains in scope and exclude all other sub-domains (option "
                                        "explicit). set the given domains including all other sub-domains in scope "
                                        "(option all). set only those sub-domains (option vhost) in scope that resolve "
                                        "to an in-scope IP address. exclude the given domains (option exclude). "
                                        "including all other sub-domains from scope. note that KIS only actively "
                                        "collects information from in-scope second-level domain/host name",
                                   default=ScopeType.all.name)
        parser_domain.add_argument('-S', '--Scope', choices=[item.name for item in ScopeType],
                                   type=str,
                                   help="like argument --scope but read the second-level domains (one per line) from file"
                                        "DOMAIN")
        parser_domain.add_argument("--source", metavar="SOURCE", type=str,
                                   help="specify the source of the second-level-domains to be added")
        # setup host name parser
        parser_host_name.add_argument('HOSTNAME', type=str, nargs="+")
        parser_host_name.add_argument("-w", "--workspace",
                                      metavar="WORKSPACE",
                                      help="use the given workspace",
                                      required=True,
                                      type=str)
        parser_host_name_group = parser_host_name.add_mutually_exclusive_group()
        parser_host_name_group.add_argument('-a', '--add',
                                            action="store_true",
                                            help="create the given host name in workspace WORKSPACE")
        parser_host_name_group.add_argument('-A', '--Add',
                                            action="store_true",
                                            help="read the given host names (one per line) from file HOSTNAME and add "
                                                 "them to workspace WORKSPACE")
        parser_host_name_group.add_argument('-d', '--delete',
                                            action="store_true",
                                            help="delete the given host name HOSTNAME together with all associated email "
                                                 "addresses in workspace WORKSPACE (use with caution)")
        parser_host_name_group.add_argument('-D', '--Delete',
                                            action="store_true",
                                            help="read the given host names (one per line) from file HOSTNAME and delete "
                                                 "them together with all associated email addresses from workspace "
                                                 "WORKSPACE")
        parser_host_name_group.add_argument('--sharphound',
                                            action="store_true",
                                            help="read the given computer.json file created by sharphound and import all "
                                                 "computer names into KIS for further intel collection")
        parser_host_name.add_argument('-s', '--scope', choices=[item.name for item in ReportScopeType],
                                      help="set the given host names HOSTNAME in or out of scope. note that KIS only "
                                           "actively collects information from in-scope host names",
                                      default=ReportScopeType.within.name)
        parser_host_name_group.add_argument("--source", metavar="SOURCE", type=str,
                                            help="specify the source of the host name to be added")
        # setup email parser
        parser_email.add_argument('EMAIL', type=str, nargs="+")
        parser_email.add_argument("-w", "--workspace",
                                  metavar="WORKSPACE",
                                  help="use the given workspace",
                                  required=True,
                                  type=str)
        parser_email_group = parser_email.add_mutually_exclusive_group(required=True)
        parser_email_group.add_argument('-a', '--add',
                                        action="store_true",
                                        help="create the given email EMAIL in workspace WORKSPACE")
        parser_email_group.add_argument('-A', '--Add',
                                        action="store_true",
                                        help="read the given emails (one per line) from file EMAIL and add them "
                                             "to workspace WORKSPACE")
        parser_email_group.add_argument('-d', '--delete',
                                        action="store_true",
                                        help="delete the given email EMAIL from workspace WORKSPACE (use with caution)")
        parser_email_group.add_argument('-D', '--Delete',
                                        action="store_true",
                                        help="read the given emails (one per line) from file NETWORK and delete them "
                                             "from workspace WORKSPACE")
        parser_email_group.add_argument("--source", metavar="SOURCE", type=str,
                                        help="specify the source of the emails to be added")
        # setup service parser
        parser_service.add_argument("-w", "--workspace",
                                    metavar="WORKSPACE",
                                    help="use the given workspace",
                                    required=True,
                                    type=str)
        parser_service_group = parser_service.add_mutually_exclusive_group(required=True)
        parser_service_group.add_argument('-a', '--add',
                                          action="store_true",
                                          help="create the given service in workspace WORKSPACE")
        parser_service_group.add_argument('-d', '--delete',
                                          action="store_true",
                                          help="delete the given service from workspace WORKSPACE (use with caution)")
        parser_service.add_argument("--host",
                                    metavar="IP",
                                    nargs="+",
                                    help="add the service to this host",
                                    required=True,
                                    type=str)
        parser_service.add_argument("--port",
                                    metavar="PORT",
                                    help="the service's port number",
                                    required=True,
                                    type=int)
        parser_service.add_argument("--protocol",
                                    choices=[item.name for item in ProtocolType],
                                    help="the service's layer 4 protocol",
                                    required=True)
        parser_service.add_argument("--service-name",
                                    type=str,
                                    metavar="NMAP",
                                    help="the nmap service name (refer to first column of file "
                                         "/usr/share/nmap/nmap-services)")
        parser_service.add_argument('--tls',
                                    action="store_true",
                                    help="if set, then the service uses TLS for secure communication")
        parser_service.add_argument("--source", metavar="SOURCE", type=str,
                                    help="specify the source of the service to be added")
        # setup company parser
        parser_company.add_argument('COMPANY', type=str, nargs="+")
        parser_company.add_argument("-w", "--workspace",
                                    metavar="WORKSPACE",
                                    help="use the given workspace",
                                    required=True,
                                    type=str)
        parser_company_group = parser_company.add_mutually_exclusive_group()
        parser_company_group.add_argument('-a', '--add',
                                          action="store_true",
                                          help="create the given company COMPANY in workspace WORKSPACE")
        parser_company_group.add_argument('-d', '--delete',
                                          action="store_true",
                                          help="delete the given company COMPANY from workspace WORKSPACE "
                                               "(use with caution)")
        parser_company_group.add_argument('--network',
                                          type=str,
                                          nargs="+",
                                          metavar="NETWORK",
                                          help="assign the company COMPANY to the given network NETWORK")
        parser_company_group.add_argument('--Network',
                                          type=str,
                                          nargs="+",
                                          metavar="NETWORK",
                                          help="read the given networks (one per line) from file NETWORK and add them to "
                                               "the company COMPANY")
        parser_company_group.add_argument('--domain',
                                          type=str,
                                          nargs="+",
                                          metavar="DOMAIN",
                                          help="assign the company COMPANY to the given domain DOMAIN")
        parser_company_group.add_argument('--Domain',
                                          type=str,
                                          nargs="+",
                                          metavar="DOMAIN",
                                          help="read the given domains (one per line) from file DOMAIN and add them to "
                                               "the company COMPANY")
        parser_company_group.add_argument('-s', '--scope', choices=[item.name for item in ReportScopeType],
                                          help="set the given company COMPANY in or out of scope. note that KIS only "
                                               "actively collects information from in-scope hosts and networks ")
        parser_company.add_argument("--source", metavar="SOURCE", type=str,
                                    help="specify the source of the company to be added")
        self._parser = parser

    def arg_parse(self, argument_list: List[str]):
        return self._parser.parse_args(argument_list)

    def check_results(self,
                      workspace_str: str,
                      networks: List[str] = None,
                      domains: List[str] = None,
                      hosts: List[str] = None,
                      emails: List[str] = None,
                      scope: ScopeType = None,
                      source_name: str = None):
        with self._engine.session_scope() as session:
            workspace = self._domain_utils.get_workspace(session=session, name=workspace_str)
            if networks is not None:
                if len(networks) > 0:
                    for item in networks:
                        result = self._ip_utils.get_network(session=session,
                                                            workspace=workspace,
                                                            network=item)
                        self.assertIsNotNone(result)
                        if scope is not None:
                            self.assertEqual(scope, result.scope)
                        if source_name:
                            self.assertEqual(source_name, result.sources[0].name)
                else:
                    result = session.query(Network) \
                        .join(Workspace) \
                        .filter(Workspace.name == workspace_str).count()
                    self.assertEqual(0, result)
            elif domains is not None:
                if len(domains) > 0:
                    for item in domains:
                        result = self._domain_utils.get_host_name(session=session,
                                                                  workspace=workspace,
                                                                  host_name=item)
                        self.assertIsNotNone(result)
                        if scope is not None:
                            self.assertEqual(scope, result.domain_name.scope)
                        if source_name:
                            self.assertEqual(source_name, result.sources[0].name)
                else:
                    result = session.query(DomainName) \
                        .join(Workspace) \
                        .filter(Workspace.name == workspace_str).count()
                    self.assertEqual(0, result)
            elif hosts is not None:
                if len(hosts) > 0:
                    for item in hosts:
                        result = self._ip_utils.get_host(session=session,
                                                         workspace=workspace,
                                                         address=item)
                        self.assertIsNotNone(result)
                        if source_name:
                            self.assertEqual(source_name, result.sources[0].name)
                else:
                    result = session.query(Host) \
                        .join(Workspace) \
                        .filter(Workspace.name == workspace_str).count()
                    self.assertEqual(0, result)
            elif emails is not None:
                if len(emails) > 0:
                    for item in emails:
                        result = self._domain_utils.get_email(session=session,
                                                              workspace=workspace,
                                                              email=item)
                        self.assertIsNotNone(result)
                        if source_name:
                            self.assertEqual(source_name, result.sources[0].name)
                else:
                    result = session.query(Email) \
                        .join(HostName) \
                        .join(DomainName) \
                        .join(Workspace) \
                        .filter(Workspace.name == workspace_str).count()
                    self.assertEqual(0, result)


class TestNetworkModule(BaseKismanageTestCase):

    def test_scope(self):
        # setup database
        self.init_db()
        network = "192.168.0.0/24"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_network(session=session,
                                workspace_str=workspace,
                                network=network,
                                scope=ScopeType.all)
        # run command
        args = self.arg_parse(["network", "-w", workspace, "--scope", "exclude", network])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           networks=[network],
                           scope=ScopeType.exclude)

    def test_Scope(self):
        # setup database
        self.init_db()
        network = "192.168.0.0/24"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_network(session=session,
                                workspace_str=workspace,
                                network=network,
                                scope=ScopeType.all)
        # run command
        with tempfile.NamedTemporaryFile(mode="w") as file:
            file.write(network)
            file.flush()
            # run command
            args = self.arg_parse(["network", "-w", workspace, "--Scope", "exclude", file.name])
            ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           networks=[network],
                           scope=ScopeType.exclude)

    def test_create_hosts(self):
        # setup database
        self.init_db()
        network = "192.168.0.0/24"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_network(session=session,
                                workspace_str=workspace,
                                network=network,
                                scope=ScopeType.all)
        # run command
        args = self.arg_parse(["network", "-w", workspace, "-c", network])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        with self._engine.session_scope() as session:
            result = session.query(Host) \
                .join(Network) \
                .join(Workspace) \
                .filter(Network.network == network,
                        Workspace.name == workspace).count()
            self.assertEqual(256, result)


class TestDomainModule(BaseKismanageTestCase):

    def test_add_inscope(self):
        # setup database
        self.init_db()
        domain = "test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        # run command
        args = self.arg_parse(["domain", "-w", workspace, "-a", domain])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           domains=[domain],
                           scope=ScopeType.all,
                           source_name="user")

    def test_Add_inscope(self):
        # setup database
        self.init_db()
        domain = "test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        # run command
        with tempfile.NamedTemporaryFile(mode="w") as file:
            file.write(domain)
            file.flush()
            args = self.arg_parse(["domain", "-w", workspace, "-A", file.name])
            ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           domains=[domain],
                           scope=ScopeType.all,
                           source_name="user")

    def test_add_outofscope(self):
        # run command
        self.init_db()
        domain = "test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        args = self.arg_parse(["domain", "-w", workspace, "-a", domain, "--scope", "all"])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           domains=[domain],
                           scope=ScopeType.all,
                           source_name="user")

    def test_Add_outofscope(self):
        # setup database
        self.init_db()
        domain = "test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        # run command
        with tempfile.NamedTemporaryFile(mode="w") as file:
            file.write(domain)
            file.flush()
            args = self.arg_parse(["domain", "-w", workspace, "-A", file.name, "--scope", "all"])
            ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           domains=[domain],
                           scope=ScopeType.all,
                           source_name="user")

    def test_delete(self):
        # setup database
        self.init_db()
        domain = "test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_domain_name(session=session, workspace_str=workspace, host_name=domain)
        # run command
        args = self.arg_parse(["domain", "-w", workspace, "-d", domain])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace, domains=[])

    def test_Delete(self):
        # setup database
        self.init_db()
        domain = "test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_domain_name(session=session, workspace_str=workspace, host_name=domain)
        # run command
        with tempfile.NamedTemporaryFile(mode="w") as file:
            file.write(domain)
            file.flush()
            args = self.arg_parse(["domain", "-w", workspace, "-D", file.name])
            ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace, domains=[])

    def test_scope(self):
        # setup database
        self.init_db()
        domain = "test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_hostname(session=session,
                                 workspace_str=workspace,
                                 host_name=domain,
                                 scope=ScopeType.all)
        # run command
        args = self.arg_parse(["domain", "-w", workspace, "--scope", "exclude", domain])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           domains=[domain],
                           scope=ScopeType.exclude)

    def test_Scope(self):
        # setup database
        self.init_db()
        domain = "test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_hostname(session=session,
                                 workspace_str=workspace,
                                 host_name=domain,
                                 scope=ScopeType.all)
        # run command
        with tempfile.NamedTemporaryFile(mode="w") as file:
            file.write(domain)
            file.flush()
            # run command
            args = self.arg_parse(["domain", "-w", workspace, "--Scope", "exclude", file.name])
            ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           domains=[domain],
                           scope=ScopeType.exclude)

    def test_strict(self):
        # setup database
        self.init_db()
        host_name = "www.test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        # run command
        args = self.arg_parse(["domain", "-w", workspace, "-a", "--scope", "strict", "test.com"])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        args = self.arg_parse(["hostname", "-w", workspace, "-a", "--scope", "within", host_name])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        with self._engine.session_scope() as session:
            session.query(DomainName).filter_by(name="test.com", scope=ScopeType.strict).one()
            session.query(HostName).filter_by(name="www", _in_scope=True).one()
        # update database
        with self._engine.session_scope() as session:
            workspace_object = self._domain_utils.get_workspace(session, workspace)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace_object,
                                               item="vpn.test.com")
        # check database
        with self._engine.session_scope() as session:
            session.query(DomainName).filter_by(name="test.com", scope=ScopeType.strict).one()
            session.query(HostName).filter_by(name="www", _in_scope=True).one()
            session.query(HostName).filter_by(name="vpn", _in_scope=False).one()

    def test_all(self):
        # setup database
        self.init_db()
        host_name = "www.test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        # run command
        args = self.arg_parse(["domain", "-w", workspace, "-a", "--scope", "all", "test.com"])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        args = self.arg_parse(["hostname", "-w", workspace, "-a", "--scope", "outside", "www.test.com"])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        with self._engine.session_scope() as session:
            session.query(DomainName).filter_by(name="test.com", scope=ScopeType.all).one()
            session.query(HostName).filter_by(name="www", _in_scope=True).one()
        # update database
        with self._engine.session_scope() as session:
            workspace_object = self._domain_utils.get_workspace(session, workspace)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace_object,
                                               item="vpn.test.com")
        # check database
        with self._engine.session_scope() as session:
            session.query(DomainName).filter_by(name="test.com", scope=ScopeType.all).one()
            session.query(HostName).filter_by(name="www", _in_scope=True).one()
            session.query(HostName).filter_by(name="vpn", _in_scope=True).one()


class TestHostModule(BaseKismanageTestCase):

    def test_add_network_scope_all(self):
        # setup database
        self.init_db()
        host = "192.168.1.1"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_network(session=session,
                                workspace_str=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.all)
        # run command
        args = self.arg_parse(["host", "-w", workspace, "-a", host])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        with self._engine.session_scope() as session:
            session.query(Host).filter_by(address=host, in_scope=True)

    def test_add_network_scope_strict(self):
        # setup database
        self.init_db()
        host = "192.168.1.1"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            workspace_object = self.create_workspace(session=session, workspace=workspace)
            self.create_network(session=session,
                                workspace_str=workspace,
                                network="192.168.1.0/24",
                                scope=ScopeType.strict)
            IpUtils.add_host(session=session,
                             workspace=workspace_object,
                             address="192.168.1.254")
        # run command
        args = self.arg_parse(["host", "-w", workspace, "-a", host])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        with self._engine.session_scope() as session:
            session.query(Host).filter_by(address=host, _in_scope=True).one()
            session.query(Host).filter_by(address="192.168.1.254", _in_scope=False).one()


class TestServiceModule(BaseKismanageTestCase):

    def test_add(self):
        # setup database
        self.init_db()
        ipv4_address = "192.168.1.1"
        workspace = self._workspaces[0]
        port = 80
        protocol = ProtocolType.tcp
        service_name = "https"
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_host(session=session, workspace_str=workspace, address=ipv4_address)
        # run command
        args = self.arg_parse(["service",
                               "-w", workspace, "-a",
                               "--host", ipv4_address,
                               "--port", str(port),
                               "--protocol", protocol.name,
                               "--service-name", service_name,
                               "--tls"])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        with self._engine.session_scope() as session:
            result = session.query(Service) \
                .join(Host) \
                .join(Workspace) \
                .filter(Service.port == port,
                        Service.protocol == protocol,
                        Host.address == ipv4_address,
                        Workspace.name == workspace).one()
            self.assertIsNotNone(result)
            self.assertEqual("ssl", result.nmap_tunnel)
            self.assertEqual(service_name, result.nmap_service_name)
            self.assertEqual(protocol, result.protocol)

    def test_delete(self):
        # setup database
        self.init_db()
        ipv4_address = "192.168.1.1"
        workspace = self._workspaces[0]
        port = 80
        protocol = ProtocolType.tcp
        with self._engine.session_scope() as session:
            self.create_service(session=session,
                                workspace_str=workspace,
                                address=ipv4_address,
                                port=port,
                                protocol_type=protocol)
        # run command
        args = self.arg_parse(["service",
                               "-w", workspace, "-d",
                               "--host", ipv4_address,
                               "--port", str(port),
                               "--protocol", protocol.name])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        with self._engine.session_scope() as session:
            result = session.query(Service) \
                .join(Host) \
                .join(Workspace) \
                .filter(Service.port == port,
                        Service.protocol == protocol,
                        Host.address == ipv4_address,
                        Workspace.name == workspace).one_or_none()
            self.assertIsNone(result)


class TestEmailModule(BaseKismanageTestCase):

    def test_add(self):
        # setup database
        self.init_db()
        email = "test@test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        # run command
        args = self.arg_parse(["email", "-w", workspace, "-a", email])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           emails=[email],
                           scope=ScopeType.all,
                           source_name="user")

    def test_add2(self):
        # setup database
        self.init_db()
        email = "test@test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        # run command
        ManageDatabase(engine=self._engine,
                       arguments=self.arg_parse(["email", "-w", workspace, "-a", email]),
                       parser=self._parser).run()
        # append a host name afterwards
        with self._engine.session_scope() as session:
            workspace_object = self.create_workspace(session=session, workspace=workspace)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace_object,
                                               item="www.test.com")
            self.create_workspace(session=session, workspace=workspace)
        with self._engine.session_scope() as session:
            session.query(HostName).filter_by(name=None, _in_scope=False).one()
            session.query(HostName).filter_by(name="www", _in_scope=False).one()
            session.query(DomainName).filter_by(name="test.com", scope=ScopeType.strict)

    def test_add3(self):
        # setup database
        self.init_db()
        email = "test@test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        # run command
        ManageDatabase(engine=self._engine,
                       arguments=self.arg_parse(["domain", "-w", workspace, "-a", "test.com", "-s", "strict"]),
                       parser=self._parser).run()
        ManageDatabase(engine=self._engine,
                       arguments=self.arg_parse(["hostname", "-w", workspace, "test.com", "--scope", "within"]),
                       parser=self._parser).run()
        ManageDatabase(engine=self._engine,
                       arguments=self.arg_parse(["email", "-w", workspace, "-a", email]),
                       parser=self._parser).run()
        # append a host name afterwards
        with self._engine.session_scope() as session:
            workspace_object = self.create_workspace(session=session, workspace=workspace)
            self._domain_utils.add_domain_name(session=session,
                                               workspace=workspace_object,
                                               item="www.test.com")
            self.create_workspace(session=session, workspace=workspace)
        with self._engine.session_scope() as session:
            session.query(HostName).filter_by(name=None, _in_scope=True).one()
            session.query(HostName).filter_by(name="www", _in_scope=False).one()
            session.query(DomainName).filter_by(name="test.com", scope=ScopeType.strict)

    def test_Add(self):
        # setup database
        self.init_db()
        email = "test@test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        # run command
        with tempfile.NamedTemporaryFile(mode="w") as file:
            file.write(email)
            file.flush()
            args = self.arg_parse(["email", "-w", workspace, "-A", file.name])
            ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           emails=[email],
                           scope=ScopeType.all,
                           source_name="user")

    def test_delete(self):
        # setup database
        self.init_db()
        email = "test@test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_email(session=session, workspace_str=workspace, email_address=email)
        # run command
        args = self.arg_parse(["email", "-w", workspace, "-d", email])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           emails=[])

    def test_Delete(self):
        # setup database
        self.init_db()
        email = "test@test.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
            self.create_email(session=session, workspace_str=workspace, email_address=email)
        # run command
        with tempfile.NamedTemporaryFile(mode="w") as file:
            file.write(email)
            file.flush()
            args = self.arg_parse(["email", "-w", workspace, "-D", file.name])
            ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        self.check_results(workspace_str=workspace,
                           emails=[])


class TestCompanyModule(BaseKismanageTestCase):

    def test_add_company(self):
        # setup database
        self.init_db()
        company1 = "unittest llc"
        company2 = "unittest llc 2"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_workspace(session=session, workspace=workspace)
        # run command
        args = self.arg_parse(["company", "-w", workspace, "-a", company1, company2])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        with self._engine.session_scope() as session:
            session.query(Company).filter_by(name=company1).one()
            session.query(Company).filter_by(name=company2).one()

    def test_assign_network(self):
        # setup database
        self.init_db()
        company = "unittest llc"
        network1 = "192.168.1.0/24"
        network2 = "192.168.2.0/24"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_network(session=session, workspace_str=workspace, network=network1)
            self.create_network(session=session, workspace_str=workspace, network=network2)
            self.create_company(session=session, workspace_str=workspace, name_str=company)
        # run command
        args = self.arg_parse(["company", "-w", workspace, company, "--network", network1, network2])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        with self._engine.session_scope() as session:
            session.query(Company).join((Network, Company.networks)).filter(Company.name == company,
                                                                            Network.network == network1).one()
            session.query(Company).join((Network, Company.networks)).filter(Company.name == company,
                                                                            Network.network == network2).one()

    def test_assign_domain(self):
        # setup database
        self.init_db()
        company = "unittest llc"
        domain_name1 = "test1.com"
        domain_name2 = "test2.com"
        workspace = self._workspaces[0]
        with self._engine.session_scope() as session:
            self.create_hostname(session=session, workspace_str=workspace, host_name=domain_name1)
            self.create_hostname(session=session, workspace_str=workspace, host_name=domain_name2)
            self.create_company(session=session, workspace_str=workspace, name_str=company)
        # run command
        args = self.arg_parse(["company", "-w", workspace, company, "--domain", domain_name1, domain_name2])
        ManageDatabase(engine=self._engine, arguments=args, parser=self._parser).run()
        # check database
        with self._engine.session_scope() as session:
            session.query(Company)\
                .join((DomainName, Company.domain_names)).filter(Company.name == company,
                                                                 DomainName.name == domain_name1).one()
            session.query(Company)\
                .join((DomainName, Company.domain_names)).filter(Company.name == company,
                                                                 DomainName.name == domain_name2).one()
