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

from database.model import Workspace
from database.model import Network
from database.model import Host
from database.model import PathType
from database.model import DomainName
from database.model import Email
from database.model import Path
from database.model import Service
from database.model import ScopeType
from database.model import ProtocolType
from database.model import ServiceState
from database.model import CredentialType
from database.utils import CloneType
from unittests.tests.core import KisCommandEnum
from unittests.tests.core import BaseTestKisCommand


class TestWorkspace(BaseTestKisCommand):
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
            self.assertIsNotNone(network)
            # Test domain and host names
            # Test test1.local
            host_name = session.query(DomainName).join(Workspace).filter(Workspace.name == self._workspaces[1]).count()
            self.assertEqual(1, host_name)
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