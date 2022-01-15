#!/usr/bin/python3
"""
this file implements core functionalities that can be used by all unittests
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

import unittest
import socket
import os
import enum
import subprocess
from typing import List
from database.model import Workspace
from database.model import Host
from database.model import HostName
from database.model import Service
from database.model import ProtocolType
from database.model import Email
from database.model import Network
from database.model import ServiceState
from database.model import Source
from database.model import CollectorName
from database.model import CollectorType
from database.model import Command
from database.model import KeyExchangeAlgorithm
from database.model import DomainName
from database.model import Path
from database.model import PathType
from database.model import FileType
from database.model import Credentials
from database.model import CredentialType
from database.model import HostHostNameMapping
from database.model import HostNameHostNameMapping
from database.model import DnsResourceRecordType
from database.model import ServiceMethod
from database.model import HttpQuery
from database.model import File
from database.model import CommandFileMapping
from database.model import AdditionalInfo
from database.model import Company
from database.model import TlsInfo
from database.model import TlsVersion
from database.model import TlsPreference
from database.model import CipherSuite
from database.model import TlsInfoCipherSuiteMapping
from database.model import AsymmetricAlgorithm
from database.model import HashAlgorithm
from database.model import CertType
from database.model import CertInfo
from database.model import VHostNameMapping
from datetime import datetime
from typing import Dict
from database.model import CommandStatus
from database.model import ScopeType
from database.model import ExecutionInfoType
from database.utils import Engine
from view.core import ReportItem
from collectors.core import XmlUtils
from collectors.core import DomainUtils
from collectors.core import IpUtils
from sqlalchemy.orm.session import Session


class BaseKisTestCase(unittest.TestCase):
    """
    This method implements all base functionalities for test cases
    """
    def __init__(self, test_name: str):
        super().__init__(test_name)
        self._engine = None
        # we re-initialize the testing database
        self._domain_utils = DomainUtils()
        self._ip_utils = IpUtils()
        self._xml_utils = XmlUtils()
        self._source_name = self.__class__.__name__
        self._report_item = ReportItem(ip="192.168.0.0/24",
                                       port=80,
                                       protocol="tcp",
                                       collector_name=self._source_name)
        self._workspaces = ['test1', 'test2']

    def setUp(self):
        self._engine = Engine(production=False)

    def tearDown(self) -> None:
        self._engine.engine.dispose()

    @staticmethod
    def _reset_report_item(report_item: ReportItem):
        if report_item:
            report_item.details = None
            report_item.report_type = None
        return report_item

    @staticmethod
    def split_domain_name(host_name: str) -> List[str]:
        tmp = host_name.split(".")
        if len(tmp) == 0:
            raise ValueError("not a valid host name")
        elif len(tmp) == 1:
            domain = tmp[0]
            host = None
        else:
            domain = ".".join(tmp[-2:])
            host = ".".join(tmp[:-2])
            host = host if host else None
        return [host, domain]

    @staticmethod
    def split_email(email_address: str) -> List[str]:
        if email_address.count("@") != 1:
            raise ValueError("not a valid email address")
        name, host_name = email_address.split("@")
        host, domain = BaseKisTestCase.split_domain_name(host_name)
        return [name, host, domain]

    @staticmethod
    def get_local_ip() -> str:
        ip_address = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
                             if not ip.startswith("127.")][:1], [
            [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in
             [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
        if not ip_address:
            raise ValueError("the os machine does not have a local IP address")
        return ip_address

    def init_db(self, load_cipher_suites: bool = False):
        self._engine.drop()
        self._engine.init(load_cipher_suites)

    def create_workspace(self,
                         session: Session,
                         workspace: str = "unittest") -> Workspace:
        return self._engine.get_or_create(session, Workspace, name=workspace)

    def create_source(self,
                      session: Session,
                      source_str: str = None) -> Source:
        source = source_str if source_str else self._source_name
        return self._engine.get_or_create(session, Source, name=source)

    def create_host(self,
                    session: Session,
                    workspace_str: str = "unittest",
                    address: str = "192.168.1.1",
                    in_scope: bool = True) -> Host:
        workspace = self.create_workspace(session, workspace=workspace_str)
        host = IpUtils.add_host(session=session,
                                workspace=workspace,
                                address=address,
                                in_scope=in_scope)
        return host

    def create_network(self,
                       session: Session,
                       workspace_str: str = "unittest",
                       network: str = "192.168.1.0/24",
                       scope: ScopeType = ScopeType.all) -> Network:
        workspace = self.create_workspace(session, workspace=workspace_str)
        host = IpUtils.add_network(session=session,
                                   workspace=workspace,
                                   network=network,
                                   scope=scope)
        return host

    def create_company(self,
                       session: Session,
                       workspace_str: str = "unittest",
                       name_str: str = "test llc",
                       ipv4_network_str: str = None,
                       host_name_str: str = None,
                       verify: bool = True,
                       source_str: str = "unittest") -> Company:
        source = None
        ipv4_network = None
        host_name = None
        if workspace_str:
            workspace = self.create_workspace(session, workspace_str)
        if source_str:
            source = self.create_source(session=session, source_str=source_str)
        if ipv4_network_str:
            ipv4_network = self.create_network(session=session,
                                               workspace_str=workspace_str,
                                               network=ipv4_network_str,
                                               scope=ScopeType.all)
        elif host_name_str:
            host_name = self.create_hostname(session=session,
                                             workspace_str=workspace_str,
                                             host_name=host_name_str,
                                             scope=ScopeType.all)
        company = self._domain_utils.add_company(session=session,
                                                 workspace=workspace,
                                                 name=name_str,
                                                 network=ipv4_network,
                                                 domain_name=host_name.domain_name if host_name else None,
                                                 verify=verify,
                                                 source=source)
        return company

    def create_host_host_name_mapping(self,
                                      session: Session,
                                      workspace_str: str = "unittest",
                                      ipv4_address: str = "192.168.1.1",
                                      host_name_str: str = "www.unittest.com",
                                      mapping_type: DnsResourceRecordType = DnsResourceRecordType.a,
                                      host_name_scope: ScopeType = ScopeType.all,
                                      host_scope: bool = True,
                                      source_str: str = None) -> HostHostNameMapping:
        source = self.create_source(session, source_str=source_str) if source_str else None
        host = self.create_host(session=session,
                                workspace_str=workspace_str,
                                address=ipv4_address,
                                in_scope=host_scope)
        host_name = self.create_hostname(session=session,
                                         workspace_str=workspace_str,
                                         host_name=host_name_str,
                                         scope=host_name_scope)
        mapping = self._domain_utils.add_host_host_name_mapping(session=session,
                                                                host=host,
                                                                host_name=host_name,
                                                                mapping_type=mapping_type,
                                                                source=source)
        return mapping

    def create_host_name_host_name_mapping(self,
                                           session: Session,
                                           workspace_str: str = "unittest",
                                           source_host_name_str: str = "www.unittest1.com",
                                           resolved_host_name_str: str = "www.unittest2.com",
                                           mapping_type: DnsResourceRecordType = None,
                                           source_str: str = None) -> HostNameHostNameMapping:
        source = self.create_source(session, source_str=source_str) if source_str else None
        source_host_name = self.create_hostname(session=session,
                                                workspace_str=workspace_str,
                                                host_name=source_host_name_str)
        resolved_host_name = self.create_hostname(session=session,
                                                  workspace_str=workspace_str,
                                                  host_name=resolved_host_name_str)
        mapping = self._domain_utils.add_host_name_host_name_mapping(session=session,
                                                                     source_host_name=source_host_name,
                                                                     resolved_host_name=resolved_host_name,
                                                                     mapping_type=mapping_type,
                                                                     source=source)
        return mapping

    def create_service(self,
                       session: Session,
                       workspace_str: str = "unittest",
                       address: str = "192.168.1.1",
                       host_name_str: str = None,
                       port: int = 80,
                       protocol_type: ProtocolType = ProtocolType.tcp,
                       state: ServiceState = ServiceState.Open,
                       nmap_service_name: str = None,
                       nmap_tunnel: str = None,
                       nmap_service_confidence: int = None,
                       nessus_service_name: str = None,
                       scope: ScopeType = ScopeType.all) -> Service:
        host = None
        host_name = None
        port = port if port else 80
        address = address if address or host_name_str else "192.168.1.1"
        if host_name_str:
            host_name = self.create_hostname(session=session,
                                             workspace_str=workspace_str,
                                             host_name=host_name_str, scope=scope)
        else:
            host = self.create_host(session=session,
                                    workspace_str=workspace_str,
                                    address=address)
        service = self._domain_utils.add_service(session=session,
                                                 port=port,
                                                 protocol_type=protocol_type,
                                                 state=state,
                                                 nmap_service_name=nmap_service_name,
                                                 nmap_service_confidence=nmap_service_confidence,
                                                 nmap_tunnel=nmap_tunnel,
                                                 host=host,
                                                 host_name=host_name,
                                                 nessus_service_name=nessus_service_name)
        return service

    def create_email(self,
                     session: Session,
                     workspace_str: str = "unittest",
                     email_address: str = "test@test.com",
                     verify: bool = True,
                     scope: ScopeType = ScopeType.exclude) -> Email:
        workspace = self.create_workspace(session, workspace=workspace_str)
        email = self._domain_utils.add_email(session=session,
                                             workspace=workspace,
                                             text=email_address,
                                             verify=verify,
                                             scope=scope)
        return email

    def create_hostname(self,
                        session: Session,
                        workspace_str: str = "unittest",
                        host_name: str = "www.test.com",
                        scope: ScopeType = ScopeType.all) -> HostName:
        workspace = self.create_workspace(session, workspace=workspace_str)
        result = self._domain_utils.add_domain_name(session=session,
                                                    workspace=workspace,
                                                    item=host_name,
                                                    scope=scope)
        return result

    def create_domain_name(self,
                           session: Session,
                           workspace_str: str = "unittest",
                           host_name: str = "test.com",
                           scope: ScopeType = ScopeType.all) -> DomainName:
        workspace = self.create_workspace(session, workspace=workspace_str)
        domain_name = self._engine.get_or_create(session, DomainName, workspace=workspace, name=host_name)
        domain_name.scope = scope
        session.flush()
        return domain_name

    def create_collector_name(self,
                              session: Session,
                              name: str = "nikto",
                              type: CollectorType = CollectorType.host_service,
                              priority: int = 0):
        return self._engine.get_or_create(session, CollectorName, name=name, type=type, priority=priority)

    def create_command(self,
                       session: Session,
                       workspace_str: str = "unittest",
                       command: List[str] = ["nikto", "https://192.168.1.1"],
                       collector_name_str: str = "nikto",
                       collector_name_type: CollectorType = CollectorType.host_service,
                       ipv4_address: str = "192.168.1.1",
                       ipv4_network_str: str = None,
                       host_name_str: str = None,
                       email_str: str = None,
                       company_name_str: str = None,
                       service_port: int = 80,
                       scope: ScopeType = ScopeType.all,
                       stdout_output: str = None,
                       output_path: str = None,
                       xml_file: str = None,
                       binary_file: str = None,
                       exit_code: int = 0,
                       json_file: str = None) -> Command:
        collector_name_str = collector_name_str if collector_name_str else "nikto"
        service = None
        ipv4_network = None
        host_name = None
        email = None
        company_name = None
        if ipv4_network_str:
            ipv4_network = self.create_network(session=session,
                                               workspace_str=workspace_str,
                                               network=ipv4_network_str,
                                               scope=scope)
            collector_name_type = CollectorType.network
        elif host_name_str:
            host_name = self.create_hostname(session=session,
                                             workspace_str=workspace_str,
                                             host_name=host_name_str,
                                             scope=scope)
            collector_name_type = CollectorType.domain
        elif email_str:
            email = self.create_email(session=session,
                                      workspace_str=workspace_str,
                                      email_address=email_str,
                                      scope=scope)
            collector_name_type = CollectorType.email
        elif company_name_str:
            company_name = self.create_company(session=session,
                                               workspace_str=workspace_str,
                                               name_str=company_name_str)
            collector_name_type = CollectorType.company
        elif ipv4_address:
            service = self.create_service(session=session,
                                          workspace_str=workspace_str,
                                          address=ipv4_address,
                                          port=service_port)
            collector_name_type = CollectorType.host_service
        collector_name = self.create_collector_name(session=session,
                                                    name=collector_name_str,
                                                    type=collector_name_type)
        result = self._domain_utils.add_command(session=session,
                                                os_command=command,
                                                collector_name=collector_name,
                                                service=service,
                                                network=ipv4_network,
                                                host_name=host_name,
                                                email=email,
                                                company=company_name)
        result.return_code = exit_code
        if result and stdout_output:
            result.stdout_output = stdout_output.split(os.linesep)
        if xml_file:
            result.execution_info[ExecutionInfoType.xml_output_file.name] = xml_file
        if json_file:
            result.execution_info[ExecutionInfoType.json_output_file.name] = json_file
        if binary_file:
            result.execution_info[ExecutionInfoType.binary_output_file.name] = binary_file
        if output_path:
            result.execution_info[ExecutionInfoType.output_path.name] = output_path
        return result

    def create_path(self,
                    session: Session,
                    workspace_str: str = "unittest",
                    path: str = "/tmp",
                    path_type: PathType = PathType.filesystem,
                    size_bytes: int = None,
                    return_code: int = None,
                    service: Service = None) -> Path:
        if not service:
            service = self.create_service(session=session,
                                          workspace_str=workspace_str)
        result = self._domain_utils.add_path(session=session,
                                             service=service,
                                             path=path,
                                             path_type=path_type,
                                             size_bytes=size_bytes,
                                             return_code=return_code)
        return result

    def create_credential(self,
                          session: Session,
                          workspace_str: str = "unittest",
                          username: str = "testuser",
                          password: str = "password",
                          credential_type: CredentialType = CredentialType.cleartext,
                          domain: str = None,
                          service: Service = None,
                          email: Email = None) -> Credentials:
        if email:
            username = None
        if not service and not email:
            service = self.create_service(session=session,
                                          workspace_str=workspace_str)
        result = self._domain_utils.add_credential(session=session,
                                                   password=password,
                                                   credential_type=credential_type,
                                                   username=username,
                                                   domain=domain,
                                                   service=service,
                                                   email=email)
        return result

    def create_tls_info(self,
                        session: Session,
                        service: Service = None,
                        version: TlsVersion = TlsVersion.tls12,
                        preference: TlsPreference = TlsPreference.server,
                        compressors: List[str] = []) -> TlsInfo:
        if not service:
            service = self.create_service(session)
        result = self._domain_utils.add_tls_info(session,
                                                 service=service,
                                                 version=version,
                                                 preference=preference,
                                                 compressors=compressors)
        return result

    def create_tls_info_cipher_suite_mapping(self,
                                             session: Session,
                                             tls_info: TlsInfo = None,
                                             cipher_suite: CipherSuite = None,
                                             order: int = 1,
                                             kex_algorithm_details: KeyExchangeAlgorithm = KeyExchangeAlgorithm.dh,
                                             prefered: bool = False) -> TlsInfoCipherSuiteMapping:
        if not tls_info:
            tls_info = self.create_tls_info(session=session)
        if not cipher_suite:
            cipher_suite = self.query_cipher_suite(session=session)
        result = self._domain_utils.add_tls_info_cipher_suite_mapping(session=session,
                                                                      tls_info=tls_info,
                                                                      cipher_suite=cipher_suite,
                                                                      order=order,
                                                                      prefered=prefered,
                                                                      kex_algorithm_details=kex_algorithm_details)
        return result

    def create_cert_info(self,
                         session: Session,
                         service: Service = None,
                         company: Company = None,
                         host_name: HostName = None,
                         common_name: str = "www.test.com",
                         issuer_name: str = "www.test.com",
                         serial_number: str = 1,
                         signature_asym_algorithm: AsymmetricAlgorithm = AsymmetricAlgorithm.rsa1024,
                         hash_algorithm: HashAlgorithm = HashAlgorithm.sha256,
                         cert_type: CertType = CertType.root,
                         signature_bits: int = 2048,
                         valid_from: datetime = datetime.now(),
                         valid_until: datetime = datetime.now(),
                         subject_alt_names: List[str] = [],
                         extension_info: Dict[str, str] = {}):
        if not service and not host_name and not company:
            service = self.create_service(session=session)
        result = self._domain_utils.add_cert_info(session=session,
                                                  service=service,
                                                  company=company,
                                                  host_name=host_name,
                                                  serial_number=serial_number,
                                                  common_name=common_name,
                                                  issuer_name=issuer_name,
                                                  signature_asym_algorithm=signature_asym_algorithm,
                                                  hash_algorithm=hash_algorithm,
                                                  cert_type=cert_type,
                                                  signature_bits=signature_bits,
                                                  valid_from=valid_from,
                                                  valid_until=valid_until,
                                                  subject_alt_names=subject_alt_names,
                                                  extension_info=extension_info)
        return result

    def query_hostname(self, session: Session, workspace_str: str, host_name: str) -> HostName:
        host, domain = self.split_domain_name(host_name)
        return session.query(HostName)\
            .join(DomainName)\
            .join(Workspace)\
            .filter(HostName.name == host,
                    DomainName.name == domain,
                    Workspace.name == workspace_str).one_or_none()

    def query_domainname(self, session: Session, workspace_str: str, domain_name: str) -> DomainName:
        return session.query(DomainName)\
            .join(Workspace)\
            .filter(DomainName.name == domain_name,
                    Workspace.name == workspace_str).one_or_none()

    def query_ipv4network(self, session: Session, workspace_str: str, ipv4_network: str) -> Network:
        return session.query(Network)\
            .join(Workspace)\
            .filter(Network.network == ipv4_network,
                    Workspace.name == workspace_str).one_or_none()

    def query_email(self, session: Session, workspace_str: str, email_address: str) -> Email:
        email, host, domain = self.split_email(email_address)
        return session.query(Email)\
            .join(HostName)\
            .join(DomainName)\
            .join(Workspace)\
            .filter(Email.address == email,
                    HostName.name == host,
                    DomainName.name == domain,
                    Workspace.name == workspace_str).one_or_none()

    def query_company(self, session: Session, workspace_str: str, name: str) -> Company:
        return session.query(Company)\
            .join(Workspace)\
            .filter(Company.name == name,
                    Workspace.name == workspace_str).one_or_none()

    def query_host(self, session: Session, workspace_str: str, ipv4_address: str) -> Host:
        return session.query(Host) \
            .join(Workspace) \
            .filter(Host.address == ipv4_address,
                    Workspace.name == workspace_str).one_or_none()

    def query_cipher_suite(self,
                           session: Session,
                           iana_name: str = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") -> CipherSuite:
        return session.query(CipherSuite).filter_by(iana_name=iana_name).one()

    def query_path(self,
                   session: Session,
                   workspace_str: str,
                   path: str,
                   ipv4_address: str = None,
                   service_port: int = 80,
                   host_name: str = None) -> Path:
        rvalue = None
        if ipv4_address:
            rvalue = session.query(Path) \
                .join(Service) \
                .join(Host) \
                .join(Workspace) \
                .filter(Host.address == ipv4_address,
                        Service.port == service_port,
                        Path.name == path,
                        Workspace.name == workspace_str).one_or_none()
        if host_name:
            host_part, domain_part = self.split_domain_name(host_name=host_name)
            rvalue = session.query(Path) \
                .join(Service) \
                .join(HostName) \
                .join(DomainName) \
                .join(Workspace) \
                .filter(HostName.name == host_part,
                        DomainName.name == domain_part,
                        Service.port == service_port,
                        Path.name == path,
                        Workspace.name == workspace_str).one_or_none()
        return rvalue

    def query_credential(self,
                         session: Session,
                         workspace_str: str,
                         username: str = "testuser",
                         ipv4_address: str = None,
                         service_port: int = 80,
                         host_name: str = None,
                         email_address: str = None) -> Credentials:
        rvalue = None
        if ipv4_address:
            rvalue = session.query(Credentials) \
                .join(Service) \
                .join(Host) \
                .join(Workspace) \
                .filter(Host.address == ipv4_address,
                        Service.port == service_port,
                        Credentials.username == username,
                        Workspace.name == workspace_str).one_or_none()
        if host_name:
            host_part, domain_part = self.split_domain_name(host_name=host_name)
            rvalue = session.query(Credentials) \
                .join(Service) \
                .join(HostName) \
                .join(DomainName) \
                .join(Workspace) \
                .filter(HostName.name == host_part,
                        DomainName.name == domain_part,
                        Service.port == service_port,
                        Credentials.username == username,
                        Workspace.name == workspace_str).one_or_none()
        if email_address:
            email_part, host_part, domain_part = self.split_email(email_address=email_address)
            rvalue = session.query(Credentials) \
                .join(Email) \
                .join(HostName) \
                .join(DomainName) \
                .join(Workspace) \
                .filter(HostName.name == host_part,
                        DomainName.name == domain_part,
                        Email.address == email_part,
                        Workspace.name == workspace_str).one_or_none()
        return rvalue

    def query_command(self,
                      session: Session,
                      workspace_str: str,
                      command_str: List[str],
                      collector_name: str,
                      collector_name_type: CollectorType = None,
                      service_port: int = 80,
                      ipv4_address: str = None,
                      ipv4_network: str = None,
                      host_name: str = None) -> Credentials:
        rvalue = None
        if ipv4_address:
            collector_name_type = collector_name_type if collector_name_type else CollectorType.host_service
            rvalue = session.query(Command) \
                .join(CollectorName) \
                .join((Service, Command.service)) \
                .join(Host) \
                .join(Workspace) \
                .filter(Host.address == ipv4_address,
                        Service.port == service_port,
                        Command.os_command.op("=")(command_str),
                        CollectorName.type == collector_name_type,
                        CollectorName.name == collector_name,
                        Workspace.name == workspace_str).one_or_none()
        if host_name:
            collector_name_type = collector_name_type if collector_name_type else CollectorType.domain
            host_part, domain_part = self.split_domain_name(host_name=host_name)
            rvalue = session.query(Command) \
                .join(CollectorName) \
                .join((HostName, Command.host_name)) \
                .join(DomainName) \
                .join(Workspace) \
                .filter(HostName.name == host_part,
                        DomainName.name == domain_part,
                        Command.os_command.op("=")(command_str),
                        CollectorName.type == collector_name_type,
                        CollectorName.name == collector_name,
                        Workspace.name == workspace_str).one_or_none()
        if ipv4_network:
            collector_name_type = collector_name_type if collector_name_type else CollectorType.network
            rvalue = session.query(Command) \
                .join(CollectorName) \
                .join((Network, Command.ipv4_network)) \
                .join(Workspace) \
                .filter(Network.network == ipv4_network,
                        Command.os_command.op("=")(command_str),
                        CollectorName.type == collector_name_type,
                        CollectorName.name == collector_name,
                        Workspace.name == workspace_str).one_or_none()
        return rvalue

    def _populate_all_tables(self, session: Session, workspace_str: str):
        """
        This method writes data into each database table
        :param session:
        :param workspace_str:
        :return:
        """
        source = self.create_source(session=session, source_str="whoishost")
        workspace = self._engine.get_or_create(session, Workspace, name=workspace_str)
        # add IPv4 network and host
        network = self.create_network(session=session,
                                      workspace_str=workspace_str,
                                      network="192.168.1.0/24")
        source.ipv4_networks.append(network)
        host = self._ip_utils.add_host(session=session,
                                       workspace=workspace,
                                       address="192.168.1.1",
                                       source=source)
        # add host names
        host_name = self._domain_utils.add_domain_name(session=session,
                                                       workspace=workspace,
                                                       item="www.unittest.com",
                                                       source=source)
        self._domain_utils.add_host_host_name_mapping(session=session,
                                                      host=host,
                                                      host_name=host_name,
                                                      mapping_type=DnsResourceRecordType.a,
                                                      source=source)
        resolved_host_name = self._domain_utils.add_domain_name(session=session,
                                                                workspace=workspace,
                                                                item="resolved.unittest.com",
                                                                source=source)
        self._domain_utils.add_host_name_host_name_mapping(session=session,
                                                           source_host_name=host_name,
                                                           resolved_host_name=resolved_host_name,
                                                           source=source,
                                                           mapping_type=DnsResourceRecordType.cname)
        # add email
        email = self.create_email(session=session,
                                  workspace_str=workspace_str,
                                  email_address="test@www.unittest.com",
                                  verify=True,
                                  scope=ScopeType.all)
        source.emails.append(email)
        # add service, paths, and methods
        service = self._domain_utils.add_service(session=session,
                                                 port=80,
                                                 protocol_type=ProtocolType.tcp,
                                                 host=host,
                                                 state=ServiceState.Open,
                                                 source=self.create_source(session=session,
                                                                           source_str="shodanhost"))
        self._domain_utils.add_url_path(session=session,
                                        service=service,
                                        url_path="/test?a=b",
                                        source=self.create_source(session=session, source_str="nikto"))
        self._domain_utils.add_service_method(session=session,
                                              name="PUT",
                                              service=service,
                                              source=self.create_source(session=session,
                                                                        source_str="nikto"))
        # add credentials
        self._domain_utils.add_credential(session=session,
                                          password="test",
                                          credential_type=CredentialType.cleartext,
                                          username="test",
                                          domain="test",
                                          source=self.create_source(session=session, source_str="ftphydra"),
                                          service=service)
        self._domain_utils.add_credential(session=session,
                                          password="test",
                                          credential_type=CredentialType.cleartext,
                                          domain="test",
                                          source=self.create_source(session=session, source_str="ftphydra"),
                                          email=email)
        # add company
        company = self._domain_utils.add_company(session=session,
                                                 workspace=workspace,
                                                 name="Test LLC",
                                                 network=network,
                                                 verify=False,
                                                 source=self.create_source(session=session, source_str="whoishost"))
        self._domain_utils.add_company(session=session,
                                       workspace=workspace,
                                       name="Test LLC",
                                       domain_name=host_name.domain_name,
                                       verify=False,
                                       source=self.create_source(session=session, source_str="whoisdomain"))
        # add additional info
        self._domain_utils.add_additional_info(session=session,
                                               name="test",
                                               values=["test"],
                                               source=self.create_source(session=session,
                                                                         source_str="tcpnmap"),
                                               service=service)
        self._domain_utils.add_additional_info(session=session,
                                               name="test",
                                               values=["test"],
                                               source=self.create_source(session=session,
                                                                         source_str="tcpnmap"),
                                               host_name=host_name)
        self._domain_utils.add_additional_info(session=session,
                                               name="test",
                                               values=["test"],
                                               source=self.create_source(session=session,
                                                                         source_str="tcpnmap"),
                                               email=email)
        self._domain_utils.add_additional_info(session=session,
                                               name="test",
                                               values=["test"],
                                               source=self.create_source(session=session,
                                                                         source_str="tcpnmap"),
                                               host=host)
        self._domain_utils.add_additional_info(session=session,
                                               name="test",
                                               values=["test"],
                                               source=self.create_source(session=session,
                                                                         source_str="tcpnmap"),
                                               ipv4_network=network)
        # add command
        self._domain_utils.add_command(session=session,
                                       os_command=["nmap", "10"],
                                       collector_name=self._engine.get_or_create(session,
                                                                                 CollectorName,
                                                                                 name="test",
                                                                                 type=CollectorType.host_service,
                                                                                 priority=0),
                                       service=service)
        self._domain_utils.add_command(session=session,
                                       os_command=["nmap", "10"],
                                       collector_name=self._engine.get_or_create(session,
                                                                                 CollectorName,
                                                                                 name="tcpnmap",
                                                                                 type=CollectorType.network,
                                                                                 priority=0),
                                       network=network)
        command = self._domain_utils.add_command(session=session,
                                                 os_command=["whois", "10"],
                                                 collector_name=self._engine.get_or_create(session,
                                                                                           CollectorName,
                                                                                           name="test",
                                                                                           type=CollectorType.host,
                                                                                           priority=0),
                                                 host=host)
        command.status = CommandStatus.completed
        self._domain_utils.add_command(session=session,
                                       os_command=["whois", "10"],
                                       collector_name=self._engine.get_or_create(session,
                                                                                 CollectorName,
                                                                                 name="test",
                                                                                 type=CollectorType.domain,
                                                                                 priority=0),
                                       host_name=host_name)
        command = self._domain_utils.add_command(session=session,
                                                 os_command=["kisimport", "10"],
                                                 collector_name=self._engine.get_or_create(session,
                                                                                           CollectorName,
                                                                                           name="test",
                                                                                           type=CollectorType.email,
                                                                                           priority=0),
                                                 email=email)
        # add file
        self._domain_utils.add_file_content(session=session,
                                            workspace=self._engine.get_or_create(session,
                                                                                 Workspace,
                                                                                 name=workspace_str),
                                            command=command,
                                            file_name="test",
                                            file_type=FileType.text,
                                            content=b'test')
        # add cert info
        self.create_cert_info(session=session, service=service, common_name="www.test.com")
        self.create_cert_info(session=session, company=company, common_name="www.test.com")
        self.create_cert_info(session=session, host_name=host_name, common_name="www.test.com")
        # add tls info
        tls_info = self.create_tls_info(session=session, service=service, version=TlsVersion.tls13)
        cipher_suite = self.query_cipher_suite(session=session, iana_name="TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
        self.create_tls_info_cipher_suite_mapping(session=session, tls_info=tls_info, cipher_suite=cipher_suite)
        # add vhosts
        session.add(VHostNameMapping(host_name=host_name, service=service, return_code=200, size_bytes=2353))
        session.add(VHostNameMapping(host=host, service=service, return_code=201, size_bytes=321))
        # TODO: Update when adding a new table

    def _check_database(self, session: Session, workspace: str):
        """
        Checks whether method _populate_all_tables populated the data correctly
        :param session:
        :param workspace:
        :return:
        """
        host = session.query(Host) \
            .join(Network) \
            .join(Workspace) \
            .filter(Workspace.name == workspace).one()
        host_name = session.query(HostName) \
            .join(DomainName) \
            .join(Workspace) \
            .filter(Workspace.name == workspace, HostName.name == "www").one()
        resolved_host_name = session.query(HostName) \
            .join(DomainName) \
            .join(Workspace) \
            .filter(Workspace.name == workspace, HostName.name == "resolved").one()
        # check host
        self.assertEqual("192.168.1.1", host.address)
        self.assertEqual("whoishost", host.sources[0].name)
        # check service and service method
        self.assertEqual(80, host.services[0].port)
        self.assertEqual("shodanhost", host.services[0].sources[0].name)
        self.assertEqual("PUT", host.services[0].service_methods[0].name)
        # check path and query
        self.assertListEqual(["/", "/test"], [item.name for item in host.services[0].paths])
        self.assertEqual("nikto", host.services[0].paths[1].sources[0].name)
        self.assertEqual("a=b", host.services[0].paths[1].queries[0].query)
        # check credentials
        self.assertEqual("test", host.services[0].credentials[0].password)
        self.assertEqual("ftphydra", host.services[0].credentials[0].sources[0].name)
        self.assertEqual("test", host_name.emails[0].credentials[0].password)
        self.assertEqual("ftphydra", host_name.emails[0].credentials[0].sources[0].name)
        # check IPv4 network and company
        self.assertEqual("192.168.1.0/24", host.ipv4_network.network)
        self.assertEqual("whoishost", host.ipv4_network.sources[0].name)
        self.assertEqual("test llc", host.ipv4_network.companies[0].name)
        self.assertEqual(workspace, host.ipv4_network.workspace.name)
        # check host name, domain, and company
        self.assertEqual("www.unittest.com", host_name.full_name)
        self.assertEqual("whoishost", host_name.sources[0].name)
        self.assertEqual("resolved.unittest.com", resolved_host_name.full_name)
        self.assertEqual("whoishost", resolved_host_name.sources[0].name)
        self.assertEqual("unittest.com", host_name.domain_name.name)
        self.assertEqual("test llc", host_name.domain_name.companies[0].name)
        self.assertEqual("whoisdomain", host_name.domain_name.companies[0].sources[0].name)
        self.assertEqual(workspace, host_name.domain_name.workspace.name)
        # check email
        self.assertEqual("test@www.unittest.com", host_name.emails[0].email_address)
        self.assertEqual("whoishost", host_name.emails[0].sources[0].name)
        # check additional info
        self.assertEqual("test", host.services[0].additional_info[0].name)
        self.assertEqual("tcpnmap", host.services[0].additional_info[0].sources[0].name)
        self.assertEqual("test", host.ipv4_network.additional_info[0].name)
        self.assertEqual("tcpnmap", host.ipv4_network.additional_info[0].sources[0].name)
        self.assertEqual("test", host.additional_info[0].name)
        self.assertEqual("tcpnmap", host.additional_info[0].sources[0].name)
        self.assertEqual("test", host_name.additional_info[0].name)
        self.assertEqual("tcpnmap", host_name.additional_info[0].sources[0].name)
        self.assertEqual("test", host_name.emails[0].additional_info[0].name)
        self.assertEqual("tcpnmap", host_name.emails[0].additional_info[0].sources[0].name)
        # check command
        self.assertEqual("test", host.commands[0].collector_name.name)
        self.assertEqual("test", host_name.commands[0].collector_name.name)
        self.assertEqual("test", host_name.emails[0].commands[0].collector_name.name)
        self.assertEqual("test", host.services[0].commands[0].collector_name.name)
        self.assertEqual("tcpnmap", host.ipv4_network.commands[0].collector_name.name)
        # cert info
        self.assertEqual("www.test.com", host.services[0].cert_info[0].common_name)
        # tls info
        self.assertEqual(TlsVersion.tls13, host.services[0].tls_info[0].version)
        self.assertEqual("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                         host.services[0].tls_info[0].cipher_suite_mappings[0].cipher_suite.iana_name)
        # check file
        self.assertEqual(b"test", host_name.emails[0].commands[0].files[0].content)
        # check vhost
        self.assertEqual(1, len(host_name.vhosts))
        self.assertEqual(200, host_name.vhosts[0].return_code)
        self.assertEqual(1, len(host.vhosts))
        self.assertEqual(201, host.vhosts[0].return_code)
        # TODO: Update when adding a new table

    def _check_database_empty(self, session: Session):
        self.assertEqual(0, session.query(Workspace).count())
        self.assertEqual(0, session.query(Network).count())
        self.assertEqual(0, session.query(Company).count())
        self.assertEqual(0, session.query(Host).count())
        self.assertEqual(0, session.query(HostName).count())
        self.assertEqual(0, session.query(HostHostNameMapping).count())
        self.assertEqual(0, session.query(HostNameHostNameMapping).count())
        self.assertEqual(0, session.query(DomainName).count())
        self.assertEqual(0, session.query(Email).count())
        self.assertEqual(0, session.query(Service).count())
        self.assertEqual(0, session.query(ServiceMethod).count())
        self.assertEqual(0, session.query(Path).count())
        self.assertEqual(0, session.query(Credentials).count())
        self.assertEqual(0, session.query(HttpQuery).count())
        self.assertEqual(0, session.query(Command).count())
        self.assertEqual(0, session.query(File).count())
        self.assertEqual(0, session.query(CommandFileMapping).count())
        self.assertEqual(6, session.query(Source).count())
        self.assertEqual(0, session.query(AdditionalInfo).count())
        self.assertEqual(5, session.query(CollectorName).count())
        self.assertEqual(0, session.query(CertInfo).count())
        self.assertEqual(0, session.query(TlsInfo).count())
        self.assertEqual(0, session.query(TlsInfoCipherSuiteMapping).count())
        self.assertEqual(0, session.query(VHostNameMapping).count())
        self.assertEqual(339, session.query(CipherSuite).count())
        # TODO: Update when adding a new table


class BaseDataModelTestCase(BaseKisTestCase):
    """
    This class implements functionalities for testing the data model
    """

    def __init__(self, test_name: str, model: type):
        super().__init__(test_name)
        self._model = model

    def _test_success(self,
                      session: Session,
                      **kwargs):
        result = self._model(**kwargs)
        session.add(result)
        session.commit()
        self.assertIsNotNone(result)
        return result

    def _test_unique_constraint(self, session: Session,
                                ex_message: str = "duplicate key value violates unique constraint",
                                **kwargs):
        try:
            result1 = self._model(**kwargs)
            result2 = self._model(**kwargs)
            session.add(result1)
            session.add(result2)
            session.commit()
        except Exception as ex:
            self.assertIn(ex_message, str(ex))
            session.rollback()
            return
        if ex_message:
            self.assertIsNone(result2)

    def _test_not_null_constraint(self,
                                  session: Session,
                                  ex_message: str = "violates not-null constraint",
                                  **kwargs):
        self._test_check_constraint(session=session,
                                    ex_message=ex_message,
                                    **kwargs)

    def _test_check_constraint(self,
                               session: Session,
                               ex_message: str = "violates check constraint",
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


class KisCommandEnum(enum.Enum):
    kiscollect = enum.auto()
    kismanage = enum.auto()
    kisreport = enum.auto()


class BaseTestKisCommand(BaseKisTestCase):
    """
    This class implements all base functionality for testing kismanage, kisreport, and kiscollect.
    """

    def __init__(self, command: KisCommandEnum, test_name: str):
        super().__init__(test_name)
        self._command = command
        self._workspace = "unittest"

    def execute(self, arguments: str, subcommand: str = None, expected_return_code: int = 0):
        """
        This method executes the current command and subcommand with the given argument and compares the return code
        with the expected return code.
        """
        command = "{} --testing {}".format(self._command.name, subcommand) \
            if subcommand else "{} --testing".format(self._command.name)
        final_command = "{} {}".format(command, arguments)
        result = subprocess.call(final_command, shell=True)
        if expected_return_code != result:
            print(final_command)
        self.assertEqual(expected_return_code, result)
