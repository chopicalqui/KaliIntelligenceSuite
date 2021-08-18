# -*- coding: utf-8 -*-
""""This file contains functionalities used by all collectors."""

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
import json
import re
import ipaddress
import xml
import xml.etree.ElementTree as ET
import logging
import hashlib
import io
import csv
import configs
from urllib.parse import urlparse
from xml.etree.ElementTree import Element
from typing import List
from typing import Dict
from typing import TypeVar
from database.model import Workspace
from database.model import HostName
from database.model import Email
from database.model import Host
from database.model import Source
from database.model import DomainName
from database.model import ProtocolType
from database.model import Network
from database.model import Path
from database.model import PathType
from database.model import HttpQuery
from database.model import Service
from database.model import Command
from database.model import CollectorType
from database.model import File
from database.model import CommandFileMapping
from database.model import Company
from database.model import Credentials
from database.model import AdditionalInfo
from database.model import ServiceState
from database.model import CollectorName
from database.model import FileType
from database.model import HostHostNameMapping
from database.model import HostNameHostNameMapping
from database.model import DnsResourceRecordType
from database.model import CipherSuite
from database.model import HashAlgorithm
from database.model import TlsInfo
from database.model import TlsVersion
from database.model import TlsPreference
from database.model import TlsInfoCipherSuiteMapping
from database.model import KeyExchangeAlgorithm
from database.model import CertInfo
from database.model import AsymmetricAlgorithm
from database.model import ExtensionType
from database.model import ScopeType
from database.model import DomainNameNotFound
from datetime import datetime
from database.model import ExecutionInfoType
from database.utils import Engine
from database.utils import CredentialType
from database.model import CertType
from database.utils import ServiceMethod
from view.core import ReportItem
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy.orm.session import Session

BaseCollector = TypeVar('collectors.os.collector.BaseCollector')

logger = logging.getLogger('collector')


class InvalidEmailFormatException(Exception):
    def __init__(self, ex):
        super().__init__(ex)


class BaseUtils:
    """This class implements all base functionality for providing intelligence services to KIS"""
    TLD_DEFINITION_FILE = 'top-level-domains.json'

    def __init__(self, **args):
        config = configs.config.Collector()
        self._re_domain = re.compile(DomainUtils.RE_DOMAIN, re.IGNORECASE)
        self._re_email = re.compile(EmailUtils.RE_EMAIL, re.IGNORECASE)
        self._top_level_domains = {}
        self._irrelevant_http_files = config.irrelevant_http_files
        self._utils_dir = os.path.join(os.path.dirname(__file__), '..', 'configs')
        self._args = args
        self._re_company_name = config.get_organization_re()
        self._re_robots_txt = [re.compile("^allow: *(?P<path>/.*)$", re.IGNORECASE),
                               re.compile("^disallow: *(?P<path>/.*)$", re.IGNORECASE),
                               re.compile("^(?P<path>/.*)", re.IGNORECASE)]
        with open(os.path.join(self._utils_dir, BaseUtils.TLD_DEFINITION_FILE), "r") as f:
            text = f.read()
            json_object = json.JSONDecoder().decode(text)
            for item in json_object["data"]:
                self._top_level_domains[item] = re.compile(".+\.{}\.?$".format(item.replace(".", "\\.")), re.IGNORECASE)

    @property
    def utils_dir(self):
        return self._utils_dir

    @staticmethod
    def get_list_as_csv(values: List[List[str]]) -> List[str]:
        """
        This method takes the given two-dimensional array and converts it into a CSV format
        :param values: The two-dimensional array to be converted
        :return:
        """
        output = io.StringIO()
        writer = csv.writer(output, dialect="excel")
        writer.writerows(values)
        text = output.getvalue()
        return text.split(os.linesep)

    @staticmethod
    def get_csv_as_list(values: List[str]) -> List[List[str]]:
        """
        This method is the counter part of the get_list_as_csv and takes a list of CSV strings and converts them into a
        two dimensional array
        :param values: The one-dimensional array that shall be converted
        :return:
        """
        return list(csv.reader(values, dialect="excel"))

    def is_verified_company_name(self, name) -> str:
        """
        This method returns the extracted company name or None if no company name matched.
        :param name: The name of the company
        :return:
        """
        result = None
        match = self._re_company_name.match(name)
        if match:
            result = match.group("name").strip()
        return result

    @staticmethod
    def add_workspace(session: Session, name: str) -> Workspace:
        """
        This method adds the given workspace to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param name: The name of the workspace to be added
        """
        workspace = BaseUtils.get_workspace(session=session, name=name)
        if not workspace:
            workspace = Workspace(name=name)
            session.add(workspace)
        return workspace

    @staticmethod
    def get_workspace(session: Session, name: str) -> Workspace:
        """
        This method returns the given workspace
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param name: The name of the workspace to be added
        """
        return session.query(Workspace).filter_by(name=name).one_or_none()

    @staticmethod
    def get_workspaces(session: Session) -> List[Workspace]:
        """
        This method returns all workspaces
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        """
        return session.query(Workspace).all()

    @staticmethod
    def delete_workspace(session: Session, workspace: str) -> None:
        """
        This method deletes the given workspace from the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param workspace: The name of the workspace to be added
        """
        session.query(Workspace).filter_by(name=workspace).delete()

    @staticmethod
    def add_host_host_name_mapping(session: Session,
                                   host: Host,
                                   host_name: HostName,
                                   mapping_type: DnsResourceRecordType,
                                   source: Source = None,
                                   report_item: ReportItem = None) -> HostHostNameMapping:
        """
        This method establishes a link between a host and a host name
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param host: The host object that shall be linked
        :param host_name: The host name object that shall be linked
        :param source: The source that identified the link
        :param mapping_type: The type of link
        :param report_item: Item that can be used for pushing information into the view
        """
        if not host or not host_name:
            raise ValueError("host and host name are mandatory")
        mapping = session.query(HostHostNameMapping) \
            .filter_by(host_id=host.id, host_name_id=host_name.id).one_or_none()
        if not mapping:
            mapping = HostHostNameMapping(host=host, host_name=host_name, type=mapping_type)
            session.add(mapping)
        if mapping_type:
            mapping.type |= mapping_type
        if source:
            mapping.sources.append(source)
        if report_item:
            source_info = " (source: {})".format(source.name) if source else ""
            report_item.details = "add potentially new link ({}) between {} and {}{}".format(mapping_type.name.upper(),
                                                                                             host.address,
                                                                                             host_name.full_name,
                                                                                             source_info)
            report_item.report_type = "GENERIC"
            report_item.notify()
        session.flush()
        return mapping

    @staticmethod
    def add_host_name_host_name_mapping(session: Session,
                                        source_host_name: HostName,
                                        resolved_host_name: HostName,
                                        source: Source = None,
                                        mapping_type: DnsResourceRecordType = None,
                                        report_item: ReportItem = None) -> HostNameHostNameMapping:
        """
        This method establishes a link between a host and a host name
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param source_host_name: The host name which resolves to the resolved host name
        :param resolved_host_name: The host name object that was resolved
        :param source: The source that identified the link
        :param mapping_type: The type of link
        :param report_item: Item that can be used for pushing information into the view
        """
        if not source_host_name or not resolved_host_name:
            raise ValueError("source and resolved host names are mandatory")
        mapping = session.query(HostNameHostNameMapping) \
            .filter_by(source_host_name_id=source_host_name.id,
                       resolved_host_name_id=resolved_host_name.id).one_or_none()
        if not mapping:
            mapping = HostNameHostNameMapping(source_host_name=source_host_name, resolved_host_name=resolved_host_name)
            session.add(mapping)
        if mapping_type:
            mapping.type |= mapping_type
        if source:
            mapping.sources.append(source)
        if report_item:
            source_info = " (source: {})".format(source.name) if source else ""
            report_item.details = "add potentially new link between {} and {}{}".format(source_host_name.full_name,
                                                                                        resolved_host_name.full_name,
                                                                                        source_info)
            report_item.report_type = "GENERIC"
            report_item.notify()
        session.flush()
        return mapping

    @staticmethod
    def add_collector_name(session: Session,
                           name: str,
                           type: CollectorType,
                           priority: int) -> CollectorName:
        result = session.query(CollectorName).filter_by(name=name, type=type).one_or_none()
        if not result:
            result = CollectorName(name=name, type=type, priority=priority)
            session.add(result)
            session.flush()
        else:
            result.priority = priority
        return result

    @staticmethod
    def add_command(session: Session,
                    os_command: List[str],
                    collector_name: CollectorName,
                    service: Service = None,
                    network: Network = None,
                    host: Host = None,
                    host_name: HostName = None,
                    email: Email = None,
                    company: Company = None,
                    xml_file: str = None,
                    json_file: str = None,
                    binary_file: str = None,
                    output_path: str = None,
                    input_file: str = None,
                    input_file_2: str = None,
                    working_directory: str = None,
                    exec_user: str = None) -> Command:
        """
        This method can be used by all collectors to create new commands in the database.
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param os_command: The os command as a list that shall be created
        :param service: The service object to which the collector belongs
        :param network: The IPv4 network object to which the collector belongs
        :param email: The email object to which the collector belongs
        :param company: The company object to which the collector belongs
        :param collector_name: The name of the collector
        :param xml_file: Path to the command's XML output file
        :param json_file: Path to the command's JSON output file
        :param binary_file: Path to the command's binary output file
        :param host: Host object to which the command belongs
        :param host_name: Host object to which the command belongs
        :param output_path: Path to the commands's output directory
        :param input_file: File which contains all the information for the target application (e.g. list of URLs for httpeyewitness)
        :param input_file_2: File which contains all the information for the target application (e.g. list of URLs for httpeyewitness)
        :param exec_user: The username with whom the command is executed
        :param working_directory: The command's working directory
        :return: The queried or newly created collector class
        """
        tmp = [str(item) for item in os_command]
        # todo: update for new collector
        if (service and host) or (service and host_name) or (service and network) or (service and email) or \
            (service and company) or (host and host_name) or (host and network) or (host and email) or \
            (host and company) or (host_name and network) or (host_name and email) or (host_name and company) or \
            (network and email) or (network and company) or (email and company):
            raise ValueError("command must be assigned either to a service, host, host name or "
                             "to an IPv4 network")
        if service:
            command = session.query(Command) \
                .join((Service, Command.service)) \
                .filter(Command.os_command.op('=')(tmp),
                        Command.collector_name_id == collector_name.id,
                        Service.id == service.id).one_or_none()
            if not command:
                command = Command(os_command=tmp,
                                  collector_name=collector_name,
                                  service=service)
                session.add(command)
                session.flush()
        elif host:
            command = session.query(Command) \
                .join((Host, Command.host)) \
                .filter(Command.os_command.op('=')(tmp),
                        Command.collector_name_id == collector_name.id,
                        Host.id == host.id).one_or_none()
            if not command:
                command = Command(os_command=tmp,
                                  collector_name=collector_name,
                                  host=host)
                session.add(command)
                session.flush()
        elif host_name:
            command = session.query(Command) \
                .join((HostName, Command.host_name)) \
                .filter(Command.os_command.op('=')(tmp),
                        Command.collector_name_id == collector_name.id,
                        HostName.id == host_name.id).one_or_none()
            if not command:
                command = Command(os_command=tmp,
                                  collector_name=collector_name,
                                  host_name=host_name)
                session.add(command)
                session.flush()
        elif network:
            command = session.query(Command) \
                .join((Network, Command.ipv4_network)) \
                .filter(Command.os_command.op('=')(tmp),
                        Command.collector_name_id == collector_name.id,
                        Network.id == network.id).one_or_none()
            if not command:
                command = Command(os_command=tmp,
                                  collector_name=collector_name,
                                  ipv4_network=network)
                session.add(command)
                session.flush()
        elif email:
            command = session.query(Command) \
                .join((Email, Command.email)) \
                .filter(Command.os_command.op('=')(tmp),
                        Command.collector_name_id == collector_name.id,
                        Email.id == email.id).one_or_none()
            if not command:
                command = Command(os_command=tmp,
                                  collector_name=collector_name,
                                  email=email)
                session.add(command)
                session.flush()
        elif company:
            command = session.query(Command) \
                .join((Company, Command.company)) \
                .filter(Command.os_command.op('=')(tmp),
                        Command.collector_name_id == collector_name.id,
                        Company.id == company.id).one_or_none()
            if not command:
                command = Command(os_command=tmp,
                                  collector_name=collector_name,
                                  company=company)
                session.add(command)
                session.flush()
        else:
            raise ValueError("command must be assigned to a service, host,  host name, or IPv4 network")
        if xml_file:
            command.execution_info[ExecutionInfoType.xml_output_file.name] = xml_file
        if json_file:
            command.execution_info[ExecutionInfoType.json_output_file.name] = json_file
        if output_path:
            command.execution_info[ExecutionInfoType.output_path.name] = output_path
        if binary_file:
            command.execution_info[ExecutionInfoType.binary_output_file.name] = binary_file
        if working_directory:
            command.execution_info[ExecutionInfoType.working_directory.name] = working_directory
        if exec_user:
            command.execution_info[ExecutionInfoType.username.name] = exec_user
        elif not exec_user and ExecutionInfoType.username.name in command.execution_info:
            del command.execution_info[ExecutionInfoType.username.name]
        command.execution_info[ExecutionInfoType.command_id.name] = command.id
        if input_file:
            if not os.path.isfile(input_file):
                raise FileNotFoundError("input file '{}' does not exist".format(input_file))
            command.execution_info[ExecutionInfoType.input_file.name] = input_file
        if input_file_2:
            if not os.path.isfile(input_file_2):
                raise FileNotFoundError("input file '{}' does not exist".format(input_file_2))
            command.execution_info[ExecutionInfoType.input_file_2.name] = input_file_2
        session.flush()
        return command

    @staticmethod
    def add_source(session: Session, name: str) -> Source:
        """
        This method adds the given company to the database
        :param session: The database session used for addition the IPv4 network
        :param name: The name of the company that should be added
        :return:
        """
        source = session.query(Source).filter_by(name=name).one_or_none()
        if not source:
            source = Source(name=name)
            session.add(source)
            session.flush()
        return source

    def add_service_method(self,
                           session: Session,
                           name: str,
                           service: Service = None,
                           source: Source = None,
                           report_item: ReportItem = None) -> ServiceMethod:
        """
        This method adds the given service method to the database
        :param session: The database session used for addition the IPv4 network
        :param name: The name of the HTTP method that should be added
        :param service: The service to which the method should be assigned
        :param source: The source object from which the URL originates
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        name = name.strip()
        service_method = session.query(ServiceMethod).filter_by(name=name, service_id=service.id).one_or_none()
        if not service_method:
            service_method = ServiceMethod(name=name, service=service)
            session.add(service_method)
            session.flush()
        if source:
            source.service_methods.append(service_method)
        if report_item:
            report_item.details = "add potentially dangerous service method {}".format(name)
            report_item.report_type = "METHOD"
            report_item.notify()
        return service_method

    def add_robots_txt(self,
                       session: Session,
                       service: Service,
                       robots_txt: List[str],
                       source: Source,
                       report_item: ReportItem = None) -> List[Path]:
        """
        This method establishes a link between a host and a host name
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service instance to which the identified paths are added
        :param robots_txt: The content of the robots.txt file that shall be parsed
        :param report_item: Item that can be used for pushing information into the view
        """
        paths = []
        for line in robots_txt:
            line = line.strip()
            line = line.split("#")[0]
            line_lower = line.lower()
            if line and line_lower.find("user-agent:") == -1 and line_lower.find("useragent:") == -1:
                for regex in self._re_robots_txt:
                    match = regex.match(line)
                    if match:
                        path = match.group("path")
                        tmp = self.add_url(session=session,
                                           service=service,
                                           url=path,
                                           source=source,
                                           report_item=report_item)
                        paths.append(tmp)
        return paths

    def add_company(self,
                    session: Session,
                    workspace: Workspace,
                    name: str,
                    network: Network = None,
                    domain_name: DomainName = None,
                    verify: bool = True,
                    source: Source = None,
                    in_scope: bool = None,
                    report_item: ReportItem = None) -> Company:
        """
        This method adds the given company to the database
        :param session: The database session used for addition the IPv4 network
        :param workspace: The workspace to which the company is added
        :param name: The name of the company that should be added
        :param verify: True if the given company name should be verified to ensure that it ends with legal entity type
        :param network: IPv4 network which is associated with the company
        :param domain_name: Domain name which is associated with the company
        :param in_scope: Specifies whether the given IP address is in scope or not
        :param source: The source object from which the URL originates
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        rvalue = None
        name = name.strip().lower()
        if not verify or (verify and self.is_verified_company_name(name)):
            rvalue = session.query(Company) \
                .filter_by(name=name,
                           workspace_id=workspace.id).one_or_none()
            if not rvalue:
                rvalue = Company(name=name, workspace=workspace)
                session.add(rvalue)
                session.flush()
            if network:
                network.companies.append(rvalue)
            if domain_name:
                domain_name.companies.append(rvalue)
            if in_scope is not None:
                rvalue.in_scope = in_scope
            if rvalue:
                if source:
                    source.companies.append(rvalue)
                if report_item:
                    if network:
                        message = "potentially new company for network {}: {}".format(network.network, name)
                    elif domain_name:
                        message = "potentially new company for domain {}: {}".format(domain_name.name, name)
                    else:
                        message = "potentially new company: {}".format(name)
                    report_item.details = message
                    report_item.report_type = "COMPANY"
                    report_item.notify()
        return rvalue

    @staticmethod
    def add_json_results(command: Command,
                         json_objects: List[Dict[str, str]]):
        """
        This method adds the given json objects to the given command
        :param command:
        :param json_objects:
        :return:
        """
        if command and json_objects:
            json_objects = [json_objects] if not isinstance(json_objects, list) else json_objects
            if not command.json_output:
                command.json_output = []
            for item in json_objects:
                if item and item not in command.json_output:
                    command.json_output.append(item)

    @staticmethod
    def add_binary_result(command: Command, content: bytes):
        """
        This method adds the given binary content to the given command
        :param command:
        :param content:
        :return:
        """
        if command and content:
            command.binary_output = content if isinstance(content, bytes) else str(content).encode("utf-8")

    def add_additional_info(self,
                            session: Session,
                            name: str,
                            values: List[str],
                            source: Source = None,
                            service: Service = None,
                            host_name: HostName = None,
                            email: Email = None,
                            company: Company = None,
                            host: Host = None,
                            ipv4_network: Network = None,
                            report_item: ReportItem = None) -> AdditionalInfo:
        """
        This method should be used by collectors to add credentials to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service object to which the additional information belongs
        :param host_name: The host name object to which the additional information belongs
        :param email: The email object to which the additional information belongs
        :param company: The email object to which the additional information belongs
        :param host: The host object to which the additional information belongs
        :param ipv4_network: The IPv4 network object to which the additional information belongs
        :param name: The name of the additional information
        :param values: List of values for the additional information
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        tmp = values if isinstance(values, list) else [values]
        values = [item for item in tmp if item]
        if not values:
            return None
        if (service and host_name) or (service and email) or (service and host) or \
            (service and ipv4_network) or (service and company) or (host_name and email) or \
            (host_name and host) or (host_name and ipv4_network) or (host_name and company) or \
            (email and host) or (email and ipv4_network) or (email and company) or \
            (host and ipv4_network) or (host and company) or (ipv4_network and company):
            raise ValueError("additional info must either be assigned to a service, host name, tag info, email, host, "
                             "or IPv4 network")
        if service:
            additional_info = session.query(AdditionalInfo).filter_by(name=name,
                                                                      service_id=service.id).one_or_none()
            if not additional_info:
                additional_info = AdditionalInfo(name=name, service=service)
                session.add(additional_info)
                session.flush()
        elif host_name:
            additional_info = session.query(AdditionalInfo).filter_by(name=name,
                                                                      host_name_id=host_name.id).one_or_none()
            if not additional_info:
                additional_info = AdditionalInfo(name=name, host_name=host_name)
                session.add(additional_info)
                session.flush()
        elif email:
            additional_info = session.query(AdditionalInfo).filter_by(name=name,
                                                                      email_id=email.id).one_or_none()
            if not additional_info:
                additional_info = AdditionalInfo(name=name, email=email)
                session.add(additional_info)
                session.flush()
        elif company:
            additional_info = session.query(AdditionalInfo).filter_by(name=name,
                                                                      company_id=company.id).one_or_none()
            if not additional_info:
                additional_info = AdditionalInfo(name=name, company=company)
                session.add(additional_info)
                session.flush()
        elif host:
            additional_info = session.query(AdditionalInfo).filter_by(name=name,
                                                                      host_id=host.id).one_or_none()
            if not additional_info:
                additional_info = AdditionalInfo(name=name, host=host)
                session.add(additional_info)
                session.flush()
        elif ipv4_network:
            additional_info = session.query(AdditionalInfo).filter_by(name=name,
                                                                      ipv4_network_id=ipv4_network.id).one_or_none()
            if not additional_info:
                additional_info = AdditionalInfo(name=name, ipv4_network=ipv4_network)
                session.add(additional_info)
                session.flush()
        else:
            raise ValueError("additional info must be assigned to a service, host name, or a tag info")
        if additional_info:
            if source:
                source.additional_info.append(additional_info)
            # Make sure that values remain unique
            for item in values:
                if item not in additional_info.values:
                    additional_info.append(item)
            if report_item:
                report_item.details = "{}: {}".format(name, ", ".join(values))
                report_item.report_type = "GENERIC"
                report_item.notify()
        return additional_info

    def add_credential(self,
                       session: Session,
                       password: str,
                       credential_type: CredentialType,
                       username: str = None,
                       domain: str = None,
                       source: Source = None,
                       service: Service = None,
                       email: Email = None,
                       report_item: ReportItem = None) -> Credentials:
        """
        This method should be used by collectors to add credentials to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service object to which the credentials belongs
        :param domain: The username that shall be added
        :param username: The username that shall be added
        :param password: The password that shall be added
        :param credential_type: The credential type that shall be added
        :param source: The source object of the current collector
        :param email: The email object to which the credentials belongs
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if username and email:
            raise ValueError("user name must not be specified together with an email address")
        if service and email:
            raise ValueError("credential must either be assigned to an email address or a service")
        if password and not credential_type:
            raise ValueError("password type is missing for password")
        if service:
            credential = session.query(Credentials) \
                .filter_by(username=username,
                           password=password,
                           domain=domain,
                           type=credential_type,
                           service_id=service.id).one_or_none()
            if not credential:
                credential = Credentials(username=username,
                                         password=password,
                                         domain=domain,
                                         type=credential_type,
                                         service=service)
                session.add(credential)
                session.flush()
            credential.complete = password is not None
            if report_item:
                if username is not None and password is not None:
                    report_item.details = "potentially new user {} with password {}".format(username, password)
                elif username is None and password is not None:
                    report_item.details = "potentially new password {}".format(password)
                elif username is not None and password is None:
                    report_item.details = "potentially new user {}".format(username)
                else:
                    report_item.details = "potentially new item"
                report_item.report_type = "CREDS"
                report_item.notify()
        elif email:
            credential = session.query(Credentials) \
                .filter_by(username=username,
                           password=password,
                           domain=domain,
                           type=credential_type,
                           email_id=email.id).one_or_none()
            if not credential:
                credential = Credentials(username=username,
                                         password=password,
                                         domain=domain,
                                         type=credential_type,
                                         email=email)
                session.add(credential)
                session.flush()
            # SNMP has only a password
            credential.complete = password is not None
            if report_item:
                report_item.details = "potentially new user {} with password {}".format(email.email_address,
                                                                                        password if password else "")
                report_item.report_type = "CREDS"
                report_item.notify()
        else:
            raise ValueError("credential must be assigned to an email address or service")
        if credential and source:
            source.credentials.append(credential)
        return credential

    @staticmethod
    def add_path(session: Session,
                 service: Service,
                 path: str,
                 path_type: PathType,
                 size_bytes: int = None,
                 return_code: int = None,
                 source: Source = None,
                 report_item: ReportItem = None) -> Path:
        """
        This method should be used by collectors to add credentials to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service object to which the credentials belongs
        :param path: The path that shall be added
        :param path_type: The path type that shall be added
        :param size_bytes: The size of the file
        :param return_code: The HTTP status code
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        rvalue = None
        if path and path_type:
            rvalue = session.query(Path).filter_by(name=path, type=path_type, service_id=service.id).one_or_none()
            if not rvalue:
                rvalue = Path(name=path, type=path_type, service=service)
                session.add(rvalue)
                session.flush()
            if size_bytes:
                rvalue.size_bytes = size_bytes
            if return_code:
                rvalue.return_code = return_code
            if rvalue:
                if source:
                    source.paths.append(rvalue)
                if report_item:
                    msg = None
                    if return_code:
                        msg = "status: {}".format(return_code)
                    if size_bytes:
                        msg = "{}, size: {}".format(msg, size_bytes) if msg else "size: {}".format(size_bytes)
                    msg = " ({})".format(msg) if msg else ""
                    report_item.details = "potentially new path/file: {}{}".format(path, msg)
                    report_item.report_type = "PATH"
                    report_item.notify()
        return rvalue

    @staticmethod
    def add_query(session: Session,
                  path: Path,
                  query: str,
                  source: Source = None,
                  report_item: ReportItem = None) -> Path:
        """
        This method should be used by collectors to add credentials to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service object to which the credentials belongs
        :param path: The path that shall be added
        :param path_type: The path type that shall be added
        :param size_bytes: The size of the file
        :param return_code: The HTTP status code
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        result = None
        if path and query:
            if len(query) < 2712:
                result = session.query(HttpQuery).filter_by(query=query, path_id=path.id).one_or_none()
                if not result:
                    result = HttpQuery(query=query, path=path)
                    session.add(result)
                    session.flush()
            else:
                logger.warning("the query part of url '{}' could not be "
                               "added as it exceeds 2712 characters.".format(url))
        return result

    @staticmethod
    def add_service(session: Session,
                    port: int,
                    protocol_type: ProtocolType,
                    state: ServiceState,
                    host: Host = None,
                    host_name: HostName = None,
                    nmap_service_name: str = None,
                    nmap_service_confidence: int = None,
                    nmap_tunnel: str = None,
                    nmap_product: str = None,
                    nmap_version: str = None,
                    nessus_service_name: str = None,
                    nessus_service_confidence: int = None,
                    source: Source = None,
                    report_item: ReportItem = None) -> Service:
        """
         This method should be used by collectors to add credentials to the database
         :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
         :param host: The host object to which the service belongs
         :param host_name: The host name object to which the service belongs
         :param port: The port number that shall be added
         :param protocol_type: The protocol type that shall be added
         :param state: Specifies the state of the service (e.g., open)
         :param nmap_service_name: Specifies the Nmap service name
         :param nmap_service_confidence: Specifies the Nmap confidence of the identified service
         :param nessus_service_name: Specifies the Nessus service name
         :param nessus_service_confidence: Specifies the Nessus confidence of the identified service
         :param nmap_product: specifies the Nmap product name
         :param nmap_version: specifies the Nmap version
         :param source: The source object of the current collector
         :param report_item: Item that can be used for pushing information into the view
         :return:
         """
        if host and host_name:
            raise ValueError("service must either be assigned to a host or a host name")
        if host:
            result = session.query(Service) \
                .filter(Service.port == port,
                        Service.protocol == protocol_type,
                        Service.host_id == host.id).one_or_none()
            if not result:
                result = Service(port=port,
                                 protocol=protocol_type,
                                 state=state,
                                 host=host)
                session.add(result)
                session.flush()
        elif host_name:
            result = session.query(Service) \
                .filter(Service.port == port,
                        Service.protocol == protocol_type,
                        Service.host_name_id == host_name.id).one_or_none()
            if not result:
                result = Service(port=port,
                                 protocol=protocol_type,
                                 state=state,
                                 host_name=host_name)
                session.add(result)
                session.flush()
        else:
            raise ValueError("service must be assigned to host or host name")
        if result:
            result.state = state if state else result.state
            result.nmap_service_name = nmap_service_name if nmap_service_name else result.nmap_service_name
            result.nmap_service_confidence = nmap_service_confidence if nmap_service_confidence \
                else result.nmap_service_confidence
            result.nmap_tunnel = nmap_tunnel if nmap_tunnel else result.nmap_tunnel
            result.nmap_product = nmap_product if nmap_product else result.nmap_product
            result.nmap_version = nmap_version if nmap_version else result.nmap_version
            result.nessus_service_name = nessus_service_name if nessus_service_name else result.nessus_service_name
            result.nessus_service_confidence = nessus_service_confidence if nessus_service_confidence \
                else result.nessus_service_confidence
            if source:
                source.services.append(result)
            if report_item:
                report_item.details = "potentially new service: {}/{} ({})".format(result.protocol_str,
                                                                                   result.port,
                                                                                   result.state_str)
                report_item.report_type = "SERVICE"
                report_item.notify()
        return result

    @staticmethod
    def get_service(session: Session,
                    port: int,
                    protocol_type: ProtocolType,
                    host: Host = None,
                    host_name: HostName = None) -> Service:
        """
         This method should be used by collectors to obtain service object from the database
         :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
         :param host: The host object to which the service belongs
         :param host_name: The host name object to which the service belongs
         :param port: The port number that shall be added
         :param protocol_type: The protocol type that shall be added
         :return:
         """
        if host and host_name:
            raise ValueError("service must either be assigned to a host or a host name")
        if host:
            rvalue = session.query(Service) \
                .filter(Service.port == port,
                        Service.protocol == protocol_type,
                        Service.host_id == host.id).one_or_none()
        elif host_name:
            rvalue = session.query(Service) \
                .filter(Service.port == port,
                        Service.protocol == protocol_type,
                        Service.host_name_id == host_name.id).one_or_none()
        else:
            raise ValueError("service must be assigned to host or host name")
        return rvalue

    @staticmethod
    def delete_service(session: Session,
                       port: int,
                       protocol_type: ProtocolType,
                       host: Host = None,
                       host_name: HostName = None) -> None:
        """
         This method should be used by collectors to delete a service from the database
         :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
         :param host: The host object to which the service belongs
         :param host_name: The host name object to which the service belongs
         :param port: The port number that shall be added
         :param protocol_type: The protocol type that shall be added
         :return:
         """
        result = DomainUtils.get_service(session=session,
                                         port=port,
                                         protocol_type=protocol_type,
                                         host=host,
                                         host_name=host_name)
        if result:
            session.delete(result)

    @staticmethod
    def add_hint(command: Command,
                 hint: str,
                 report_item: ReportItem = None) -> None:
        """
        This method adds a hint for the given command to the database
        :param command: The command instance that contains the results of the command execution
        :param hint: The hint that should be added to the database
        :param report_item: Item that can be used for pushing information into the view
        """
        if hint:
            if not command.hint:
                command.hint = ["try the following command(s)"]
            if hint not in command.hint:
                command.hint.append(hint)
            if report_item:
                report_item.details = hint
                report_item.report_type = "HINT"
                report_item.notify()

    def add_certificate(self,
                        session: Session,
                        command: Command,
                        content: str,
                        type: CertType = None,
                        source: Source = None,
                        report_item: ReportItem = None) -> File:
        """
        This method adds a certificate to the database and thereby extracts host names
        :param session: The database session used for addition the file path
        :param command: The command to which the file should be attached
        :param type: Specifies whether the certificate is an entity, bridge, or root certificate
        :param content: The certificate
        :param source: The source object from which the URL originates
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        content_bytes = content.encode("utf-8")
        certificate = CertificateUtils(content_bytes)
        host_names = certificate.subject_alt_name
        host_names.append(certificate.issuer_name)
        signature_algorithm = certificate.signature_asym_algorithm
        hash_algorithm = certificate.signature_hash_algorithm
        for host_name in host_names:
            host_name_object = self.add_domain_name(session=session,
                                                    workspace=command.workspace,
                                                    item=host_name,
                                                    source=source,
                                                    report_item=report_item)
            if host_name_object:
                for company in certificate.organizations:
                    self.add_company(session=session,
                                     workspace=command.workspace,
                                     name=company,
                                     domain_name=host_name_object.domain_name,
                                     source=source,
                                     report_item=report_item)
            else:
                logger.debug("ignoring host name due to invalid domain: {}".format(host_name))
        if command.service or command.host_name or command.company:
            if signature_algorithm and hash_algorithm:
                self.add_cert_info(session=session,
                                   service=command.service,
                                   company=command.company,
                                   host_name=command.host_name if not command.service else None,
                                   common_name=certificate.common_name,
                                   issuer_name=certificate.issuer_name,
                                   signature_asym_algorithm=signature_algorithm,
                                   hash_algorithm=hash_algorithm,
                                   cert_type=type,
                                   signature_bits=certificate.signature_bits,
                                   valid_from=certificate.not_valid_before,
                                   valid_until=certificate.not_valid_after,
                                   subject_alt_names=certificate.subject_alt_name,
                                   extension_info=certificate.extensions,
                                   serial_number=certificate.cert.serial_number,
                                   source=source,
                                   report_item=report_item)
            else:
                logger.error("certificate does not contain signature or hash algorithm and therefore was not added.")
        if not host_names:
            for company in certificate.organizations:
                self.add_company(session=session,
                                 workspace=command.workspace,
                                 name=company,
                                 source=source,
                                 report_item=report_item)
        for email_address in certificate.email_addresses:
            self.add_email(session=session,
                           workspace=command.workspace,
                           text=email_address,
                           source=source,
                           report_item=report_item)
        return self.add_file_content(session=session,
                                     command=command,
                                     file_type=FileType.certificate,
                                     file_name="{}.pem".format(command.file_name),
                                     workspace=command.workspace,
                                     content=content_bytes,
                                     report_item=report_item)

    @staticmethod
    def add_file_content(session: Session,
                         workspace: Workspace,
                         command: Command,
                         file_name: str,
                         file_type: FileType,
                         content: bytes,
                         report_item: ReportItem = None) -> File:
        """
        This method adds the given file to the database and attaches it to the given command.
        :param session: The database session used for addition the file path
        :param workspace: The workspace to which the file shall be added
        :param file_name: Name of the file to be added
        :param file_type: The type of file that is added
        :param content: Content of the file to be added
        :param command: The command to which the file should be attached
        :return: Instance of the file inserted
        """
        if not content:
            return None
        sha256_value = hashlib.sha256(content).hexdigest()
        file = session.query(File).filter_by(sha256_value=sha256_value,
                                             workspace_id=workspace.id,
                                             type=file_type).one_or_none()
        if not file:
            file = File(sha256_value=sha256_value,
                        type=file_type,
                        content=content,
                        workspace=workspace)
            session.add(file)
            mapping = CommandFileMapping(command=command, file=file, file_name=file_name)
            session.add(mapping)
            session.flush()
        else:
            mapping = session.query(CommandFileMapping).filter_by(command_id=command.id,
                                                                  file_id=file.id).one_or_none()
            if not mapping:
                mapping = CommandFileMapping(command=command, file=file, file_name=file_name)
                session.add(mapping)
                session.flush()
            mapping.name = file_name
        if report_item:
            report_item.details = "add file content: {}".format(file_name)
            report_item.report_type = "FILE"
            report_item.notify()
        return file

    @staticmethod
    def add_file(session: Session,
                 workspace: Workspace,
                 command: Command,
                 file_path: str,
                 file_type: FileType) -> File:
        """
        This method adds the given file to the database and attaches it to the given command.
        :param session: The database session used for addition the file path
        :param workspace: The workspace to which the file shall be added
        :param file_path: Path to the file to be inserted
        :param file_type: The type of file that is added
        :param command: The command to which the file should be attached
        :return: Instance of the file inserted
        """
        file_name = os.path.basename(file_path)
        if not os.path.isfile(file_path):
            raise FileNotFoundError("file '{}' does not exist".format(file_path))
        with open(file_path, "rb") as file:
            content = file.read()
            file = BaseUtils.add_file_content(session=session,
                                              workspace=workspace,
                                              command=command,
                                              file_name=file_name,
                                              file_type=file_type,
                                              content=content)
        return file

    def add_url(self,
                session: Session,
                service: Service,
                url: str,
                status_code: int = None,
                size_bytes: int = None,
                source: Source = None,
                report_item: ReportItem = None,
                add_all: bool = False) -> Path:
        """
        This method adds the given URL (path and query part) to the database
        :param session: The database session used for addition the URL
        :param service: The service to which the URL belongs
        :param url: The URL that shall be added to the database
        :param status_code: The access code
        :param size_bytes: Size of response body or file content in bytes
        :param source: The source object from which the URL originates
        :param report_item: Item that can be used for pushing information into the view
        :param add_all: If true, then also files with extensions like js, css, woff, jpg, png, etc. are added
        :return: The newly added path object
        """
        url_object = urlparse(url)
        path = None
        if url_object.path and url_object.query:
            path_str = url_object.path
            query_str = url_object.query
        elif url_object.path and not url_object.query:
            path_str = url_object.path
            query_str = None
        elif not url_object.path and url_object.query:
            path_str = "/"
            query_str = url_object.query
        else:
            path_str = None
            query_str = None
        if path_str:
            path_str = path_str if path_str[0] == '/' else "/{}".format(path_str)
            extension = path_str.split(".")[-1]
            path_str = path_str if add_all or (
                        not add_all and extension not in self._irrelevant_http_files) else os.path.dirname(path_str)
            path = BaseUtils.add_path(session=session,
                                      service=service,
                                      path=path_str,
                                      path_type=PathType.http,
                                      size_bytes=size_bytes,
                                      return_code=status_code,
                                      source=source,
                                      report_item=report_item)
            BaseUtils.add_query(session=session,
                                path=path,
                                query=query_str,
                                source=source,
                                report_item=report_item)
        return path

    @staticmethod
    def add_tls_info(session: Session,
                     service: Service,
                     version: TlsVersion,
                     preference: TlsPreference = None,
                     heartbleed: bool = None,
                     compressors: List[str] = [],
                     report_item: ReportItem = None) -> TlsInfo:
        """
        This method should be used by collectors to add credentials to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service object to which the credentials belongs
        :param version: The TLS version to be added
        :param preference: The TLS preference of the TLS version
        :param compressors: A list of compressors to be added\
        :param heartbleed: Specifies whether the TLS version is vulnerable to heartbleed
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        rvalue = session.query(TlsInfo).filter_by(service_id=service.id, version=version).one_or_none()
        if not rvalue:
            rvalue = TlsInfo(service=service, version=version, preference=preference, heartbleed=heartbleed)
            session.add(rvalue)
            session.flush()
        if preference:
            rvalue.preference = preference
        if compressors:
            rvalue.compressors = compressors
        if heartbleed:
            rvalue.heartbleed = heartbleed
        return rvalue

    @staticmethod
    def add_tls_info_cipher_suite_mapping(session: Session,
                                          tls_info: TlsInfo,
                                          kex_algorithm_details: KeyExchangeAlgorithm,
                                          order: int = None,
                                          kex_bits: int = None,
                                          prefered: bool = None,
                                          iana_name: str = None,
                                          gnutls_name: str = None,
                                          openssl_name: str = None,
                                          cipher_suite: CipherSuite = None,
                                          source: Source = None,
                                          report_item: ReportItem = None) -> TlsInfoCipherSuiteMapping:
        """
        This method should be used by collectors to add credentials to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param tls_info: The TLS info for which a mapping shall be created
        :param cipher_suite: The TLS cipher suite for which a mapping shall be created
        :param kex_algorithm_details: Contains details about the used key exchange algorithm
        :param kex_bits: Contains details about the used key exchange algorithm bit length
        :param iana_name: The cipher suite string in the IANA format
        :param openssl_name: The cipher suite string in the OpenSSL format
        :param gnutls_name: The cipher suite string in the GNU TLS format
        :param order: The order of the TLS cipher suite
        :param prefered: Specifies whether the TLS cipher suite is prefered
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        error_source = "{} - ".format(source.name.lower()) if source else ""
        if (cipher_suite and iana_name) or (cipher_suite and openssl_name) or (cipher_suite and gnutls_name) or \
            (iana_name and openssl_name) or (iana_name and gnutls_name) or (openssl_name and gnutls_name):
            raise ValueError("only one of the parameters is allowed: cipher_suite, iana_name, openssl_cipher, or "
                             "gnutls_name")
        if cipher_suite:
            pass
        elif iana_name:
            cipher_suite = session.query(CipherSuite).filter_by(iana_name=iana_name).one_or_none()
            if cipher_suite is None:
                logger.error("{}cipher suite '{}' does not exist. ignoring cipher suite".format(error_source,
                                                                                                iana_name))
                return None
        elif openssl_name:
            cipher_suite = session.query(CipherSuite).filter_by(openssl_full=openssl_name).one_or_none()
            if cipher_suite is None:
                logger.error("{}cipher suite '{}' does not exist. ignoring cipher suite".format(error_source,
                                                                                                openssl_name))
                return None
        elif gnutls_name:
            cipher_suite = session.query(CipherSuite).filter_by(gnutls_name=gnutls_name).one_or_none()
            if cipher_suite is None:
                # These are fixes for sslscan
                if gnutls_name.startswith("TLS_"):
                    cipher_suite = session.query(CipherSuite).filter_by(iana_name=gnutls_name).one_or_none()
                if cipher_suite is None and gnutls_name == 'RC4-MD5':
                    cipher_suite = session.query(CipherSuite).\
                        filter_by(iana_name='TLS_RSA_WITH_RC4_128_MD5').one_or_none()
                if cipher_suite is None and gnutls_name == 'RC4-SHA':
                    cipher_suite = session.query(CipherSuite).\
                        filter_by(iana_name='TLS_RSA_WITH_RC4_128_SHA').one_or_none()
                if cipher_suite is None:
                    logger.error("{}cipher suite '{}' does not exist. "
                                 "ignoring cipher suite".format(error_source,
                                                                gnutls_name))
                    return None

        else:
            raise ValueError("at least one of the parameters is mandatory: cipher_suite, iana_name, openssl_cipher, or "
                             "gnutls_name")
        rvalue = session.query(TlsInfoCipherSuiteMapping)\
            .filter_by(tls_info_id=tls_info.id,
                       cipher_suite_id=cipher_suite.id,
                       kex_algorithm_details=kex_algorithm_details).one_or_none()
        if not rvalue:
            rvalue = TlsInfoCipherSuiteMapping(tls_info=tls_info,
                                               cipher_suite=cipher_suite,
                                               kex_algorithm_details=kex_algorithm_details)
            session.add(rvalue)
            session.flush()
        if prefered:
            rvalue.prefered = prefered
        if order:
            rvalue.order = order
        if kex_bits:
            rvalue.kex_bits = kex_bits
        if source:
            source.tls_info_cipher_suite_mappings.append(rvalue)
        return rvalue

    def add_cert_info(self,
                      session: Session,
                      serial_number: int,
                      common_name: str,
                      issuer_name: str,
                      signature_asym_algorithm: AsymmetricAlgorithm,
                      hash_algorithm: HashAlgorithm,
                      cert_type: CertType,
                      signature_bits: int,
                      valid_from: datetime,
                      valid_until: datetime,
                      subject_alt_names: List[str] = [],
                      extension_info: Dict[str, Dict[str, str]] = {},
                      source: Source = None,
                      service: Service = None,
                      host_name: HostName = None,
                      company: Company = None,
                      report_item: ReportItem = None) -> CertInfo:
        """
        This method adds certificate information to the given service
        :param session: The database session used for addition the URL
        :param serial_number: The certificate's serial number
        :param common_name: The certificate's common name
        :param issuer_name: The certificate's issuer name
        :param signature_asym_algorithm: The certificate's asymmetric algorithm
        :param hash_algorithm: The certificate's hash algorithm
        :param cert_type: The certificate's type
        :param valid_from: The certificate's start date
        :param valid_until: The certificate's end date
        :param subject_alt_names: The certificate's alternative subject names
        :param extension_info: Additional certificate information
        :param source: The source object from which the URL originates
        :param report_item: Item that can be used for pushing information into the view
        :param service: The service to which the URL belongs
        :param host_name: The host name to which the URL belongs
        :param company: The company to which the URL belongs
        :return:
        """
        if (service and host_name) or (service and company) or (host_name and company):
            raise ValueError("cert info must either be assigned to a service, host name, or company")
        serial_number_str = str(serial_number)
        if service:
            result = session.query(CertInfo).filter_by(service_id=service.id,
                                                       serial_number=serial_number_str).one_or_none()
        elif host_name:
            result = session.query(CertInfo).filter_by(host_name_id=host_name.id,
                                                       serial_number=serial_number_str).one_or_none()
        elif company:
            result = session.query(CertInfo).filter_by(company_id=company.id,
                                                       serial_number=serial_number_str).one_or_none()
        else:
            raise ValueError("cert info must have a service, host name, or company")
        if not result:
            result = CertInfo(service=service,
                              host_name=host_name,
                              company=company,
                              serial_number=serial_number_str,
                              common_name=common_name,
                              issuer_name=issuer_name,
                              signature_bits=signature_bits,
                              valid_from=valid_from,
                              valid_until=valid_until,
                              signature_asym_algorithm=signature_asym_algorithm,
                              hash_algorithm=hash_algorithm,
                              cert_type=cert_type)
            session.add(result)
            session.flush()
        if extension_info:
            result.extension_info = extension_info
        if subject_alt_names:
            result.subject_alt_names = [item.lower() for item in subject_alt_names]
        if source:
            source.cert_info.append(result)
        return result

    def add_dns_names(self,
                      session: Session,
                      workspace: Workspace,
                      items: List[str],
                      host: Host = None,
                      source: Source = None) -> List[HostName]:
        """
        This method inserts the given list of DNS names into the database.
        :param session:
        :param workspace:
        :param items:
        :param host:
        :param source:
        :return:
        """
        dedup = {}
        for item in items:
            if item:
                if (host and item != host.address and item not in dedup) or (not host and item not in dedup):
                    self.add_dns_name(session, workspace, item, host, source)
                    session.flush()
                    dedup[item] = True
        return list(dedup.values())

    def get_second_level_domain_name(self, domain_name: DomainName) -> str:
        """
        This method removes the TLD and just returns the second level domain.
        :param domain_name:
        :return:
        """
        result = None
        if domain_name.name:
            tld = self.matches_tld(domain_name.name)
            if tld:
                result = domain_name.name.rstrip(tld)
                result = result.rstrip(".")
            else:
                result = ".".join(domain_name.name.split(".")[0:-1])
        return result

    def split_host_name(self, host_name: str) -> List[str]:
        """
        This method splits the given host name into domain name and host names.
        :param host_name:
        :return:
        """
        result = None
        if host_name is None:
            return result
        host_name = re.sub("^\*\.", "", host_name)
        if len(host_name) < 3:
            return result
        if "." not in host_name:
            return [host_name]
        host_name = host_name.lower()
        host_name = host_name.strip(".")
        if host_name:
            tld = self.matches_tld(host_name)
            if tld:
                host_name = host_name[:-(len(tld) + 1)]
                result = host_name.split(".")
                result.append(tld)
        return result

    @staticmethod
    def _add_domain_name(session: Session,
                         workspace: Workspace,
                         domain_name: str,
                         scope: ScopeType) -> HostName:
        result = session.query(DomainName).filter_by(name=domain_name, workspace=workspace).one_or_none()
        if not result:
            domain_name = DomainName(name=domain_name, workspace=workspace, scope=scope)
            session.add(domain_name)
            session.flush()
            host_name = session.query(HostName).filter_by(name=None, domain_name_id=domain_name.id).one_or_none()
            if not host_name:
                host_name = HostName(name=None, domain_name=domain_name)
                session.add(host_name)
                session.flush()
        else:
            host_name = session.query(HostName).filter_by(name=None, domain_name_id=result.id).one()
        return host_name

    def add_dns_name(self,
                     session: Session,
                     workspace: Workspace,
                     item: str,
                     host: Host = None,
                     source: Source = None,
                     scope: ScopeType = None,
                     mapping_type: DnsResourceRecordType = None) -> HostName:
        """
        This method inserts the given DNS name (e.g., www.mozilla.com) into the database.
        """
        result = None
        item = item.lower()
        item = item.rstrip(".")
        host_name_items = self.split_host_name(item)
        if host_name_items is None:
            return result
        levels = len(host_name_items)
        # we only have a domain name (e.g, google.com)
        if levels == 1 or levels == 2:
            host_name = BaseUtils._add_domain_name(session=session,
                                                   workspace=workspace,
                                                   domain_name=item,
                                                   scope=scope)
            if source:
                host_name.sources.append(source)
            if host:
                BaseUtils.add_host_host_name_mapping(session=session,
                                                     host=host,
                                                     host_name=host_name,
                                                     source=source,
                                                     mapping_type=mapping_type)
            session.flush()
            result = host_name
        # we have a host and domain name
        elif levels > 2:
            domain_name = ".".join(host_name_items[-2:])
            # add the domain
            domain_object = BaseUtils._add_domain_name(session=session,
                                                       workspace=workspace,
                                                       domain_name=domain_name,
                                                       scope=scope)
            result = domain_object
            if source:
                domain_object.sources.append(source)
            domain_object = domain_object.domain_name
            # add all sub-domains to host_name table
            host_name_items.reverse()
            for i in range(3, len(host_name_items) + 1):
                host_name_list = host_name_items[2:i]
                host_name_list.reverse()
                host_name = ".".join(host_name_list)
                last_char = host_name[-1]
                if last_char != "*" and last_char != ".":
                    host_name_object = session.query(HostName) \
                        .filter_by(name=host_name,
                                   domain_name_id=domain_object.id).one_or_none()
                    if not host_name_object:
                        host_name_object = HostName(name=host_name,
                                                    domain_name=domain_object)
                        session.add(host_name_object)
                        session.flush()
                    if source:
                        host_name_object.sources.append(source)
                    if host:
                        BaseUtils.add_host_host_name_mapping(session=session,
                                                             host=host,
                                                             host_name=host_name_object,
                                                             source=source,
                                                             mapping_type=mapping_type)
                    result = host_name_object
        return result

    def get_host_name(self,
                      session: Session,
                      workspace: Workspace,
                      host_name: str) -> HostName:
        """
        This method returns the database object based on the given host name
        :param session:
        :param workspace:
        :param host_name:
        :return:
        """
        result = None
        host_name_items = self.split_host_name(host_name=host_name)
        if host_name_items is None:
            return result
        levels = len(host_name_items)
        # we only have a domain name (e.g, google.com)
        if levels == 2:
            result = session.query(HostName)\
                .join(DomainName)\
                .join(Workspace)\
                .filter(HostName.name.is_(None),
                        DomainName.name == ".".join(host_name_items),
                        Workspace.id == workspace.id).one_or_none()
        elif levels >= 2:
            host_name = ".".join(host_name_items[:-2])
            domain_name = ".".join(host_name_items[-2:])
            result = session.query(HostName) \
                .join(DomainName) \
                .join(Workspace) \
                .filter(HostName.name == host_name,
                        DomainName.name == domain_name,
                        Workspace.id == workspace.id).one_or_none()
        return result

    def delete_domain_name(self,
                           session: Session,
                           workspace: Workspace,
                           domain_name: str):
        result = session.query(DomainName) \
            .join(Workspace) \
            .filter(Workspace.id == workspace.id, DomainName.name == domain_name).one_or_none()
        if not result:
            raise DomainNameNotFound(domain_name)
        session.delete(result)

    def delete_host_name(self,
                         session: Session,
                         workspace: Workspace,
                         host_name: str) -> None:
        """
        This method deletes the database object based on the given host name
        :param session:
        :param workspace:
        :param host_name:
        :return:
        """
        result = DomainUtils.get_host_name(session=session, workspace=workspace, host_name=host_name)
        if result is not None:
            if result.name is not None:
                session.delete(result)
            else:
                raise ValueError("{} is not a valid host name.".format(host_name))

    def matches_tld(self, domain: str) -> str:
        """
        This method determines the given domain's top-level domain (TLD).
        :param domain: The domain whose TLD should be identified.
        :return: The domain's TLD or None
        """
        result = None
        for key, value in self._top_level_domains.items():
            if value.match(domain):
                result = key
                break
        return result

    def is_valid_domain(self, domain: str) -> bool:
        """
        This method verifies whether the given domain has a valid structure.
        :param domain: The domain that should be verified.
        :return: True if the domain is valid
        """
        rvalue = False
        if self._re_domain.match(domain):
            tld = domain.rstrip(".").split(".")[-1]
            rvalue = tld in self._top_level_domains
        return rvalue

    def extract_domains(self, text: str) -> List[str]:
        """
        Extracts domains from the given string.
        :param text: The string from which domains shall be extracted.
        :return: List of domains
        """
        rvalue = []
        if not text:
            return rvalue
        for item in self._re_domain.finditer(text):
            domain_name = item.group("domain").lower()
            tld = domain_name.split(".")[-1]
            if tld in self._top_level_domains:
                rvalue.append(domain_name)
        return rvalue

    @staticmethod
    def query_host_name(session,
                        workspace: Workspace,
                        host_name: str) -> HostName:
        """
        Returns the corresponding host name object, if the host_name exist in the database.
        :param session:
        :param workspace:
        :param host_name
        :return:
        """
        rvalue = None
        if not host_name:
            return rvalue
        host_name = host_name.lower()
        host_name = host_name[:-1] if host_name[-1] == "." else host_name
        host_name_items = host_name.split(".")
        levels = len(host_name_items)
        # we only have a domain name (e.g, google.com)
        if levels == 2:
            rvalue = session.query(HostName)\
                .join(DomainName).filter(DomainName.name == host_name,
                                         DomainName.workspace_id == workspace.id,
                                         HostName.name == None).one_or_none()
        # we have a host and domain name
        elif levels > 2:
            host_name = ".".join(host_name_items[:-2])
            domain_name = ".".join(host_name_items[-2:])
            rvalue = session.query(HostName)\
                .join(DomainName).filter(DomainName.name == domain_name,
                                         DomainName.workspace_id == workspace.id,
                                         HostName.name == host_name).one_or_none()
        return rvalue

    @staticmethod
    def delete_host_name(session: Session, workspace: Workspace, host_name: str):
        """
        Returns the corresponding host name object, if the host_name exist in the database.
        :param session:
        :param workspace:
        :param host_name
        :return:
        """
        host_name = DomainUtils.query_host_name(session, workspace, host_name)
        if host_name and not host_name.name:
            session.delete(host_name.domain_name)
        elif host_name:
            session.delete(host_name)

    def add_host_name(self,
                      session: Session,
                      workspace: Workspace,
                      name: str,
                      in_scope: bool,
                      source: Source = None) -> HostName:
        """
        This method adds the given sub-domain. Note that the corresponding second-level domain must already exists.
        """
        result = None
        if not name:
            return result
        name = name.lstrip("*.")
        name = name.lower()
        host_name_items = self.split_host_name(name)
        if not host_name_items or len(host_name_items) < 2:
            raise ValueError("{} is not a valid sub-domain".format(name))
        domain_name = ".".join(host_name_items[-2:])
        # The host name's second-level domain must exist
        if session.query(DomainName)\
            .join(Workspace)\
            .filter(Workspace.id == workspace.id,
                    DomainName.name == domain_name).count() <= 0:
            raise DomainNameNotFound(domain_name)
        result = self.add_domain_name(session=session,
                                      workspace=workspace,
                                      item=name,
                                      source=source)
        if not result:
            raise ValueError("{} was not added to the database")
        if result._in_scope != in_scope:
            result._in_scope = in_scope
        return result

    def add_sld(self,
                session: Session,
                workspace: Workspace,
                name: str,
                scope: ScopeType,
                source: Source = None) -> DomainName:
        """
        This method adds the given second-level domain.
        """
        result = None
        if not name:
            return result
        name = name.lstrip("*.")
        name = name.lower()
        host_name_items = self.split_host_name(name)
        if len(host_name_items) != 2:
            raise ValueError("{} is not a second-level domain".format(name))
        result = self.add_domain_name(session=session,
                                      workspace=workspace,
                                      item=name,
                                      source=source,
                                      scope=scope)
        if not result:
            raise ValueError("{} was not added to the database")
        if result.domain_name.scope != scope:
            result.domain_name.scope = scope
        if source not in result.sources:
            result.sources.append(source)
        return result.domain_name

    def add_domain_name(self,
                        session: Session,
                        workspace: Workspace,
                        item: str,
                        source: Source = None,
                        scope: ScopeType = None,
                        verify: bool = False,
                        report_item: ReportItem = None) -> HostName:
        """
        This method inserts the given DNS name (e.g., www.mozilla.com) into the database.
        :param session:
        :param workspace:
        :param item:
        :param host:
        :param source:
        :param verify:
        :param scope:
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        result = None
        if not item:
            return result
        item = item.lstrip("*.")
        item = item.lower()
        if item and (not verify or (verify and self.is_valid_domain(item))):
            result = self.add_dns_name(session=session,
                                       workspace=workspace,
                                       item=item,
                                       source=source,
                                       scope=scope)
            if result and report_item:
                report_item.details = "potentially new host name {}".format(result.full_name)
                report_item.report_type = "DOMAIN"
                report_item.notify()
        return result

    def is_valid_email(self, email: str) -> bool:
        """
        This method verifies whether the given domain has a valid structure.
        :param email: The email that should be verified.
        :return: True if the email is valid
        """
        rvalue = False
        if self._re_email.match(email):
            tld = email.split(".")[-1]
            rvalue = tld in self._top_level_domains
        return rvalue

    def extract_emails(self, text: str, domain_name: str = None) -> List[str]:
        """
        Extracts emails from the given string.
        :param text: The string from which domains shall be extracted.
        :return: List of domains
        """
        rvalue = []
        regex = re.compile("(?P<email>[\w\.%\+\-_]+@{})".format(domain_name)) if domain_name else self._re_email
        for item in regex.finditer(text):
            email = item.group("email").lower()
            if email and not domain_name:
                tld = email.split(".")[-1]
                if tld in self._top_level_domains:
                    rvalue.append(email)
            elif email:
                rvalue.append(email)
        return rvalue

    def add_email(self,
                  session: Session,
                  workspace: Workspace,
                  text: str,
                  source: Source = None,
                  verify: bool = True,
                  report_item: ReportItem = None,
                  scope: ScopeType = None) -> Email:
        """
        This method adds the given email address to the workspace
        :param session: Database session used to add the email address
        :param workspace: Workspace  in which the email address is used
        :param text: The email address to be added
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :param verify: If true then the host name's structure is verified before it is added to the database
        :return: Email object or none
        """
        rvalue = None
        if not verify or (verify and self.is_valid_email(text)):
            email, host_name = text.lower().split("@")
            host_name = self.add_domain_name(session=session,
                                             workspace=workspace,
                                             item=host_name,
                                             source=source,
                                             verify=verify,
                                             report_item=report_item,
                                             scope=scope)
            if host_name:
                rvalue = Engine.get_or_create(session, Email, address=email, host_name=host_name)
                if source:
                    rvalue.sources.append(source)
                if rvalue and report_item:
                    report_item.details = "potentially new email address {}".format(text)
                    report_item.report_type = "EMAIL"
                    report_item.notify()
        return rvalue

    def get_email(self,
                  session: Session,
                  workspace: Workspace,
                  email: str) -> Email:
        """
        This method returns the given email address as a database object
        :param session: Database session used to add the email address
        :param workspace: Workspace  in which the email address is used
        :return: Email object or none
        """
        result = None
        if email and email.count("@") == 1:
            _, host_name = email.split("@")
            result = self.get_host_name(session=session, workspace=workspace, host_name=host_name)
        return result

    @staticmethod
    def get_company(session: Session,
                    workspace: Workspace,
                    name: str) -> Network:
        """
        This method shall be used to get a company from the database
        :param session: Database session used to add the email address
        :param workspace: The workspace to which the network shall be added
        :param name: Company that should be returned from the database
        """
        name_lower = name.lower()
        return session.query(Company).join(Workspace).filter(Company.name == name_lower,
                                                             Workspace.name == workspace.name).one_or_none()

    def delete_email(self,
                     session: Session,
                     workspace: Workspace,
                     email: str) -> None:
        """
        This method returns the given email address as a database object
        :param session: Database session used to add the email address
        :param workspace: Workspace  in which the email address is used
        :return: Email object or none
        """
        result = self.get_email(session=session, workspace=workspace, email=email)
        if result:
            session.delete(result)


class JsonUtils(BaseUtils):
    """This class provides utils in regard to JSON objects"""
    def __init__(self, **args):
        super().__init__(**args)

    @staticmethod
    def get_attribute_value(json_object: Dict, path: str, default_value = None):
        """
        This method returns the content of the attribute specified by the path.
        :param json_object: The JSON object that is searched
        :param path: Path (e.g. data/value/) that specifies which attribute shall be returned\
        :param default_value: The default value that shall be returned if the requested path does not exist
        :return:
        """
        path = path[1:] if path[0] == '/' else path
        current_position = json_object
        for value in path.split("/"):
            if isinstance(current_position, dict) and value in current_position:
                current_position = current_position[value]
            else:
                current_position = None
                break
        return current_position if current_position else default_value

    @staticmethod
    def find_attribute(json_object: dict, name: str) -> List[dict]:
        """
        This method returns a list of attributes that match the given name
        :param json_object: The JSON object that is searched
        :param name: The name of the attribute that shall be returned
        :param default_value: The default value that shall be returned if the requested path does not exist
        :return:
        """
        rvalue = []
        if isinstance(json_object, list):
            for item in json_object:
                rvalue += JsonUtils.find_attribute(item, name)
        elif isinstance(json_object, dict):
            if name in json_object and isinstance(json_object[name], dict):
                rvalue.append(json_object[name])
            for key in json_object.keys():
                rvalue += JsonUtils.find_attribute(json_object[key], name)
        return rvalue

    @staticmethod
    def get_json_attribute(json_object: dict, name: str):
        """Returns the given JSON attribute and None if it does not exist"""
        rvalue = json_object[name] if name in json_object else None
        rvalue = rvalue if rvalue != "" else None
        return rvalue


class CertificateUtils:
    """This class provides utils in regard to certificates"""

    # Source: http://oid-info.com/get/1.3.14.3.2
    SECSIG_OIDS = {"1.3.14.3.2.1": "rsa",
                   "1.3.14.3.2.2": "md4WitRSA",
                   "1.3.14.3.2.3": "md5WithRSA",
                   "1.3.14.3.2.4": "md4WithRSAEncryption",
                   "1.3.14.3.2.6": "desECB",
                   "1.3.14.3.2.7": "desCBC",
                   "1.3.14.3.2.8": "desOFB",
                   "1.3.14.3.2.9": "desCFB",
                   "1.3.14.3.2.10": "desMAC",
                   "1.3.14.3.2.11": "rsaSignature",
                   "1.3.14.3.2.12": "dsa",
                   "1.3.14.3.2.13": "dsaWithSHA",
                   "1.3.14.3.2.14": "mdc2WithRSASignature",
                   "1.3.14.3.2.15": "shaWithRSASignature",
                   "1.3.14.3.2.16": "dhWithCommonModulus",
                   "1.3.14.3.2.17": "desEDE",
                   "1.3.14.3.2.18": "sha",
                   "1.3.14.3.2.19": "mdc-2",
                   "1.3.14.3.2.20": "dsaCommon",
                   "1.3.14.3.2.21": "dsaCommonWithSHA",
                   "1.3.14.3.2.22": "rsaKeyTransport",
                   "1.3.14.3.2.23": "keyed-hash-seal",
                   "1.3.14.3.2.24": "md2WithRSASignature",
                   "1.3.14.3.2.25": "md5WithRSASignature",
                   "1.3.14.3.2.26": "sha1",
                   "1.3.14.3.2.27": "dsaWithSHA1",
                   "1.3.14.3.2.28": "dsaWithCommonSHA1",
                   "1.3.14.3.2.29": "sha1WithRSAEncryption"}

    def __init__(self, pem_cert: bytes, **args):
        super().__init__(**args)
        self._cert = x509.load_pem_x509_certificate(pem_cert, default_backend())

    @property
    def cert(self):
        return self._cert

    @property
    def common_name(self) -> str:
        rvalue = [attribute.value for attribute in self._cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)]
        if len(rvalue) == 1:
            rvalue = rvalue[0]
        elif len(rvalue) > 1:
            raise NotImplementedError("more than one common name not implemented.")
        return rvalue

    @property
    def issuer_name(self) -> str:
        rvalue= [attribute.value for attribute in self._cert.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME)]
        if len(rvalue) == 1:
            rvalue = rvalue[0]
        elif len(rvalue) > 1:
            raise NotImplementedError("more than one issuer name not implemented.")
        return rvalue

    @property
    def organizations(self) -> List[str]:
        return [attribute.value for attribute in self._cert.subject.get_attributes_for_oid(x509.OID_ORGANIZATION_NAME)]

    @property
    def email_addresses(self) -> List[str]:
        return [attribute.value for attribute in self._cert.subject.get_attributes_for_oid(x509.OID_EMAIL_ADDRESS)]

    @property
    def public_key(self) -> AsymmetricAlgorithm:
        rvalue = None
        if isinstance(self._cert.public_key(), asymmetric.rsa.RSAPublicKey):
            rvalue = AsymmetricAlgorithm.rsa
        else:
            logger.error("public key '{}' unknown in "
                         "CertificateUtils.public_key".format(self._cert.public_key()))
        return rvalue

    @property
    def not_valid_before(self) -> datetime:
        return self._cert.not_valid_before

    @property
    def not_valid_after(self) -> datetime:
        return self._cert.not_valid_after

    @property
    def subject_alt_name(self) -> List[str]:
        entries = []
        try:
            ext = self._cert.extensions.get_extension_for_oid(x509.OID_SUBJECT_ALTERNATIVE_NAME)
            entries = ext.value.get_values_for_type(x509.DNSName)
            entries = entries if isinstance(entries, list) else [entries]
        except:
            pass
        return entries

    @staticmethod
    def _cmp_oids(oid, oid_list) -> bool:
        rvalue = False
        for item in oid_list:
            rvalue = oid == getattr(x509, item)
            if rvalue:
                break
        return rvalue

    @staticmethod
    def der_to_pem(der_content: bytes) -> str:
        """
        Converts the given certificate from DER to PEM format
        :param pem_content:
        :return:
        """
        result = x509.load_der_x509_certificate(der_content, default_backend())
        result = result.public_bytes(Encoding.PEM)
        result = result.decode("utf-8")
        return result

    @property
    def signature_asym_algorithm(self) -> AsymmetricAlgorithm:
        result = None
        rsa_oids = [item for item in dir(x509) if "_RSA_" in item]
        dsa_oids = [item for item in dir(x509) if "_DSA_" in item]
        ecdsa_oids = [item for item in dir(x509) if "_ECDSA_" in item]
        if CertificateUtils._cmp_oids(self._cert.signature_algorithm_oid, rsa_oids):
            result = AsymmetricAlgorithm.rsa
        elif CertificateUtils._cmp_oids(self._cert.signature_algorithm_oid, dsa_oids):
            result = AsymmetricAlgorithm.dsa
        elif CertificateUtils._cmp_oids(self._cert.signature_algorithm_oid, ecdsa_oids):
            result = AsymmetricAlgorithm.ecdsa
        else:
            if self._cert.signature_algorithm_oid.dotted_string in self.SECSIG_OIDS:
                if "RSA".lower() in self.SECSIG_OIDS[self._cert.signature_algorithm_oid.dotted_string].lower():
                    result = AsymmetricAlgorithm.rsa
                elif "DSA".lower() in self.SECSIG_OIDS[self._cert.signature_algorithm_oid.dotted_string].lower():
                    result = AsymmetricAlgorithm.dsa
                elif "ECDSA".lower() in self.SECSIG_OIDS[self._cert.signature_algorithm_oid.dotted_string].lower():
                    result = AsymmetricAlgorithm.ecdsa
            if not result:
                logger.error("algorithm '{}' unknown in CertificateUtils."
                             "signature_asym_algorithm".format(self._cert.signature_algorithm_oid.dotted_string))
        return result

    @property
    def signature_hash_algorithm(self) -> HashAlgorithm:
        result = None
        if isinstance(self._cert.signature_hash_algorithm, hashes.SHA1):
            result = HashAlgorithm.sha1
        elif isinstance(self._cert.signature_hash_algorithm, hashes.MD5):
            result = HashAlgorithm.md5
        elif isinstance(self._cert.signature_hash_algorithm, hashes.SHA224):
            result = HashAlgorithm.sha224
        elif isinstance(self._cert.signature_hash_algorithm, hashes.SHA256):
            result = HashAlgorithm.sha256
        elif isinstance(self._cert.signature_hash_algorithm, hashes.SHA384):
            result = HashAlgorithm.sha384
        elif isinstance(self._cert.signature_hash_algorithm, hashes.SHA512):
            result = HashAlgorithm.sha512
        else:
            logger.error("algorithm '{}' unknown in CertificateUtils."
                         "signature_hash_algorithm".format(self._cert.signature_hash_algorithm.dotted_string))
        return result

    @property
    def signature_algorithm_str(self) -> str:
        return self._cert.signature_algorithm_oid._name

    @property
    def signature_bits(self) -> int:
        return len(self._cert.signature)*8

    @property
    def extensions(self) -> Dict[str, Dict[str, str]]:
        rvalue = {}
        for item in self._cert.extensions:
            if isinstance(item.value, x509.extensions.ExtendedKeyUsage):
                rvalue[ExtensionType.extended_key_usage.name] = {"oid": item.oid.dotted_string,
                                                                 "name": item.oid._name,
                                                                 "critical": item._critical,
                                                                 "values": [value._name
                                                                            for value in item.value]}
            elif isinstance(item.value, x509.extensions.KeyUsage):
                rvalue[ExtensionType.key_usage.name] = {"oid": item.oid.dotted_string,
                                                        "name": item.oid._name,
                                                        "critical": item._critical,
                                                        "values": [key[1:] for key, value in vars(item.value).items() if
                                                                   value]}
            else:
                try:
                    rvalue[item.oid._name] = {"oid": item.oid.dotted_string,
                                              "name": item.oid._name,
                                              "critical": item._critical,
                                              "values": [key[1:] for key, value in vars(item.value).items() if
                                                         value]}
                except Exception as ex:
                    logger.exception(ex)
        return rvalue


class IpUtils(BaseUtils):
    """This class provides utils in regard to IPv4 addresses"""
    RE_IPV4 = "[0-9]{1,3}(\.[0-9]{1,3}){3,3}"

    def __init__(self, **args):
        super().__init__(**args)

    @staticmethod
    def is_valid_address(address: str) -> bool:
        """
        Returns true if the given string has the format of a valid IPv4/IPv6 address
        :param address:
        :return:
        """
        result = True
        try:
            ipaddress.ip_address(address)
        except ValueError:
            result = False
        return result

    @staticmethod
    def is_valid_cidr_range(ipv4_range: str):
        """
        Returns true if the given string has the format of a valid IPv4/IPv6 CIDR range
        :param ipv4_range:
        :return:
        """
        result = True
        try:
            ipaddress.ip_network(ipv4_range, strict=True)
        except ValueError:
            result = False
        return result

    @staticmethod
    def qualys_to_cidr(range: str) -> List[ipaddress.IPv4Network]:
        """
        This method takes as an input a string containing a network range in Qualys format (e.g., 192.168.0.0 -
        192.168.0.255) and returns an ipaddress.IPv4Network object (CIDR format).

        :param range: The string which should be converted into CIDR format/ipaddress.IPv4Network object
        :return: A ipaddress.IPv4Network object
        """
        tmp = range.split("-")
        if len(tmp) != 2:
            raise ValueError("the following range is not in qualys format: {}".format(range))
        from_address, to_address = tmp
        from_address = ipaddress.ip_address(from_address.strip())
        to_address = ipaddress.ip_address(to_address.strip())
        return [ipaddr for ipaddr in ipaddress.summarize_address_range(from_address, to_address)]

    @staticmethod
    def add_network(session: Session,
                    workspace: Workspace,
                    network: str,
                    scope: ScopeType = None,
                    source: Source = None,
                    report_item: ReportItem = None) -> Network:
        """
        This method shall be used to add a network to the database
        :param session: Database session used to add the email address
        :param workspace: The workspace to which the network shall be added
        :param network: Network that should be added to the database
        :param scope: Specifies whether the given network is in scope
        :param report_item: Item that can be used for pushing information into the view
        :param source: The source object of the current collector
        :return: Database object
        """
        result = None
        if IpUtils.is_valid_cidr_range(network):
            result = session.query(Network).join(Workspace).filter(Network.network == network,
                                                                   Workspace.name == workspace.name).one_or_none()
            if not result:
                result = Network(network=network, workspace=workspace, scope=scope)
                session.add(result)
                session.flush()
            elif scope is not None:
                result.scope = scope
            if result:
                if source:
                    result.sources.append(source)
                if report_item:
                    report_item.details = "potentially new IP network: {}".format(network)
                    report_item.report_type = "NETWORK"
                    report_item.notify()
        return result

    @staticmethod
    def get_network(session: Session,
                    workspace: Workspace,
                    network: str) -> Network:
        """
        This method shall be used to get a network from the database
        :param session: Database session used to add the email address
        :param workspace: The workspace to which the network shall be added
        :param network: Network that should be returned from the database
        """
        result = None
        if IpUtils.is_valid_cidr_range(network) or IpUtils.is_valid_address(network):
            result = session.query(Network).join(Workspace).filter(Network.network == network,
                                                                   Workspace.name == workspace.name).one_or_none()
        return result

    @staticmethod
    def delete_network(session: Session,
                       workspace: Workspace,
                       network: str) -> None:
        """
        This method shall be used to delete a network from the database
        :param session: Database session used to add the email address
        :param workspace: The workspace to which the network shall be added
        :param network: Network that should be added to the database
        """
        result = IpUtils.get_network(session=session, workspace=workspace, network=network)
        if result:
            session.delete(result)

    @staticmethod
    def add_host(session: Session,
                 workspace: Workspace,
                 address: str,
                 source: Source = None,
                 in_scope: bool = None,
                 report_item: ReportItem = None) -> Host:
        """
        This method shall be used to add an IPv4 address to the database
        :param session: Database session used to add the email address
        :param workspace: The workspace to which the network shall be added
        :param address: IPv4/IPv6 address that should be added to the database
        :param in_scope: Specifies whether the given IP address is in scope or not
        :param source: Source information
        :param report_item: Item that can be used for pushing information into the view
        :return: Database object
        """
        rvalue = None
        if address and IpUtils.is_valid_address(address):
            rvalue = session.query(Host).filter_by(address=address, workspace_id=workspace.id).one_or_none()
            if not rvalue:
                rvalue = Host(address=address, workspace=workspace, in_scope=in_scope)
                session.add(rvalue)
                session.flush()
            if in_scope is not None:
                rvalue.in_scope = in_scope
            if source:
                rvalue.sources.append(source)
            if rvalue and report_item:
                report_item.details = "potentially new host: {}".format(address)
                report_item.report_type = "IP"
                report_item.notify()
        return rvalue

    @staticmethod
    def get_host(session: Session,
                 workspace: Workspace,
                 address: str) -> Host:
        """
        This method shall be used to obtain a host object via the given IPv4/IPv6 address from the database
        :param session: Database session used to add the email address
        :param workspace: The workspace to which the network shall be added
        :param address: IPv4/IPv6 address whose host object should be returned from the database
        :return: Database object
        """
        return session.query(Host).filter_by(address=address, workspace_id=workspace.id).one_or_none()

    @staticmethod
    def delete_host(session: Session,
                    workspace: Workspace,
                    address: str) -> None:
        """
        This method shall be used to delete a host object via the given IPv4/IPv6 address in the database
        :param session: Database session used to add the email address
        :param workspace: The workspace to which the network shall be added
        :param address: IPv4 address whose host object should be deleted
        :return: Database object
        """
        result = IpUtils.get_host(session=session, workspace=workspace, address=address)
        if result:
            session.delete(result)

    @staticmethod
    def get_excluded_hosts(session: Session,
                           network: Network) -> List[str]:
        """
        Returns a list of IPv4/IPv6 addresses that are not in-scope of the current IPv4 network. This method is used by
        collectors like Nmap to exclude out-of-scope IP addresses from the network scan
        """
        result = []
        if network.scope is None or network.scope == ScopeType.exclude:
            result = [str(item) for item in ipaddress.ip_network(network.network)]
        elif network.scope == ScopeType.strict:
            for address in ipaddress.ip_network(network.network):
                address_str = address.compressed
                host = session.query(Host) \
                    .join(Network) \
                    .join(Workspace) \
                    .filter(Workspace.id == network.workspace_id,
                            Network.id == network.id,
                            Host.address == address_str).one_or_none()
                if host is None or not host.in_scope:
                    result.append(address_str)
        return result


class DomainUtils(BaseUtils):
    """This class provides utils in regard to domains"""
    RE_DOMAIN = "(?P<domain>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])\.?"
    RE_EMAIL = "(?P<email>[\w\.%\+\-_]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9])"

    def __init__(self, **args):
        super().__init__(**args)


class EmailUtils(DomainUtils):
    """This class provides utils in regard to emails"""

    def __init__(self, **args):
        super().__init__(**args)


class XmlUtils:
    """
    This class provides utils for XML processing
    """

    @staticmethod
    def get_element_text(parent_tag, query: str) -> str:
        """
        This method searches a tag in the parent_tag based on the given find query. If the tag was found, then the
        content of the tag is returned, else None is returned
        :param parent_tag: The tag within which the search is performed
        :param query: The search query
        :return:
        """
        result =parent_tag.find(query)
        if result is not None:
            result = result.text
        return result

    @staticmethod
    def get_xml_attribute(attribute_name: str, attributes: dict) -> str:
        """
        This method returns the value of the given attribute name from a dictionary of attribute name value pairs.
        :param attribute_name: The attribute name for which the value shall be obtained.
        :param attributes: The dictionary containing all attributes.
        :return: Returns the value of the corresponding attribute name or none, if the name does not exist.
        """
        return_value = None
        if attributes is not None:
            if attribute_name in attributes:
                return_value = attributes[attribute_name].strip()
            return return_value

    @staticmethod
    def get_xml_text(tag_name: List) -> str:
        return_value = None
        if len(tag_name) == 1:
            return_value = tag_name[0].text.strip()
        elif len(tag_name) > 1:
            raise NotImplementedError("getText is not implemented for more than two elements.")
        return return_value


class NmapUtils:
    """
    This class implements utils for processing Nmap XML files
    """

    def __init__(self, xml_output: str) -> None:
        self._root = None
        if xml_output:
            try:
                self._root = ET.fromstring(xml_output)
            except xml.etree.ElementTree.ParseError:
                try:
                    self._root = ET.fromstring(xml_output + "</nmaprun>")
                except xml.etree.ElementTree.ParseError:
                    self._root = None

    def get_host_tag_by_ipv4(self, ipv4_address: str) -> Element:
        """
        This method returns the host XML tag for the given IPv4 address
        :param ipv4_address: The IPv4 address for which the host XML tag shall be returned
        :return: The host XML tag
        """
        if self._root:
            for host_tag in self._root.findall('host'):
                for addr in host_tag.findall('address'):
                    type = XmlUtils.get_xml_attribute("addrtype", addr.attrib)
                    if type == "ipv4":
                        if ipv4_address == XmlUtils.get_xml_attribute("addr", addr.attrib):
                            return host_tag
        return None

    def get_host_tags_by_host_name(self, host_name: str) -> List[Element]:
        """
        This method returns the host XML tags for the given host name
        :param host_name: The host name for which the host XML tag shall be returned
        :return: The host XML tag
        """
        rvalue = []
        lhost_name = host_name.lower()
        if self._root:
            for host_tag in self._root.findall('host'):
                for host_names in host_tag.findall("hostnames/*"):
                    name = XmlUtils.get_xml_attribute("name", host_names.attrib)
                    if name.lower() == lhost_name:
                        rvalue.append(host_tag)
        return rvalue

    def get_service_by_port_number(self, host_tag: Element, protocol: ProtocolType, port_number: int) -> Element:
        """
        This method returns the port XML tag of the given host XML tag for the given layer 4 protocol and port number
        :param host_tag: The host XML tag of which the port XML tag shall be returned
        :param protocol: The layer 4 protocol for which the port XML tag shall be returned
        :param port_number: The port number for which the port XML tag shall be returned
        :return: The port XML tag
        """
        if self._root and host_tag:
            for port_tag in host_tag.findall('*/port'):
                service_protocol = XmlUtils.get_xml_attribute("protocol", port_tag.attrib)
                if service_protocol == 'tcp':
                    service_protocol = ProtocolType.tcp
                elif service_protocol == 'udp':
                    service_protocol = ProtocolType.tcp
                else:
                    raise NotImplementedError("Protocol '{}' not implemented.".format(service_protocol))
                service_port = XmlUtils.get_xml_attribute("portid", port_tag.attrib)
                if protocol == service_protocol and port_number == int(service_port):
                    return port_tag
        return None

    def get_service(self,
                    protocol: ProtocolType,
                    port_number: int,
                    ipv4_address: str = None,
                    host_name: str = None) -> List[Element]:
        """
        This method returns the port XML tag based on the given IPv4 address, protocol, and port number
        :param ipv4_address: The IPv4 address for which the host XML tag shall be returned
        :param host_name: The host_name for which the host XML tag shall be returned
        :param protocol: The layer 4 protocol for which the port XML tag shall be returned
        :param port_number: The port number for which the port XML tag shall be returned
        :return: The port XML tags
        """
        service_tags = []
        if ipv4_address:
            host_tag = self.get_host_tag_by_ipv4(ipv4_address)
            if host_tag:
                service_tag = self.get_service_by_port_number(host_tag, protocol, port_number)
                service_tags.append(service_tag)
        elif host_name:
            host_tags = self.get_host_tags_by_host_name(host_name)
            for host_tag in host_tags:
                service_tag = self.get_service_by_port_number(host_tag, protocol, port_number)
                service_tags.append(service_tag)
        return service_tags

