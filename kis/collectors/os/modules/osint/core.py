# -*- coding: utf-8 -*-
"""
this file implements core functionality to integrate kismanage into kiscollect
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

import logging
import ipaddress
import os
import re
from typing import List
from typing import Dict
from configs.config import ApiConfig
from collectors.core import IpUtils
from collectors.core import JsonUtils
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import Ipv4NetworkCollector
from collectors.os.core import PopenCommand
from database.model import CollectorName
from database.model import Workspace
from database.model import Host
from database.model import Network
from database.model import HostName
from database.model import Source
from database.model import Command
from database.model import Service
from database.model import Email
from database.model import Company
from database.model import ProtocolType
from database.model import ServiceState
from database.model import CredentialType
from database.model import IpSupport
from database.model import PathType
from database.model import ExecutionInfoType
from database.model import CertType
from database.model import Path
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('collector')


# todo: update for new collector
class BaseKisImport(BaseCollector):
    """
    This class implements core functionality for kismanage
    """

    def __init__(self, argument_name: str, source: str, **kwargs):
        super().__init__(**kwargs)
        self._source = source
        self._api_config = ApiConfig()
        self._json_utils = JsonUtils()
        self._argument_name = argument_name

    def api_credentials_available(self) -> bool:
        """
        This method shall be implemented by sub classes. They should verify whether their API keys are set in the
        configuration file
        :return: Return true if API credentials are set, else false
        """
        raise NotImplementedError("method must be implemented by sub class")

    # todo: update for new collector
    def _get_commands(self,
                      session: Session,
                      collector_name: CollectorName,
                      workspace: Workspace,
                      output_path: str,
                      input_file: str = None,
                      host: Host = None,
                      network: Network = None,
                      host_name: HostName = None,
                      email: Email = None,
                      company: Company = None,
                      service: Service = None,
                      path: Path = None) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        python3_command = self._path_python3
        kisimport_command = self._path_kisimport
        if not self.api_credentials_available():
            logger.warning("api keys not set in config file '{}' for "
                           "collector {}".format(self._api_config.full_path,
                                                 collector_name.name))
            return collectors
        if host:
            target = host.address
        elif network:
            target = network.network
        elif host_name:
            target = host_name.domain_name.name
        elif email:
            target = email.email_address
        elif company:
            target = company.name
        elif service:
            target = service.get_urlparse().geturl()
        elif path:
            target = path.get_path()
        else:
            raise ValueError("parameter host, host_name, email, company, service, or path is required")
        if not os.path.isfile(kisimport_command):
            raise FileNotFoundError("script '{}' does not exist".format(kisimport_command))
        # Create command
        os_command = [python3_command,
                      kisimport_command,
                      "kiscollect",
                      '-w', workspace.name,
                      "-O", ExecutionInfoType.output_path.argument,
                      "--id", ExecutionInfoType.command_id.argument]
        if input_file:
            os_command += [self._argument_name, ExecutionInfoType.input_file.argument]
        else:
            os_command += [self._argument_name, target]
        # Add command to database
        command = self._get_or_create_command(session,
                                              os_command,
                                              collector_name,
                                              host=host,
                                              network=network,
                                              host_name=host_name,
                                              email=email,
                                              company=company,
                                              output_path=output_path,
                                              service=service,
                                              path=path,
                                              input_file=input_file)
        command.execution_info[ExecutionInfoType.command_id.name] = str(command.id)
        collectors.append(command)
        return collectors

    def _add_host_names(self,
                        session: Session,
                        host_names: List[HostName],
                        command: Command,
                        source: Source,
                        report_item: ReportItem,
                        dedup_host_names: Dict[str, bool] = {}):
        if host_names:
            for host_name in host_names:
                if host_name not in dedup_host_names:
                    dedup_host_names[host_name] = True
                    self.add_host_name(session=session,
                                       command=command,
                                       host_name=host_name,
                                       source=source,
                                       verify=True,
                                       report_item=report_item)

    def parse_shodan_data(self,
                          session: Session,
                          command: Command,
                          host: Host,
                          source: Source,
                          data: dict,
                          dedup_host_names: dict,
                          report_item: ReportItem,
                          **kwargs):
        tls_tunnel = None
        nmap_service_name = None
        anonymous = None
        port = self._json_utils.get_attribute_value(data, "port")
        host_names = self._json_utils.get_attribute_value(data, "hostnames", default_value=[])
        info = self._json_utils.get_attribute_value(data, "info")
        domains = self._json_utils.get_attribute_value(data, "domains", default_value=[])
        product = self._json_utils.get_attribute_value(data, "product")
        version = self._json_utils.get_attribute_value(data, "version")
        protocol_type = self._json_utils.get_attribute_value(data, "transport")
        vulns = self._json_utils.get_attribute_value(data, "vulns", default_value={})
        host_names.extend(domains)
        if protocol_type == "tcp":
            protocol_type = ProtocolType.tcp
        elif protocol_type == "udp":
            protocol_type = ProtocolType.udp
        else:
            raise NotImplementedError("Case for protocol '{}' not implemented".format(protocol_type))
        if "ssl" in data and isinstance(data["ssl"], dict):
            ssl_item = data["ssl"]
            tls_tunnel = "ssl"
            certificate_chain = self._json_utils.get_attribute_value(ssl_item, "chain", default_value=[])
            cert_count = len(certificate_chain)
            for i in range(0, cert_count):
                if i == 0:
                    cert_type = CertType.identity
                elif i == (cert_count - 1):
                    cert_type = CertType.root
                else:
                    cert_type = CertType.intermediate
                self.add_certificate(session=session,
                                     command=command,
                                     content=certificate_chain[i],
                                     type=cert_type,
                                     source=source,
                                     report_item=report_item)
        if "http" in data and isinstance(data["http"], dict):
            nmap_service_name = "https" if tls_tunnel == "ssl" else "http"
        elif "ftp" in data and isinstance(data["ftp"], dict):
            nmap_service_name = "ftp"
            anonymous = self._json_utils.get_attribute_value(data["ftp"], "anonymous")
        elif "ssh" in data and isinstance(data["ssh"], dict):
            nmap_service_name = "ssh"
        self._add_host_names(session=session,
                             host_names=host_names,
                             command=command,
                             source=source,
                             report_item=report_item,
                             dedup_host_names=dedup_host_names)
        if protocol_type and port:
            service = self.add_service(session=session,
                                       port=port,
                                       protocol_type=protocol_type,
                                       state=ServiceState.Open,
                                       host=host,
                                       nmap_service_name=nmap_service_name,
                                       nmap_service_confidence=10,
                                       nmap_tunnel=tls_tunnel,
                                       nmap_product=product,
                                       nmap_version=version,
                                       source=source,
                                       report_item=report_item)
            if anonymous:
                self.add_credential(session=session,
                                    command=command,
                                    password="anonymous",
                                    credential_type=CredentialType.Cleartext,
                                    username="anonymous",
                                    source=source,
                                    service=service,
                                    report_item=report_item)
            if nmap_service_name in ["http", "https"]:
                http_title = self._json_utils.get_attribute_value(data, "http/title")
                if http_title:
                    self.add_additional_info(session=session,
                                             command=command,
                                             name="HTTP title",
                                             values=[http_title],
                                             source=source,
                                             service=service,
                                             report_item=report_item)
                http_server = self._json_utils.get_attribute_value(data, "http/server")
                if http_title:
                    self.add_additional_info(session=session,
                                             command=command,
                                             name="HTTP server",
                                             values=[http_server],
                                             source=source,
                                             service=service,
                                             report_item=report_item)
                robots = self._json_utils.get_attribute_value(data, "http/robots")
                if robots:
                    self.add_robots_txt(session=session,
                                        command=command,
                                        service=service,
                                        robots_txt=robots.split(os.linesep),
                                        source=source,
                                        report_item=report_item)
                location = self._json_utils.get_attribute_value(data, "http/location")
                if location and location[0] == "/":
                    self.add_path(session=session,
                                  command=command,
                                  service=service,
                                  path=location,
                                  path_type=PathType.Http,
                                  source=source,
                                  report_item=report_item)
            additional_vuln_info = []
            for key, value in vulns.items():
                # format: CVE,CVSSv3,CVSSv2,Plugin ID,Summary
                cvssv2 = self._json_utils.get_attribute_value(value, "cvss", default_value="")
                summary = self._json_utils.get_attribute_value(value, "summary", default_value="")
                additional_vuln_info.append([key, None, cvssv2, None, summary])
            if additional_vuln_info:
                vulnerabilities = []
                vulnerabilities.extend(additional_vuln_info)
                vulnerabilities = self.get_list_as_csv(vulnerabilities)
                self.add_additional_info(session=session,
                                         command=command,
                                         name="CVEs",
                                         values=vulnerabilities,
                                         service=service,
                                         source=source,
                                         report_item=report_item)

    def verify_results(self, session: Session,
                       command: Command,
                       source: Source,
                       report_item: ReportItem,
                       process: PopenCommand = None, **kwargs) -> None:
        """This method analyses the results of the command execution.

        After the execution, this method checks the OS command's results to determine the command's execution status as
        well as existing vulnerabilities (e.g. weak login credentials, NULL sessions, hidden Web folders). The
        stores the output in table command. In addition, the collector might add derived information to other tables as
        well.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param source: The source object of the current collector
        :param report_item: Item that can be used for reporting potential findings in the UI
        :param process: The PopenCommand object that executed the given result. This object holds stderr, stdout, return
        code etc.
        """
        if command.return_code and command.return_code > 0:
            command.hide = True
            self._set_execution_failed(session=session, command=command)


class BaseKisImportHost(BaseKisImport):
    """
    This class implements core functionality for kismanage for host-based collectors
    """

    def __init__(self, ip_support: IpSupport, **kwargs):
        super().__init__(**kwargs)
        self._ip_support = ip_support

    def create_host_commands(self,
                             session: Session,
                             host: Host,
                             collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly craeated Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param host: The host based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        if host.supports_version(self._ip_support) and ipaddress.ip_address(host.address).is_global:
            # Create output directory
            output_path = self.create_path(host=host)
            # Create command
            tmp = self._get_commands(session=session,
                                     host=host,
                                     collector_name=collector_name,
                                     workspace=host.workspace,
                                     output_path=output_path)
            collectors.extend(tmp)
        return collectors


class BaseKisImportNetwork(BaseKisImport, Ipv4NetworkCollector):
    """
    This class implements core functionality for kismanage for host-based collectors
    """

    def __init__(self, ip_support: IpSupport, **kwargs):
        super().__init__(**kwargs)
        self._ip_support = ip_support

    def create_ipv4_network_commands(self,
                                     session: Session,
                                     network: Network,
                                     collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given IPv4 network.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param ipv4_network: The IPv4 network based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        if network.supports_version(self._ip_support) and \
                network.network != "0.0.0.0/0" and \
                network.network != "::1" and \
                network.network != "::/0" and \
                ipaddress.ip_network(network.network).is_global:
            # Create output directory
            output_path = self.create_path(network=network)
            # Create command
            tmp = self._get_commands(session=session,
                                     network=network,
                                     collector_name=collector_name,
                                     workspace=network.workspace,
                                     output_path=output_path)
            collectors.extend(tmp)
        return collectors


class BaseKisImportDomain(BaseKisImport):
    """
    This class implements core functionality for kismanage for domain-based collectors
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def create_domain_commands(self,
                               session: Session,
                               host_name: HostName,
                               collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly craeated Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param host_name: The host based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        if not host_name.name:
            # Create output directory
            output_path = self.create_path(host_name=host_name)
            # Create command
            tmp = self._get_commands(session=session,
                                     host_name=host_name,
                                     collector_name=collector_name,
                                     workspace=host_name.domain_name.workspace,
                                     output_path=output_path)
            collectors.extend(tmp)
        return collectors


class BaseKisImportEmail(BaseKisImport):
    """
    This class implements core functionality for kismanage for email-based collectors
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def create_email_commands(self,
                              session: Session,
                              email: Email,
                              collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly craeated Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param email: The email address object based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        # Create output directory
        output_path = self.create_path(email=email)
        # Create command
        tmp = self._get_commands(session=session,
                                 email=email,
                                 collector_name=collector_name,
                                 workspace=email.host_name.domain_name.workspace,
                                 output_path=output_path)
        collectors.extend(tmp)
        return collectors


class BaseKisImportCompany(BaseKisImport):
    """
    This class implements core functionality for kismanage for company-based collectors
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def create_company_commands(self,
                                session: Session,
                                company: Company,
                                collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly craeated Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param email: The email address object based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        # Create output directory
        output_path = self.create_path(company=company)
        # Create command
        tmp = self._get_commands(session=session,
                                 company=company,
                                 collector_name=collector_name,
                                 workspace=company.workspace,
                                 output_path=output_path)
        collectors.extend(tmp)
        return collectors


class BaseWhoisHostNetwork(BaseCollector):
    """
    This class implements core functionality whois-based collectors that collect information based on hosts and networks
    """

    def __init__(self, **kwargs):
        super().__init__(active_collector=False,
                         timeout=10,
                         delay_min=2,
                         delay_max=5,
                         **kwargs)
        self._relevant_attributes = ["descr", "address", "role", "orgname", "organization", "org-name"]
        self._re_organizations = re.compile("^(({})):\s+(?P<name>.+?{}).*$".format(")|(".join(self._relevant_attributes),
                                                                                 self._re_legal_entities),
                                            re.IGNORECASE)
        self._re_ip_network_range = re.compile("^((inetnum)|(netrange)):\s*(?P<range>.+)\s*$", re.IGNORECASE)
        self._re_ipv4_network_cidr = re.compile("^cidr:\s*(?P<range>.+)\s*$", re.IGNORECASE)
        self._re_ipv6_network_cidr = re.compile("^inet6num:\s*(?P<range>.+)\s*$", re.IGNORECASE)

    def _split_cidr(self, cidr: str) -> List[str]:
        result = []
        if cidr:
            result = [item.strip() for item in cidr.split(",")]
        return result

    def verify_results(self, session: Session,
                       command: Command,
                       source: Source,
                       report_item: ReportItem,
                       process: PopenCommand = None, **kwargs) -> None:
        """This method analyses the results of the command execution.

        After the execution, this method checks the OS command's results to determine the command's execution status as
        well as existing vulnerabilities (e.g. weak login credentials, NULL sessions, hidden Web folders). The
        stores the output in table command. In addition, the collector might add derived information to other tables as
        well.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param source: The source object of the current collector
        :param report_item: Item that can be used for reporting potential findings in the UI
        :param process: The PopenCommand object that executed the given result. This object holds stderr, stdout, return
        code etc.
        """
        companies = {}
        email_objects = {}
        network_objects = {}
        command.hide = True
        # extract company names
        for line in command.stdout_output:
            match = self._re_organizations.match(line)
            if match:
                name = match.group("name").strip().lower()
                companies[name] = None
        # extract IPv4/IPv6 networks and emails
        for line in command.stdout_output:
            match_ip_network_range = self._re_ip_network_range.match(line)
            match_ipv4_network_cidr = self._re_ipv4_network_cidr.match(line)
            match_ipv6_network_cidr = self._re_ipv6_network_cidr.match(line)
            emails = self._email_utils.extract_emails(line)
            for email in emails:
                email_objects[email] = None
            if match_ip_network_range:
                try:
                    for item in IpUtils.qualys_to_cidr(match_ip_network_range.group("range")):
                        network_objects[str(item)] = None
                except ValueError as ex:
                    logger.exception(ex)
            elif match_ipv4_network_cidr:
                try:
                    for item in self._split_cidr(match_ipv4_network_cidr.group("range")):
                        network_objects[item] = None
                except ValueError as ex:
                    logger.exception(ex)
            elif match_ipv6_network_cidr:
                try:
                    for item in self._split_cidr(match_ipv6_network_cidr.group("range")):
                        network_objects[item] = None
                except ValueError as ex:
                    logger.exception(ex)
        # saving companies, IPv4/IPv6 networks, and emails
        for item in network_objects.keys():
            network = self.add_network(session=session,
                                       command=command,
                                       network=item,
                                       source=source,
                                       report_item=report_item)
            if not network:
                logger.debug("ignoring network '{}' due to invalid format.".format(item))
            else:
                for name in companies.keys():
                    company = self.add_company(session=session,
                                               workspace=command.workspace,
                                               name=name,
                                               network=network,
                                               source=source,
                                               report_item=report_item)
                    if not company:
                        logger.debug("ignoring company '{}' due to invalid format.".format(company))
        for item in email_objects.keys():
            email = self.add_email(session=session,
                                   command=command,
                                   email=item,
                                   source=source,
                                   report_item=report_item)
            if not email:
                logger.debug("ignoring email '{}' due to invalid format.")
            else:
                for name in companies.keys():
                    company = self.add_company(session=session,
                                               workspace=command.workspace,
                                               name=name,
                                               domain_name=email.host_name.domain_name,
                                               source=source,
                                               report_item=report_item)
                    if not company:
                        logger.debug("ignoring company '{}' due to invalid format.".format(company))
