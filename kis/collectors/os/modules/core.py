# -*- coding: utf-8 -*-
"""
this module implements core functionality used by all modules
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
import re
import random
import time
import logging
import glob
import enum
import json
import pwd
import stat
from urllib.parse import urlparse
from database.model import Service
from database.model import Host
from database.model import HostName
from database.model import DomainName
from database.model import Network
from database.model import Credentials
from database.model import CredentialType
from database.model import ProtocolType
from database.model import Source
from database.model import CollectorName
from database.model import Path
from database.model import Command
from database.model import ServiceState
from database.model import PathType
from database.model import Email
from database.model import CollectorType
from database.model import Company
from database.model import FileType
from database.model import File
from database.model import ServiceMethod
from database.model import Workspace
from database.model import TlsVersion
from database.model import TlsPreference
from database.model import TlsInfo
from database.model import KeyExchangeAlgorithm
from database.model import CipherSuite
from database.model import TlsInfoCipherSuiteMapping
from database.model import AsymmetricAlgorithm
from database.model import HashAlgorithm
from database.model import CertType
from database.model import CertInfo
from database.model import CommandStatus
from database.model import IpSupport
from database.model import ExecutionInfoType
from database.model import VhostChoice
from database.utils import Engine
from database.utils import HostHostNameMapping
from database.utils import HostNameHostNameMapping
from database.utils import DnsResourceRecordType
from threading import Lock
from configs import config
from collectors.os.core import PopenCommand
from collectors.core import NmapUtils
from collectors.core import XmlUtils
from collectors.core import DomainUtils
from collectors.core import EmailUtils
from collectors.core import IpUtils
from collectors.core import JsonUtils
from typing import List
from typing import Dict
from view.core import ReportItem
from sqlalchemy.orm.session import Session
from urllib.parse import ParseResult
from collectors.core import BaseUtils
from datetime import datetime

logger = logging.getLogger('collector.core')


class CommandCreationFailed(Exception):
    """This class shall be thrown, when an operating system command should not be created."""

    def __init__(self, message: str):
        super().__init__(message)


class ExecutionFailedException(Exception):
    """This class shall be thrown, when an operating system command did not finish successfully"""

    def __init__(self, command: Command):
        super().__init__("Execution of command with database ID {} failed".format(command.id))


class Delay:
    """This class is responsible for delaying command executions"""
    def __init__(self, delay_min: int, delay_max: int, print_commands: bool = False, analyze_commands: bool = False):
        if delay_min and delay_max and delay_min > delay_max:
            raise ValueError("min delay larger than max delay")
        self._print_commands = print_commands
        self._analyze_commands = analyze_commands
        self._delay_min = delay_min if not (self._print_commands or self._analyze_commands) else 0
        self._delay_max = delay_max if not (self._print_commands or self._analyze_commands) else 0
        self._delay_min = self._delay_min if self._delay_min and self._delay_min >= 0 else 0
        self._delay_max = self._delay_max if (self._delay_max and self._delay_max >= 0) and \
                                              self._delay_min != self._delay_max else 0

    def sleep_active(self) -> bool:
        """
        Retruns true if sleep times are set
        :return:
        """
        return self._delay_min > 0 or self._delay_max > 0

    @property
    def sleep_time(self) -> bool:
        """
        This method returns the current sleep time
        :return:
        """
        sleep = 0
        if self._delay_min and not self._delay_max:
            sleep = self._delay_min
        elif not self._delay_min and self._delay_max:
            sleep = self._delay_max
        elif self._delay_min and self._delay_max:
            sleep = random.randrange(self._delay_min, self._delay_max)
        return sleep

    def sleep(self) -> None:
        """
        This method determines how long to sleep before continuing the work
        :return:
        """
        if self.sleep_time > 0:
            time.sleep(self.sleep_time)


class BaseExtraServiceInfoExtraction:
    """This base class provides base functionality to extract extra information from services."""

    def __init__(self,
                 session,
                 service: Service,
                 workspace: Workspace,
                 source: Source,
                 domain_utils: DomainUtils,
                 ip_utils: IpUtils,
                 stdout = None,
                 report_item: ReportItem = None,
                 command: Command = None,
                 **args):
        """

        :param session: The database session to query or update information stored in the database.
        :param service: The service instance for which information shall be extracted.
        """
        self._session = session
        self._service = service
        self._source = source
        self._command = command
        self._workspace = workspace
        self._args = args
        self._stdout = stdout
        self._domain_utils = domain_utils
        self._ip_utils = ip_utils
        self._report_item = report_item

    def _extract_ntlm_info(self, port_tag, tag_id: str) -> None:
        """This method extracts NTLM information"""
        for script_tag in port_tag.findall("*/[@id='{}']".format(tag_id)):
            info = XmlUtils.get_element_text(script_tag, "./elem[@key='NetBIOS_Domain_Name']")
            if info is not None and self._service.host:
                self._service.host.workgroup = info
            info = XmlUtils.get_element_text(script_tag, "./elem[@key='DNS_Computer_Name']")
            if info is not None:
                host_name = self._domain_utils.add_domain_name(session=self._session,
                                                               workspace=self._workspace,
                                                               item=info,
                                                               source=self._source,
                                                               verify=True,
                                                               report_item=self._report_item)
                if not host_name:
                    logger.debug("ignoring computer name '{}' due to invalid format".format(info))
                else:
                    resource_type = DnsResourceRecordType.a if self._service.host.version == 4 \
                        else DnsResourceRecordType.aaaa
                    self._domain_utils.add_host_host_name_mapping(self._session,
                                                                  host=self._service.host,
                                                                  host_name=host_name,
                                                                  source=self._source,
                                                                  mapping_type=resource_type,
                                                                  report_item=self._report_item)
            info = XmlUtils.get_element_text(script_tag, "./elem[@key='DNS_Domain_Name']")
            if info is not None:
                host_name = self._domain_utils.add_domain_name(session=self._session,
                                                               workspace=self._workspace,
                                                               item=info,
                                                               source=self._source,
                                                               verify=True,
                                                               report_item=self._report_item)
                if not host_name:
                    logger.debug("ignoring domain name '{}' due to invalid format".format(info))
                else:
                    resource_type = DnsResourceRecordType.a if self._service.host.version == 4 \
                        else DnsResourceRecordType.aaaa
                    self._domain_utils.add_host_host_name_mapping(self._session,
                                                                  host=self._service.host,
                                                                  host_name=host_name,
                                                                  source=self._source,
                                                                  mapping_type=resource_type,
                                                                  report_item=self._report_item)
            info = XmlUtils.get_element_text(script_tag, "./elem[@key='DNS_Tree_Name']")
            if info is not None:
                host_name = self._domain_utils.add_domain_name(session=self._session,
                                                               workspace=self._workspace,
                                                               item=info,
                                                               source=self._source,
                                                               verify=True,
                                                               report_item=self._report_item)
                if not host_name:
                    logger.debug("ignoring tree name '{}' due to invalid format".format(info))
                else:
                    resource_type = DnsResourceRecordType.a if self._service.host.version == 4 \
                        else DnsResourceRecordType.aaaa
                    self._domain_utils.add_host_host_name_mapping(self._session,
                                                                  host=self._service.host,
                                                                  host_name=host_name,
                                                                  source=self._source,
                                                                  mapping_type=resource_type,
                                                                  report_item=self._report_item)

    def extract(self, extra_info_tag):
        """This method extracts the required information."""
        raise NotImplementedError("This method must be implemented!")


class ServiceDescriptorBase:
    """This class implements base functionality to describe a service"""

    def __init__(self,
                 default_tcp_ports = [],
                 default_udp_ports = [],
                 nmap_tcp_service_names = [],
                 nmap_udp_service_names = [],
                 nessus_tcp_service_names = [],
                 nessus_udp_service_names = []):
        self._default_tcp_ports = default_tcp_ports
        self._default_udp_ports = default_udp_ports
        self._nmap_tcp_service_names = [re.compile(item) for item in nmap_tcp_service_names]
        self._nmap_udp_service_names = [re.compile(item) for item in nmap_udp_service_names]
        self._nessus_tcp_service_names = [re.compile(item) for item in nessus_tcp_service_names]
        self._nessus_udp_service_names = [re.compile(item) for item in nessus_udp_service_names]

    def match_tls(self, service: Service):
        """
        This method checks whether the given service supports TLS
        :param service: The service that is checked
        :return: True if the service matches the service descriptor
        """
        return service.nmap_tunnel == "ssl" and service.protocol == ProtocolType.tcp

    def match_port(self, service: Service):
        """
        This method checks whether the given service matches this service descriptor based on the port number
        :param service: The service that is checked
        :return: True if the service matches the service descriptor
        """
        return (service.protocol == ProtocolType.tcp and service.port in self._default_tcp_ports) or \
               (service.protocol == ProtocolType.udp and service.port in self._default_udp_ports)

    def match_nmap_service_name(self, service: Service):
        """
        This method checks whether the given service matches this service descriptor based on the Nmap or Nessus
        service name
        :param service: The service that is checked
        :return: True if the service matches the service descriptor
        """
        rvalue = False
        if service.nmap_service_name:
            if service.protocol == ProtocolType.tcp:
                for item in self._nmap_tcp_service_names:
                    if item.match(service.nmap_service_name):
                        rvalue = True
                        break
            else:
                for item in self._nmap_udp_service_names:
                    if item.match(service.nmap_service_name):
                        rvalue = True
                        break
        elif service.nessus_service_name:
            if service.protocol == ProtocolType.tcp:
                for item in self._nessus_tcp_service_names:
                    if item.match(service.nessus_service_name):
                        rvalue = True
                        break
            else:
                for item in self._nessus_udp_service_names:
                    if item.match(service.nessus_service_name):
                        rvalue = True
                        break
        else:
            rvalue = self.match_port(service)
        return rvalue


class OutputType(enum.Enum):
    stderr = enum.auto()
    stdout = enum.auto()


class CommandFailureRule:
    """This class defines a rule for identifying a command execution failue"""

    def __init__(self, regex: re.Pattern, output_type: OutputType):
        self._regex = regex
        self._type = output_type

    def has_failed(self, command: Command) -> bool:
        """
        Returns true if one line of the commant output matches the regular expression
        :param command:
        :return:
        """
        if self._type == OutputType.stderr:
            lines = command.stderr_output
        elif self._type == OutputType.stdout:
            lines = command.stdout_output
        else:
            raise NotImplementedError("case for type {} not implemented".format(self._type.name))
        for line in lines:
            if self._regex.match(line):
                return True
        return False


class BaseCollector(config.Collector):
    """This class implements the base interface to create Kali collectors."""

    def __init__(self,
                 priority: int,
                 timeout: int,
                 name: str,
                 output_dir: str,
                 engine: Engine,
                 http_proxy: str = None,
                 cookies: List[str] = {},
                 ui_manager = None,
                 print_commands: bool = None,
                 threads: int = 1,
                 hashes: bool = None,
                 active_collector: bool = True,
                 service_descriptors: List[ServiceDescriptorBase] = [],
                 delay_min: int = 0,
                 delay_max: int = 0,
                 force_delay_min: int = 0,
                 force_delay_max: int = 0,
                 force_timeout: int = 0,
                 max_threads: int = 0,
                 analyze: bool = False,
                 ignore: bool = True,
                 vhost: str = None,
                 execution_class: PopenCommand = PopenCommand,
                 exec_user: str = "nobody",
                 **kwargs):
        """
        This is the base class for all collectors.

        This class contains all functionality to manage a collector, to create its commands as well as to update the
        database after each command is executed.

        :param priority: The priority of the collector. The lower the priority, the earlier the commands are created
        and executed
        :param timeout: The maximum execution time after which a command is killed.
        :param name: The name of the collector (e.g., httpnikto)
        :param output_dir: The temporary directory where intermediate files can be written
        :param engine: The database object, which allows interacting with the database
        :param http_proxy: HTTP proxy that shall be used by web collectors
        :param cookies: HTTP cookies that shall be used by web collectors
        :param ui_manager: UI manager object, which allows interacting with the UI
        :param print_commands: If true, commands are only printed and not executed
        :param threads: The number of threads that execute commands. Potentially useful for collectors during command
        creation
        :param hashes: List of NTLM hashes for authentication attempts
        :param active_collector: If true, then the collector actively interacts with the target, else information is
        collected from a third-party
        :param service_descriptors: Object that defines on which services the collector shall be executed
        :param delay_min: The collector's minimum default delay
        :param delay_max: The collector's maximum default delay
        :param force_delay_min: The minimum delay specified by the user. If specified, then the collectors delay is
        overwritten
        :param force_delay_max: The maximum delay specified by the user. If specified, then the collectors delay is
        overwritten
        :param force_timeout: The maximum execution time specified by the user. If specified, then the collector is
        automatically terminated after force_timeout seconds
        :param exec_user: The user name in whose context all operating system commands that were created by the
        collector are executed
        :max_threads: The maximum number of threads that are allowed to execute commands created by this collector
        :analyze: If true, then output is analyzed and not commands are created. Potentially useful for collectors
        during command output analysis
        :execution_class: Specifies which object performs the execution of the created commands
        """
        super().__init__()
        self._update_db_lock = Lock()
        self._domain_utils = DomainUtils()
        self._email_utils = EmailUtils()
        self._ip_utils = IpUtils()
        self._json_utils = JsonUtils()
        self._priority = priority
        self._timeout = force_timeout if force_timeout else timeout
        self._active_collector = active_collector
        self._name = name
        self._output_dir = output_dir
        self._engine = engine
        self._number_of_threads = threads
        self._ui_manager = ui_manager
        self._hashes = hashes
        self.execution_class = execution_class
        self._http_proxy = urlparse(http_proxy) if http_proxy else None
        self._cookies = cookies if cookies else []
        self._kwargs = kwargs
        self._min_delay = force_delay_min if force_delay_min else delay_min
        self._max_delay = force_delay_max if force_delay_max else delay_max
        self._max_threads = 1 if self._min_delay or self._max_delay else max_threads
        self._dns_server = self.get_commandline_argument_value("dns_server")
        self._user_agent = self.get_commandline_argument_value("user_agent")
        self._password = self.get_commandline_argument_value("password")
        self._password_file = self.get_commandline_argument_value("password_file")
        self._user = self.get_commandline_argument_value("user")
        self._domain = self.get_commandline_argument_value("domain")
        self._user_file = self.get_commandline_argument_value("user_file")
        self._combo_file = self.get_commandline_argument_value("combo_file")
        self._user = self.get_commandline_argument_value("user")
        self._password = self.get_commandline_argument_value("password")
        self._proxychains = self.get_commandline_argument_value("proxychains")
        self._analyze = analyze
        self._ignore = ignore
        if vhost:
            if isinstance(vhost, VhostChoice):
                self._vhost = vhost
            elif isinstance(vhost, str):
                self._vhost = VhostChoice[vhost]
        else:
            self._vhost = None
        tmp = self.get_commandline_argument_value("wordlist_files")
        self._wordlist_files = tmp if tmp else []
        self._print_commands = print_commands
        self.exec_user = pwd.getpwnam(exec_user)
        self._delay = Delay(delay_min=self._min_delay,
                            delay_max=self._max_delay,
                            print_commands=print_commands,
                            analyze_commands=analyze)
        self._service_descriptors = service_descriptors if isinstance(service_descriptors, list) else [service_descriptors]

    @property
    def max_threads(self) -> int:
        return self._max_threads

    @property
    def name(self) -> str:
        return self._name

    @property
    def output_dir(self) -> str:
        return self._output_dir

    @property
    def engine(self) -> Engine:
        return self._engine

    @property
    def priority(self) -> int:
        return self._priority

    @property
    def timeout(self) -> int:
        return self._timeout

    @property
    def http_proxy(self) -> ParseResult:
        return self._http_proxy

    @property
    def active_collector(self) -> bool:
        return self._active_collector

    @staticmethod
    def get_invalid_argument_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify invalid arguments
        """
        return []

    @staticmethod
    def get_failed_regex() -> List[CommandFailureRule]:
        """
        This method returns regular expressions that allows KIS to identify failed command executions
        """
        return []

    def sleep(self):
        self._delay.sleep()

    def add_report_item(self, report_item):
        """
        Use this method to add a new report item to the curse window Report Items
        :param report_item: The report item that shall be reported
        :return:
        """
        self._ui_manager.add_report_item(report_item)

    def match_service_tls(self, service: Service):
        """
        This method checks whether the given service supports TLS
        :param service: The service that is checked
        :return: True if the service matches the service descriptor
        """
        rvalue = False
        for item in self._service_descriptors:
            rvalue = item.match_tls(service)
            if rvalue:
                break
        rvalue = rvalue or service.port in [443, 3389, 8443]
        return rvalue

    def match_service_port(self, service: Service):
        """
        This method checks whether the given service matches this service descriptor based on the port number
        :param service: The service that is checked
        :return: True if the service matches the service descriptor
        """
        for item in self._service_descriptors:
            rvalue = item.match_port(service)
            if rvalue:
                break
        return rvalue

    def match_nmap_service_name(self, service: Service):
        """
        This method checks whether the given service matches this service descriptor based on the Nmap service name
        :param service: The service that is checked
        :return: True if the service matches the service descriptor
        """
        rvalue = True
        for item in self._service_descriptors:
            rvalue = item.match_nmap_service_name(service)
            if rvalue:
                break
        return rvalue

    def get_commandline_argument_value(self, argument_name: str):
        """
        This method returns the commandline argument value for the given argument name.

        :param argument_name: The argument's name for which the value shall be returned.
        :return The argument's value if the argument exists, else None
        """
        return self._kwargs[argument_name] if argument_name in self._kwargs else None

    def _set_execution_failed(self, session: Session, command: Command) -> None:
        command.status = CommandStatus.failed

    def _set_execution_complete(self, session: Session, command: Command) -> None:
        command.status = CommandStatus.completed

    @staticmethod
    def create_credential_arguments(argument_name_username: str = None,
                                    username: str = None,
                                    argument_name_password: str = None,
                                    password: str = None,
                                    argument_name_domain: str = None,
                                    domain: str = None,
                                    hash_options: List[str] = None) -> List[str]:
        """
        This method should be used by all collectors to create the argument list for commands
        :param argument_name_username: The argument name for the user
        :param username: The user name
        :param argument_name_password: The argument name for the password
        :param password: The password
        :param argument_name_domain: The argument name for the domain
        :param domain: The domain or workgroup
        :param is_hash: True if the password is a hash
        :return:
        """
        result = []
        if username:
            result += [argument_name_username, username]
        if password:
            result += [argument_name_password, password]
        if domain:
            result += [argument_name_domain, domain]
        if hash_options:
            result += hash_options
        return result

    def add_robots_txt(self,
                       session: Session,
                       command: Command,
                       service: Service,
                       robots_txt: List[str],
                       source: Source,
                       report_item: ReportItem = None) -> List[Path]:
        """
        This method establishes a link between a host and a host name
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param service: The service instance to which the identified paths are added
        :param robots_txt: The content of the robots.txt file that shall be parsed
        :param source: The source that identified the link
        :param report_item: Item that can be used for pushing information into the view
        """
        if report_item:
            report_item.listener = self._ui_manager
        paths = self._domain_utils.add_robots_txt(session=session,
                                                  service=service,
                                                  robots_txt=robots_txt,
                                                  source=source,
                                                  report_item=report_item)
        return paths

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
        if report_item:
            report_item.listener = self._ui_manager
        service_method = self._domain_utils.add_service_method(session=session,
                                                               name=name,
                                                               service=service,
                                                               source=source,
                                                               report_item=report_item)
        return service_method

    def add_host_host_name_mapping(self,
                                   session: Session,
                                   command: Command,
                                   host: Host,
                                   host_name: HostName,
                                   source: Source,
                                   mapping_type: DnsResourceRecordType = None,
                                   report_item: ReportItem = None) -> HostHostNameMapping:
        """
        This method establishes a link between a host and a host name
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param host: The host object that shall be linked
        :param host_name: The host name object that shall be linked
        :param source: The source that identified the link
        :param mapping_type: The type of link
        :param report_item: Item that can be used for pushing information into the view
        """
        if report_item:
            report_item.listener = self._ui_manager
        host = self._ip_utils.add_host_host_name_mapping(session=session,
                                                         host=host,
                                                         host_name=host_name,
                                                         source=source,
                                                         mapping_type=mapping_type,
                                                         report_item=report_item)
        return host

    def add_host_name_host_name_mapping(self,
                                        session: Session,
                                        command: Command,
                                        source_host_name: HostName,
                                        resolved_host_name: HostName,
                                        source: Source,
                                        mapping_type: DnsResourceRecordType,
                                        report_item: ReportItem = None) -> HostNameHostNameMapping:
        """
        This method establishes a link between a host and a host name
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param source_host_name: The host name which resolves to the resolved host name
        :param resolved_host_name: The host name object that was resolved
        :param source: The source that identified the link
        :param mapping_type: The type of link
        :param report_item: Item that can be used for pushing information into the view
        """
        if report_item:
            report_item.listener = self._ui_manager
        mapping = self._domain_utils.add_host_name_host_name_mapping(session=session,
                                                                     source_host_name=source_host_name,
                                                                     resolved_host_name=resolved_host_name,
                                                                     source=source,
                                                                     mapping_type=mapping_type,
                                                                     report_item=report_item)
        return mapping

    def add_host(self,
                 session: Session,
                 command: Command,
                 address: str,
                 source: Source = None,
                 report_item: ReportItem = None) -> Host:
        """
        This method should be used by collectors to add hosts to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param address: The IPv4/IPv6 address that shall be added
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        host = self._ip_utils.add_host(session=session,
                                       workspace=command.workspace,
                                       address=address,
                                       source=source,
                                       report_item=report_item)
        return host

    def add_network(self,
                    session: Session,
                    command: Command,
                    network: str,
                    source: Source = None,
                    report_item: ReportItem = None) -> Network:
        """
        This method should be used by collectors to add hosts to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param network: The IPv4/IPv6 network that shall be added
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        network = self._ip_utils.add_network(session=session,
                                             workspace=command.workspace,
                                             network=network,
                                             source=source,
                                             report_item=report_item)
        return network

    def add_source(self,
                   session: Session,
                   name: str) -> Source:
        """
        This method should be used by collectors to add hosts to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param name: The source name that shall be added
        :return:
        """
        source = self._ip_utils.add_source(session=session, name=name)
        return source

    def add_company(self,
                    session: Session,
                    workspace: Workspace,
                    name: str,
                    network: Network = None,
                    domain_name: DomainName = None,
                    verify: bool = True,
                    in_scope: bool = None,
                    source: Source = None,
                    report_item: ReportItem = None) -> Company:
        """
        This method adds the given company to the database
        :param session: The database session used for adding the company
        :param workspace: The workspace to which the company shall be added
        :param name: The name of the company that should be added
        :param verify: True if the given company name should be verified to ensure that it ends with legal entity type
        :param network: IPv4 network which is associated with the company
        :param domain_name: Domain name which is associated with the company
        :param in_scope: Specifies whether the given IP address is in scope or not
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        rvalue = self._domain_utils.add_company(session=session,
                                                workspace=workspace,
                                                name=name,
                                                network=network,
                                                domain_name=domain_name,
                                                verify=verify,
                                                in_scope=in_scope,
                                                source=source,
                                                report_item=report_item)
        return rvalue

    def add_service(self,
                    session: Session,
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
        :param nmap_product: specifies the Nmap product name
        :param nmap_version: specifies the Nmap version
        :param nessus_service_name: Specifies the Nessus service name
        :param nessus_service_confidence: Specifies the Nessus confidence of the identified service
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        rvalue = self._domain_utils.add_service(session=session,
                                                port=port,
                                                protocol_type=protocol_type,
                                                state=state,
                                                host=host,
                                                host_name=host_name,
                                                nmap_service_name=nmap_service_name,
                                                nmap_service_confidence=nmap_service_confidence,
                                                nmap_tunnel=nmap_tunnel,
                                                nmap_product=nmap_product,
                                                nmap_version=nmap_version,
                                                nessus_service_name=nessus_service_name,
                                                nessus_service_confidence=nessus_service_confidence,
                                                source=source,
                                                report_item=report_item)
        return rvalue

    def add_certificate(self,
                        session: Session,
                        command: Command,
                        content: str,
                        type: CertType,
                        source: Source = None,
                        report_item: ReportItem = None) -> File:
        """
        This method adds a certificate to the database and thereby extracts host names
        :param session: The database session used for addition the file path
        :param command: The command to which the file should be attached
        :param content: The certificate that should be added
        :param type: Specifies whether the certificate is an entity, bridge, or root certificate
        :param source: The source object from which the URL originates
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        certificate = self._domain_utils.add_certificate(session=session,
                                                         command=command,
                                                         content=content,
                                                         type=type,
                                                         source=source,
                                                         report_item=report_item)
        return certificate

    def add_file_content(self,
                         session: Session,
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
        file = self._domain_utils.add_file_content(session=session,
                                                   workspace=workspace,
                                                   command=command,
                                                   file_name=file_name,
                                                   file_type=file_type,
                                                   content=content,
                                                   report_item=report_item)
        return file

    def add_file(self,
                 session: Session,
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
        file = self._domain_utils.add_file(session=session,
                                           workspace=command.workspace,
                                           command=command,
                                           file_path=file_path,
                                           file_type=file_type)
        return file

    def add_host_name(self,
                      session: Session,
                      command: Command,
                      host_name: str,
                      source: Source = None,
                      verify: bool = True,
                      report_item: ReportItem = None) -> HostName:
        """
        This method should be used by collectors to add host names to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param host: The host object to which the host name belongs to
        :param host_name: The host name that shall be added
        :param source: The source object of the current collector
        :param verify: If true then the host name's structure is verified before it is added to the database
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        host_name = self._domain_utils.add_domain_name(session=session,
                                                       workspace=command.workspace,
                                                       item=host_name,
                                                       source=source,
                                                       verify=verify,
                                                       report_item=report_item)
        return host_name

    def add_email(self,
                  session: Session,
                  command: Command,
                  email: str,
                  source: Source = None,
                  report_item: ReportItem = None,
                  verify: bool = False) -> Path:
        """
        This method should be used by collectors to add credentials to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param workspace: Workspace to which the email shall be added
        :param command: The command instance that contains the results of the command execution
        :param email: The email that shall be added
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :param verify: If true then the host name's structure is verified before it is added to the database
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        email = self._email_utils.add_email(session=session,
                                            workspace=command.workspace,
                                            text=email,
                                            source=source,
                                            report_item=report_item,
                                            verify=verify)
        return email

    def get_list_as_csv(self, values: List[List[str]]) -> List[str]:
        """
        This method tages the given two-dimensional array and converts it into a CSV format
        :param values: The two-dimensional array to be converted
        :return:
        """
        return self._domain_utils.get_list_as_csv(values)

    def get_csv_as_list(self, values: List[str]) -> List[List[str]]:
        """
        This method is the counter part of the get_list_as_csv and takes a list of CSV strings and converts them into a
        two dimensional array
        :param values: The one-dimensional array that shall be converted
        :return:
        """
        return self._domain_utils.get_csv_as_list(values)

    def add_additional_info(self,
                            session: Session,
                            command: Command,
                            name: str,
                            values: List[str],
                            source: Source = None,
                            service: Service = None,
                            host_name: HostName = None,
                            email: Email = None,
                            company: Company = None,
                            report_item: ReportItem = None) -> Credentials:
        """
        This method should be used by collectors to add credentials to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance that contains the results of the command execution
        :param service: The service object to which the additional information belongs
        :param host_name: The host name object to which the additional information belongs
        :param email: The email object to which the additional information belongs
        :param company: The company object to which the additional information belongs
        :param name: The name of the additional information
        :param values: List of values for the additional information
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        rvalue = self._domain_utils.add_additional_info(session=session,
                                                        name=name,
                                                        values=values,
                                                        source=source,
                                                        service=service,
                                                        host_name=host_name,
                                                        email=email,
                                                        company=company,
                                                        report_item=report_item)
        return rvalue

    def add_credential(self,
                       session: Session,
                       command: Command,
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
        :param command: The command instance that contains the results of the command execution
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
        if report_item:
            report_item.listener = self._ui_manager
        rvalue = self._domain_utils.add_credential(session=session,
                                                   username=username,
                                                   password=password,
                                                   credential_type=credential_type,
                                                   domain=domain,
                                                   source=source,
                                                   service=service,
                                                   email=email,
                                                   report_item=report_item)
        return rvalue

    def add_hint(self,
                 command: Command,
                 hint: str,
                 report_item: ReportItem = None) -> None:
        """
        This method adds a hint for the given command to the database
        :param command: The command instance that contains the results of the command execution
        :param hint: The hint that should be added to the database
        :param report_item: Item that can be used for pushing information into the view
        """
        if report_item:
            report_item.listener = self._ui_manager
        self._domain_utils.add_hint(command=command,
                                    hint=hint,
                                    report_item=report_item)

    def add_path(self,
                 session: Session,
                 command: Command,
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
        :param command: The command instance that contains the results of the command execution
        :param service: The service object to which the credentials belongs
        :param path: The path that shall be added
        :param path_type: The path type that shall be added
        :param size_bytes: The size of the file
        :param return_code: The HTTP status code
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        rvalue = self._domain_utils.add_path(session=session,
                                             service=service,
                                             path=path,
                                             path_type=path_type,
                                             size_bytes=size_bytes,
                                             return_code=return_code,
                                             source=source,
                                             report_item=report_item)
        return rvalue

    def add_url(self,
                session: Session,
                service: Service,
                url: str,
                status_code: int = None,
                size_bytes: int = None,
                source: Source = None,
                report_item: ReportItem = None) -> Path:
        """
        This method adds the given URL to the database
        :param session: The database session used for addition the URL
        :param service: The service to which the URL belongs
        :param url: The URL that shall be added to the database
        :param status_code: The access code
        :param size_bytes: The size of the response body in bytes
        :param source: The source object from which the URL originates
        :param report_item: Item that can be used for pushing information into the view
        :return: The newly added path object
        """
        if report_item:
            report_item.listener = self._ui_manager
        rvalue = self._domain_utils.add_url(session=session,
                                            service=service,
                                            url=url,
                                            status_code=status_code,
                                            size_bytes=size_bytes,
                                            source=source,
                                            report_item=report_item)
        return rvalue

    def add_tls_info(self,
                     session: Session,
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
        :param compressors: A list of compressors to be added
        :param heartbleed: Specifies whether the TLS version is vulnerable to heartbleed
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        result = self._domain_utils.add_tls_info(session=session,
                                                 service=service,
                                                 version=version,
                                                 preference=preference,
                                                 compressors=compressors,
                                                 heartbleed=heartbleed,
                                                 report_item=report_item)
        return result

    def add_tls_info_cipher_suite_mapping(self,
                                          session: Session,
                                          tls_info: TlsInfo,
                                          order: int,
                                          kex_algorithm_details: KeyExchangeAlgorithm = None,
                                          iana_name: str = None,
                                          gnutls_name: str = None,
                                          openssl_name: str = None,
                                          cipher_suite: CipherSuite = None,
                                          prefered: bool = None,
                                          source: Source = None,
                                          report_item: ReportItem = None) -> TlsInfoCipherSuiteMapping:
        """
        This method should be used by collectors to add credentials to the database
        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param tls_info: The TLS info for which a mapping shall be created
        :param kex_algorithm_details: Contains details about the used key exchange algorithm
        :param cipher_suite: The TLS cipher suite for which a mapping shall be created
        :param iana_name: The cipher suite string in the IANA format
        :param openssl_name: The cipher suite string in the OpenSSL format
        :param gnutls_name: The cipher suite string in the GNU TLS format
        :param order: The order of the TLS cipher suite
        :param prefered: Specifies whether the TLS cipher suite is prefered
        :param source: The source object of the current collector
        :param report_item: Item that can be used for pushing information into the view
        :return:
        """
        if report_item:
            report_item.listener = self._ui_manager
        result = self._domain_utils.add_tls_info_cipher_suite_mapping(session=session,
                                                                      tls_info=tls_info,
                                                                      cipher_suite=cipher_suite,
                                                                      order=order,
                                                                      prefered=prefered,
                                                                      kex_algorithm_details=kex_algorithm_details,
                                                                      iana_name=iana_name,
                                                                      gnutls_name=gnutls_name,
                                                                      openssl_name=openssl_name,
                                                                      source=source,
                                                                      report_item=report_item)
        return result

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
                      extension_info: Dict[str, str] = {},
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
        :param signature_bits: The size of the signature in bits
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
        if report_item:
            report_item.listener = self._ui_manager
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
                                                  valid_until=valid_until,
                                                  valid_from=valid_from,
                                                  subject_alt_names=subject_alt_names,
                                                  extension_info=extension_info,
                                                  source=source,
                                                  report_item=report_item)
        return result

    # todo: update for new collector
    def create_xml_file_path(self,
                             service: Service = None,
                             host: Host = None,
                             network: Network = None,
                             email: Email = None,
                             host_name: HostName = None,
                             domain_name: DomainName = None,
                             company: Company = None,
                             file_suffix: str = None,
                             sub_directory: str = None,
                             create_new: bool = False,
                             delete_existing: bool = False) -> str:
        """
        This method creates an output directory and returns a unique filename that can be used by the OS command to
        write XML output, which later can be imported into the database.
        :param service: The service for which the path shall be created
        :param host: The host for which the path shall be created
        :param email: The email for which the path shall be created
        :param network: The IPv4 network for which the path shall be created
        :param host_name: The host name for which the path shall be created
        :param domain_name: The domain name for which the path shall be created
        :param file_suffix: Information that will be appended to the file name and before the file extension
        :param company: The company for which the path shall be created
        :param sub_directory: Creates the given sub directory in the respective IP address directory
        :param create_new: If the sub directory already exist, then it creates a new one
        :param delete_existing: Deletes the file if it already exists
        :return: Path of the file
        """
        return self.create_file_path(service=service,
                                     host=host,
                                     network=network,
                                     email=email,
                                     host_name=host_name,
                                     domain_name=domain_name,
                                     company=company,
                                     file_suffix=file_suffix,
                                     file_extension="xml",
                                     sub_directory=sub_directory,
                                     create_new=create_new,
                                     delete_existing=delete_existing)

    # todo: update for new collector
    def create_text_file_path(self,
                              service: Service = None,
                              host: Host = None,
                              network: Network = None,
                              email: Email = None,
                              host_name: HostName = None,
                              domain_name: DomainName = None,
                              company: Company = None,
                              file_suffix: str = None,
                              sub_directory: str = None,
                              create_new: bool = False,
                              delete_existing: bool = False) -> str:
        """
        This method creates an output directory and returns a unique filename that can be used by the OS command to
        write text output, which later can be imported into the database.
        :param service: The service for which the path shall be created
        :param host: The host for which the path shall be created
        :param email: The email for which the path shall be created
        :param network: The IPv4 network for which the path shall be created
        :param host_name: The host name for which the path shall be created
        :param domain_name: The domain name for which the path shall be created
        :param company: The company for which the path shall be created
        :param file_suffix: Information that will be appended to the file name and before the file extension
        :param sub_directory: Creates the given sub directory in the respective IP address directory
        :param create_new: If the sub directory already exist, then it creates a new one
        :param delete_existing: Deletes the file if it already exists
        :return: Path of the file
        """
        return self.create_file_path(service=service,
                                     host=host,
                                     network=network,
                                     email=email,
                                     host_name=host_name,
                                     domain_name=domain_name,
                                     company=company,
                                     file_suffix=file_suffix,
                                     file_extension="txt",
                                     sub_directory=sub_directory,
                                     create_new=create_new,
                                     delete_existing=delete_existing)

    # todo: update for new collector
    def create_json_file_path(self,
                              service: Service = None,
                              host: Host = None,
                              network: Network = None,
                              email: Email = None,
                              host_name: HostName = None,
                              domain_name: DomainName = None,
                              company: Company = None,
                              file_suffix: str = None,
                              sub_directory: str = None,
                              create_new: bool = False,
                              delete_existing: bool = False) -> str:
        """
        This method creates an output directory and returns a unique filename that can be used by the OS command to
        write JSON output, which later can be imported into the database.
        :param service: The service for which the path shall be created
        :param host: The host for which the path shall be created
        :param email: The email for which the path shall be created
        :param network: The IPv4 network for which the path shall be created
        :param host_name: The host name for which the path shall be created
        :param domain_name: The domain name for which the path shall be created
        :param company: The company for which the path shall be created
        :param file_suffix: Information that will be appended to the file name and before the file extension
        :param sub_directory: Creates the given sub directory in the respective IP address directory
        :param create_new: If the sub directory already exist, then it creates a new one
        :param delete_existing: Deletes the file if it already exists
        :return: Path of the file
        """
        return self.create_file_path(service=service,
                                     host=host,
                                     network=network,
                                     email=email,
                                     host_name=host_name,
                                     domain_name=domain_name,
                                     company=company,
                                     file_suffix=file_suffix,
                                     file_extension="json",
                                     sub_directory=sub_directory,
                                     create_new=create_new,
                                     delete_existing=delete_existing)

    # todo: update for new collector
    def create_file_path(self,
                         service: Service = None,
                         host: Host = None,
                         network: Network = None,
                         email: Email = None,
                         host_name: HostName = None,
                         domain_name: DomainName = None,
                         company: Company = None,
                         file_suffix: str = None,
                         file_extension: str = None,
                         sub_directory: str = None,
                         create_new: bool = False,
                         delete_existing: bool = False) -> str:
        """
        This method creates an output directory and returns a unique filename that can be used by the OS command to
        write output files, which later can be imported into the database.
        :param service: The service for which the path shall be created
        :param host: The host for which the path shall be created
        :param email: The email for which the path shall be created
        :param network: The IPv4 network for which the path shall be created
        :param host_name: The host name for which the path shall be created
        :param domain_name: The domain name for which the path shall be created
        :param company: The company for which the path shall be created
        :param file_suffix: Information that will be appended to the file name and before the file extension
        :param file_extension: File extension
        :param sub_directory: Creates the given sub directory in the respective IP address directory
        :param create_new: If the sub directory already exist, then it creates a new one
        :param delete_existing: Deletes the file if it already exists
        :return: Path of the file
        """
        return_value = self.create_result_file_path(service=service,
                                                    host=host,
                                                    network=network,
                                                    email=email,
                                                    host_name=host_name,
                                                    domain_name=domain_name,
                                                    company=company,
                                                    file_suffix=file_suffix,
                                                    file_extension=file_extension,
                                                    sub_directory=sub_directory,
                                                    create_new=create_new,
                                                    delete_existing=delete_existing)
        return return_value

    # todo: update for new collector
    def create_result_file_path(self,
                                service: Service = None,
                                host: Host = None,
                                network: Network = None,
                                email: Email = None,
                                host_name: HostName = None,
                                domain_name: DomainName = None,
                                company: Company = None,
                                file_suffix: str = None,
                                file_extension: str = None,
                                sub_directory: str = None,
                                create_new: bool = False,
                                delete_existing: bool = False) -> str:
        """
        This method creates an output directory and returns a unique filename that can be used by the OS command to
        write output (e.g., in form of JSON or XML objects) and later imported these information into the database.
        :param service: The service for which the path shall be created
        :param host: The host for which the path shall be created
        :param email: The email for which the path shall be created
        :param network: The IPv4 network for which the path shall be created
        :param host_name: The host name for which the path shall be created
        :param domain_name: The domain name for which the path shall be created
        :param company: The company for which the path shall be created
        :param file_suffix: Information that will be appended to the file name and before the file extension
        :param file_extension: File extension
        :param sub_directory: Creates the given sub directory in the respective IP address directory
        :param create_new: If the sub directory already exist, then it creates a new one
        :return: Path of the file
        """
        path = self.create_path(service=service,
                                host=host,
                                network=network,
                                email=email,
                                host_name=host_name,
                                domain_name=domain_name,
                                company=company,
                                sub_directory=sub_directory,
                                create_new=create_new)
        if service:
            log_file = "{}_{}-{}-{}".format(self.name, service.address, service.protocol.name, service.port)
        elif host:
            log_file = "{}_{}".format(self.name, host.address)
        elif host_name:
            log_file = "{}_{}".format(self.name, host_name.full_name)
        elif domain_name:
            log_file = "{}_{}".format(self.name, domain_name.name)
        elif network:
            log_file = "{}_{}".format(self.name, network.network.replace("/", "_"))
        elif email:
            log_file = "{}_{}".format(self.name, email.email_address)
        elif company:
            log_file = "{}_{}".format(self.name, company.name.replace(" ", "-"))
        else:
            raise NotImplementedError("case not implemented")
        if file_suffix:
            log_file = "{}-{}".format(log_file, file_suffix)
        if file_extension:
            log_file = "{}.{}".format(log_file, file_extension)
        log_file_path = os.path.join(path, log_file)
        if os.path.isfile(log_file_path):
            if delete_existing:
                os.remove(log_file_path)
            else:
                os.chown(log_file_path, uid=self.exec_user.pw_uid, gid=self.exec_user.pw_gid)
        return log_file_path

    # todo: update for new collector
    def create_path(self,
                    service: Service = None,
                    host: Host = None,
                    network: Network = None,
                    email: Email = None,
                    host_name: HostName = None,
                    domain_name: DomainName = None,
                    company: Company = None,
                    sub_directory: str = None,
                    create_new: bool = False) -> str:
        """
        This method creates a standardized log directory for the OS command
        :param service: The service for which the path shall be created
        :param host: The host for which the path shall be created
        :param email: The email for which the path shall be created
        :param network: The IPv4 network for which the path shall be created
        :param host_name: The host name for which the path shall be created
        :param domain_name: The domain name for which the path shall be created
        :param company: The company for which the path shall be created
        :param sub_directory: Creates the given sub directory in the respective IP address directory
        :param create_new: If the sub directory already exist, then it creates a new one
        :return: Path of the file
        """
        if service:
            item = service.address
        elif host:
            item = host.address
        elif host_name:
            item = host_name.full_name
        elif domain_name:
            item = domain_name.name
        elif network:
            item = network.network.replace("/", "_")
        elif email:
            item = email.email_address
        elif company:
            item = company.name.replace(" ", "-")
        else:
            raise NotImplementedError("case not implemented")
        path = os.path.join(self.output_dir, item)
        if not os.path.exists(path):
            os.makedirs(path)
            os.chmod(path, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
        if sub_directory:
            sub_path = os.path.join(path, sub_directory)
            i = 1
            while os.path.exists(sub_path) and create_new:
                sub_path = "{}/{}_{:03d}".format(path, sub_directory, i)
                i = i + 1
            path = sub_path
        return path

    def import_output_files(self, command: Command):
        """
        This method imports the XML and JSON output files into the database
        :param command: The command object into which the XML and JSON objects should be imported
        :return:
        """
        if ExecutionInfoType.xml_output_file.name in command.execution_info:
            file = command.execution_info[ExecutionInfoType.xml_output_file.name]
            if os.path.isfile(file):
                with open(file, "r") as f:
                    command.xml_output = f.read()
            else:
                logger.warning("could not find XML file '{}'.".format(file))
        if ExecutionInfoType.json_output_file.name in command.execution_info:
            file = command.execution_info[ExecutionInfoType.json_output_file.name]
            if os.path.isfile(file):
                with open(file, "r") as f:
                    content = f.read()
                try:
                    json_object = json.loads(content)
                    BaseUtils.add_json_results(command, [json_object])
                except Exception as ex:
                    logger.exception(ex)
            else:
                logger.warning("could not find JSON file '{}'.".format(file))
        if ExecutionInfoType.binary_output_file.name in command.execution_info:
            file = command.execution_info[ExecutionInfoType.binary_output_file.name]
            if os.path.isfile(file):
                with open(file, "rb") as f:
                    command.binary_output = f.read()
            else:
                logger.warning("could not find binary file '{}'.".format(file))

    @staticmethod
    def get_report_item(command: Command) -> ReportItem:
        """
        This method creates and returns a report item based on the given command
        :param command:
        :return:
        """
        # todo new collector
        report_item = None
        if command.collector_name.type == CollectorType.service or \
                command.collector_name.type == CollectorType.host:
            report_item = ReportItem(ip=command.host.address,
                                     collector_name=command.collector_name.name,
                                     port=command.service.port if command.service else None,
                                     protocol=command.service.protocol_str if command.service else None)
        elif command.collector_name.type == CollectorType.ipv4_network:
            report_item = ReportItem(ip=command.ipv4_network.network,
                                     collector_name=command.collector_name.name)
        elif command.collector_name.type == CollectorType.host_name_service or \
                command.collector_name.type == CollectorType.domain:
            report_item = ReportItem(ip=command.host_name.full_name,
                                     collector_name=command.collector_name.name,
                                     port=command.service.port if command.service else None,
                                     protocol=command.service.protocol_str if command.service else None)
        elif command.collector_name.type == CollectorType.email:
            report_item = ReportItem(ip=command.email.email_address,
                                     collector_name=command.collector_name.name)
        elif command.collector_name.type == CollectorType.company:
            report_item = ReportItem(ip=command.company.name,
                                     collector_name=command.collector_name.name)
        return report_item

    def add_execution_info_str(self, os_command: Command, key: str, value: str) -> None:
        """
        This method adds the given key value pair to the command
        :param os_command:
        :param key:
        :param value:
        :return:
        """
        os_command.execution_info[key] = str(value)


    def get_execution_info_str(self, os_command: Command, key: str) -> str:
        """
        This method returns the value of the given key from the given OS command
        :param os_command:
        :param key:
        :param value:
        :return:
        """
        rvalue = None
        if key in os_command.execution_info:
            rvalue = os_command.execution_info[key]
        return rvalue

    def add_execution_info_enum(self, os_command: Command, info: enum.Enum) -> None:
        """
        This method adds the given key value pair to the command
        :param os_command:
        :param info:
        :return:
        """
        self.add_execution_info_str(os_command, info.__class__.__name__, info.name)

    def get_execution_info_enum(self, os_command: Command, info: enum.Enum) -> enum.Enum:
        """
        This method returns the value of the given key from the given OS command
        :param os_command:
        :param info:
        :return:
        """
        rvalue =  self.get_execution_info_str(os_command, info.__name__)
        if rvalue:
            rvalue = info[rvalue]
        return rvalue

    def _get_or_create_command(self,
                               session: Session,
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
                               output_path: str = None,
                               input_file: str = None,
                               input_file_2: str = None,
                               binary_file: str = None) -> Command:
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
        :param input_file: File which contains all the information for the target application (e.g. list of URLs for
        httpeyewitness)
        :return: The queried or newly created collector class
        """
        # todo: update for new collector
        if self._proxychains:
            os_command.insert(0, self._path_proxychains)
        working_directory = self.create_path(service=service,
                                             network=network,
                                             host=host,
                                             host_name=host_name,
                                             email=email,
                                             company=company)
        return self._domain_utils.add_command(session=session,
                                              os_command=os_command,
                                              collector_name=collector_name,
                                              service=service,
                                              network=network,
                                              host=host,
                                              host_name=host_name,
                                              email=email,
                                              company=company,
                                              xml_file=xml_file,
                                              json_file=json_file,
                                              output_path=output_path,
                                              input_file=input_file,
                                              input_file_2=input_file_2,
                                              binary_file=binary_file,
                                              working_directory=working_directory,
                                              exec_user=self.exec_user.pw_name)

    def verify_command_execution(self,
                                 session: Session,
                                 command: Command,
                                 source: Source,
                                 report_item: ReportItem,
                                 process: PopenCommand = None) -> None:
        """
        This method is called after each command execution to determine command execution failure and analyze output
        """
        failed = False
        if command.status == CommandStatus.terminated:
            command.hide = True
        # determine if command execution failed
        for regex in self.get_failed_regex():
            if regex.has_failed(command):
                self._set_execution_failed(session=session, command=command)
                failed = True
                break
        # verify command execution results
        if not failed:
            self.verify_results(session,
                                command=command,
                                source=source,
                                report_item=report_item,
                                process=process)

    def process_command_results(self,
                                engine: Engine,
                                command_id: int,
                                status: CommandStatus,
                                process: PopenCommand = None) -> None:
        """This method stores the command's output in the database and analyses the results of the command execution.

        After the execution, this method checks the OS command's results to determine the command's execution status as
        well as existing vulnerabilities (e.g. weak login credentials, NULL sessions, hidden Web folders). The
        stores the output in table command. In addition, the collector might add derived information to other tables as
        well.

        :param engine: The database engine used to connect to the database
        :param command_id: The commands primary key ID in the database
        :param status: The command's execution status
        :param process: The PopenCommand object that executed the given result. This object holds stderr, stdout, return
        code etc.
        """
        with self._update_db_lock:
            with engine.session_scope() as session:
                command = session.query(Command).filter_by(id=command_id).one()
                source = engine.get_or_create(session, Source, name=command.collector_name.name)
                command.return_code = process.return_code
                command.stdout_output = process.stdout_list
                command.stderr_output = process.stderr_list
                command.stop_time = process.stop_time
                command.start_time = process.start_time
                command.status = status
                try:
                    self.import_output_files(command)
                except Exception as e:
                    logger.exception(e)
                session.commit()
                report_item = BaseCollector.get_report_item(command)
                self.verify_command_execution(session,
                                              command=command,
                                              source=source,
                                              report_item=report_item,
                                              process=process)

    def start_command_execution(self, session: Session, command: Command) -> bool:
        """
        This method allows the consumer threat to check whether the command should be executed. If this method returns
        false, then the command execution is not started. This is useful when another command of the same collector
        already identified the interesting information.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance to be executed
        :return: True, if the command should be executed, False if not.
        """
        return True

    def _remove_console_color(self, line: str) -> str:
        """
        removes console color coding from line
        :param line:
        :return:
        """
        return re.sub("{}\[[0-9]{{1,2}}m".format(chr(27)), "", line)

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
        raise NotImplementedError("The function is not implemented!")


class SmbClientAuthenticationType(enum.Enum):
    Username_Password = 0
    No_Password = 1


class BaseSmbClient(BaseCollector):
    """
    This class implements basic functionality for collectors that use smbclient
    """

    def __init__(self,
                 priority: int,
                 timeout: int,
                 service_descriptors: ServiceDescriptorBase,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=service_descriptors,
                         **kwargs)
        self._failed_status = ["NT_STATUS_ACCESS_DENIED",
                               "NT_STATUS_HOST_UNREACHABLE",
                               "NT_STATUS_INVALID_PARAMETER",
                               "NT_STATUS_IO_TIMEOUT",
                               "NT_STATUS_LOGON_FAILURE",
                               "NT_STATUS_NETWORK_ACCESS_DENIED",
                               "NT_STATUS_NO_LOGON_SERVERS",
                               "NT_STATUS_RESOURCE_NAME_NOT_FOUND",
                               "NT_STATUS_REVISION_MISMATCH",
                               "NT_STATUS_WRONG_PASSWORD"]

    def _create_commands(self,
                         session: Session,
                         service: Service,
                         collector_name: CollectorName,
                         arguments: List[str] = [],
                         path: str = "") -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        command = self._path_smbclient
        if path:
            path = path if path[0] == "/" else "/{}".format(path)
        if self.match_service_port(service):
            if not service.has_credentials and self._user and self._password:
                user_argument = "{}".format(self._user) if self._user else "''"
                password_argument = "{}".format(self._password) if self._password else "''"
                credentials = self.create_credential_arguments(argument_name_username="-U",
                                                               username='{}%{}'.format(user_argument,
                                                                                       password_argument),
                                                               argument_name_domain="-W",
                                                               domain=self._domain)
                os_command = [command]
                os_command += arguments
                os_command += ["//{}{}".format(service.host.address, path)]
                os_command += credentials
                collectors.append(self._get_or_create_command(session, os_command, collector_name, service=service))
            elif not service.has_credentials and not self._user and not self._password:
                os_command = [command]
                os_command += arguments
                os_command += ["//{}{}".format(service.host.address, path), "-N"]
                collectors.append(self._get_or_create_command(session, os_command, collector_name, service=service))
                os_command = [command]
                os_command += arguments
                os_command += ["//{}{}".format(service.host.address, path), "-U", "''%''"]
                collectors.append(self._get_or_create_command(session, os_command, collector_name, service=service))
            else:
                for item in service.credentials:
                    if item.complete:
                        user_argument = "{}".format(self._user) if self._user else "''"
                        password_argument = "{}".format(self._password) if self._password else "''"
                        credentials = self.create_credential_arguments(argument_name_username="-U",
                                                                       username='{}%{}'.format(user_argument,
                                                                                               password_argument),
                                                                       argument_name_domain="-W",
                                                                       domain=self._domain)
                        os_command = [command]
                        os_command += arguments
                        os_command += ["-L", "//{}{}".format(service.host.address, path)]
                        os_command += credentials
                        collectors.append(self._get_or_create_command(session,
                                                                      os_command,
                                                                      collector_name,
                                                                      service=service))
        return collectors


class BaseCrackMapExec(BaseCollector):
    """
    This class implements basic functionality for collectors that use CrackMapExec
    """

    def __init__(self,
                 priority: int,
                 timeout: int,
                 service_descriptors: ServiceDescriptorBase,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=service_descriptors,
                         **kwargs)

    def _create_credential_arguments(self, user: str, password: str, domain: str, is_hash: bool):
        """
        This method creates the credential arguments for CrackMapExec based on the given arguments
        :param user: The user name
        :param password: The password
        :param domain: The domain
        :return:
        """
        result = []
        result += ["-u", user]
        if is_hash:
            result += ["-H", password]
        else:
            result += ["-p='{}'".format(password)]
        if domain:
            result += ["-d", domain]
        return result

    def _create_commands(self,
                         session: Session,
                         service: Service,
                         collector_name: CollectorName,
                         module: str,
                         arguments: List[str] = []) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :param module: Crackmapexec module to be used for collection
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        ipv4_address = service.host.ipv4_address
        if ipv4_address and self.match_service_port(service):
            os_command = [self._path_crackmapexec, module, "--port", service.port]
            if not service.has_credentials and self._user and self._password:
                os_command += self._create_credential_arguments(self._user, self._password, self._domain, self._hashes)
                os_command += arguments
                os_command.append(ipv4_address)
                collectors.append(self._get_or_create_command(session, os_command, collector_name, service=service))
            elif not service.has_credentials and not self._user and not self._password:
                os_command += arguments
                os_command.append(ipv4_address)
                collectors.append(self._get_or_create_command(session, os_command, collector_name, service=service))
            else:
                for item in service.credentials:
                    if item.complete:
                        os_command += self._create_credential_arguments(item.username,
                                                                        item.password,
                                                                        item.domain,
                                                                        item.type != CredentialType.Cleartext)
                        os_command += arguments
                        os_command.append(ipv4_address)
                        collectors.append(self._get_or_create_command(session,
                                                                      os_command,
                                                                      collector_name,
                                                                      service=service))
        return collectors


class ChangeProtocol(enum.Enum):
    http = 1
    ssh = 2
    ssh_key = 3


class BaseChangeme(BaseCollector):
    """
    This class implements basic functionality for collectors that use Changeme
    """
    def __init__(self,
                 priority: int,
                 timeout: int,
                 service_descriptors: ServiceDescriptorBase,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=service_descriptors,
                         **kwargs)

    @staticmethod
    def get_invalid_argument_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify invalid arguments
        """
        return [re.compile("^.*error: unrecognized arguments: (?P<argument>.+?)$", re.IGNORECASE)]

    @staticmethod
    def get_service_unreachable_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify services that are not reachable
        """
        return []

    def _create_commands(self,
                         session: Session,
                         service: Service,
                         collector_name: CollectorName,
                         protocol: ChangeProtocol,
                         json_file: str,
                         target: str,
                         options: List[str] = []) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :param options: Additional commandline arguments
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        address = service.address
        if address:
            os_command = [self._path_changeme,
                          "--fresh",
                          "-v",
                          "--protocol", protocol.name]
            os_command += options
            if json_file:
                os_command += ['--output', ExecutionInfoType.json_output_file.argument]
            if self._delay.sleep_active:
                os_command += ['--delay', self._delay.sleep_time]
            if protocol == ChangeProtocol.http:
                if self._http_proxy:
                    os_command += ['--proxy', self._http_proxy]
                if self._http_proxy:
                    os_command += ['--proxy', self._http_proxy]
                if self._user_agent:
                    os_command += ['--useragent', '{}'.format(self._user_agent)]
                else:
                    os_command += ['--useragent', '{}'.format(self._default_user_agent_string)]
                os_command.append(target)
            elif protocol == ChangeProtocol.ssh or protocol == ChangeProtocol.ssh_key:
                os_command.append(target)
            collector = self._get_or_create_command(session,
                                                    os_command,
                                                    collector_name,
                                                    service=service,
                                                    json_file=json_file)
            collectors.append(collector)
        return collectors

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
        found_credentials = False
        if command.return_code != 0:
            self._set_execution_failed(session, command)
        for json_object in command.json_output:
            if "results" in json_object:
                found_credentials = True
                for item in json_object["results"]:
                    username = item["username"] if "username" in item else ""
                    password = item["password"] if "password" in item else ""
                    target = item["target"] if "target" in item else None
                    self.add_credential(session=session,
                                        command=command,
                                        password=password,
                                        username=username,
                                        source=source,
                                        credential_type=CredentialType.Cleartext,
                                        service=command.service,
                                        report_item=report_item)
                    if target:
                        self.add_url(session=session,
                                     service=command.service,
                                     url=target,
                                     source=source,
                                     report_item=report_item)
        command.hide = found_credentials


class BaseMsfConsole(BaseCollector):
    """
    This class implements basic functionality for collectors that use msfconsole
    """
    def __init__(self,
                 priority: int,
                 timeout: int,
                 service_descriptors: ServiceDescriptorBase,
                 ip_support: IpSupport = IpSupport.all,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         exec_user="root",
                         service_descriptors=service_descriptors,
                         **kwargs)
        self._ip_support = ip_support

    def _create_commands(self,
                         session: Session,
                         service: Service,
                         collector_name: CollectorName,
                         module: str,
                         rhost: str = None,
                         rhosts: str = None,
                         port: int = None,
                         rport: int = None,
                         ssl: bool = None,
                         additional_commands: List[str] = [],
                         xml_file: str = None,
                         json_file: str = None,
                         output_path: str = None,
                         input_file: str = None,
                         binary_file: str = None,
                         **kwargs) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :param options: Additional commandline arguments
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        if self._ip_support == IpSupport.all and (rhost or rhosts) and (port or rport):
            command = "use {}".format(module)
            if rhost:
                command += ";set RHOST {}".format(rhost)
            elif rhosts:
                command += ";set RHOSTS {}".format(rhosts)
            if port:
                command += ";set PORT {}".format(port)
            if rport:
                command += ";set RPORT {}".format(rport)
            if ssl is not None:
                command += ";set SSL {}".format("true" if ssl else "false")
            if additional_commands:
                command += ";" + ";".join(additional_commands)
            command += ";run;exit"
            os_command = [self._path_msfconsole, "-qx", command]
            collector = self._get_or_create_command(session,
                                                    os_command,
                                                    collector_name,
                                                    service=service,
                                                    xml_file=xml_file,
                                                    json_file=json_file,
                                                    binary_file=binary_file,
                                                    output_path=output_path,
                                                    input_file=input_file)
            collectors.append(collector)
        return collectors


class BaseEyeWitness(BaseCollector):
    """
    This class implements basic functionality for collectors that use Eyewitness
    """
    def __init__(self,
                 priority: int,
                 timeout: int,
                 service_descriptors: ServiceDescriptorBase,
                 file_extension: str,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=service_descriptors,
                         **kwargs)
        self._file_extension = file_extension

    @staticmethod
    def get_failed_regex() -> List[CommandFailureRule]:
        """
        This method returns regular expressions that allows KIS to identify failed command executions
        """
        return [CommandFailureRule(regex=re.compile("^\[\*\] WebDriverError when connecting to.*$"),
                                   output_type=OutputType.stdout)]

    def _create_commands(self,
                         session: Session,
                         service: Service,
                         collector_name: CollectorName,
                         protocol: str,
                         output_path: str,
                         options: List[str] = [],
                         url_str: str = None,
                         input_file: str = None) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :param options: Additional commandline arguments
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        address = service.address
        if address:
            arguments = []
            if input_file:
                arguments += ["-f", ExecutionInfoType.input_file.argument]
            if output_path:
                arguments += ['-d', ExecutionInfoType.output_path.argument]
            arguments += options
            os_command = [self._path_eyewitness,
                          protocol,
                          '--no-prompt',
                          '--no-dns',
                          '--threads', '1']
            if url_str:
                os_command += ['--single', url_str]
            elif not input_file:
                os_command += ['--single', address, '--only-ports', str(service.port)]
            os_command += arguments
            collector = self._get_or_create_command(session,
                                                    os_command,
                                                    collector_name,
                                                    service=service,
                                                    output_path=output_path,
                                                    input_file=input_file)
            collectors.append(collector)
        return collectors

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
        command.hide = True
        for line in command.stdout_output:
            if line == "Message: timeouts":
                self._set_execution_failed(session, command)
        if ExecutionInfoType.output_path.name in command.execution_info and \
                command.execution_info[ExecutionInfoType.output_path.name]:
            path = command.execution_info[ExecutionInfoType.output_path.name] \
                if command.execution_info[ExecutionInfoType.output_path.name][-1] != '/' else \
                command.execution_info[ExecutionInfoType.output_path.name][:-1]
            for filename in glob.iglob('{}/**/*.{}'.format(path, self._file_extension), recursive=True):
                BaseUtils.add_file(session=session,
                                   workspace=command.service.workspace,
                                   command=command,
                                   file_path=filename,
                                   file_type=FileType.screenshot)


class BaseDotDotPwn(BaseCollector):
    """
    This class implements basic functionality for collectors that use dotdotpwn.
    """
    def __init__(self,
                 priority: int,
                 timeout: int,
                 service_descriptors: ServiceDescriptorBase,
                 module: str,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=service_descriptors,
                         **kwargs)
        self._module = module
        self._re_vulnerable = re.compile("^.+? (?P<value>(\.\.\/)+.+?) <- VULNERABLE!")

    def _create_commands(self,
                         session: Session,
                         service: Service,
                         collector_name: CollectorName,
                         user: str=None,
                         password: str=None,
                         additional_arguments: List[str]=[]) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :param options: Additional commandline argumenttts
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        if not self._print_commands:
            raise CommandCreationFailed("Commands for collector '{}' can only be created with option -S because "
                                        "dotdotpwn requires user interaction.".format(collector_name.name))
        address = service.address
        if address:
            os_command = [self._path_dotdotpwn,
                          '-m', self._module,
                          '-d', '5',
                          '-x', str(service.port),
                          '-b',
                          '-q',
                          '-h', address]
            if user:
                os_command.extend(['-U', '{}'.format(user)])
            if password:
                os_command.extend(['-P', '{}'.format(password)])
            if service.host.os_family:
                if service.host.os_family.lower() == "windows":
                    os_command.extend(["-o", "windows"])
                elif service.host.os_family.lower() in ['linux', 'unix']:
                    os_command.extend(["-o", "unix"])
                else:
                    os_command.append("-O")
            if service.nmap_tunnel == 'ssl':
                os_command.append('-s')
            os_command += additional_arguments
            collector = self._get_or_create_command(session, os_command, collector_name, service=service)
            collectors.append(collector)
        return collectors

    def create_service_commands(self,
                                session: Session,
                                service: Service,
                                collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        if self.match_nmap_service_name(service):
            if self._user:
                tmp = self._create_commands(session, service, collector_name, self._user, self._password)
                collectors.extend(tmp)
            else:
                for credential in service.credentials:
                    if credential.complete and credential.type == CredentialType.Cleartext:
                        tmp = self._create_commands(session,
                                                    service,
                                                    collector_name,
                                                    credential.username,
                                                    credential.password)
                        collectors.extend(tmp)
        return collectors

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
        for line in command.stdout_output:
            match_vulnerable = self._re_vulnerable.match(line)
            if match_vulnerable:
                path_str = match_vulnerable.group("value")
                if self._module == "http":
                    self.add_path(session=session,
                                  command=command,
                                  service=command.service,
                                  path=path_str,
                                  path_type=PathType.Http,
                                  source=source,
                                  report_item=report_item)
                elif self._module in ["ftp", "tftp"]:
                    self.add_path(session=session,
                                  command=command,
                                  service=command.service,
                                  path=path_str,
                                  path_type=PathType.FileSystem,
                                  source=source,
                                  report_item=report_item)


class BaseNmap(BaseCollector):
    """
    This class implements basic functionality for collectors that use Nmap.
    """

    def __init__(self,
                 priority: int,
                 timeout: int,
                 service_descriptors: ServiceDescriptorBase,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         exec_user="root",
                         service_descriptors=service_descriptors,
                         **kwargs)
        self._nmap_xml_extractor_classes = nmap_xml_extractor_classes

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    @staticmethod
    def get_failed_regex() -> List[CommandFailureRule]:
        """
        This method returns regular expressions that allows KIS to identify failed command executions
        """
        return [CommandFailureRule(regex=re.compile("^.*setup_target: failed to determine route to.*$"),
                                   output_type=OutputType.stderr),
                CommandFailureRule(regex=re.compile("^.*WARNING: No targets were specified, so 0 hosts scanned.*$"),
                                   output_type=OutputType.stderr)]

    def __create_commands(self,
                          session: Session,
                          service: Service,
                          collector_name: CollectorName,
                          nse_scripts: List[str],
                          nse_script_arguments: List[str] = [],
                          additional_arguments: List[str] = []) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :param nse_scripts: The names of the NSE scripts
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        address = service.address
        if address:
            xml_file = self.create_xml_file_path(service=service)
            scan_type = "-sS" if service.protocol == ProtocolType.tcp else "-sU"
            if nse_script_arguments:
                nse_arguments = ["--script-args={}".format(",".join(nse_script_arguments))]
            else:
                nse_arguments = []
            os_command = [self._path_nmap,
                          "-Pn",
                          scan_type,
                          "-n",
                          "--version-all",
                          "-sV",
                          "-oX", ExecutionInfoType.xml_output_file.argument,
                          "--script", ",".join(nse_scripts)]
            if service.host and service.host.version == 6:
                os_command.append("-6")
            os_command += additional_arguments
            os_command += nse_arguments + ["-p", str(service.port), address]
            collector = self._get_or_create_command(session,
                                                    os_command,
                                                    collector_name,
                                                    service=service,
                                                    xml_file=xml_file)
            collectors.append(collector)
        return collectors

    def _create_commands(self,
                         session: Session,
                         service: Service,
                         collector_name: CollectorName,
                         nse_scripts: List[str],
                         nse_script_arguments: List[str] = []) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :param nse_scripts: The names of the NSE scripts
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        if service.host is not None:
            collectors = self.__create_commands(session=session,
                                                service=service,
                                                collector_name=collector_name,
                                                nse_scripts=nse_scripts,
                                                nse_script_arguments=nse_script_arguments)
        elif service.host_name is not None:
            # resolve host name to IPv4 address
            if service.host_name.in_scope(CollectorType.host_name_service):
                collectors = self.__create_commands(session=session,
                                                    service=service,
                                                    collector_name=collector_name,
                                                    nse_scripts=nse_scripts,
                                                    nse_script_arguments=nse_script_arguments)
            # resolve host name to IPv6 address
            if service.host_name.in_scope_ipv6(CollectorType.host_name_service):
                collectors = self.__create_commands(session=session,
                                                    service=service,
                                                    collector_name=collector_name,
                                                    nse_scripts=nse_scripts,
                                                    nse_script_arguments=nse_script_arguments,
                                                    additional_arguments=["-6"])
        else:
            raise NotImplementedError("this case is not implemented")
        return collectors

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
        if command.xml_output:
            utils = NmapUtils(command.xml_output)
            if command.return_code != 0:
                self._set_execution_failed(session, command)
                return
            if command.collector_name.type == CollectorType.service:
                host_tags = [utils.get_host_tag_by_ipv4(ipv4_address=command.service.address)]
            elif command.collector_name.type == CollectorType.host_name_service:
                host_tags = utils.get_host_tags_by_host_name(host_name=command.target_name)
            else:
                raise NotImplementedError("case not implemented for "
                                          "collector type {}".format(command.collector_name.type.name))
            for host_tag in host_tags:
                port_tag = utils.get_service_by_port_number(host_tag=host_tag,
                                                            protocol=command.service.protocol,
                                                            port_number=command.service.port)
                if port_tag:
                    service_tag = port_tag.find("service")
                    if service_tag:
                        if not command.service.nmap_product:
                            command.service.nmap_product = XmlUtils.get_xml_attribute("product", service_tag.attrib)
                        if not command.service.nmap_version:
                            command.service.nmap_version = XmlUtils.get_xml_attribute("version", service_tag.attrib)
                        if not command.service.nmap_version:
                            command.service.nmap_tunnel = XmlUtils.get_xml_attribute("tunnel", service_tag.attrib)
                        if not command.service.nmap_extra_info:
                            command.service.nmap_extra_info = XmlUtils.get_xml_attribute("extrainfo",
                                                                                         service_tag.attrib)
                    for extractor_class in self._nmap_xml_extractor_classes:
                        if report_item:
                            report_item.listener = self._ui_manager
                        extractor = extractor_class(session=session,
                                                    workspace=command.workspace,
                                                    command=command,
                                                    service=command.service,
                                                    source=source,
                                                    domain_utils=self._domain_utils,
                                                    ip_utils=self._ip_utils,
                                                    report_item=report_item)
                        extractor.extract(host_tag=host_tag, port_tag=port_tag)
                        # Determine port state
                    port_state_tag = port_tag.findall("state[1]")[0].attrib
                    port_state = XmlUtils.get_xml_attribute("state", port_state_tag)
                    port_state = Service.get_service_state(port_state)
                    if port_state != ServiceState.Open:
                        self._set_execution_failed(session, command)


class BaseMedusa(BaseCollector):
    """
    This class implements basic functionality for collectors that use Medusa.
    """
    def __init__(self,
                 priority: int,
                 timeout: int,
                 service_descriptors: ServiceDescriptorBase,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=service_descriptors,
                         **kwargs)
        self._re_creds = re.compile(
            "^ACCOUNT FOUND: .+ User: (?P<user>.+)Password: (?P<password>.+) \[SUCCESS \(.+\)\]$")

    def _create_commands(self,
                         session: Session,
                         service: Service,
                         collector_name: CollectorName,
                         medusa_module: str,
                         user_file: str = None,
                         password_file: str = None,
                         combo_file: str = None,
                         user: str = None,
                         password: str = None,
                         medusa_module_argment: str=None,
                         stop_when_found: bool=True) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :param medusa_module: The name of the module to be used
        :param user_file: The file containing all user names
        :param password_file: The file containing all passwords
        :param combo_file: The file containing user password pairs separated by a colon
        :param medusa_module_argment: An optional argument for the hydra_module
        :param stop_when_found: Stop brute-force attack when credentials are found
        :return: List of Collector instances that shall be processed.
        """
        commands = []
        if user_file and not os.path.isfile(user_file):
            raise FileNotFoundError("User file '{}' does not exist!".format(user_file))
        if password_file and not os.path.isfile(password_file):
            raise FileNotFoundError("Password file '{}' does not exist!".format(password_file))
        if combo_file and not os.path.isfile(combo_file):
            raise FileNotFoundError("Password file '{}' does not exist!".format(combo_file))
        if service.host.ipv4_address:
            os_command = [self._path_medusa]
            if user:
                os_command.extend(["-u", user])
            if password:
                os_command.extend(["-p", password])
            if user_file and not user:
                os_command.extend(["-U", user_file])
            if password_file and not password:
                os_command.extend(["-P", password_file])
            if combo_file and not user and not password and not user_file and not password_file:
                os_command.extend(["-C", combo_file])
            if stop_when_found:
                os_command.append("-f")
            if len(os_command) == 1:
                raise ValueError("Hydra requires user credentials to test for!")
            os_command.extend(["-n", str(service.port),
                               "-h", service.host.ipv4_address])
            if self._hashes:
                os_command.extend(["-m", "PASS:HASH"])
            os_command.extend(["-M", medusa_module])
            if medusa_module_argment:
                os_command.append(medusa_module_argment)
            command = self._get_or_create_command(session, os_command, collector_name, service=service)
            if self._hashes:
                self.add_execution_info_enum(command, CredentialType.Hash)
            else:
                self.add_execution_info_enum(command, CredentialType.Cleartext)
            commands.append(command)
        return commands

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
        credentials_found = False
        for line in command.stdout_output:
            match_creds = self._re_creds.match(line)
            if match_creds:
                user = match_creds.group("user")
                password = match_creds.group("password")
                credentials_found = True
                self.add_credential(session=session,
                                    command=command,
                                    username=user,
                                    password=password,
                                    credential_type=CredentialType.Cleartext,
                                    source=source,
                                    service=command.service,
                                    report_item=report_item)
        command.hide = not credentials_found


class BaseHydra(BaseCollector):
    """
    This class implements basic functionality for collectors that use Hydra.
    """
    def __init__(self,
                 priority: int,
                 timeout: int,
                 service_descriptors: ServiceDescriptorBase,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=service_descriptors,
                         **kwargs)
        self._re_creds = re.compile("^\[.+?\]\[.+?\] host: .+?(   login: (?P<user>.+?))?(   password: (?P<password>.+?))?$")

    def _create_commands(self,
                         session: Session,
                         service: Service,
                         collector_name: CollectorName,
                         hydra_module: str,
                         user_file: str = None,
                         password_file: str = None,
                         combo_file: str = None,
                         user: str = None,
                         password: str = None,
                         default_file: str=None,
                         hydra_module_argment: str=None,
                         stop_when_found: bool=True) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :param hydra_module: The name of the module to be used
        :param user_file: The file containing all user names
        :param password_file: The file containing all passwords
        :param combo_file: The file containing user password pairs separated by a colon
        :param default_file: The default combo file no file is explicitly specified
        :param hydra_module_argment: An optional argument for the hydra_module
        :param stop_when_found: Stop brute-force attack when credentials are found
        :return: List of Collector instances that shall be processed.
        """
        commands = []
        if default_file and not os.path.isfile(default_file):
            raise FileNotFoundError("password file '{}' does not exist!".format(default_file))
        if user_file and not os.path.isfile(user_file):
            raise FileNotFoundError("user file '{}' does not exist!".format(user_file))
        if password_file and not os.path.isfile(password_file):
            raise FileNotFoundError("password file '{}' does not exist!".format(password_file))
        if combo_file and not os.path.isfile(combo_file):
            raise FileNotFoundError("combo file '{}' does not exist!".format(combo_file))
        if service.address:
            os_command = [self._path_hydra]
            if user:
                os_command.extend(["-l", user])
            if password:
                os_command.extend(["-p", password])
            if user_file and not user:
                os_command.extend(["-L", user_file])
            if password_file and not password:
                os_command.extend(["-P", password_file])
            if combo_file and not user and not password and not user_file and not password_file:
                os_command.extend(["-C", combo_file])
            if default_file and len(os_command) == 1:
                os_command.extend(["-C", default_file])
            if stop_when_found:
                os_command.append("-f")
            if len(os_command) == 1:
                raise ValueError("hydra requires user credentials to test for!")
            os_command.extend(["-s", str(service.port),
                               "-I",
                               "-{}".format(service.host.version),
                               service.address])
            if self._hashes:
                os_command.extend(["-m", "LocalHash"])
            os_command.append(hydra_module)
            if hydra_module_argment:
                os_command.append(hydra_module_argment)
            command = self._get_or_create_command(session, os_command, collector_name, service=service)
            if self._hashes:
                self.add_execution_info_enum(command, CredentialType.Hash)
            else:
                self.add_execution_info_enum(command, CredentialType.Cleartext)
            commands.append(command)
        return commands

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
        credential_type = self.get_execution_info_enum(command, CredentialType)
        credential_type = credential_type if credential_type else CredentialType.Cleartext
        credentials_found = False
        for line in command.stdout_output:
            match_creds = self._re_creds.match(line)
            if match_creds:
                user = match_creds.group("user")
                password = match_creds.group("password")
                credentials_found = True
                credential = self.add_credential(session=session,
                                                 command=command,
                                                 username=user,
                                                 password=password,
                                                 credential_type=credential_type,
                                                 source=source,
                                                 service=command.service,
                                                 report_item=report_item)
                if not credential:
                    logger.debug("ignoring credentials in line: {}".format(line))
        command.hide = not credentials_found


# todo: update for new collector
class BaseCollectorType:
    """
    The different collector types must be derived from this class
    """

    @staticmethod
    def get_collector_type_name() -> str:
        raise NotImplementedError("method not implemented")


class ServiceCollector(BaseCollectorType):
    """
    Collectors that operate on a service level must be a sub class of this class
    """

    @staticmethod
    def get_collector_type_name() -> str:
        return "service"

    def create_service_commands(self,
                                session: Session,
                                service: Service,
                                collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        raise NotImplementedError("the function is not implemented!")


class HostCollector(BaseCollectorType):
    """
    Collectors that operate on a host level must be sub class of this class
    """

    @staticmethod
    def get_collector_type_name() -> str:
        return "host"

    def create_host_commands(self,
                             session: Session,
                             host: Host,
                             collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param host: The host based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        raise NotImplementedError("the function is not implemented!")


class DomainCollector(BaseCollectorType):
    """
    Collectors that operate on a domain level must be a sub class of this class
    """

    @staticmethod
    def get_collector_type_name() -> str:
        return "domain"

    def create_domain_commands(self,
                               session: Session,
                               host_name: HostName,
                               collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param host_name: The host name based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        raise NotImplementedError("the function is not implemented!")


class Ipv4NetworkCollector(BaseCollectorType):
    """
    Collectors that operate on a IPv4 network level must be a sub class of this class
    """

    @staticmethod
    def get_collector_type_name() -> str:
        return "network"

    def create_ipv4_network_commands(self,
                                     session: Session,
                                     ipv4_network: Network,
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
        raise NotImplementedError("the function is not implemented!")


class HostNameServiceCollector(BaseCollectorType):
    """
    Collectors that operate on an domain/service level must be a sub class of this class
    """

    @staticmethod
    def get_collector_type_name() -> str:
        return "hostname_service"

    def create_host_name_service_commands(self,
                                          session: Session,
                                          service: Service,
                                          collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given host name.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        raise NotImplementedError("the function is not implemented!")


class EmailCollector(BaseCollectorType):
    """
    Collectors that operate on an email level must be a sub class of this class
    """

    @staticmethod
    def get_collector_type_name() -> str:
        return "email"

    def create_email_commands(self,
                              session: Session,
                              email: Email,
                              collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given host name.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param email: The email object based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        raise NotImplementedError("the function is not implemented!")


class CompanyCollector(BaseCollectorType):
    """
    Collectors that operate on a company level must be a sub class of this class
    """

    @staticmethod
    def get_collector_type_name() -> str:
        return "company"

    def create_company_commands(self,
                                session: Session,
                                company: Company,
                                collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given company.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param company: The company object based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        raise NotImplementedError("the function is not implemented!")
