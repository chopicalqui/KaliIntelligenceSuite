# -*- coding: utf-8 -*-
"""
run tool sslyze on each identified in-scope TLS service to obtain information about the TLS configuration as well as the
certificate
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

import re
import logging
import xml
import json
from typing import List
from collectors.os.modules.core import XmlUtils
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.tls.core import BaseTlsCollector
from collectors.os.modules.rdp.core import RdpServiceDescriptor
from collectors.os.modules.ldap.core import LdapServiceDescriptor
from collectors.os.modules.ftp.core import FtpServiceDescriptor
from collectors.os.modules.email.core import Pop3ServiceDescriptor
from collectors.os.modules.email.core import ImapServiceDescriptor
from collectors.os.modules.email.core import SmtpServiceDescriptor
from collectors.os.modules.core import CommandFailureRule
from collectors.os.modules.core import OutputType
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Service
from database.model import Command
from database.model import CollectorName
from database.model import Source
from database.model import CertType
from database.model import TlsPreference
from database.model import TlsInfo
from database.model import TlsInfoCipherSuiteMapping
from database.model import ExecutionInfoType
from view.core import ReportItem
from sqlalchemy.orm.session import Session
import xml.etree.ElementTree as ET

logger = logging.getLogger('sslyze')


class CollectorClass(BaseTlsCollector, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=41100,
                         timeout=0,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    @staticmethod
    def get_failed_regex() -> List[CommandFailureRule]:
        """
        This method returns regular expressions that allows KIS to identify failed command executions
        """
        return [CommandFailureRule(regex=re.compile("^.*=> WARNING: Could not complete an SSL/TLS handshake with the "
                                                    "server; discarding corresponding tasks.*$"),
                                   output_type=OutputType.stdout),
                CommandFailureRule(regex=re.compile("^.*=> WARNING: Connection rejected; discarding corresponding "
                                                    "tasks.*$"),
                                   output_type=OutputType.stdout)]

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
        result = []
        if service.host_name.name:
            result = self.create_service_commands(session, service, collector_name)
        return result

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
        if self.match_service_tls(service) and ((service.host and service.host.ipv4_address) or (
                service.host_name and not service.host_name.resolves_to_in_scope_ipv6_address())):
            json_file = self.create_json_file_path(service=service)
            os_command = [self._path_sslyze,
                          '--sslv2',
                          '--sslv3',
                          '--tlsv1',
                          '--tlsv1_1',
                          '--tlsv1_2',
                          '--tlsv1_3',
                          '--certinfo']
            if RdpServiceDescriptor().match_nmap_service_name(service):
                os_command.append("--starttls=rdp")
            elif LdapServiceDescriptor().match_nmap_service_name(service):
                os_command.append("--starttls=ldap")
            elif FtpServiceDescriptor().match_nmap_service_name(service):
                os_command.append("--starttls=ftp")
            elif ImapServiceDescriptor().match_nmap_service_name(service):
                os_command.append("--starttls=imap")
            elif SmtpServiceDescriptor().match_nmap_service_name(service):
                os_command.append("--starttls=smtp")
            elif Pop3ServiceDescriptor().match_nmap_service_name(service):
                os_command.append("--starttls=pop3")
            os_command.extend(['--json_out', ExecutionInfoType.json_output_file.argument,
                               "{}:{}".format(service.address, service.port)])
            collector = self._get_or_create_command(session,
                                                    os_command,
                                                    collector_name,
                                                    service=service,
                                                    json_file=json_file)
            collectors.append(collector)
        return collectors

    def _add_cipher_suites(self,
                           session: Session,
                           source: Source,
                           report_item: ReportItem,
                           tls_info: TlsInfo,
                           parent_tag,
                           prefered: bool) -> List[TlsInfoCipherSuiteMapping]:
        result = []
        if parent_tag is not None:
            for cipher_tag in parent_tag.findall("cipherSuite"):
                cipher = XmlUtils.get_xml_attribute("name", cipher_tag.attrib)
                mapping = self.add_tls_info_cipher_suite_mapping(session=session,
                                                                 tls_info=tls_info,
                                                                 order=0,
                                                                 kex_algorithm_details=None,
                                                                 iana_name=cipher,
                                                                 prefered=prefered,
                                                                 source=source,
                                                                 report_item=report_item)
                result.append(mapping)
        return result

    def parse_cipher_suite(self,
                           cipher_suite_json: dict,
                           session: Session,
                           tls_info: TlsInfo,
                           source: Source,
                           prefered_cipher_suite: str,
                           report_item: ReportItem):
        if "cipher_suite" in cipher_suite_json:
            if "name" in cipher_suite_json["cipher_suite"]:
                pass
            else:
                raise NotImplementedError("unexpected JSON format (missing attribute 'name')")
        else:
            raise NotImplementedError("unexpected JSON format (missing attribute 'cipher_suite')")


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
        if command.return_code != 0:
            self._set_execution_failed(session=session, command=command)
        try:
            if command.json_output:
                for json_object in command.json_output:
                    if "server_scan_results" in json_object:
                        for results in json_object["server_scan_results"]:
                            if "scan_commands_results" in results:
                                scan_commands_results = results["scan_commands_results"]
                                for section in scan_commands_results.keys():
                                    if section == "certificate_info":
                                        if "certificate_deployments" in scan_commands_results[section]:
                                            for deployment in scan_commands_results[section]["certificate_deployments"]:
                                                if "received_certificate_chain" in deployment and \
                                                   isinstance(deployment["received_certificate_chain"], list):
                                                    chain = deployment["received_certificate_chain"]
                                                    i = 1
                                                    for item in chain:
                                                        if "as_pem" in item:
                                                            self.add_certificate(session=session,
                                                                                 command=command,
                                                                                 content=item["as_pem"],
                                                                                 type=CertType.identity if i == 1 else
                                                                                 CertType.intermediate if i < len(chain)
                                                                                 else CertType.root,
                                                                                 source=source,
                                                                                 report_item=report_item)
                                                            i += 1
                                                        else:
                                                            raise NotImplementedError(
                                                                "unexpected JSON format (missing attribute 'as_pem')")
                                                else:
                                                    raise NotImplementedError(
                                                        "unexpected JSON format (missing attribute "
                                                        "'received_certificate_chain')")
                                        else:
                                            raise NotImplementedError(
                                                "unexpected JSON format (missing attribute "
                                                "'received_certificate_chain')")
                                    else:
                                        if "tls_version_used" in scan_commands_results[section] and \
                                                "accepted_cipher_suites" in scan_commands_results[section]:
                                            preferred_cipher = None
                                            preferred_kex = None
                                            preference = None
                                            tls_version_used = scan_commands_results[section]["tls_version_used"]
                                            accepted_cipher_suites = scan_commands_results[section]["accepted_cipher_suites"]
                                            tls_version = TlsInfo.get_tls_version(tls_version_used)
                                            if "cipher_suite_preferred_by_server" in scan_commands_results[section] and \
                                                    scan_commands_results[section]["cipher_suite_preferred_by_server"]:
                                                cipher_suite_preferred_by_server = scan_commands_results[section]["cipher_suite_preferred_by_server"]
                                                if "cipher_suite" in cipher_suite_preferred_by_server and \
                                                        cipher_suite_preferred_by_server["cipher_suite"] and \
                                                        "name" in cipher_suite_preferred_by_server["cipher_suite"]:
                                                    preferred_cipher = cipher_suite_preferred_by_server["cipher_suite"]["name"]
                                                    preference = TlsPreference.server
                                                if "ephemeral_key" in cipher_suite_preferred_by_server and \
                                                        cipher_suite_preferred_by_server["ephemeral_key"] and \
                                                        "curve_name" in cipher_suite_preferred_by_server["ephemeral_key"]:
                                                    preferred_kex = cipher_suite_preferred_by_server["ephemeral_key"]["curve_name"]
                                            # todo
                                            elif "cipher_suite_preferred_by_client" in scan_commands_results[section] and \
                                                    scan_commands_results[section]["cipher_suite_preferred_by_client"]:
                                                cipher_suite_preferred_by_client = scan_commands_results[section]["cipher_suite_preferred_by_client"]
                                                if "cipher_suite" in cipher_suite_preferred_by_client and \
                                                        cipher_suite_preferred_by_client["cipher_suite"] and \
                                                        "name" in cipher_suite_preferred_by_client["cipher_suite"]:
                                                    preferred_cipher = cipher_suite_preferred_by_client["cipher_suite"]["name"]
                                                    preference = TlsPreference.client
                                                if "ephemeral_key" in cipher_suite_preferred_by_client and \
                                                        cipher_suite_preferred_by_client["ephemeral_key"] and \
                                                        "curve_name" in cipher_suite_preferred_by_client["ephemeral_key"]:
                                                    preferred_kex = cipher_suite_preferred_by_client["ephemeral_key"]["curve_name"]
                                            if accepted_cipher_suites:
                                                tls_info = self.add_tls_info(session=session,
                                                                             service=command.service,
                                                                             version=tls_version,
                                                                             preference=preference,
                                                                             report_item=report_item)
                                                if tls_info:
                                                    order = len(accepted_cipher_suites)
                                                    for cipher_suite_json in accepted_cipher_suites:
                                                        kex_info = None
                                                        kex_name = None
                                                        kex_bits = None
                                                        if "ephemeral_key" in cipher_suite_json and \
                                                                cipher_suite_json["ephemeral_key"] and \
                                                                "curve_name" in cipher_suite_json["ephemeral_key"]:
                                                            kex_name = cipher_suite_json["ephemeral_key"]["curve_name"]
                                                            kex_bits = cipher_suite_json["ephemeral_key"]["size"]
                                                            kex_info = TlsInfoCipherSuiteMapping.\
                                                                get_kex_algorithm(kex_name, source)
                                                        if "cipher_suite" in cipher_suite_json and \
                                                            "name" in cipher_suite_json["cipher_suite"]:
                                                            tls_cipher = cipher_suite_json["cipher_suite"]["name"]
                                                            self._domain_utils.add_tls_info_cipher_suite_mapping(
                                                                session=session,
                                                                tls_info=tls_info,
                                                                order=order,
                                                                kex_algorithm_details=kex_info,
                                                                kex_bits=kex_bits,
                                                                iana_name=tls_cipher,
                                                                source=source,
                                                                prefered=(preferred_cipher == tls_cipher and
                                                                          preferred_kex == kex_name),
                                                                report_item=report_item)
                                                            order -= 1
                                                        else:
                                                            raise NotImplementedError(
                                                                "unexpected JSON format (missing attribute "
                                                                "'cipher_suite' and 'name')")
                                                else:
                                                    raise ValueError("no TLS information found")
                                        else:
                                            raise NotImplementedError(
                                                "unexpected JSON format (missing attribute "
                                                "'tls_version_used' or 'accepted_cipher_suites')")
                            else:
                                raise NotImplementedError(
                                    "unexpected JSON format (missing attribute 'scan_commands_results')")
                    else:
                        raise NotImplementedError("unexpected JSON format (missing attribute 'server_scan_results')")
        except xml.etree.ElementTree.ParseError as e:
            logger.exception(e)
