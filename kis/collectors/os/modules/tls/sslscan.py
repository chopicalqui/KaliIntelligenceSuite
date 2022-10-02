# -*- coding: utf-8 -*-
"""
run tool sslscan on each identified in-scope TLS service to obtain information about the TLS configuration as well as
the certificate
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

import xml
import logging
from typing import List
from collectors.core import XmlUtils
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.tls.core import BaseTlsCollector
from collectors.os.modules.ftp.core import FtpServiceDescriptor
from collectors.os.modules.rdp.core import RdpServiceDescriptor
from collectors.os.modules.email.core import SmtpServiceDescriptor
from collectors.os.modules.mysql.core import MySqlServiceDescriptor
from collectors.os.modules.mssql.core import MsSqlServiceDescriptor
from collectors.os.modules.ldap.core import LdapServiceDescriptor
from collectors.os.modules.pgsql.core import PostgresSqlServiceDescriptor
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Service
from database.model import Command
from database.model import CollectorName
from database.model import Source
from database.model import CertInfo
from database.model import CertType
from database.model import TlsInfo
from database.model import TlsInfoCipherSuiteMapping
from database.model import ExecutionInfoType
from view.core import ReportItem
from sqlalchemy.orm.session import Session
import xml.etree.ElementTree as ET

logger = logging.getLogger('sslscan')


class CollectorClass(BaseTlsCollector, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=41320,
                         timeout=0,
                         **kwargs)
        self._xml_utils = XmlUtils()

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def _create_command(self,
                        session: Session,
                        service: Service,
                        collector_name: CollectorName,
                        ipv6: bool) -> List[BaseCollector]:
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
        address = service.address
        if address:
            matches = True
            xml_file = self.create_xml_file_path(service)
            os_command = [self._path_sslscan,
                          '-6' if ipv6 else '-4',
                          '--show-certificate',
                          '--ocsp',
                          '--no-color',
                          '--xml={}'.format(ExecutionInfoType.xml_output_file.argument)]
            if self.match_service_tls(service) or (MsSqlServiceDescriptor().match_nmap_service_name(service)):
                pass
            elif LdapServiceDescriptor().match_nmap_service_name(service):
                os_command.append('--starttls-ldap')
            elif FtpServiceDescriptor().match_nmap_service_name(service):
                os_command.append('--starttls-ftp')
            elif SmtpServiceDescriptor().match_nmap_service_name(service):
                os_command.append('--starttls-smtp')
            elif MySqlServiceDescriptor().match_nmap_service_name(service):
                os_command.append('--starttls-mysql')
            elif PostgresSqlServiceDescriptor().match_nmap_service_name(service):
                os_command.append('--starttls-psql')
            elif RdpServiceDescriptor().match_nmap_service_name(service):
                os_command.append('--rdp')
            else:
                matches = False
            if matches:
                if ipv6:
                    os_command.append("[{}]:{}".format(address, service.port))
                else:
                    os_command.append("{}:{}".format(address, service.port))
                collector = self._get_or_create_command(session,
                                                        os_command,
                                                        collector_name,
                                                        service=service,
                                                        xml_file=xml_file)
                collectors.append(collector)
        return collectors

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
        if service.host_name.name or self._scan_tld:
            # resolve host name to IPv4 address
            if service.host_name.resolves_to_in_scope_ipv4_address():
                result = self._create_command(session=session,
                                              service=service,
                                              collector_name=collector_name,
                                              ipv6=False)
            # resolve host name to IPv6 address
            if service.host_name.resolves_to_in_scope_ipv6_address():
                result = self._create_command(session=session,
                                              service=service,
                                              collector_name=collector_name,
                                              ipv6=True)
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
        return self._create_command(session=session,
                                    service=service,
                                    collector_name=collector_name,
                                    ipv6=service.host.ip_address.version == 6)

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
        try:
            tls_info_list = {}
            if command.xml_output:
                xml_root = ET.fromstring(command.xml_output)
                if xml_root is None:
                    return
                results_tag = xml_root.find("ssltest")
                if results_tag is None:
                    return
                certinfo = results_tag.find("./certificates/*/certificate-blob")
                if certinfo is not None and certinfo.text:
                    self.add_cert_info(session=session,
                                       cert_info=CertInfo(pem=certinfo.text, cert_type=CertType.identity),
                                       command=command,
                                       source=source,
                                       report_item=report_item)
                else:
                    logger.error("no certificate information found.")
                order = 1
                for cipher_tag in results_tag.findall("cipher"):
                    status = self._xml_utils.get_xml_attribute("status", cipher_tag.attrib)
                    sslversion = self._xml_utils.get_xml_attribute("sslversion", cipher_tag.attrib)
                    cipher = self._xml_utils.get_xml_attribute("cipher", cipher_tag.attrib)
                    curve = self._xml_utils.get_xml_attribute("curve", cipher_tag.attrib)
                    tls_version = TlsInfo.get_tls_version(sslversion)
                    if tls_version:
                        heartbleed_tag = results_tag.find("heartbleed[@sslversion='{}']".format(sslversion))
                        heartbleed = self._xml_utils.get_xml_attribute("vulnerable", heartbleed_tag.attrib)
                        heartbleed = heartbleed != "0"
                        if sslversion not in tls_info_list:
                            tls_info_list[sslversion] = self.add_tls_info(session=session,
                                                                          service=command.service,
                                                                          version=tls_version,
                                                                          heartbleed=heartbleed)
                            order = 1
                        if tls_info_list[sslversion]:
                            tls_info = tls_info_list[sslversion]
                            kex_algorithm = TlsInfoCipherSuiteMapping.get_kex_algorithm(curve) if curve else None
                            # sslscan does not consistently use one cipher suite notation.
                            mapping = self.add_tls_info_cipher_suite_mapping(session=session,
                                                                             tls_info=tls_info,
                                                                             order=order,
                                                                             kex_algorithm_details=kex_algorithm,
                                                                             gnutls_name=cipher,
                                                                             prefered=status == "preferred",
                                                                             source=source,
                                                                             report_item=report_item)
                            if not mapping:
                                mapping = self.add_tls_info_cipher_suite_mapping(session=session,
                                                                                 tls_info=tls_info,
                                                                                 order=order,
                                                                                 kex_algorithm_details=kex_algorithm,
                                                                                 iana_name=cipher,
                                                                                 prefered=status == "preferred",
                                                                                 source=source,
                                                                                 report_item=report_item)
                                if not mapping:
                                    mapping = self.add_tls_info_cipher_suite_mapping(session=session,
                                                                                     tls_info=tls_info,
                                                                                     order=order,
                                                                                     kex_algorithm_details=kex_algorithm,
                                                                                     openssl_name=cipher,
                                                                                     prefered=status == "preferred",
                                                                                     source=source,
                                                                                     report_item=report_item)
                                    if not mapping:
                                        logger.error(
                                            "cipher suite '{}' does not exist. ignoring cipher suite".format(cipher))
                            if mapping:
                                order += 1
        except xml.etree.ElementTree.ParseError as e:
            logger.exception(e)
