# -*- coding: utf-8 -*-
"""
run tool nmap with all safe NSE scripts on all identified in-scope TLS services to obtain certificate information
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
import os
from typing import List
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.tls.core import BaseTlsCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from collectors.os.core import PopenCommandOpenSsl
from database.model import Service
from database.model import Command
from database.model import CollectorName
from database.model import Source
from database.model import CertType
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('certopenssl')


class CollectorClass(BaseTlsCollector, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=41330,
                         timeout=120,
                         execution_class=PopenCommandOpenSsl,
                         **kwargs)
        self._re_cert = re.compile("(?P<cert>-+BEGIN CERTIFICATE-+.+?-+END CERTIFICATE-+)", re.DOTALL)

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
        if address and (self.match_service_tls(service) or service.nmap_service_name == "ms-wbt-server"):
            os_command = [self._path_openssl,
                          's_client',
                          '-showcerts',
                          '-6' if ipv6 else '-4']
            if ipv6:
                os_command.append("[{}]:{}".format(address, service.port))
            else:
                os_command.append("{}:{}".format(address, service.port))
            collector = self._get_or_create_command(session,
                                                    os_command,
                                                    collector_name,
                                                    service=service)
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
        output = os.linesep.join(command.stdout_output)
        certificates = self._re_cert.findall(output)
        certificates_len = len(certificates)
        if certificates_len == 0:
            self._set_execution_failed(session, command)
        for i in range(0, certificates_len):
            if i == 0:
                cert_type = CertType.identity
            elif i == (certificates_len - 1):
                cert_type = CertType.root
            else:
                cert_type = CertType.intermediate
            self.add_cert_info(session=session,
                               pem=certificates[i],
                               cert_type=cert_type,
                               command=command,
                               source=source,
                               report_item=report_item)
