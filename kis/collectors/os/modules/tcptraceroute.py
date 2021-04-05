# -*- coding: utf-8 -*-
"""
run tool traceroute on the first open in-scope TCP service to determine the communication path the target host
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
from typing import List
from database.model import Service
from database.model import Source
from database.model import ProtocolType
from database.model import Host
from database.model import Command
from database.model import CollectorName
from database.model import ServiceState
from database.utils import Engine
from collectors.core import XmlUtils
from collectors.os.modules.core import HostCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseExtraServiceInfoExtraction
from collectors.os.core import PopenCommand
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('tcptraceroute')


class TracerouteExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by traceroute.
    """
    TRACE_COMMAND = "trace"

    def __init__(self, session, service: Service, **args):
        super().__init__(session, service, **args)
        self._source_traceroute = Engine.get_or_create(self._session, Source, name="nmap-traceroute")

    def _extract_ipv4_addresses(self, host_tag) -> None:
        """This method extracts IPv4 addresses from traceroute command"""
        trace_tags = host_tag.findall("{}".format(TracerouteExtraction.TRACE_COMMAND))
        for trace_tag in trace_tags:
            for hop_tag in trace_tag.findall("hop"):
                ipv4_address = XmlUtils.get_xml_attribute("ipaddr", hop_tag.attrib)
                if ipv4_address:
                    host = self._ip_utils.add_host(session=self._session,
                                                   workspace=self._workspace,
                                                   address=ipv4_address,
                                                   source=self._source_traceroute,
                                                   report_item=self._report_item)
                    if not host:
                        logger.debug("ignoring IPv4 address due to invalid format: {}".format(ipv4_address))

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_ipv4_addresses(kwargs["host_tag"])


class CollectorClass(BaseCollector, HostCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=1820,
                         timeout=0,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def _get_commands(self,
                      session: Session,
                      host: Host,
                      collector_name: CollectorName,
                      command: str,
                      tcp_port: int) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        os_command = [command, "-{}".format(host.version), host.address, tcp_port]
        collector = self._get_or_create_command(session, os_command, collector_name, host=host)
        collectors.append(collector)
        return collectors

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
        collectors = []
        command = self._path_tcptraceroute
        target_service = session.query(Service).filter(Service.host_id == host.id,
                                                       Service.state == ServiceState.Open,
                                                       Service.protocol == ProtocolType.tcp).order_by(Service.port).first()
        if target_service:
            tmp = self._get_commands(session, host, collector_name, command, target_service.port)
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
        re_hop = re.compile("^\s*[0-9]+\s+(?P<domain>.+?)\s\((?P<ipv4_address>.+?)\).*$")
        for line in command.stdout_output:
            match_host = re_hop.match(line)
            if match_host:
                ipv4_address = match_host.group("ipv4_address").strip()
                domain = match_host.group("domain").strip().lower()
                host = self.add_host(session=session,
                                     command=command,
                                     address=ipv4_address,
                                     source=source,
                                     report_item=report_item)
                if not host:
                    logger.debug("ignoring host due to invalid IPv4 address in line: {}".format(line))
                if domain != ipv4_address:
                    host_name = self.add_host_name(session=session,
                                                   command=command,
                                                   host_name=domain,
                                                   source=source,
                                                   report_item=report_item)
                    if not host_name:
                        logger.debug("ignoring host name due to invalid domain in line: {}".format(line))
