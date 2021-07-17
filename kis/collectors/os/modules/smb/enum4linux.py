# -*- coding: utf-8 -*-
"""
run tool enum4linux on each identified in-scope SMB service
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
from database.utils import Engine
from database.model import PathType
from typing import List
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.smb.core import BaseSmbCollector
from collectors.os.modules.core import BaseCollector
from collectors.os.core import PopenCommand
from database.model import Service
from database.model import Command
from database.model import CollectorName
from view.core import ReportItem
from database.model import Source
from sqlalchemy.orm.session import Session


class CollectorClass(BaseSmbCollector, ServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=91100,
                         timeout=0,
                         **kwargs)
        self._re_workgroup = re.compile("^\[\+\] Got domain/workgroup name: (.+)$")
        self._re_os_version = re.compile(
            "^\[\+\] Got OS info for .+? from smbclient: Domain=\[(.+?)] OS=\[(.+?)\] Server=\[(.+?)\]$")
        self._re_share = re.compile("^//.+?/(?P<share>.+?)\s+Mapping:\s(?P<mapping>[A-Z]+),?\s+Listing:"
                                    "\s+(?P<listing>.*)$")

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

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
        ipv4_address = service.host.ipv4_address
        if ipv4_address and self.match_service_port(service):
            os_command = [self._path_smb4linux,
                          "-a",
                          "-r",
                          "-K", "3",
                          "-o",
                          "-i",
                          ipv4_address]
            collector = self._get_or_create_command(session, os_command, collector_name, service=service)
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
        for line in command.stdout_output:
            match_workgroup = self._re_workgroup.match(line)
            match_os_version = self._re_os_version.match(line)
            match_share = self._re_share.match(line)
            if match_workgroup:
                workgroup = match_workgroup.group(1).strip()
                if workgroup:
                    command.service.host.workgroup = workgroup
                    if command.service.host.workgroup:
                        report_item.details = \
                            "potential workgroup for host {} found: {}".format(command.service.host.ipv4_address,
                                                                               command.service.host.workgroup.name)
                        report_item.report_type = "WORKGROUP"
                        self.add_report_item(report_item)
            elif match_os_version:
                match_workgroup = match_os_version.group(1).strip()
                os_details = match_os_version.group(2).strip()
                service_details = match_os_version.group(3).strip()
                workgroup = match_workgroup.group(1).strip()
                if workgroup:
                    command.service.host.workgroup = workgroup
                    if command.service.host.workgroup:
                        report_item.details = \
                            "potential workgroup for host {} found: {}".format(command.service.host.ipv4_address,
                                                                               command.service.host.workgroup.name)
                        report_item.report_type = "WORKGROUP"
                        self.add_report_item(report_item)
                if os_details:
                    command.service.host.os_details = os_details
                    if " windows " in os_details.lower() and not command.service.host.os_family:
                        command.service.host.os_family = "windows"
                    if " samba " in service_details.lower() and not command.service.host.os_family:
                        command.service.host.os_family = "linux"
                    if command.service.host.os_family:
                        report_item.details = \
                            "potential operating system for host {} found: {}".format(command.service.host.ipv4_address,
                                                                                      command.service.host.os_family)
                        report_item.report_type = "OS"
                        self.add_report_item(report_item)
            elif match_share:
                share = match_share.group("share")
                mapping = match_share.group("mapping").lower()
                listing = match_share.group("listing").lower()
                code = 200 if mapping == "ok" or listing == "ok" else 401
                path = self.add_path(session=session,
                                     command=command,
                                     service=command.service,
                                     path=share,
                                     path_type=PathType.smb_share,
                                     source=source,
                                     report_item=report_item)
                if path:
                    path.return_code = code

