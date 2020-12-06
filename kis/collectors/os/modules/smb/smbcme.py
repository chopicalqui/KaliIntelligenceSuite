# -*- coding: utf-8 -*-
"""
run tool crackmapexec on each identified in-scope SMB service to obtain general SMB information
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
from typing import List
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.smb.core import SmbServiceDescriptor
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseCrackMapExec
from collectors.os.core import PopenCommand
from database.model import Service
from database.model import Command
from database.model import CollectorName
from view.core import ReportItem
from database.model import Source
from sqlalchemy.orm.session import Session


class CollectorClass(BaseCrackMapExec, ServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=13100,
                         timeout=0,
                         exec_user="kali",
                         service_descriptors=SmbServiceDescriptor(),
                         **kwargs)
        self._smb_info_re = re.compile(
            "^.+\[\*\].*? (?P<os>.+?) \(name:(?P<name>.+?)\) \(domain:(?P<domain>.+?)\) \(signing:(?P<signing>.+?)\) \(SMBv1:(?P<smbv1>.+?)\)$")

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
        if self.match_service_port(service):
            tmp = self._create_commands(session=session,
                                        service=service,
                                        collector_name=collector_name,
                                        module="smb")
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
        if command.return_code != 0:
            command.hide = False
            self._set_execution_failed(session, command)
            return
        else:
            command.hide = True
        for line in command.stdout_output:
            line = line.strip()
            match = self._smb_info_re.match(line)
            if match:
                os_info = match.group("os").strip()
                domain = match.group("domain").strip()
                signing = match.group("signing").strip().lower()
                smbv1 = match.group("smbv1").strip().lower()
                if domain:
                    command.host.workgroup = domain
                    self.add_host_name(session=session,
                                       command=command,
                                       host_name=domain,
                                       source=source,
                                       verify=True,
                                       report_item=report_item)
                if os_info:
                    if "windows" in os_info.lower():
                        command.host.os_family = "windows"
                    command.host.os_details = os_info
                if signing and signing in ['true', 'false']:
                    command.service.smb_message_signing = signing == 'true'
                report_item.listener = self._ui_manager
                report_item.details = "SMB message signing: {}, SMBv1: {}".format(signing, smbv1)
                report_item.report_type = "SMB"
                report_item.notify()
