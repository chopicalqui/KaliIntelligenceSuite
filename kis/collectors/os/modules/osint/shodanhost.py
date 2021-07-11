# -*- coding: utf-8 -*-
"""
run tool kisimport on each identified in-scope and non-private IPv4/IPv6 address to obtain host information via
shodan.io. depending on the number IP addresses in the current workspace, it might be desired to limit the number of
OS commands by using the optional argument --filter
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
from collectors.os.modules.core import HostCollector
from collectors.os.modules.osint.core import BaseKisImportHost
from collectors.apis.shodan import BaseShodan
from collectors.os.core import PopenCommand
from collectors.core import JsonUtils
from database.model import Command
from database.model import Source
from database.model import HostName
from database.model import IpSupport
from view.core import ReportItem
from sqlalchemy.orm.session import Session
from typing import List
from typing import Dict

logger = logging.getLogger('shodanhost')


class CollectorClass(BaseKisImportHost, HostCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=520,
                         timeout=0,
                         argument_name="--shodan-host",
                         ip_support=IpSupport.all,
                         source=BaseShodan.SOURCE_NAME,
                         delay_min=1,
                         **kwargs)
        self._json_utils = JsonUtils()

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    def api_credentials_available(self) -> bool:
        """
        This method shall be implemented by sub classes. They should verify whether their API keys are set in the
        configuration file
        :return: Return true if API credentials are set, else false
        """
        return self._api_config.config.get("shodan", "api_key")

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
        dedup_host_names = {}
        if command.return_code and command.return_code > 0:
            self._set_execution_failed(session=session, command=command)
            return
        for object in command.json_output:
            ipv4_address = self._json_utils.get_attribute_value(object, "ip_str")
            host_names = self._json_utils.get_attribute_value(object, "hostnames")
            self._add_host_names(session=session,
                                 host_names=host_names,
                                 command=command,
                                 source=source,
                                 report_item=report_item,
                                 dedup_host_names=dedup_host_names)
            host = self.add_host(session=session,
                                 command=command,
                                 address=ipv4_address,
                                 source=source,
                                 report_item=report_item)
            if host:
                for data in self._json_utils.get_attribute_value(object, "data", default_value=[]):
                    self.parse_shodan_data(session=session,
                                           command=command,
                                           host=host,
                                           source=source,
                                           data=data,
                                           dedup_host_names=dedup_host_names,
                                           report_item=report_item)
            else:
                logger.debug("ignoring IPv4 address: {}".format(ipv4_address))
