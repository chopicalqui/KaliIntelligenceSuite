# -*- coding: utf-8 -*-
"""
run tool kismanage on each identified in-scope and non-private IPv4/IPv6 network to obtain host information via
shodan.io
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
from collectors.os.modules.osint.core import BaseKisImportNetwork
from collectors.apis.shodan import BaseShodan
from collectors.os.core import PopenCommand
from collectors.core import JsonUtils
from database.model import Command
from database.model import Source
from database.model import Network
from database.model import ScopeType
from database.model import IpSupport
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('shodannetwork')


class CollectorClass(BaseKisImportNetwork):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=520,
                         timeout=0,
                         argument_name="--shodan-network",
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

    def start_command_execution(self, session: Session, command: Command) -> bool:
        """
        This method allows the consumer threat to check whether the command should be executed. If this method returns
        false, then the command execution is not started. This is useful when another command of the same collector
        already identified the interesting information.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param command: The command instance to be executed
        :return: True, if the command should be executed, False if not.
        """
        # We only execute, if there is no larger in-scope network.
        if self._whitelist_network_filter:
            filter = [str(item) for item in self._whitelist_network_filter]
            count = session.query(Network) \
                .filter(Network.scope == ScopeType.all) \
                .filter(Network.network.in_(filter)) \
                .filter(Network.network.op(">>")(command.ipv4_network.network)).count()
        elif self._blacklist_network_filter:
            count = 0
            network = command.ipv4_network.ip_network
            for item in self._blacklist_network_filter:
                if network.version == item.version and command.ipv4_network.ip_network.subnet_of(item):
                    count = 1
                    break
        else:
            count = session.query(Network) \
                .filter(Network.scope == ScopeType.all) \
                .filter(Network.network.op(">>")(command.ipv4_network.network)).count()
        return count == 0

    def verify_results(self,
                       session: Session,
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
        for json_object in command.json_output:
            if "matches" in json_object:
                for object in json_object["matches"]:
                    ipv4_address = self._json_utils.get_attribute_value(object, "ip_str")
                    host_names = self._json_utils.get_attribute_value(object, "hostnames")
                    company = self._json_utils.get_attribute_value(object, "isp")
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
                    if company:
                        self.add_company(session=session,
                                         workspace=command.workspace,
                                         name=company,
                                         verify=True,
                                         source=source,
                                         report_item=report_item)
                    self.parse_shodan_data(session=session,
                                           command=command,
                                           host=host,
                                           source=source,
                                           data=object,
                                           dedup_host_names=dedup_host_names,
                                           report_item=report_item)
