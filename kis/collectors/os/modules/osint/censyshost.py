# -*- coding: utf-8 -*-
"""
run tool kismanage on each identified in-scope and non-private IPv4 address to obtain host information via censys.io.
depending on the number of IP addresses in the current workspace, it might be desired to limit the number of OS
commands by using the optional argument --filter
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
from view.core import ReportItem
from database.model import Source
from database.model import Command
from database.model import PathType
from database.model import IpSupport
from database.model import ProtocolType
from database.model import ServiceState
from collectors.os.core import PopenCommand
from collectors.os.modules.core import HostCollector
from collectors.os.modules.osint.core import BaseKisImportHost
from collectors.core import JsonUtils
from collectors.apis.censys import CensysIpv4
from sqlalchemy.orm.session import Session
from urllib.parse import urlparse

logger = logging.getLogger('censyshost')


class CollectorClass(BaseKisImportHost, HostCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=530,
                         timeout=0,
                         argument_name="--censys-host",
                         exec_user="kali",
                         ip_support=IpSupport.ipv4,
                         source=CensysIpv4.SOURCE,
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
        return self._api_config.config.get("censys", "api_uid") and self._api_config.config.get("censys", "api_key")

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
        super().verify_results(session=session,
                               command=command,
                               source=source,
                               report_item=report_item,
                               process=process)
        for json_object in command.json_output:
            # TODO: asn
            # asn = JsonUtils.get_attribute_value(json_object, "autonomous_system/asn")
            network = JsonUtils.get_attribute_value(json_object, "autonomous_system/bgp_prefix")
            host_names = JsonUtils.get_attribute_value(json_object, "dns/names", default_value=[])
            host_names += JsonUtils.get_attribute_value(json_object, "dns/reverse_dns/names", default_value=[])
            # Add network
            if network and not self.add_network(session=session,
                                                command=command,
                                                network=network,
                                                source=source,
                                                report_item=report_item):
                logger.debug("ignoring network '{}' due to invalid format.".format(network))
            # Parse services
            for item in json_object["services"]:
                port = int(item["port"])
                name = item["_decoded"]
                protocol = ProtocolType[item["transport_protocol"].lower()]
                has_tls = "tls" in item
                service = self.add_service(session=session,
                                           port=port,
                                           protocol_type=protocol,
                                           state=ServiceState.Open,
                                           nmap_tunnel="ssl" if has_tls else None,
                                           nmap_service_name=name,
                                           host=command.host,
                                           source=source,
                                           report_item=report_item)
                # JSON object does not contain raw certificate
                if name == "http":
                    uri = JsonUtils.get_attribute_value(item, "http/request/uri")
                    status_code = JsonUtils.get_attribute_value(item, "http/response/status_code")
                    if uri:
                        path = urlparse(uri).path
                        if path:
                            self.add_path(session=session,
                                          command=command,
                                          service=service,
                                          path=path,
                                          path_type=PathType.http,
                                          return_code=status_code,
                                          source=source,
                                          report_item=report_item)
                    # Add redirect header
                    for location in JsonUtils.get_attribute_value(item, "http/response/headers/Location"):
                        self.add_url(session=session,
                                     command=command,
                                     url=location,
                                     source=source,
                                     report_item=report_item)
                    server_headers = JsonUtils.get_attribute_value(item, "http/response/headers/Server")
                    # Add additional information
                    self.add_additional_info(session=session,
                                             command=command,
                                             name="HTTP server",
                                             values=server_headers,
                                             service=service,
                                             source=source,
                                             report_item=report_item)
                    html_title = JsonUtils.get_attribute_value(item, "http/response/html_title")
                    self.add_additional_info(session=session,
                                             command=command,
                                             name="HTTP title",
                                             values=html_title,
                                             service=service,
                                             source=source,
                                             report_item=report_item)
                if has_tls:
                    host_names += JsonUtils.get_attribute_value(item,
                                                                "tls/certificates/leaf_data/names",
                                                                default_value=[])
            # Add host names
            for host_name in set(host_names):
                if not self.add_host_name(session=session,
                                          command=command,
                                          host_name=host_name,
                                          source=source,
                                          verify=True,
                                          report_item=report_item):
                    logger.debug("ignoring host name '{}' due to invalid format.".format(host_name))
