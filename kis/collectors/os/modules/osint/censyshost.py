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
from collectors.os.modules.osint.core import BaseKisImportHost
from collectors.os.modules.core import HostCollector
from collectors.apis.censys import CensysIpv4
from collectors.os.core import PopenCommand
from collectors.core import JsonUtils
from database.model import Command
from database.model import Source
from database.model import ProtocolType
from database.model import ServiceState
from database.model import IpSupport
from view.core import ReportItem
from sqlalchemy.orm.session import Session

logger = logging.getLogger('censyshost')


class CollectorClass(BaseKisImportHost, HostCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=530,
                         timeout=0,
                         argument_name="--censys-host",
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
            if "metadata" in json_object:
                os = JsonUtils.get_attribute_value(json_object, "metadata/os")
                if os and not command.host.os_family:
                    command.host.os_family = os
            if "protocols" in json_object:
                protocols_info = self._json_utils.get_json_attribute(json_object, "protocols")
                if protocols_info:
                    for protocol_info in protocols_info:
                        service_info = JsonUtils.get_attribute_value(json_object, protocol_info)
                        if service_info:
                            domains = []
                            port = int(protocol_info.split("/")[0])
                            service = self.add_service(session=session,
                                                       port=port,
                                                       protocol_type=ProtocolType.tcp,
                                                       state=ServiceState.Open,
                                                       host=command.host,
                                                       source=source,
                                                       report_item=report_item)
                            for tls_attribute in JsonUtils.find_attribute(service_info, "tls"):
                                domains = JsonUtils.get_attribute_value(tls_attribute, "certificate/parsed/names")
                                domains = domains if domains else []
                                tmp = JsonUtils.get_attribute_value(tls_attribute,
                                                                    "tls/certificate/parsed/extensions/"
                                                                    "subject_alt_name/dns_names")
                                domains = domains + (tmp if tmp else [])
                                if domains:
                                    service.nmap_tunnel = "ssl"
                            for metadata_attribute in JsonUtils.find_attribute(service_info, "metadata"):
                                product = JsonUtils.get_attribute_value(metadata_attribute, "product")
                                version = JsonUtils.get_attribute_value(metadata_attribute, "version")
                                manufacturer = JsonUtils.get_attribute_value(metadata_attribute, "manufacturer")
                                if manufacturer and product:
                                    service.nmap_product = "{} {}".format(manufacturer, product)
                                elif manufacturer and not product:
                                    service.nmap_product = manufacturer
                                elif product:
                                    service.nmap_product = product
                                if version:
                                    service.nmap_version = version
                            html_title = JsonUtils.get_attribute_value(service_info, "get/title")
                            if html_title:
                                self.add_additional_info(session=session,
                                                         command=command,
                                                         name="HTTP title",
                                                         values=[html_title],
                                                         service=service,
                                                         source=source,
                                                         report_item=report_item)
                            html_server = JsonUtils.get_attribute_value(service_info, "get/headers/server")
                            if html_server:
                                self.add_additional_info(session=session,
                                                         command=command,
                                                         name="HTTP server",
                                                         values=[html_server],
                                                         service=service,
                                                         source=source,
                                                         report_item=report_item)
                            for item in domains:
                                self.add_host_name(session=session,
                                                   command=command,
                                                   host_name=item,
                                                   source=source,
                                                   host=command.host,
                                                   verify=True,
                                                   report_item=report_item)