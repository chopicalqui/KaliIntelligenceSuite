# -*- coding: utf-8 -*-
""""This file contains common functionality to import Masscan scan results in XML format into the database."""

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
from database.model import Workspace
from database.model import Service
from database.model import Source
from database.model import ServiceState
from database.utils import Engine
from collectors.filesystem.core import BaseDatabaseXmlImporter
from typing import List
import xml.etree.ElementTree as ET

logger = logging.getLogger('masscan')


class DatabaseImporter(BaseDatabaseXmlImporter):
    """
    This class parses the Nmap scan results stored in XML format into the database for further analysis.
    """

    def __init__(self, session, workspace: Workspace, input_files: List[str], **kwargs):
        """

        :param session: The database session used to import the data
        :param workspace: The project into which the data shall be imported
        :param input_files: The list of XML file names that shall be imported
        """
        super().__init__(session, workspace, input_files, Source.MASSCAN, **kwargs)

    def _import_file(self, input_file: str) -> None:
        """
        This method imports the given file into the database.
        :param input_file: The file to be imported
        :return:
        """
        with open(input_file, "r") as f:
            xml_content = f.read()
        self.import_content(xml_content)

    def import_content(self, xml_content: str) -> None:
        """
        This method imports the given XML content into the database.
        :param xml_content: The XML content
        :return:
        """
        try:
            root = ET.fromstring(xml_content)
        except xml.etree.ElementTree.ParseError:
            return
        source = Engine.get_or_create(self._session, Source, name=self._source)
        for host_tag in root.findall('host'):
            ipv4_address = None
            ipv6_address = None
            mac_address = None
            for addr in host_tag.findall('address'):
                type = DatabaseImporter.get_xml_attribute("addrtype", addr.attrib)
                if type == "ipv4":
                    ipv4_address = DatabaseImporter.get_xml_attribute("addr", addr.attrib)
                elif type == "ipv6":
                    ipv6_address = DatabaseImporter.get_xml_attribute("addr", addr.attrib)
                elif type == "mac":
                    mac_address = DatabaseImporter.get_xml_attribute("addr", addr.attrib)
            if ipv4_address:
                host = self._ip_utils.add_host(session=self._session,
                                               workspace=self._workspace,
                                               address=ipv4_address,
                                               source=source,
                                               report_item=self._report_item)
            elif ipv6_address:
                host = self._ip_utils.add_host(session=self._session,
                                               workspace=self._workspace,
                                               address=ipv6_address,
                                               source=source,
                                               report_item=self._report_item)
            else:
                raise NotImplementedError("the case that the host neither has an IPv4 nor an IPv6 address is not "
                                          "implemented!")
            host.mac_address = mac_address
            for port in host_tag.findall('*/port'):
                port_state = DatabaseImporter.get_xml_attribute("state", port.findall("state[1]")[0].attrib)
                if "open" in port_state.lower():
                    service_protocol = DatabaseImporter.get_xml_attribute("protocol", port.attrib)
                    service_port = DatabaseImporter.get_xml_attribute("portid", port.attrib)
                    service_protocol = Service.get_protocol_type(service_protocol)
                    service = self._session.query(Service) \
                        .filter(Service.port == service_port,
                                Service.protocol == service_protocol,
                                Service.host_id == host.id).one_or_none()
                    if not service:
                        self._domain_utils.add_service(session=self._session,
                                                       port=service_port,
                                                       protocol_type=service_protocol,
                                                       state=ServiceState.Open,
                                                       host=host,
                                                       source=source,
                                                       report_item=self._report_item)
