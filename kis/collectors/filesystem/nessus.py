# -*- coding: utf-8 -*-
""""This file contains common functionality to import Nessus scan results in XML format into the database."""

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

from collectors.core import XmlUtils
from database.model import Workspace
from database.model import Service
from database.model import Source
from database.model import ServiceState
from database.utils import Engine
from collectors.filesystem.core import BaseDatabaseXmlImporter
from typing import List
import xml.etree.ElementTree as ET


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
        super().__init__(session, workspace, input_files, Source.NESSUS, **kwargs)

    def _import_file(self, input_file: str) -> None:
        """
        This method imports the given file into the database.
        :param input_file: The file to be imported
        :return:
        """
        tree = ET.parse(input_file)
        root = tree.getroot()
        source = Engine.get_or_create(self._session, Source, name=self._source)
        for host_tag in root.findall('*/ReportHost'):
            host = None
            properties = host_tag.find("HostProperties")
            ip_address = DatabaseImporter.get_xml_attribute("name", host_tag.attrib)
            if properties:
                ipv4_address = properties.find("*/[@name='host-ip']")
                ipv4_address = ipv4_address.text if ipv4_address is not None else ip_address
                os_info = properties.find("*/[@name='os']")
                os_info = os_info.text if os_info is not None else None
                host = self._ip_utils.add_host(session=self._session,
                                               workspace=self._workspace,
                                               address=ipv4_address,
                                               source=source,
                                               report_item=self._report_item)
                host.os_family = os_info.lower() if os_info is not None and host.os_family is None else None
            if host:
                for item in host_tag.findall("ReportItem"):
                    port = int(DatabaseImporter.get_xml_attribute("port", item.attrib))
                    severity = int(DatabaseImporter.get_xml_attribute("severity", item.attrib))
                    protocol = DatabaseImporter.get_xml_attribute("protocol", item.attrib)
                    service_name = DatabaseImporter.get_xml_attribute("svc_name", item.attrib)
                    if service_name:
                        if service_name[-1] == '?':
                            confidence = 7
                            service_name = service_name[:-1]
                        else:
                            confidence = 10
                    else:
                        confidence = None
                    protocol = Service.get_protocol_type(protocol)
                    if protocol:
                        if port > 0:
                            plugin_id = DatabaseImporter.get_xml_attribute("pluginID", item.attrib)
                            plugin_name = DatabaseImporter.get_xml_attribute("pluginName", item.attrib)
                            nmap_tunnel = "ssl" if plugin_id == "56984" and \
                                                   plugin_name == "SSL / TLS Versions Supported" else None
                            service = self._domain_utils.add_service(session=self._session,
                                                                     port=port,
                                                                     protocol_type=protocol,
                                                                     state=ServiceState.Open,
                                                                     nessus_service_confidence=confidence,
                                                                     nessus_service_name=service_name,
                                                                     host=host,
                                                                     nmap_tunnel=nmap_tunnel,
                                                                     source=source,
                                                                     report_item=self._report_item)
                            # add vulnerability information
                            if severity > 0:
                                description = XmlUtils.get_element_text(item, "description")
                                cve = XmlUtils.get_element_text(item, "cve")
                                cvss_base_score = XmlUtils.get_element_text(item, "cvss_base_score")
                                cvss3_base_score = XmlUtils.get_element_text(item, "cvss3_base_score")
                                row = [[cve,
                                        cvss3_base_score,
                                        cvss_base_score,
                                        "{} - {}".format(plugin_id,
                                                         plugin_name),
                                        description]]
                                vulnerability = self._domain_utils.get_list_as_csv(row)
                                self._domain_utils.add_additional_info(session=self._session,
                                                                       service=service,
                                                                       name="CVEs",
                                                                       values=vulnerability,
                                                                       source=source,
                                                                       report_item=self._report_item)

