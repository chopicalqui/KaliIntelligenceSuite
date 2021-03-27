# -*- coding: utf-8 -*-
""""This file contains common functionality to import Nmap scan results in XML format into the database."""

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
import xml
import logging
import xml.etree.ElementTree as ET
from collectors.nmapcore import NmapExtractor
from database.model import Workspace
from database.model import Service
from database.model import DnsResourceRecordType
from database.model import Source
from database.utils import Engine
from collectors.filesystem.core import BaseDatabaseXmlImporter
from typing import List

logger = logging.getLogger('nmap')


class DatabaseImporter(BaseDatabaseXmlImporter):
    """
    This class parses the Nmap scan results stored in XML format into the database for further analysis.
    """

    SMB_SERVICE_NAME = ["microsoft-ds", 'netbios-ssn']
    HTTP_SERVICE_NAME = ["http"]
    HTTPS_SERVICE_NAME = ["https"]
    SMTP_SERVICE_NAME = ["email"]
    RPCINFO_SERVICE_NAME = ["rpcbind"]

    def __init__(self, session, workspace: Workspace, input_files: List[str], **kwargs):
        """

        :param session: The database session used to import the data
        :param workspace: The project into which the data shall be imported
        :param input_files: The list of XML file names that shall be imported
        """
        super().__init__(session, workspace, input_files, Source.NMAP, **kwargs)
        self.extractor = NmapExtractor()
        self._re_http_response = re.compile("HTTP\/\d+\.\d+\s\d+\s[0-9a-zA-Z\s]+")

    def _analyze_fingerprint(self, service: Service, port_tag: str) -> None:
        """
        This method analyzes the results of the NSE script fingerprint and updates the given
        service accordingly
        """
        script = port_tag.findall("*/[@id='fingerprint-strings']")
        if script and service.nmap_service_name not in ["http", "https"]:
            output = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            if self._re_http_response.findall(output):
                print("[I]   update service name '{}' of {}:{} ({}) to 'http'".format(service.nmap_service_name,
                                                                                      service.host.address,
                                                                                      service.port,
                                                                                      service.protocol.name.lower()),
                      file=self._stdout)
                service.nmap_service_name = "https" if service.tls else "http"

    def _import_file(self, input_file: str) -> None:
        """
        This method imports the given file into the database.
        :param input_file: The file to be imported
        :return:
        """
        with open(input_file, "r") as f:
            xml_content = f.read()
        self.import_content(xml_content)

    def _create_host(self,
                     source: Source,
                     host_up: bool,
                     host_up_reason: str,
                     host_tag,
                     ipv4_address: str = None,
                     ipv6_address: str = None,
                     mac_address: str = None):
        if ipv4_address:
            host = self._ip_utils.add_host(session=self._session,
                                           workspace=self._workspace,
                                           address=ipv4_address,
                                           source=source,
                                           report_item=self._report_item)
            resource_type = DnsResourceRecordType.a
        elif ipv6_address:
            host = self._ip_utils.add_host(session=self._session,
                                           workspace=self._workspace,
                                           address=ipv6_address,
                                           source=source,
                                           report_item=self._report_item)
            resource_type = DnsResourceRecordType.aaaa
        else:
            raise NotImplementedError("missing IPv4 and IPv6 address")
        host.mac_address = mac_address
        host.is_up = host_up
        host.reason_up = host_up_reason
        # assign host names to IP address
        for hostname in host_tag.findall('*/hostname'):
            domain_name_str = DatabaseImporter.get_xml_attribute("name", hostname.attrib)
            domain_type = DatabaseImporter.get_xml_attribute("type", hostname.attrib)
            domain_name = self._domain_utils.add_domain_name(session=self._session,
                                                             workspace=self._workspace,
                                                             item=domain_name_str,
                                                             host=host,
                                                             source=source,
                                                             verify=True,
                                                             report_item=self._report_item)
            if domain_type == "user":
                self._domain_utils.add_host_host_name_mapping(self._session,
                                                              host=host,
                                                              host_name=domain_name,
                                                              source=source,
                                                              mapping_type=resource_type,
                                                              report_item=self._report_item)
            else:
                logger.debug("domain '{}' of type '{}' not linked to IP address "
                             "'{}' because case is not implemented.".format(domain_name_str,
                                                                            domain_type,
                                                                            str(host.ip_address)))
        return host

    def import_content(self, xml_content: str) -> None:
        """
        This method imports the given XML content into the database.
        :param xml_content: The XML content
        :return:
        """
        try:
            root = ET.fromstring(xml_content)
        except xml.etree.ElementTree.ParseError:
            root = ET.fromstring(xml_content + "</nmaprun>")
        source = Engine.get_or_create(self._session, Source, name=self._source)
        re_domain = re.compile("^Domain: (?P<domain>.+?), Site: .*$")
        for host_tag in root.findall('host'):
            host = None
            ipv4_address = None
            ipv6_address = None
            mac_address = None
            status_tag = host_tag.findall("status")
            host_up = None
            host_up_reason = None
            if status_tag:
                host_up = DatabaseImporter.get_xml_attribute("state", status_tag[0].attrib) == "up"
                host_up_reason = DatabaseImporter.get_xml_attribute("reason", status_tag[0].attrib)
            port_tags = host_tag.findall('*/port')
            for addr in host_tag.findall('address'):
                type = DatabaseImporter.get_xml_attribute("addrtype", addr.attrib)
                if type == "ipv4":
                    ipv4_address = DatabaseImporter.get_xml_attribute("addr", addr.attrib)
                if type == "ipv6":
                    ipv6_address = DatabaseImporter.get_xml_attribute("addr", addr.attrib)
                if type == "mac":
                    mac_address = DatabaseImporter.get_xml_attribute("addr", addr.attrib)
            if not host_up:
                print("[I]   host '{}' is down and thus, is not imported.".format(ipv4_address),
                      file=self._stdout)
                continue
            if ipv4_address and ipv6_address:
                raise NotImplementedError("case IPv4 and IPv6 address available at the same time is not implemented")
            host_created = False
            for port in port_tags:
                port_state_tag = port.findall("state[1]")[0].attrib
                port_state = DatabaseImporter.get_xml_attribute("state", port_state_tag)
                extra_reason = DatabaseImporter.get_xml_attribute("reason", port_state_tag)
                service_protocol = DatabaseImporter.get_xml_attribute("protocol", port.attrib)
                service_protocol = Service.get_protocol_type(service_protocol)
                port_state = Service.get_service_state(port_state)
                if port_state in self._service_states:
                    if not host_created:
                        host_created = True
                        # at least one service exists and therefore, we create the host
                        host = self._create_host(source,
                                                 host_up,
                                                 host_up_reason,
                                                 host_tag,
                                                 ipv4_address,
                                                 ipv6_address,
                                                 mac_address)
                    service_port = DatabaseImporter.get_xml_attribute("portid", port.attrib)
                    service = self._domain_utils.add_service(session=self._session,
                                                             port=service_port,
                                                             protocol_type=service_protocol,
                                                             state=port_state,
                                                             host=host,
                                                             source=source,
                                                             report_item=self._report_item)
                    service.nmap_service_state_reason = extra_reason
                    services = port.findall("service[1]")
                    if len(services) == 1:
                        service_tag = services[0]
                        nmap_service_confidence = DatabaseImporter.get_xml_attribute("conf", service_tag.attrib)
                        nmap_service_confidence = int(nmap_service_confidence) \
                            if nmap_service_confidence is not None else None
                        service_name = DatabaseImporter.get_xml_attribute("name", service_tag.attrib)
                        service.nmap_service_name_original = service_name
                        tunnel = DatabaseImporter.get_xml_attribute("tunnel", service_tag.attrib)
                        if service_name == "http" and tunnel == "ssl":
                            service_name = DatabaseImporter.HTTPS_SERVICE_NAME[0]
                        service.nmap_service_name = service_name
                        service.nmap_service_confidence = nmap_service_confidence
                        service.nmap_product = DatabaseImporter.get_xml_attribute("product", service_tag.attrib)
                        service.nmap_version = DatabaseImporter.get_xml_attribute("version", service_tag.attrib)
                        service.nmap_os_type = DatabaseImporter.get_xml_attribute("ostype", service_tag.attrib)
                        service.nmap_tunnel = DatabaseImporter.get_xml_attribute("tunnel", service_tag.attrib)
                        if service.nmap_os_type and host.os_family is None:
                            os = service.nmap_os_type.lower()
                            host.os_family = "windows" if " windows " in os else os
                        if not service.nmap_tunnel and service_name == DatabaseImporter.HTTPS_SERVICE_NAME[0]:
                            service.nmap_tunnel = "ssl"
                        for item in ["debian", "ubuntu"]:
                            if service.nmap_version and item in service.nmap_version.lower() and host.os_family is None:
                                host.os_family = "linux"
                        hostname = DatabaseImporter.get_xml_attribute("hostname", service_tag.attrib)
                        hostname_levels = len(hostname.split(".")) if hostname else 0
                        if hostname:
                            host_name = self._domain_utils.add_domain_name(session=self._session,
                                                                           workspace=host.workspace,
                                                                           item=hostname,
                                                                           host=host,
                                                                           source=source,
                                                                           verify=True,
                                                                           report_item=self._report_item)
                            if not host_name:
                                print("[I]   ignoring host name: {}".format(hostname.lower()), file=self._stdout)
                        extra_info = DatabaseImporter.get_xml_attribute("extrainfo", service_tag.attrib)
                        if extra_info:
                            service.nmap_extra_info = extra_info
                            match_domain = re_domain.match(extra_info)
                            if match_domain:
                                domain = match_domain.group("domain")
                                domain_level = len(domain)
                                if hostname_levels == 1 and domain_level > 1:
                                    self._domain_utils.add_domain_name(session=self._session,
                                                                       workspace=self._workspace,
                                                                       item="{}.{}".format(hostname, domain),
                                                                       host=host,
                                                                       source=source,
                                                                       verify=True,
                                                                       report_item=self._report_item)
                                else:
                                    self._domain_utils.add_domain_name(session=self._session,
                                                                       workspace=self._workspace,
                                                                       item=domain,
                                                                       host=host,
                                                                       source=source,
                                                                       verify=True,
                                                                       report_item=self._report_item)
                        self._analyze_fingerprint(service, port)
                        # Extract additional information from XML
                        self.extractor.execute(session=self._session,
                                               workspace=self._workspace,
                                               domain_utils=self._domain_utils,
                                               ip_utils=self._ip_utils,
                                               service=service,
                                               source=source,
                                               report_item=self._report_item,
                                               service_tag=extra_info,
                                               host_tag=host_tag,
                                               port_tag=port)
                    elif len(services) > 1:
                        raise NotImplementedError("more than one service identified. this case has not "
                                                  "been implemented!")
                if not host_created:
                    print("[I]   host '{}' did not have any services to import and thus, "
                          "is ignored".format(ipv4_address), file=self._stdout)
            # if not host_created:
            #     host = self._create_host(source,
            #                              host_up,
            #                              host_up_reason,
            #                              host_tag,
            #                              ipv4_address,
            #                              ipv6_address,
            #                              mac_address)
            os_tag = host_tag.find("os")
            if host and os_tag is not None:
                for item in os_tag.findall("*/osclass"):
                    accuracy = DatabaseImporter.get_xml_attribute("accuracy", item.attrib)
                    if accuracy and int(accuracy) == 100:
                        osfamily = DatabaseImporter.get_xml_attribute("osfamily", item.attrib)
                        host.os_family = osfamily.lower() if osfamily is not None and host.os_family is None else None
