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

import os
import re
import xml
import logging
import xml.etree.ElementTree as ET
import collectors
from collectors.filesystem.core import BaseExtraServiceInfoExtraction
from collectors.core import XmlUtils
from database.model import Workspace
from database.model import Service
from database.model import DnsResourceRecordType
from database.model import Source
from database.model import PathType
from database.model import ProtocolType
from database.model import ServiceState
from database.model import CertType
from database.model import TlsInfoCipherSuiteMapping
from database.model import TlsInfo
from database.utils import Engine
from collectors.filesystem.core import BaseDatabaseXmlImporter
from sqlalchemy.orm.session import Session
from typing import List
from typing import Type

logger = logging.getLogger('nmap')


class ExtractionMapper:
    """
    This class checks whether the given service matches the service descriptor and if it does, then it performs the
    extraction.
    """

    def __init__(self,
                 nmap_extractor_class: Type[BaseExtraServiceInfoExtraction],
                 service_descriptor_classes = [],
                 tls_info: bool = False):
        self._service_descriptors = [item() for item in service_descriptor_classes]
        self._nmap_extractor_class = nmap_extractor_class
        self._tls_info = tls_info

    def run_extraction(self,
                       session: Session,
                       workspace: Workspace,
                       domain_utils,
                       ip_utils,
                       service: Service,
                       source: Source,
                       report_item,
                       **kwargs):
        extractor = self._nmap_extractor_class(session=session,
                                               workspace=workspace,
                                               domain_utils=domain_utils,
                                               ip_utils=ip_utils,
                                               service=service,
                                               source=source,
                                               report_item=report_item)
        if self._service_descriptors:
            for item in self._service_descriptors:
                if (not self._tls_info and item.match_nmap_service_name(service)) or \
                        (self._tls_info and item.match_tls(service)):
                    extractor.extract(**kwargs)
                    break
        else:
            extractor.extract(**kwargs)


class SmbExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information (e.g. user names, SMB shares) from SMB services.
    """
    SMB_ENUM_USERS = "smb-enum-users"
    SMB_ENUM_SHARES = "smb-enum-shares"
    SMB_SECURITY_MODE = "smb-security-mode"
    SMB2_SECURITY_MODE = "smb2-security-mode"
    SMB_OS_DISCOVERY = "smb-os-discovery"

    def __init__(self, session: Session, service: Service, **kwargs):
        super().__init__(session, service, **kwargs)
        self._re_user = re.compile("^(?P<domain>.*)\\\\(?P<user>.*) \(RID: (?P<rid>[0-9]+)\)$")
        self._re_path = re.compile("^\\\\\\\\.*?\\\\(?P<name>.+)$")

    def _extract_shares(self, host_tag):
        """Extracts SMB share information disclosed by SMB"""
        script = host_tag.findall("*/script/[@id='{}']".format(SmbExtraInfoExtraction.SMB_ENUM_SHARES))
        script_count = len(script)
        if script_count == 1:
            for table in script[0].findall("./table"):
                name = DatabaseImporter.get_xml_attribute("key", table.attrib)
                path_match = self._re_path.match(name)
                if path_match:
                    name = path_match.group("name")
                if name:
                    self._domain_utils.add_path(session=self._session,
                                                service=self._service,
                                                path=name,
                                                source=self._source,
                                                path_type=PathType.Smb_Share,
                                                report_item=self._report_item)
        elif script_count > 1:
            raise NotImplementedError("expected only one '/script/[@id='smb-enum-shares']' entry in "
                                      "'parseSmbEnumShares'.")

    def _extract_smb_message_signing(self, host_tag):
        """Extracts SMB share information disclosed by SMB"""
        script = host_tag.findall("*/script/[@id='{}']".format(SmbExtraInfoExtraction.SMB_SECURITY_MODE))
        for item in script:
            message_signing_tag = item.find("./elem[@key='message_signing']")
            if not message_signing_tag:
                self._domain_utils.add_additional_info(session=self._session,
                                                       name="SMB message signing",
                                                       values=[message_signing_tag.text],
                                                       source=self._source,
                                                       service=self._service,
                                                       report_item=self._report_item)

    def _extract_smb2_message_signing(self, host_tag):
        """Extracts SMB share information disclosed by SMB"""
        script = host_tag.findall("*/script/[@id='{}']".format(SmbExtraInfoExtraction.SMB2_SECURITY_MODE))
        for item in script:
            for table_tag in item.findall("table"):
                smb_version = XmlUtils.get_xml_attribute("key", table_tag.attrib)
                message = XmlUtils.get_element_text(table_tag, "elem")
                if smb_version and message:
                    self._domain_utils.add_additional_info(session=self._session,
                                                           name="SMB2 message signing",
                                                           values=["{} ({})".format(message, smb_version)],
                                                           source=self._source,
                                                           service=self._service,
                                                           report_item=self._report_item)

    def _extract_smb_os_discovery(self, host_tag):
        """Extracts SMB share information disclosed by SMB"""
        script = host_tag.findall("*/script/[@id='{}']".format(SmbExtraInfoExtraction.SMB_OS_DISCOVERY))
        for item in script:
            info = XmlUtils.get_element_text(item, "./elem[@key='os']")
            if info is not None:
                self._service.host.os_details = info
                if "windows" in info.lower():
                    self._service.host.os_family = "windows"
            info = XmlUtils.get_element_text(item, "./elem[@key='NetBIOS computer name']")
            if info is not None:
                self._service.host.workgroup = info
            if info is not None:
                self._service.host.os_details = info
                if "windows" in info.lower():
                    self._service.host.os_family = "windows"
            info = XmlUtils.get_element_text(item, "./elem[@key='FQDN']")
            if info is not None:
                self._domain_utils.add_domain_name(session=self._session,
                                                   workspace=self._workspace,
                                                   item=info,
                                                   host=self._service.host,
                                                   source=self._source,
                                                   verify=True,
                                                   report_item=self._report_item)
            info = XmlUtils.get_element_text(item, "./elem[@key='Domain name']")
            if info is not None:
                self._domain_utils.add_domain_name(session=self._session,
                                                   workspace=self._workspace,
                                                   item=info,
                                                   host=self._service.host,
                                                   source=self._source,
                                                   verify=True,
                                                   report_item=self._report_item)
            info = XmlUtils.get_element_text(item, "./elem[@key='Forest name']")
            if info is not None:
                self._domain_utils.add_domain_name(session=self._session,
                                                   workspace=self._workspace,
                                                   item=info,
                                                   host=self._service.host,
                                                   source=self._source,
                                                   verify=True,
                                                   report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts disclosed information from SMB services."""
        self._extract_shares(kwargs["host_tag"])
        self._extract_smb_message_signing(kwargs["host_tag"])
        self._extract_smb2_message_signing(kwargs["host_tag"])
        self._extract_smb_os_discovery(kwargs["host_tag"])


class MsSqlExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information (e.g. user names, SMB shares) from MS-SQL services.
    """
    MSSQL_TCP_PORTS = "ms-sql-info"
    MSSQL_NTLM_INFO = "ms-sql-ntlm-info"

    def __init__(self, session, service: Service, **args):
        super().__init__(session, service, **args)

    def _extract_sql_info(self, host_tag):
        """This method extracts the required information."""
        script = host_tag.findall("*/script/[@id='{}']".format(MsSqlExtraInfoExtraction.MSSQL_TCP_PORTS))
        script_count = len(script)
        if script_count == 1:
            for table in script[0].findall("./table"):
                tcp_port = DatabaseImporter.get_xml_text(table.findall(".//*[@key='TCP port']"))
                if tcp_port:
                    service = self._domain_utils.add_service(session=self._session,
                                                             port=tcp_port,
                                                             protocol_type=ProtocolType.tcp,
                                                             state=ServiceState.Open,
                                                             host=self._service.host,
                                                             source=self._source,
                                                             report_item=self._report_item)
                    if service:
                        service.nmap_service_name = DatabaseImporter.MSSQL_SERVICE_NAME[0]
        elif script_count > 1:
            raise NotImplementedError("expected only one '/script/[@id='{}']' entry.".format(
                MsSqlExtraInfoExtraction.MSSQL_TCP_PORTS))

    def _extract_ntlm_info(self, port_tag) -> None:
        """This method extracts NTLM information"""
        super()._extract_ntlm_info(port_tag, tag_id=MsSqlExtraInfoExtraction.MSSQL_NTLM_INFO)

    def extract(self, **kwargs):
        """This method extracts disclosed information from SMB services."""
        self._extract_sql_info(kwargs["host_tag"])
        self._extract_ntlm_info(kwargs["port_tag"])


class HttpExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information from MS-SQL services.
    """
    HTTP_METHODS = "http-methods"
    ROBOTS_TXT = "http-robots.txt"
    WEB_PATHS = "web-paths"
    HTTP_TITLE = "http-title"
    HTTP_SERVER_HEADER = "http-server-header"
    HTTP_AUTH_FINDER = "http-auth-finder"
    HTTP_BACKUP_FINDER = "http-backup-finder"
    HTTP_COMMENTS_DISPLAYER = "http-comments-displayer"
    HTTP_NTLM_INFO = "http-ntlm-info"
    HTTP_ENUM = "http-enum"
    HTTP_SECURITY_HEADERS = "http-security-headers"

    def __init__(self, session, service: Service, **args):
        super().__init__(session, service, **args)
        self._re_http_auth_finder = re.compile("^\s*(?P<url>https?://.*?)\s+[A-Z].*$", re.IGNORECASE)
        self._re_http_backup_finder = re.compile("^\s*(?P<url>https?://.*?)$", re.IGNORECASE)
        self._re_comments_displayer_path = re.compile("^\s*Path:\s*(?P<url>https?://.*?)$", re.IGNORECASE)
        self._re_http_enum = re.compile("^\s*(?P<path>.+?):.*$")
        self._source_auth_finder = Engine.get_or_create(self._session,
                                                        Source,
                                                        name=HttpExtraInfoExtraction.HTTP_AUTH_FINDER)
        self._source_robots_txt = Engine.get_or_create(self._session,
                                                       Source,
                                                       name=HttpExtraInfoExtraction.ROBOTS_TXT)

    def _extract_http_title(self, port_tag: str) -> None:
        """This method extracts the HTTP title"""
        script = port_tag.findall("*/[@id='{}']".format(HttpExtraInfoExtraction.HTTP_TITLE))
        if len(script) > 0:
            output = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            if output:
                self._domain_utils.add_additional_info(session=self._session,
                                                       name="HTTP title",
                                                       values=[output],
                                                       source=self._source,
                                                       service=self._service,
                                                       report_item=self._report_item)

    def _extract_http_server_header(self, port_tag: str) -> None:
        """This method extracts the HTTP title"""
        script = port_tag.findall("*/[@id='{}']".format(HttpExtraInfoExtraction.HTTP_SERVER_HEADER))
        if len(script) > 0:
            output = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            if output:
                self._domain_utils.add_additional_info(session=self._session,
                                                       name="HTTP server header",
                                                       values=[output],
                                                       source=self._source,
                                                       service=self._service,
                                                       report_item=self._report_item)

    def _extract_robots_txt(self, port_tag: str) -> None:
        """This method extracts web paths disclosed by the robots.txt file."""
        script = port_tag.findall("*/[@id='{}']".format(HttpExtraInfoExtraction.ROBOTS_TXT))
        if len(script) > 0:
            output = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            if output:
                tmp = output.split(os.linesep)
                for line in tmp[1:]:
                    for item in line.split(" "):
                        self._domain_utils.add_url(session=self._session,
                                                   service=self._service,
                                                   url=item,
                                                   source=self._source_robots_txt,
                                                   report_item=self._report_item)

    def _extract_http_auth_finder(self, port_tag):
        """This method extracts URLs"""
        script = port_tag.findall(".//*[@id='{}']".format(HttpExtraInfoExtraction.HTTP_AUTH_FINDER))
        if len(script) > 0:
            output = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            if output:
                tmp = output.split(os.linesep)
                for line in tmp:
                    match = self._re_http_auth_finder.match(line)
                    if match:
                        self._domain_utils.add_url(session=self._session,
                                                   service=self._service,
                                                   url=match.group("url"),
                                                   source=self._source_auth_finder,
                                                   report_item=self._report_item)

    def _extract_http_comments_displayer(self, port_tag):
        """This method extracts URLs"""
        script = port_tag.findall(".//*[@id='{}']".format(HttpExtraInfoExtraction.HTTP_COMMENTS_DISPLAYER))
        if len(script) > 0:
            output = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            if output:
                dedup = {}
                for line in output.split(os.linesep):
                    match = self._re_comments_displayer_path.match(line)
                    if match:
                        url = match.group("url")
                        if url not in dedup:
                            dedup[url] = True
                            self._domain_utils.add_url(session=self._session,
                                                       service=self._service,
                                                       url=url,
                                                       source=self._source_auth_finder,
                                                       report_item=self._report_item)

    def _extract_http_backup_finder(self, port_tag):
        """This method extracts URLs"""
        script = port_tag.findall(".//*[@id='{}']".format(HttpExtraInfoExtraction.HTTP_BACKUP_FINDER))
        if len(script) > 0:
            output = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            if output:
                tmp = output.split(os.linesep)
                for line in tmp:
                    match = self._re_http_backup_finder.match(line)
                    if match:
                        self._domain_utils.add_url(session=self._session,
                                                   service=self._service,
                                                   url=match.group("url"),
                                                   source=self._source,
                                                   report_item=self._report_item)

    def _extract_http_methods(self, port_tag):
        """This method extracts the HTTP methods supported by the web server."""
        script = port_tag.findall(".//*[@key='Supported Methods']")
        if len(script) > 0:
            for item in script[0].findall("*"):
                self._domain_utils.add_service_method(session=self._session,
                                                      name=item.text,
                                                      service=self._service)

    def _extract_ntlm_info(self, port_tag) -> None:
        """This method extracts NTLM information"""
        super()._extract_ntlm_info(port_tag, tag_id=HttpExtraInfoExtraction.HTTP_NTLM_INFO)

    def _extract_http_enum(self, port_tag: str) -> None:
        """This method extracts the enumerated file paths"""
        script = port_tag.findall("*/[@id='{}']".format(HttpExtraInfoExtraction.HTTP_ENUM))
        if len(script) > 0:
            output = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            if output:
                for line in output.split(os.linesep):
                    match = self._re_http_enum.match(line)
                    if match:
                        path = match.group("path")
                        self._domain_utils.add_path(session=self._session,
                                                    service=self._service,
                                                    path=path,
                                                    path_type=PathType.Http,
                                                    source=self._source,
                                                    report_item=self._report_item)

    def _extract_security_headers(self, port_tag: str) -> None:
        """This security headers"""
        for script_tag in port_tag.findall("script/[@id='{}']".format(HttpExtraInfoExtraction.HTTP_SECURITY_HEADERS)):
            for table_tag in script_tag.findall("table"):
                key = XmlUtils.get_xml_attribute("key", table_tag.attrib)
                if key:
                    key = key.strip()
                    values = []
                    for elem in table_tag.findall("elem"):
                        values.append(elem.text.strip())
                    if values:
                        self._domain_utils.add_additional_info(session=self._session,
                                                               name=key,
                                                               values=values,
                                                               source=self._source,
                                                               service=self._service,
                                                               report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts HTTP information disclosed by the HTTP service."""
        self._extract_robots_txt(kwargs["port_tag"])
        self._extract_http_methods(kwargs["port_tag"])
        self._extract_http_title(kwargs["port_tag"])
        self._extract_http_server_header(kwargs["port_tag"])
        self._extract_http_auth_finder(kwargs["port_tag"])
        self._extract_http_backup_finder(kwargs["port_tag"])
        self._extract_http_comments_displayer(kwargs["port_tag"])
        self._extract_ntlm_info(kwargs["port_tag"])
        self._extract_http_enum(kwargs["port_tag"])
        self._extract_security_headers(kwargs["port_tag"])


class SshExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information from SSH services.
    """
    SSH2_ENUM_ALGOS = "ssh2-enum-algos"

    def __init__(self, session, service: Service, **kwargs):
        super().__init__(session, service, **kwargs)
        self._re_weak_algorithms = [re.compile("^.+\-cbc$"), re.compile("^arcfour((128)|(256))?$")]

    def _extract_ssh2_enum_algos(self, port_tag):
        """Extracts SMB share information disclosed by SMB"""
        weak_algorithms = []
        for script_tag in port_tag.findall("script/[@id='{}']".format(SshExtraInfoExtraction.SSH2_ENUM_ALGOS)):
            for algorithm_table in script_tag.findall("table[@key='encryption_algorithms']"):
                for elem in algorithm_table.findall("elem"):
                    for item in self._re_weak_algorithms:
                        match = item.match(elem.text)
                        if match:
                            weak_algorithms.append(elem.text)
        if weak_algorithms:
            self._domain_utils.add_additional_info(session=self._session,
                                                   name="Weak SSH encryption",
                                                   values=weak_algorithms,
                                                   source=self._source,
                                                   service=self._service,
                                                   report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts disclosed information from SMB services."""
        self._extract_ssh2_enum_algos(kwargs["port_tag"])


class SmtpExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by SMTP service.
    """
    SMTP_COMMANDS = "email-commands"
    SMTP_NTLM_INFO = "smtp-ntlm-info"

    def __init__(self, session, service: Service, **args):
        super().__init__(session, service, **args)

    def _extract_smtp_commands(self, port_tag) -> None:
        """This method extracts the supported SMTP commands disclosed by the SMTP service"""
        script = port_tag.findall("*/[@id='{}']".format(SmtpExtraInfoExtraction.SMTP_COMMANDS))
        if len(script) > 0:
            tmp = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            commands = tmp.strip().split(" ")
            for command in commands:
                command = re.sub("[\W,\.\+_]", "", command)
                if not command.isnumeric():
                    self._domain_utils.add_service_method(session=self._session,
                                                          name=command,
                                                          service=self._service)

    def _extract_ntlm_info(self, port_tag) -> None:
        """This method extracts NTLM information"""
        super()._extract_ntlm_info(port_tag, tag_id=SmtpExtraInfoExtraction.SMTP_NTLM_INFO)

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_smtp_commands(kwargs["port_tag"])
        self._extract_ntlm_info(kwargs["port_tag"])


class RdpExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by RDP service.
    """
    RDP_NTLM_INFO = "rdp-ntlm-info"
    RDP_ENUM_ENCRYPTION = "rdp-enum-encryption"

    def __init__(self, session, service: Service, **args):
        super().__init__(session, service, **args)

    def _extract_ntlm_info(self, port_tag) -> None:
        """This method extracts NTLM information"""
        super()._extract_ntlm_info(port_tag, tag_id=RdpExtraInfoExtraction.RDP_NTLM_INFO)

    def _extract_rdp_encryption(self, port_tag) -> None:
        """This method extracts RDP encryption information"""
        script = port_tag.findall("*/[@id='{}']".format(RdpExtraInfoExtraction.RDP_ENUM_ENCRYPTION))
        if len(script) > 0:
            output = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            if output:
                security_layer_section = False
                encryption_level_section = False
                protocol_version_section = False
                rdp_security_layers = []
                rdp_encryption_level = []
                rdp_protocol_version = []
                for line in output.split(os.linesep):
                    line = line.strip()
                    if line == "Security layer":
                        security_layer_section = True
                    elif line == "RDP Encryption level: Client Compatible":
                        security_layer_section = False
                        encryption_level_section = True
                    elif line == "RDP Protocol Version:":
                        security_layer_section = False
                        encryption_level_section = False
                        line = line.replace("RDP Protocol Version:", "").strip()
                        rdp_protocol_version.append(line)
                    elif security_layer_section:
                        rdp_security_layers.append(line)
                    elif encryption_level_section:
                        rdp_encryption_level.append(line)
                if rdp_security_layers:
                    self._domain_utils.add_additional_info(session=self._session,
                                                           name="RDP security layers",
                                                           values=rdp_security_layers,
                                                           source=self._source,
                                                           service=self._service,
                                                           report_item=self._report_item)
                if rdp_encryption_level:
                    self._domain_utils.add_additional_info(session=self._session,
                                                           name="RDP encryption layers",
                                                           values=rdp_encryption_level,
                                                           source=self._source,
                                                           service=self._service,
                                                           report_item=self._report_item)
                if rdp_protocol_version:
                    self._domain_utils.add_additional_info(session=self._session,
                                                           name="RDP protocol version",
                                                           values=rdp_protocol_version,
                                                           source=self._source,
                                                           service=self._service,
                                                           report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_ntlm_info(kwargs["port_tag"])
        self._extract_rdp_encryption(kwargs["port_tag"])


class TftpExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by TFTP service.
    """
    TFTP_ENUM = "tftp-enum"

    def __init__(self, session, service: Service, **args):
        super().__init__(session, service, **args)

    def _extract_tftp_paths(self, port_tag) -> None:
        """This method extracts the supported SMTP commands disclosed by the SMTP service"""
        script = port_tag.findall("*/[@id='{}']".format(TftpExtraInfoExtraction.TFTP_ENUM))
        if len(script) > 0:
            output = DatabaseImporter.get_xml_attribute("output", script[0].attrib)
            if output:
                for path_str in output.split(os.linesep):
                    path_str = path_str.strip()
                    self._domain_utils.add_path(session=self._session,
                                                service=self._service,
                                                path=path_str,
                                                path_type=PathType.FileSystem,
                                                source=self._source,
                                                report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_tftp_paths(kwargs["port_tag"])


class RpcInfoExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by RpcInfo service.
    """
    RPC_INFO = "rpcinfo"

    def __init__(self, session, service: Service, **args):
        super().__init__(session, service, **args)
        self._re_process = re.compile("^\s*\d+\s+[\d\,]+\s+(?P<port>\d+)/(?P<protocol>[a-zA-Z]*)\s+(?P<service>.*)$")
        self._source_rpc_info = Engine.get_or_create(self._session, Source, name=Source.RPCINFO)

    def _extract_rpc_info(self, port_tag) -> None:
        """This method determines additional services disclosed by rpcinfo"""
        script = port_tag.findall("*/[@id='{}']".format(RpcInfoExtraInfoExtraction.RPC_INFO))
        if len(script) > 0:
            tmp = DatabaseImporter.get_xml_attribute("output", script[0].attrib).split(os.linesep)
            for item in tmp:
                match = self._re_process.match(item)
                if match:
                    port = match.group("port")
                    protocol = match.group("protocol")
                    protocol = Service.get_protocol_type(protocol)
                    service_name = match.group("service")
                    service = self._domain_utils.add_service(session=self._session,
                                                             port=port,
                                                             protocol_type=protocol,
                                                             host=self._service.host,
                                                             state=ServiceState.Internal,
                                                             source=self._source_rpc_info,
                                                             report_item=self._report_item)
                    if service:
                        service.nmap_service_name = service_name if not service.nmap_service_name \
                            else service.nmap_service_name
                        service.state = ServiceState.Internal if service.state != ServiceState.Open else service.state

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_rpc_info(kwargs["port_tag"])


class CertInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by RpcInfo service.
    """
    CERT_INFO = "ssl-cert"

    def __init__(self, session, service: Service, **args):
        super().__init__(session, service, **args)

    def _extract_dns_info(self, port_tag) -> None:
        """This method determines additional services disclosed by rpcinfo"""
        script = port_tag.find("*/[@id='{}']".format(CertInfoExtraction.CERT_INFO))
        if script:
            pem_tag = script.find("./elem[@key='pem']")
            if not pem_tag and self._command:
                content = pem_tag.text
                self._domain_utils.add_certificate(session=self._session,
                                                   command=self._command,
                                                   content=content,
                                                   type=CertType.identity,
                                                   source=self._source,
                                                   report_item=self._report_item)

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_dns_info(kwargs["port_tag"])


class TlsInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information disclosed by RpcInfo service.
    """
    TLS_INFO = "ssl-enum-ciphers"

    def __init__(self, session, service: Service, **args):
        super().__init__(session, service, **args)

    def _get_elem_text(self, parent_tag, query: str) -> str:
        result = parent_tag.find(query)
        if result is not None:
            result = result.text
        return result

    def _extract_tls_info(self, port_tag) -> None:
        """This method determines additional services disclosed by rpcinfo"""
        script = port_tag.find("*/[@id='{}']".format(TlsInfoExtraction.TLS_INFO))
        if script:
            for tls_version_tag in script.findall("table"):
                order = 0
                tls_version_str = DatabaseImporter.get_xml_attribute("key", tls_version_tag.attrib)
                tls_version = TlsInfo.get_tls_version(tls_version_str)
                if tls_version:
                    preference_str = self._get_elem_text(tls_version_tag, query="elem[@key='cipher preference']")
                    preference = TlsInfo.get_tls_preference(preference_str)
                    if preference:
                        tls_info = self._domain_utils.add_tls_info(session=self._session,
                                                                   service=self._service,
                                                                   version=tls_version,
                                                                   preference=preference,
                                                                   report_item=self._report_item)
                        compressor_tag = tls_version_tag.find("table[@key='compressors']")
                        if compressor_tag is not None:
                            tls_info.compressors = [item.text for item in compressor_tag.findall("elem")
                                                    if item.text != 'NULL']
                        for cipher_tag in tls_version_tag.findall("table[@key='ciphers']"):
                            for table_tag in cipher_tag.findall("table"):
                                order += 1
                                kex_info = self._get_elem_text(table_tag, query="elem[@key='kex_info']")
                                kex_info = TlsInfoCipherSuiteMapping.get_kex_algorithm(kex_info, self._source)
                                if kex_info:
                                    tls_cipher = self._get_elem_text(table_tag, query="elem[@key='name']")
                                    self._domain_utils.add_tls_info_cipher_suite_mapping(session=self._session,
                                                                                         tls_info=tls_info,
                                                                                         order=order,
                                                                                         kex_algorithm_details=kex_info,
                                                                                         iana_name=tls_cipher,
                                                                                         source=self._source,
                                                                                         prefered=order == 1,
                                                                                         report_item=self._report_item)
                    else:
                        raise NotImplementedError("unknown TLS preference: {}".format(preference_str))
                else:
                    raise NotImplementedError("unknown TLS version: {}".format(tls_version_str))

    def extract(self, **kwargs):
        """This method extracts the required information."""
        self._extract_tls_info(kwargs["port_tag"])


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
                ipv4_address = DatabaseImporter.get_xml_attribute("ipaddr", hop_tag.attrib)
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


class DatabaseImporter(BaseDatabaseXmlImporter):
    """
    This class parses the Nmap scan results stored in XML format into the database for further analysis.
    """

    MSSQL_SERVICE_NAME = ["ms-sql-m", "ms-sql-s"]
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
        self._extraction_mappers = [ExtractionMapper(service_descriptor_classes=[collectors.os.modules.smb.core.SmbServiceDescriptor],
                                                     nmap_extractor_class=SmbExtraInfoExtraction),
                                    ExtractionMapper(service_descriptor_classes=[collectors.os.modules.mssql.core.MsSqlServiceDescriptor],
                                                     nmap_extractor_class=MsSqlExtraInfoExtraction),
                                    ExtractionMapper(service_descriptor_classes=[collectors.os.modules.http.core.HttpServiceDescriptor],
                                                     nmap_extractor_class=HttpExtraInfoExtraction),
                                    ExtractionMapper(service_descriptor_classes=[collectors.os.modules.email.core.SmtpServiceDescriptor],
                                                     nmap_extractor_class=SmtpExtraInfoExtraction),
                                    ExtractionMapper(service_descriptor_classes=[collectors.os.modules.rdp.core.RdpServiceDescriptor],
                                                     nmap_extractor_class=RdpExtraInfoExtraction),
                                    ExtractionMapper(service_descriptor_classes=[collectors.os.modules.rpc.core.RpcBindServiceDescriptor],
                                                     nmap_extractor_class=RpcInfoExtraInfoExtraction),
                                    ExtractionMapper(service_descriptor_classes=[collectors.os.modules.tls.core.TlsServiceDescriptor],
                                                     nmap_extractor_class=CertInfoExtraction,
                                                     tls_info=True),
                                    ExtractionMapper(service_descriptor_classes=[collectors.os.modules.tls.core.TlsServiceDescriptor],
                                                     nmap_extractor_class=TlsInfoExtraction,
                                                     tls_info=True),
                                    ExtractionMapper(nmap_extractor_class=TracerouteExtraction),
                                    ExtractionMapper(service_descriptor_classes=[collectors.os.modules.tftp.core.TftpServiceDescriptor],
                                                     nmap_extractor_class=TftpExtraInfoExtraction),
                                    ExtractionMapper(service_descriptor_classes=[collectors.os.modules.ssh.core.SshServiceDescriptor],
                                                     nmap_extractor_class=SshExtraInfoExtraction)]
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
                            self._domain_utils.add_additional_info(session=self._session,
                                                                   name="Nmap Extrainfo",
                                                                   values=[extra_info],
                                                                   source=source,
                                                                   service=service,
                                                                   report_item=self._report_item)
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
                        for mapper in self._extraction_mappers:
                            mapper.run_extraction(session=self._session,
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
