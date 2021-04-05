# -*- coding: utf-8 -*-
"""
implements all base functionality for HTTP collectors
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
import os
from typing import List
from collectors.os.modules.core import CommandFailureRule
from collectors.os.modules.core import OutputType
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import BaseMsfConsole
from collectors.os.modules.core import BaseEyeWitness
from collectors.os.modules.core import BaseChangeme
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import BaseDotDotPwn
from collectors.os.modules.core import ServiceDescriptorBase
from collectors.os.modules.core import BaseExtraServiceInfoExtraction
from database.utils import Engine
from database.model import CollectorName
from database.model import Service
from database.model import Source
from database.model import PathType
from collectors.core import XmlUtils
from sqlalchemy.orm.session import Session
from urllib.parse import unquote
from urllib.parse import urlparse


class HttpServiceDescriptor(ServiceDescriptorBase):
    """This class describes how an HTTP service looks like"""

    def __init__(self):
        super().__init__(default_tcp_ports=[80, 443],
                         # If you update this list, then you also have to update the last part of database function: assign_services_to_host_name
                         nmap_tcp_service_names=["^ssl\|http$",
                                                 "^http$",
                                                 "^http\-alt$",
                                                 "^https$",
                                                 "^http\-proxy$",
                                                 "^sgi-soap$",
                                                 "^caldav$"],
                         # If you update this list, then you also have to update the last part of database function: assign_services_to_host_name
                         nessus_tcp_service_names=["^www$",
                                                   "^http\-alt$",
                                                   "^http$",
                                                   "^https$",
                                                   "^pcsync\-https$",
                                                   "^homepage$",
                                                   "^greenbone\-administrator$",
                                                   "^openvas\-administrator$"])


class BaseHttpCollector(BaseCollector):
    """
    This is the base class for all HTTP collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=HttpServiceDescriptor(),
                         **kwargs)


class BaseHttpHydra(BaseHydra):
    """
    This class implements basic functionality for HTTP collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=HttpServiceDescriptor(),
                         **kwargs)


class BaseHttpEyewitness(BaseEyeWitness):
    """
    This class implements basic functionality for HTTP collectors that use Eyewitness.
    """
    def __init__(self, priority,
                 timeout,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=HttpServiceDescriptor(),
                         **kwargs)


class BaseHttpChangeme(BaseChangeme):
    """
    This class implements basic functionality for HTTP collectors that use changeme.
    """
    def __init__(self, priority,
                 timeout,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=HttpServiceDescriptor(),
                         **kwargs)


class BaseHttpMsfConsole(BaseMsfConsole):
    """
    This class implements basic functionality for HTTP collectors that use changeme.
    """
    def __init__(self, priority,
                 timeout,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=HttpServiceDescriptor(),
                         **kwargs)


class BaseHttpNmap(BaseNmap):
    """
    This class implements basic functionality for HTTP collectors that use Nmap.
    """
    def __init__(self, priority,
                 timeout,
                 nmap_xml_extractor_classes: List[BaseExtraServiceInfoExtraction],
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=HttpServiceDescriptor(),
                         nmap_xml_extractor_classes=nmap_xml_extractor_classes,
                         **kwargs)


class BaseHttpDotDotPwn(BaseDotDotPwn):
    """
    This class implements basic functionality for HTTP collectors that use Dotdotpwn.
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=HttpServiceDescriptor(),
                         module="http",
                         **kwargs)


class BaseHttpGoBuster(BaseHttpCollector):
    """
    This class implements basic functionality for GoBuster web collectors
    """

    def __init__(self, mode: str, **kwargs):
        super().__init__(**kwargs)
        self._mode = mode

    @staticmethod
    def get_invalid_argument_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify invalid arguments
        """
        return [re.compile("^\s*Error: unknown flag: (?P<argument>.+?)\s*$", re.IGNORECASE),
                re.compile("^\s*Error: unknown shorthand flag: '.+?' in (?P<argument>.+?)\s*$", re.IGNORECASE)]

    @staticmethod
    def get_service_unreachable_regex() -> List[re.Pattern]:
        """
        This method returns a regular expression that allows KIS to identify services that are not reachable
        """
        return [re.compile("^\s*Error: error on running ((goubster)|(gobuster)): unable to connect to.*$",
                           re.IGNORECASE)]

    @staticmethod
    def get_failed_regex() -> List[CommandFailureRule]:
        """
        This method returns regular expressions that allows KIS to identify failed command executions
        """
        return [CommandFailureRule(regex=re.compile("^Error: error on running ((goubster)|(gobuster)): unable to connect to.*$"),
                                   output_type=OutputType.stderr),
                CommandFailureRule(regex=re.compile("^.*Error: the server returns a status code that matches the "
                                                    "provided options for non existing urls.*$"),
                                   output_type=OutputType.stderr)]

    def _get_commands(self,
                      session: Session,
                      service: Service,
                      collector_name: CollectorName,
                      command: str,
                      wordlists: List[str],
                      user: str = None,
                      password: str = None,
                      additional_arguments: List[str] = []) -> List[BaseCollector]:
        """Returns a list of commands based on the provided information."""
        collectors = []
        url = service.get_urlparse()
        number_threads = 1 if self._delay.sleep_active() else 10
        if url:
            for wordlist in wordlists:
                if not os.path.isfile(wordlist):
                    raise FileNotFoundError("word list '{}' does not exist!".format(wordlist))
                os_command = [command,
                              self._mode,
                              '-z',
                              '-t', number_threads,
                              '-w', wordlist]
                os_command += additional_arguments
                # Add additional settings, if available
                if self._user_agent:
                    os_command.extend(['-a', '{}'.format(self._user_agent)])
                else:
                    os_command.extend(['-a', '{}'.format(self._default_user_agent_string)])
                if self._cookies:
                    os_command.extend(['-c', "; ".join(self._cookies)])
                else:
                    os_command.append("-k")
                if self._http_proxy:
                    os_command.extend(['-p', self.http_proxy.geturl()])
                if user:
                    os_command.extend(['-U', user])
                if password:
                    os_command.extend(['-P', password])
                os_command += ['-u', service.get_urlparse().geturl()]
                collector = self._get_or_create_command(session, os_command, collector_name, service=service)
                collectors.append(collector)
        return collectors


class HttpExtraInfoExtraction(BaseExtraServiceInfoExtraction):
    """
    This class extracts extra information from MS-SQL services.
    """
    HTTP_METHODS = "http-methods"
    ROBOTS_TXT = "http-robots.txt"
    WEB_PATHS = "web-paths"
    HTTP_TITLE = "http-title"
    HTTP_HEADERS = "http-headers"
    HTTP_SERVER_HEADER = "http-server-header"
    HTTP_AUTH_FINDER = "http-auth-finder"
    HTTP_BACKUP_FINDER = "http-backup-finder"
    HTTP_COMMENTS_DISPLAYER = "http-comments-displayer"
    HTTP_NTLM_INFO = "http-ntlm-info"
    HTTP_ENUM = "http-enum"
    HTTP_SECURITY_HEADERS = "http-security-headers"

    def __init__(self, session: Session, service: Service, **args):
        super().__init__(session, service, **args)
        self._re_http_auth_finder = re.compile("^\s*(?P<url>https?://.*?)\s+[A-Z].*$", re.IGNORECASE)
        self._re_http_backup_finder = re.compile("^\s*(?P<url>https?://.*?)$", re.IGNORECASE)
        self._re_comments_displayer_path = re.compile("^\s*Path:\s*(?P<url>https?://.*?)$", re.IGNORECASE)
        self._re_http_enum = re.compile("^\s*(?P<path>.+?):.*$")
        self._re_location = re.compile("^\s+Location:\s*(?P<value>.+)\s*$", re.IGNORECASE | re.M)
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
            output = XmlUtils.get_xml_attribute("output", script[0].attrib)
            if output:
                self._domain_utils.add_additional_info(session=self._session,
                                                       name="HTTP title",
                                                       values=[output],
                                                       source=self._source,
                                                       service=self._service,
                                                       report_item=self._report_item)
                host_names = self._domain_utils.extract_domains(unquote(output))
                for host_name in host_names:
                    self._domain_utils.add_domain_name(session=self._session,
                                                       workspace=self._workspace,
                                                       item=host_name,
                                                       source=self._source,
                                                       verify=True,
                                                       report_item=self._report_item)

    def _extract_http_server_header(self, port_tag: str) -> None:
        """This method extracts the HTTP title"""
        script = port_tag.findall("*/[@id='{}']".format(HttpExtraInfoExtraction.HTTP_SERVER_HEADER))
        if len(script) > 0:
            output = XmlUtils.get_xml_attribute("output", script[0].attrib)
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
            output = XmlUtils.get_xml_attribute("output", script[0].attrib)
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
            output = XmlUtils.get_xml_attribute("output", script[0].attrib)
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
            output = XmlUtils.get_xml_attribute("output", script[0].attrib)
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
            output = XmlUtils.get_xml_attribute("output", script[0].attrib)
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
            output = XmlUtils.get_xml_attribute("output", script[0].attrib)
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

    def _extract_http_headers(self, port_tag):
        """This method extracts information from HTTP headers."""
        for script_tag in port_tag.findall("script/[@id='{}']".format(HttpExtraInfoExtraction.HTTP_HEADERS)):
            output = XmlUtils.get_xml_attribute("output", script_tag.attrib)
            locations = [item.strip() for item in self._re_location.findall(output)]
            if locations:
                self._domain_utils.add_additional_info(session=self._session,
                                                       name="HTTP Header Location",
                                                       values=locations,
                                                       source=self._source,
                                                       service=self._service,
                                                       report_item=self._report_item)
                for location in locations:
                    url = urlparse(location)
                    if url.netloc:
                        self._domain_utils.add_domain_name(session=self._session,
                                                           workspace=self._workspace,
                                                           item=url.netloc,
                                                           source=self._source,
                                                           verify=True,
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
        self._extract_http_headers(kwargs["port_tag"])
