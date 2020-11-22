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
from collectors.filesystem.nmap import BaseExtraServiceInfoExtraction
from database.model import CollectorName
from database.model import Service
from sqlalchemy.orm.session import Session


class HttpServiceDescriptor(ServiceDescriptorBase):
    """This class describes how an HTTP service looks like"""

    def __init__(self):
        super().__init__(default_tcp_ports=[80, 443],
                         nmap_tcp_service_names=["^ssl\|http$",
                                                 "^http$",
                                                 "^http-alt$",
                                                 "^https$",
                                                 "^http\-proxy$",
                                                 "^sgi-soap$",
                                                 "^caldav$"],
                         nessus_tcp_service_names=["^www$",
                                                   "^http\-alt$",
                                                   "^http$",
                                                   "^https$",
                                                   "^pcsync-https$",
                                                   "^homepage$",
                                                   "^greenbone-administrator$",
                                                   "^openvas-administrator$"])


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
                              '-q',
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
