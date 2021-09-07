# -*- coding: utf-8 -*-
"""
run tool eyewitness on each identified in-scope HTTP(S) service path to create screenshots. use optional argument
--user-agent to specify a different user agent string or optional argument --http-proxy to specify an HTTP proxy
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

import os
import re
from typing import List
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import CommandFailureRule
from collectors.os.modules.core import OutputType
from collectors.os.modules.http.core import BaseHttpEyewitness
from collectors.os.modules.core import BaseCollector
from database.model import Service
from database.model import CollectorName
from sqlalchemy.orm.session import Session


class CollectorClass(BaseHttpEyewitness, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=100100,
                         timeout=3600,
                         max_threads=5,
                         exec_user="kali",
                         file_extension="png",
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

    @staticmethod
    def get_failed_regex() -> List[CommandFailureRule]:
        """
        This method returns regular expressions that allows KIS to identify failed command executions
        """
        return [CommandFailureRule(regex=re.compile("^Message: connection refused$"),
                                   output_type=OutputType.stdout),
                CommandFailureRule(regex=re.compile("^\[\*\] WebDriverError when connecting to.*$"),
                                   output_type=OutputType.stdout),
                CommandFailureRule(regex=re.compile("^sqlite3.DatabaseError: database disk image is malformed$"),
                                   output_type=OutputType.stderr)]

    def create_host_name_service_commands(self,
                                          session: Session,
                                          service: Service,
                                          collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given host name.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        result = []
        if service.host_name.name or self._scan_tld:
            result = self.create_service_commands(session, service, collector_name)
        return result

    def create_service_commands(self,
                                session: Session,
                                service: Service,
                                collector_name: CollectorName) -> List[BaseCollector]:
        """This method creates and returns a list of commands based on the given service.

        This method determines whether the command exists already in the database. If it does, then it does nothing,
        else, it creates a new Collector entry in the database for each new command as well as it creates a corresponding
        operating system command and attaches it to the respective newly created Collector class.

        :param session: Sqlalchemy session that manages persistence operations for ORM-mapped objects
        :param service: The service based on which commands shall be created.
        :param collector_name: The name of the collector as specified in table collector_name
        :return: List of Collector instances that shall be processed.
        """
        collectors = []
        command = self._path_eyewitness
        address = service.address
        if not os.path.isfile(command):
            raise FileNotFoundError("Command '{}' does not exist!".format(command))
        if address and self.match_nmap_service_name(service):
            url = service.get_urlparse()
            service_paths = [url.geturl()] if url else []
            for path in service.paths:
                url = path.get_urlparse()
                if url:
                    service_paths.append(url.geturl())
                    service_paths.extend([item.geturl() for item in path.get_queries()])
            if service_paths:
                output_path = self.create_path(service=service, sub_directory="output", create_new=True)
                if self._user_agent:
                    arguments = ['--user-agent', '{}'.format(self._user_agent)]
                else:
                    arguments = ['--user-agent', '{}'.format(self._default_user_agent_string)]
                if self._http_proxy:
                    proxy_ip, proxy_port = self._http_proxy.netloc.split(":")
                    arguments += ['--proxy-ip', proxy_ip,
                                  '--proxy-port', proxy_port]
                elif self._eyewitness_proxy_ip and self._eyewitness_proxy_port:
                    arguments += ['--proxy-ip', self._eyewitness_proxy_ip,
                                  '--proxy-port', self._eyewitness_proxy_port]
                if len(service_paths) > 1:
                    tool_path = self.create_path(service=service)
                    input_file = os.path.join(tool_path, "paths.txt")
                    with open(input_file, "w") as f:
                        for url in service_paths:
                            f.write(url + os.linesep)
                    collector = self._create_commands(session,
                                                      service,
                                                      collector_name,
                                                      "--web",
                                                      output_path=output_path,
                                                      options=arguments,
                                                      input_file=input_file)
                else:
                    collector = self._create_commands(session,
                                                      service,
                                                      collector_name,
                                                      "--web",
                                                      output_path=output_path,
                                                      options=arguments,
                                                      url_str=service_paths[0])
                collectors += collector
        return collectors
