# -*- coding: utf-8 -*-
"""
run tool gobuster on each identified Apache, Apache Tomcat, Microsoft IIS, NetWare, Nginx, PHP, SAP, WebLogic, or
WebSphere web server using a webserver-specific wordlist to identify additional information.

for more information refer to argument --httpgobuster
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
from typing import List
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.http.httpgobuster import CollectorClass as HttpGoBuster
from collectors.os.modules.core import BaseCollector
from database.model import CollectorName
from database.model import Service
from database.model import CredentialType
from sqlalchemy.orm.session import Session

logger = logging.getLogger('httpgobustersmart')


class CollectorClass(HttpGoBuster, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._priority = 51110

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

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
        command = self._path_gobuster
        if self.match_nmap_service_name(service) and service.nmap_product:
            wordlists = []
            # https://www.shodan.io/search/facet?facet=product&query=websphere
            if "apache" in service.nmap_product.lower():
                wordlists.append(self._webserver_apache)
            if "IIS" in service.nmap_product:
                wordlists.append(self._webserver_microsoft_iis)
            if "NetWare" in service.nmap_product:
                wordlists.append(self._webserver_netware)
            if "nginx" in service.nmap_product.lower():
                wordlists.append(self._webserver_nginx)
            if "PHP" in service.nmap_product:
                wordlists.append(self._webserver_php)
            if "SAP" in service.nmap_product:
                wordlists.append(self._webserver_sap)
            if "Tomcat" in service.nmap_product:
                wordlists.append(self._webserver_apache_tomcat)
            if "WebLogic" in service.nmap_product:
                wordlists.append(self._webserver_weblogic)
            if "WebSphere" in service.nmap_product:
                wordlists.append(self._webserver_websphere)
            if wordlists:
                if not service.has_credentials:
                    tmp = self._get_commands(session,
                                             service,
                                             collector_name,
                                             command,
                                             wordlists,
                                             self._user,
                                             self._password,
                                             additional_arguments=["-d"])
                    collectors.extend(tmp)
                else:
                    for credential in service.credentials:
                        if credential.complete and credential.type == CredentialType.cleartext:
                            tmp = self._get_commands(session,
                                                     service,
                                                     collector_name,
                                                     command,
                                                     wordlists,
                                                     credential.username,
                                                     credential.password,
                                                     additional_arguments=["-d"])
                            collectors.extend(tmp)
        return collectors
