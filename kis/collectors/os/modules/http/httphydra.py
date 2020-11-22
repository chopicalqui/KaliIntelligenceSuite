# -*- coding: utf-8 -*-
"""
(INCOMPLETE) check given HTACCESS protected paths for known credentials using hydra. the option's argument is either -
or a list of paths. use options -p and -u; -P and -U; or -C to test for known user names and password. if the option's
value is -, then httphydra, searches the already identified paths for paths which have known default credentials
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

from typing import List
from collectors.os.modules.core import HostNameServiceCollector
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.core import BaseCollector
from database.model import Service
from database.model import CollectorName
from collectors.os.modules.http.core import BaseHttpHydra
from sqlalchemy.orm.session import Session


class CollectorClass(BaseHttpHydra, ServiceCollector, HostNameServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=91500,
                         timeout=0,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "type": str, "nargs": "*", "metavar": "PATHS"}

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
        if service.host_name.name:
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
        os_commands = []
        address = service.address
        if address and self.match_nmap_service_name(service):
            paths = self.get_commandline_argument_value("httphydra")
            module = "https-get" if service.nmap_tunnel == "ssl" else "http-get"
            if paths and "-" not in paths:
                for path in paths:
                    if path:
                        path = path if path[0] == '/' else "/{}".format(path)
                        tmp = self._create_commands(session,
                                                    service,
                                                    collector_name,
                                                    module,
                                                    self._user_file,
                                                    self._password_file,
                                                    self._combo_file,
                                                    self._user,
                                                    self._password,
                                                    hydra_module_argment=path)
                        os_commands.extend(tmp)
            else:
                for path in service.paths:
                    if path.name in ["/manager/html", "/manager/status", "/manager/html/", "/manager/status/"]:
                        tmp = self._create_commands(session,
                                                    service,
                                                    collector_name,
                                                    module,
                                                    self._apache_tomcat_default_users,
                                                    self._apache_tomcat_default_passwords,
                                                    hydra_module_argment=path.name)
                        os_commands.extend(tmp)
                    elif path.name in ['/xampp', '/xampp/']:
                        tmp = self._create_commands(session,
                                                    service,
                                                    collector_name,
                                                    module,
                                                    self._http_default_users,
                                                    self._http_default_passwords,
                                                    hydra_module_argment=path.name)
                        os_commands.extend(tmp)
                    elif path.name in ['/wp-login', '/wp-login/']:
                        pass
                    elif path.name in ['/phpmyadmin', '/phpMyAdmin', '/phpmyadmin/', '/phpMyAdmin/']:
                        pass
                    elif path.name in ['/webdav']:
                        pass
        return os_commands


