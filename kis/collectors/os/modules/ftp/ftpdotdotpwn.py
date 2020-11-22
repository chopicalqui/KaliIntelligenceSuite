# -*- coding: utf-8 -*-
"""
run tool dotdotpwn on each identified in-scope FTP service where access credentials are known to KIS. alternatively, use
optional arguments -u and -p to specify a user name and password. note, this collector only works in combination with
argument -S as dotdotpwn requires user interaction. argument -S prints the commands and then you have to execute them
manually
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
from collectors.os.modules.core import ServiceCollector
from collectors.os.modules.ftp.core import BaseFtpDotDotPwn
from database.model import Service
from database.model import CollectorName
from database.model import CredentialType
from collectors.os.modules.core import BaseCollector
from sqlalchemy.orm.session import Session
from typing import List

logger = logging.getLogger('ftpdotdotpwn')


class CollectorClass(BaseFtpDotDotPwn, ServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=9999,
                         timeout=0,
                         **kwargs)

    @staticmethod
    def get_argparse_arguments():
        return {"help": __doc__, "action": "store_true"}

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
        if service.host.version == 4 and self.match_nmap_service_name(service):
            if self._user and self._password:
                tmp = self._create_commands(session, service, collector_name, self._user, self._password)
                collectors.extend(tmp)
            else:
                for credential in service.credentials:
                    if credential.complete and credential.type == CredentialType.Cleartext:
                        tmp = self._create_commands(session,
                                                    service,
                                                    collector_name,
                                                    credential.username,
                                                    credential.password)
                        collectors.extend(tmp)
        return collectors
