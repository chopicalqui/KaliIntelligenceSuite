# -*- coding: utf-8 -*-
"""
run tool nmap on each identified in-scope SMB services to query an MSRPC endpoint mapper for a list of mapped services.
if credentials for SMB authentication are known to KIS, then they will be automatically used. alternatively, use
optional arguments -u, -p, and -d to provide a user name, a password/NTLM hash, and domain/workgroup for authentication
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
from collectors.os.modules.core import BaseCollector
from collectors.os.modules.smb.core import BaseSmbNmap
from collectors.os.modules.smb.core import SmbExtraInfoExtraction
from database.model import Service
from database.model import CollectorName
from database.model import CredentialType
from sqlalchemy.orm.session import Session

logger = logging.getLogger('msrpcenum')


class CollectorClass(BaseSmbNmap, ServiceCollector):
    """This class implements a collector module that is automatically incorporated into the application."""

    def __init__(self, **kwargs):
        super().__init__(priority=2750,
                         timeout=0,
                         nmap_xml_extractor_classes=[SmbExtraInfoExtraction],
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
        if self.match_nmap_service_name(service):
            nse_scripts = ["msrpc-enum"]
            if not service.has_credentials:
                arguments = self.create_credential_argument(username=self._user,
                                                            password=self._password,
                                                            domain=self._domain,
                                                            credential_type=CredentialType.Hash if self._hashes else
                                                            CredentialType.Cleartext)
                collectors = self._create_commands(session,
                                                   service,
                                                   collector_name,
                                                   nse_scripts=nse_scripts,
                                                   nse_script_arguments=arguments)
            else:
                for item in service.credentials:
                    if item.complete:
                        arguments = self.create_credential_argument(username=item.username,
                                                                    password=item.password,
                                                                    domain=item.domain,
                                                                    credential_type=item.type)
                        collectors.append(self._create_commands(session,
                                                                service,
                                                                collector_name,
                                                                nse_scripts=nse_scripts,
                                                                nse_script_arguments=arguments))
        return collectors

