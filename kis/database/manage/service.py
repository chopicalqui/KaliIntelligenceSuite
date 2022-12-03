#!/usr/bin/env python3

"""
allows managing services
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2022 Lukas Reiter

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

import argparse
from database.model import HostNotFound
from database.model import Workspace
from database.model import Source
from database.model import ProtocolType
from database.model import ServiceState
from sqlalchemy.orm.session import Session
from .core import ManagerCommandBase


class Service(ManagerCommandBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        parser = sub_parser.add_parser(self.name, help=__doc__.strip())
        parser.add_argument("-w", "--workspace",
                                    metavar="WORKSPACE",
                                    help="use the given workspace",
                                    required=True,
                                    type=str)
        parser_group = parser.add_mutually_exclusive_group(required=True)
        parser_group.add_argument('-a', '--add',
                                  action="store_true",
                                  help="create the given service in workspace WORKSPACE")
        parser_group.add_argument('-d', '--delete',
                                  action="store_true",
                                  help="delete the given service from workspace WORKSPACE (use with caution)")
        parser.add_argument("--host",
                            metavar="IP",
                            nargs="+",
                            help="add the service to this host",
                            required=True,
                            type=str)
        parser.add_argument("--port",
                            metavar="PORT",
                            help="the service's port number",
                            required=True,
                            type=int)
        parser.add_argument("--protocol",
                            choices=[item.name for item in ProtocolType],
                            help="the service's layer 4 protocol",
                            required=True)
        parser.add_argument("--service-name",
                            type=str,
                            metavar="NMAP",
                            help="the nmap service name (refer to first column of file "
                                 "/usr/share/nmap/nmap-services)")
        parser.add_argument('--tls',
                            action="store_true",
                            help="if set, then the service uses TLS for secure communication")
        parser.add_argument("--source", metavar="SOURCE", type=str,
                            help="specify the source of the service to be added")

    def _execute(self, args: argparse.Namespace, session: Session, workspace: Workspace, source: Source, **kwargs):
        """
        Executes the given subcommand.
        """
        type = ProtocolType[args.protocol]
        for host in args.host:
            host = host.strip()
            host_object = self._host_utils.get_host(session=session,
                                                    workspace=workspace,
                                                    address=host)
            if not host_object:
                raise HostNotFound(host)
            if args.add:
                self._domain_utils.add_service(session=session,
                                               port=args.port,
                                               protocol_type=type,
                                               state=ServiceState.Open,
                                               host=host_object,
                                               nmap_service_name=args.service_name,
                                               nmap_service_confidence=10,
                                               nmap_tunnel="ssl" if args.tls else None,
                                               source=source)
            elif args.delete:
                self._domain_utils.delete_service(session=session,
                                                  port=args.port,
                                                  protocol_type=type,
                                                  host=host_object)
