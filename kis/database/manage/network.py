#!/usr/bin/env python3

"""
allows managing networks
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
import ipaddress
from database.utils import Engine
from database.model import ScopeType
from database.model import Workspace
from database.model import Source
from sqlalchemy.orm.session import Session
from .core import ManagerCommandBase


class Network(ManagerCommandBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        parser = sub_parser.add_parser(self.name, help=__doc__.strip())
        parser.add_argument('NETWORK', type=str, nargs="+")
        parser.add_argument("-w", "--workspace",
                            metavar="WORKSPACE",
                            help="use the given workspace",
                            required=True,
                            type=str)
        parser_group = parser.add_mutually_exclusive_group()
        parser_group.add_argument('-a', '--add',
                                  action="store_true",
                                  help="create the given network NETWORK in workspace WORKSPACE")
        parser_group.add_argument('-A', '--Add',
                                  action="store_true",
                                  help="read the given networks (one per line) from file NETWORK and add them to "
                                       "workspace WORKSPACE")
        parser_group.add_argument('-d', '--delete',
                                  action="store_true",
                                  help="delete the given networks NETWORK together with all associated host "
                                       "information in workspace WORKSPACE (use with caution)")
        parser_group.add_argument('-D', '--Delete',
                                  action="store_true",
                                  help="read the given networks (one per line) from file NETWORK and delete them "
                                       "from workspace WORKSPACE. Note that only the given NETWORK but no "
                                       "associated host information is deleted")
        parser.add_argument('-s', '--scope', choices=[item.name for item in ScopeType],
                            type=str,
                            help="set only the given networks in scope and exclude all IP addresses (option "
                                 "explicit). set the given networks including all IP addresses in scope (option "
                                 "all). exclude the given networks including all IP addresses from scope. set "
                                 "only those IP addresses (option vhost) in scope to which an in-scope host "
                                 "name resolves to. note that KIS only actively collects information from "
                                 "in-scope hosts and networks",
                            default=ScopeType.all.name)
        parser.add_argument('-S', '--Scope', choices=[item.name for item in ScopeType],
                            type=str,
                            help="like argument --scope but read the networks (one per line) from file "
                                 "NETWORK")
        parser.add_argument('-c', '--create-hosts',
                            action="store_true",
                            help="add the given networks NETWORK to workspace WORKSPACE and add all IP "
                                 "addresses of these networks to hosts table")
        parser.add_argument("--source", metavar="SOURCE", type=str,
                            help="specify the source of the networks to be added")

    def _execute(self,
                 args: argparse.Namespace,
                 engine: Engine,
                 session: Session,
                 workspace: Workspace,
                 source: Source,
                 **kwargs):
        """
        Executes the given subcommand.
        """
        scope = ScopeType[args.Scope] if args.Scope else ScopeType[args.scope]
        for network in self._get_items(args=args, name="NETWORK"):
            if args.add or args.Add:
                ipv4_network = self._host_utils.add_network(session=session,
                                                            workspace=workspace,
                                                            network=network,
                                                            scope=scope,
                                                            source=source)
                if not ipv4_network:
                    raise ValueError("adding network '{}' failed".format(network))
            elif args.delete or args.Delete:
                self._host_utils.delete_network(session=session,
                                                workspace=workspace,
                                                network=network)
            elif args.scope or args.Scope:
                result = self._host_utils.get_network(session=session,
                                                      workspace=workspace,
                                                      network=network)
                if not result:
                    raise ValueError("cannot set scope as network '{}' does not exist".format(network))
                elif result.scope != scope:
                    result.scope = scope
            if args.create_hosts and not (args.delete or args.Delete):
                ipv4_network = self._host_utils.add_network(session=session,
                                                            workspace=workspace,
                                                            network=network,
                                                            scope=scope,
                                                            source=source)
                if not ipv4_network:
                    raise ValueError("adding network '{}' failed".format(network))
                for ipv4_address in ipaddress.ip_network(ipv4_network.network):
                    self._host_utils.add_host(session=session,
                                              workspace=workspace,
                                              address=str(ipv4_address),
                                              source=source)
