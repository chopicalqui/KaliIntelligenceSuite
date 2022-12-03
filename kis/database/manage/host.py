#!/usr/bin/env python3

"""
allows managing hosts
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
from database.model import ReportScopeType
from database.model import Workspace
from database.model import Source
from sqlalchemy.orm.session import Session
from .core import ManagerCommandBase


class Host(ManagerCommandBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        parser = sub_parser.add_parser(self.name, help=__doc__.strip())
        parser.add_argument('IP', type=str, nargs="+")
        parser.add_argument("-w", "--workspace",
                            metavar="WORKSPACE",
                            help="use the given workspace",
                            required=True,
                            type=str)
        parser_group = parser.add_mutually_exclusive_group()
        parser_group.add_argument('-a', '--add',
                                  action="store_true",
                                  help="create the given host with IP address IP in workspace WORKSPACE")
        parser_group.add_argument('-A', '--Add',
                                  action="store_true",
                                  help="read the given IP addresses (one per line) from file IP and add them to "
                                       "workspace WORKSPACE")
        parser_group.add_argument('-d', '--delete',
                                  action="store_true",
                                  help="delete the given host with address IP together with all associated host "
                                       "information in workspace WORKSPACE (use with caution)")
        parser_group.add_argument('-D', '--Delete',
                                  action="store_true",
                                  help="read the given IP addresses (one per line) from file IP and delete them "
                                       "together with all associated host information from workspace WORKSPACE")
        parser.add_argument('-s', '--scope', choices=[item.name for item in ReportScopeType],
                            help="set the given hosts IP in or out of scope. note that KIS only "
                                 "actively collects information from in-scope hosts and networks ",
                            default=ReportScopeType.within.name)
        parser.add_argument('-S', '--Scope', choices=[item.name for item in ReportScopeType],
                            type=str,
                            help="like argument --scope but read the hosts (one per line) from file IP")
        parser.add_argument("--source", metavar="SOURCE", type=str,
                            help="specify the source of the hosts to be added")

    def _execute(self, args: argparse.Namespace, session: Session, workspace: Workspace, source: Source, **kwargs):
        """
        Executes the given subcommand.
        """
        scope = ReportScopeType[args.Scope] if args.Scope else ReportScopeType[args.scope]
        in_scope = scope == ReportScopeType.within
        for host in self._get_items(args=args, name="IP"):
            if args.add or args.Add:
                host_object = self._host_utils.add_host(session=session,
                                                        workspace=workspace,
                                                        address=host,
                                                        in_scope=in_scope,
                                                        source=source)
                if not host_object:
                    raise ValueError("adding host with IP address '{}' failed".format(host))
            elif args.delete or args.Delete:
                self._host_utils.delete_host(session=session,
                                             workspace=workspace,
                                             address=host)
            elif args.scope or args.Scope:
                result = self._host_utils.get_host(session=session, workspace=workspace, address=host)
                if not result:
                    raise ValueError("cannot set scope as host '{}' does not exist".format(host))
                result.in_scope = in_scope
            else:
                raise NotImplementedError()
