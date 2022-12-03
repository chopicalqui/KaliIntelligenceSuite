#!/usr/bin/env python3

"""
allows managing host names (sub-domains of second-level domains)
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

import json
import argparse
from database.model import ReportScopeType
from database.model import Workspace
from database.model import Source
from database.model import DomainNameNotFound
from sqlalchemy.orm.session import Session
from .core import ManagerCommandBase


class HostName(ManagerCommandBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        parser = sub_parser.add_parser(self.name, help=__doc__.strip())
        parser.add_argument('HOSTNAME', type=str, nargs="+")
        parser.add_argument("-w", "--workspace",
                            metavar="WORKSPACE",
                            help="use the given workspace",
                            required=True,
                            type=str)
        parser_group = parser.add_mutually_exclusive_group()
        parser_group.add_argument('-a', '--add',
                                  action="store_true",
                                  help="create the given host name in workspace WORKSPACE")
        parser_group.add_argument('-A', '--Add',
                                  action="store_true",
                                  help="read the given host names (one per line) from file HOSTNAME and add "
                                       "them to workspace WORKSPACE")
        parser_group.add_argument('-d', '--delete',
                                  action="store_true",
                                  help="delete the given host name HOSTNAME together with all associated email "
                                       "addresses in workspace WORKSPACE (use with caution)")
        parser_group.add_argument('-D', '--Delete',
                                  action="store_true",
                                  help="read the given host names (one per line) from file HOSTNAME and delete "
                                       "them together with all associated email addresses from workspace "
                                       "WORKSPACE")
        parser_group.add_argument('--sharphound',
                                  action="store_true",
                                  help="read the given computer.json file created by sharphound and import all "
                                       "computer names into KIS for further intel collection")
        parser.add_argument('-s', '--scope', choices=[item.name for item in ReportScopeType],
                            help="set the given host names HOSTNAME in or out of scope. note that KIS only "
                                 "actively collects information from in-scope host names",
                            default=ReportScopeType.within.name)
        parser.add_argument('-S', '--Scope', choices=[item.name for item in ReportScopeType],
                            type=str,
                            help="like argument --scope but read the hosts (one per line) from file HOSTNAME")
        parser.add_argument("--source", metavar="SOURCE", type=str,
                            help="specify the source of the host name to be added")

    def _execute(self, args: argparse.Namespace, session: Session, workspace: Workspace, source: Source, **kwargs):
        """
        Executes the given subcommand.
        """
        scope = ReportScopeType[args.scope]
        in_scope = scope == ReportScopeType.within
        exception_thrown = None
        for host_name_str in self._get_items(args=args, name="HOSTNAME"):
            host_name_str = host_name_str.strip()
            if args.add or args.Add:
                try:
                    host_name = self._domain_utils.add_host_name(session=session,
                                                                 workspace=workspace,
                                                                 name=host_name_str,
                                                                 in_scope=in_scope,
                                                                 source=source)
                    if not host_name:
                        raise ValueError("adding host name '{}' failed".format(host_name_str))
                except DomainNameNotFound as ex:
                    if args.debug:
                        domain_name_str = self._domain_utils.extract_domain_name_from_host_name(name=host_name_str)
                        print(domain_name_str)
                        exception_thrown = ex
                    else:
                        raise ex
            elif args.sharphound:
                for host_name_str in self._get_items(args=args, name="HOSTNAME"):
                    host_name_str = host_name_str.strip()
                    with open(host_name_str, "rb") as file:
                        json_object = json.loads(file.read())
                        if "computers" in json_object and isinstance(json_object["computers"], list):
                            source = self._domain_utils.add_source(session=session, name="sharphound")
                            for item in json_object["computers"]:
                                if "Properties" in item and "name" in item["Properties"]:
                                    computer_name = item["Properties"]["name"]
                                    try:
                                        host_name = self._domain_utils.add_host_name(session=session,
                                                                                     workspace=workspace,
                                                                                     name=computer_name,
                                                                                     in_scope=in_scope,
                                                                                     source=source)
                                        if not host_name:
                                            raise ValueError("adding host name '{}' failed".format(item))
                                    except DomainNameNotFound as ex:
                                        if args.debug:
                                            domain_name_str = self._domain_utils.extract_domain_name_from_host_name(
                                                name=computer_name)
                                            print(domain_name_str)
                                            exception_thrown = ex
                                        else:
                                            raise ex
                                else:
                                    raise KeyError("invalid sharphound computer file. file does not contain "
                                                   "attribute 'Properties' and/or 'name'")
                        else:
                            raise KeyError("invalid sharphound computer file. file does not contain "
                                           "attribute 'computers'")
                if exception_thrown:
                    raise exception_thrown
            elif args.delete or args.Delete:
                self._domain_utils.delete_host_name(session=session,
                                                    workspace=workspace,
                                                    host_name=host_name_str)
            else:
                result = self._domain_utils.get_host_name(session=session,
                                                          workspace=workspace,
                                                          host_name=host_name_str)
                if not result:
                    raise ValueError("cannot set scope as host name '{}' does not exist".format(host_name_str))
                elif result._in_scope != in_scope:
                    result._in_scope = in_scope
        if exception_thrown:
            raise exception_thrown
