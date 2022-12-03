#!/usr/bin/env python3

"""
allows managing second-level domains
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
from database.model import ScopeType
from database.model import Workspace
from database.model import Source
from database.model import DomainName
from sqlalchemy.orm.session import Session
from .core import ManagerCommandBase


class Domain(ManagerCommandBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        parser = sub_parser.add_parser(self.name, help=__doc__.strip())
        parser.add_argument('DOMAIN', type=str, nargs="+")
        parser.add_argument("-w", "--workspace",
                            metavar="WORKSPACE",
                            help="use the given workspace",
                            required=True,
                            type=str)
        parser_group = parser.add_mutually_exclusive_group()
        parser_group.add_argument('-a', '--add',
                                  action="store_true",
                                  help="create the given second-level domain DOMAIN in workspace WORKSPACE")
        parser_group.add_argument('-A', '--Add',
                                  action="store_true",
                                  help="read the given second-level domain (one per line) from file DOMAIN and "
                                       "add them to workspace WORKSPACE")
        parser_group.add_argument('-d', '--delete',
                                  action="store_true",
                                  help="delete the given second-level domain DOMAIN together with all associated "
                                       "host names and email addresses from workspace WORKSPACE (use with caution)")
        parser_group.add_argument('-D', '--Delete',
                                  action="store_true",
                                  help="read the given second-level domain (one per line) from file DOMAIN and "
                                       "delete them together with all associated host names and emails from "
                                       "workspace WORKSPACE")
        parser.add_argument('-s', '--scope', choices=[item.name for item in ScopeType],
                            type=str,
                            help="set only the given domains in scope and exclude all other sub-domains (option "
                                 "explicit). set the given domains including all other sub-domains in scope "
                                 "(option all). set only those sub-domains (option vhost) in scope that resolve "
                                 "to an in-scope IP address. exclude the given domains (option exclude). "
                                 "including all other sub-domains from scope. note that KIS only actively "
                                 "collects information from in-scope second-level domain/host name",
                            default=ScopeType.all.name)
        parser.add_argument('-S', '--Scope', choices=[item.name for item in ScopeType],
                            type=str,
                            help="like argument --scope but read the second-level domains (one per line) from file "
                                 "DOMAIN")
        parser.add_argument("--source", metavar="SOURCE", type=str,
                            help="specify the source of the second-level-domains to be added")

    def _execute(self, args: argparse.Namespace, session: Session, workspace: Workspace, source: Source, **kwargs):
        """
        Executes the given subcommand.
        """
        scope = ScopeType[args.Scope] if args.Scope else args.scope
        for domain in self._get_items(args=args, name="DOMAIN"):
            domain = domain.strip()
            if args.add or args.Add:
                domain_object = self._domain_utils.add_sld(session=session,
                                                           workspace=workspace,
                                                           name=domain,
                                                           scope=scope,
                                                           source=source)
                if not domain_object:
                    raise ValueError("adding domain '{}' failed".format(domain))
            elif args.delete or args.Delete:
                self._domain_utils.delete_domain_name(session=session,
                                                      workspace=workspace,
                                                      domain_name=domain)
            elif args.scope or args.Scope:
                result = session.query(DomainName) \
                    .join(Workspace) \
                    .filter(Workspace.id == workspace.id, DomainName.name == domain).one_or_none()
                if not result:
                    raise ValueError("cannot set scope as second-level domain '{}' does not exist".format(domain))
                elif result.scope != scope:
                    result.scope = scope
