#!/usr/bin/env python3

"""
allows managing companies
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


class Company(ManagerCommandBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        parser = sub_parser.add_parser(self.name, help=__doc__.strip())
        parser.add_argument('COMPANY', type=str, nargs="+")
        parser.add_argument("-w", "--workspace",
                            metavar="WORKSPACE",
                            help="use the given workspace",
                            required=True,
                            type=str)
        parser_group = parser.add_mutually_exclusive_group()
        parser_group.add_argument('-a', '--add',
                                  action="store_true",
                                  help="create the given company COMPANY in workspace WORKSPACE")
        parser_group.add_argument('-A', '--Add',
                                  action="store_true",
                                  help="read the given company names (one per line) from file COMPANY and add them to "
                                       "workspace WORKSPACE")
        parser_group.add_argument('-d', '--delete',
                                  action="store_true",
                                  help="delete the given company COMPANY from workspace WORKSPACE "
                                       "(use with caution)")
        parser_group.add_argument('-D', '--Delete',
                                  action="store_true",
                                  help="read the given company names (one per line) from file COMPANY and delete them "
                                       "from workspace WORKSPACE")
        parser.add_argument('--network',
                            type=str,
                            nargs="+",
                            metavar="NETWORK",
                            help="assign the company COMPANY to the given network NETWORK")
        parser.add_argument('--Network',
                            type=str,
                            nargs="+",
                            metavar="NETWORK",
                            help="read the given networks (one per line) from file NETWORK and add them to "
                                 "the company COMPANY")
        parser.add_argument('--domain',
                            type=str,
                            nargs="+",
                            metavar="DOMAIN",
                            help="assign the company COMPANY to the given domain DOMAIN")
        parser.add_argument('--Domain',
                            type=str,
                            nargs="+",
                            metavar="DOMAIN",
                            help="read the given domains (one per line) from file DOMAIN and add them to "
                                 "the company COMPANY")
        parser_scope_group = parser.add_mutually_exclusive_group()
        parser_scope_group.add_argument('-s', '--scope', choices=[item.name for item in ReportScopeType],
                                        help="set the given company COMPANY in or out of scope. note that KIS only "
                                             "actively collects information from in-scope hosts and networks")
        parser_scope_group.add_argument('-S', '--Scope', choices=[item.name for item in ReportScopeType],
                                        type=str,
                                        help="like argument --scope but read the hosts (one per line) from file COMPANY")
        parser.add_argument("--source", metavar="SOURCE", type=str,
                            help="specify the source of the company to be added")
        parser.add_argument("--verified",
                            action="store_true",
                            help="specifies whether the link between the company and the specified network/domain has"
                                 "been manually verified and confirmed.")

    def _execute(self, args: argparse.Namespace, session: Session, workspace: Workspace, source: Source, **kwargs):
        """
        Executes the given subcommand.
        """
        in_scope = None
        if args.Scope:
            in_scope = ReportScopeType[args.Scope] == ReportScopeType.within
        elif args.scope:
            in_scope = ReportScopeType[args.scope] == ReportScopeType.within
        for company in self._get_items(args=args, name="COMPANY"):
            company_object = None
            if args.add or args.Add:
                company_object = self._domain_utils.add_company(session=session,
                                                                workspace=workspace,
                                                                name=company,
                                                                in_scope=in_scope,
                                                                source=source,
                                                                verify=False)
                if not company_object:
                    raise ValueError("adding company '{}' failed".format(company))
            elif args.delete or args.Delete:
                self._domain_utils.delete_company(session=session,
                                                  workspace=workspace,
                                                  name=company)
                continue
            elif in_scope:
                result = self._domain_utils.get_company(session=session, workspace=workspace, name=company)
                if not result:
                    raise ValueError("cannot set scope as company '{}' does not exist".format(company))
                result.in_scope = in_scope
                continue
            if "network" in args and args.network:
                company_object = company_object if company_object else self._domain_utils.get_company(session=session,
                                                                                                      workspace=workspace,
                                                                                                      name=company)
                for network in args.network:
                    network_object = self._host_utils.get_network(session=session,
                                                                  workspace=workspace,
                                                                  network=network)
                    if not network_object:
                        raise ValueError("could not find network '{}' in database".format(network))
                    self._domain_utils.add_company_network_mapping(session=session,
                                                                   company=company_object,
                                                                   network=network_object,
                                                                   source=source,
                                                                   verified=args.verified)
            if "Network" in args and args.Network:
                company_object = company_object if company_object else self._domain_utils.get_company(session=session,
                                                                                                      workspace=workspace,
                                                                                                      name=company)
                for network in self._get_items(args=args, name="Network"):
                    network_object = self._host_utils.get_network(session=session,
                                                                  workspace=workspace,
                                                                  network=network)
                    if not network_object:
                        raise ValueError("could not find network '{}' in database".format(network))
                    self._domain_utils.add_company_network_mapping(session=session,
                                                                   company=company_object,
                                                                   network=network_object,
                                                                   source=source,
                                                                   verified=args.verified)
            if "domain" in args and args.domain:
                company_object = company_object if company_object else self._domain_utils.get_company(session=session,
                                                                                                      workspace=workspace,
                                                                                                      name=company)
                for domain in args.domain:
                    host_name_object = self._domain_utils.get_host_name(session=session,
                                                                        workspace=workspace,
                                                                        host_name=domain)
                    if not host_name_object:
                        raise ValueError("could not find domain '{}' in database".format(domain))
                    self._domain_utils.add_company_domain_name_mapping(session=session,
                                                                       company=company_object,
                                                                       host_name=host_name_object,
                                                                       source=source,
                                                                       verified=args.verified)
            if "Domain" in args and args.Domain:
                company_object = company_object if company_object else self._domain_utils.get_company(session=session,
                                                                                                      workspace=workspace,
                                                                                                      name=company)
                for domain in self._get_items(args=args, name="Domain"):
                    host_name_object = self._domain_utils.get_host_name(session=session,
                                                                        workspace=workspace,
                                                                        host_name=domain)
                    if not host_name_object:
                        raise ValueError("could not find domain '{}' in database".format(domain))
                    self._domain_utils.add_company_domain_name_mapping(session=session,
                                                                       company=company_object,
                                                                       host_name=host_name_object,
                                                                       source=source,
                                                                       verified=args.verified)
