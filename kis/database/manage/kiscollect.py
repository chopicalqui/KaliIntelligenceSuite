#!/usr/bin/env python3

"""
contains functionality used by kiscollect
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
from database.model import Workspace
from collectors.apis.shodan import ShodanHost
from collectors.apis.shodan import ShodanNetwork
from collectors.apis.censys import CensysIpv4
from collectors.apis.censys import CensysDomain
from collectors.apis.hunter import Hunter
from collectors.apis.securitytrails import SecurityTrails
from collectors.apis.haveibeenpwned import HaveIBeenPwnedBreachedAcccount
from collectors.apis.haveibeenpwned import HaveIBeenPwnedPasteAcccount
from collectors.apis.builtwith import BuiltWith
from collectors.apis.hostio import HostIo
from collectors.apis.burpsuite import BurpSuiteProfessional
from collectors.apis.virustotal import Virustotal
from collectors.apis.certspotter import Certspotter
from collectors.apis.crtsh import CrtshDomain
from collectors.apis.crtsh import CrtshCompany
from collectors.apis.viewdns import ViewDns
from sqlalchemy.orm.session import Session
from .core import ManagerCommandBase


class KisCollect(ManagerCommandBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_classes = {}
        self.file_classes = {}

    def add_api_query_argument(self, parser, argument_name: str, metavar: str, api_name: str, api_class: type):
        """
        This method is a helper to create consistent argument descriptions.
        """
        self.api_classes[argument_name.strip("-").replace("-", "_")] = api_class
        return parser.add_argument(argument_name, metavar=metavar, type=str,
                                   help='query information for the given IPv4 address from the {} API and '
                                        'add it to the given workspace (see argument -A or -w) in the KIS '
                                        'database. argument -O is mandatory and is used to store the raw '
                                        'data returned by the API in this output directory. this argument '
                                        'is usually only used by the script kiscollect'.format(api_name))

    def add_api_file_argument(self, parser, argument_name: str, source_argument: str, api_class: type):
        pass

    def add_all(self,
                parser,
                api_argument_name: str,
                file_argument_name: str,
                api_metavar: str,
                api_name: str,
                api_class: type):
        self.add_api_query_argument(parser=parser,
                                    argument_name=api_argument_name,
                                    metavar=api_metavar,
                                    api_name=api_name,
                                    api_class=api_class)
        self.add_api_file_argument(parser=parser,
                                   argument_name=file_argument_name,
                                   source_argument=api_argument_name,
                                   api_class=api_class)

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
        parser.add_argument('-O',
                            '--output-dir',
                            metavar='DIR',
                            required=True,
                            type=str,
                            help='output directory for storing intermediate results')
        parser.add_argument("--id",
                            metavar="ID",
                            required=True,
                            help="represents the internal database ID for the command that executes the command",
                            type=int)
        parser_group = parser.add_mutually_exclusive_group(required=True)
        self.add_all(parser=parser_group,
                     api_argument_name='--shodan-host',
                     file_argument_name='--shodan-host-files',
                     api_metavar='IP',
                     api_name='shodan.io',
                     api_class=ShodanHost)
        self.add_all(parser=parser_group,
                     api_argument_name='--shodan-network',
                     file_argument_name='--shodan-network-files',
                     api_metavar='NETWORK',
                     api_name='shodan.io',
                     api_class=ShodanNetwork)
        self.add_all(parser=parser_group,
                     api_argument_name='--censys-host',
                     file_argument_name='--censys-host-files',
                     api_metavar='IP',
                     api_name='censys.io',
                     api_class=CensysIpv4)
        self.add_all(parser=parser_group,
                     api_argument_name='--censys-domain',
                     file_argument_name='--censys-domain-files',
                     api_metavar='DOMAIN',
                     api_name='censys.io',
                     api_class=CensysDomain)
        self.add_all(parser=parser_group,
                     api_argument_name='--hunter',
                     file_argument_name='--hunter-files',
                     api_metavar='DOMAIN',
                     api_name='hunter.io',
                     api_class=Hunter)
        self.add_all(parser=parser_group,
                     api_argument_name='--securitytrails',
                     file_argument_name='--securitytrails-files',
                     api_metavar='DOMAIN',
                     api_name='securitytrails.com',
                     api_class=SecurityTrails)
        self.add_all(parser=parser_group,
                     api_argument_name='--haveibeenbreach',
                     file_argument_name='--haveibeenbreach-files',
                     api_metavar='EMAIL',
                     api_name='haveibeenpwned.com',
                     api_class=HaveIBeenPwnedBreachedAcccount)
        self.add_all(parser=parser_group,
                     api_argument_name='--haveibeenpaste',
                     file_argument_name='--haveibeenpaste-files',
                     api_metavar='EMAIL',
                     api_name='haveibeenpwned.com',
                     api_class=HaveIBeenPwnedPasteAcccount)
        self.add_all(parser=parser_group,
                     api_argument_name='--builtwith',
                     file_argument_name='--builtwith-files',
                     api_metavar='DOMAIN',
                     api_name='builtwith.com',
                     api_class=BuiltWith)
        self.add_all(parser=parser_group,
                     api_argument_name='--hostio',
                     file_argument_name='--hostio-files',
                     api_metavar='DOMAIN',
                     api_name='host.io',
                     api_class=HostIo)
        self.add_all(parser=parser_group,
                     api_argument_name='--virustotal',
                     file_argument_name='--virustotal-files',
                     api_metavar='DOMAIN',
                     api_name='virustotal.com',
                     api_class=Virustotal)
        self.add_all(parser=parser_group,
                     api_argument_name='--certspotter',
                     file_argument_name='--certspotter-files',
                     api_metavar='DOMAIN',
                     api_name='certspotter.com',
                     api_class=Certspotter)
        self.add_all(parser=parser_group,
                     api_argument_name='--crtshdomain',
                     file_argument_name='--crtshdomain-files',
                     api_metavar='DOMAIN',
                     api_name='crt.sh',
                     api_class=CrtshDomain)
        self.add_all(parser=parser_group,
                     api_argument_name='--crtshcompany',
                     file_argument_name='--crtshcompany-files',
                     api_metavar='DOMAIN',
                     api_name='crt.sh',
                     api_class=CrtshCompany)
        self.add_all(parser=parser_group,
                     api_argument_name='--reversewhois',
                     file_argument_name='--reversewhois-files',
                     api_metavar='COMPANY',
                     api_name='viewdns.info',
                     api_class=ViewDns)
        self.add_api_query_argument(parser_group,
                                    argument_name='--burpsuitepro',
                                    metavar='WEBSITE',
                                    api_name='Burp Suite Professional REST API',
                                    api_class=BurpSuiteProfessional)

    def _execute(self, args: argparse.Namespace, session: Session, workspace: Workspace, **kwargs):
        """
        Executes the given subcommand.
        """
        for name in self.api_classes:
            if name in args and getattr(args, name):
                api = self.api_classes[name](session=session,
                                             workspace=workspace,
                                             command_id=args.id)
                api.collect_api(getattr(args, name),
                                output_directory=args.output_dir)
        for name in self.file_classes:
            if name in args and getattr(args, name):
                api = self.api_classes[name](session=session,
                                             workspace=workspace,
                                             command_id=args.id)
                api.collect_filesystem(json_files=getattr(args, name),
                                       output_directory=args.output_dir)
