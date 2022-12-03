#!/usr/bin/env python3

"""
allows managing workspaces
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

import sys
import os
import json
import logging
import argparse
import traceback
import ipaddress
from database.utils import Engine
from database.utils import Setup
from database.utils import DeclarativeBase
from database.utils import CloneType
from database.model import HostNotFound
from database.model import ScopeType
from database.model import ReportScopeType
from database.model import WorkspaceNotFound
from database.model import Workspace
from database.model import Source
from database.model import DomainName
from database.model import ProtocolType
from database.model import ServiceState
from database.model import DomainNameNotFound
from database.model import DatabaseVersionMismatchError
from database.model import DatabaseUninitializationError
from collectors.core import IpUtils
from collectors.core import DomainUtils
from collectors.filesystem.nmap import DatabaseImporter as NmapDatabaseImporter
from collectors.filesystem.nessus import DatabaseImporter as NessusDatabaseImporter
from collectors.filesystem.masscan import DatabaseImporter as MasscanDatabaseImporter
from collectors.apis.core import ApiCollectionFailed
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
from database.config import BaseConfig
from database.config import SortingHelpFormatter
from sqlalchemy.orm.session import Session
from typing import List
from .core import ManagerCommandBase


class Workspace(ManagerCommandBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        choices = [item.name.replace("_", "-") for item in CloneType]
        choices.remove(CloneType.host_hostname_mappings.name.replace("_", "-"))
        parser = sub_parser.add_parser(self.name, help=__doc__.strip())
        parser.add_argument('WORKSPACE', type=str, nargs="+")
        parser_group = parser.add_mutually_exclusive_group(required=True)
        parser_group.add_argument('-a', '--add',
                                  action="store_true",
                                  help="create the given workspace WORKSPACE in KIS database")
        parser_group.add_argument('-d', '--delete',
                                  action="store_true",
                                  help="delete the given workspace WORKSPACE together with all associated "
                                       "information from KIS database (use with caution)")
        parser_group.add_argument('-c', '--clone',
                                  type=str,
                                  help="the source workspace that shall be cloned")
        parser.add_argument('-t', '--tables',
                            nargs="*",
                            type=str,
                            default=choices,
                            choices=[item.name.replace("_", "-") for item in CloneType],
                            help="list of tables that shall be cloned into the new workspace")
        parser.add_argument('-s', '--source',
                            type=str,
                            help="the source workspace that shall be cloned")

    def _execute(self, args: argparse.Namespace, engine: Engine, session: Session, **kwargs):
        """
        Executes the given subcommand.
        """
        if args.add:
            for item in args.WORKSPACE:
                self._domain_utils.add_workspace(session, item)
        elif args.delete:
            for item in args.WORKSPACE:
                self._domain_utils.delete_workspace(session, item)
        elif args.clone:
            clone_types = [CloneType[item.replace("-", "_")] for item in args.tables]
            for item in args.WORKSPACE:
                engine.clone_workspace(source_workspace_str=args.clone,
                                       destination_workspace_str=item,
                                       clone_types=clone_types)
