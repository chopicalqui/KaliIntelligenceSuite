#!/usr/bin/env python3

"""
this script implements all functionalities to set up and manage the PostgreSql database. it allows performing the
initial setup; creating and restoring PostgreSql database backups as well as adding and deleting workspaces, networks,
IP addresses, second-level domains/host names, and emails. kismanage is also used by kiscollect to query APIs like
Builtwith.com, Censys.io, Hunter.io, etc.
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


class ManagerCommandBase:
    """
    This module implements all functionalities to dynamically build the kismanage argparser.
    """

    def __init__(self, name: str, domain_utils: DomainUtils, host_utils: IpUtils, **kwargs):
        self.name = name
        self._domain_utils = domain_utils
        self._host_utils = host_utils

    @staticmethod
    def get_report_argument_parser(description: str, epilog: str = None) -> argparse.ArgumentParser:
        """
        This method creates and initializes the manager's argparser.
        """
        return argparse.ArgumentParser(description=description,
                                       formatter_class=SortingHelpFormatter,
                                       epilog=epilog)

    @staticmethod
    def add_subparsers(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
        """
        This method adds a subparser to the given parser and returns it.
        """
        return parser.add_subparsers(help='list of available database modules', dest="module")

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        raise NotImplementedError("not implemented")

    def _execute(self, **kwargs):
        """
        Executes the given subcommand.
        """
        raise NotImplementedError("not implemented")

    def _get_items(self, args: argparse.Namespace, name: str) -> List[str]:
        results = []
        if name in args:
            items = getattr(args, name) \
                if isinstance(getattr(args, name), list) else [getattr(args, name)]
            if name in ["Domain", "Network"] and (
                    ("Domain" in args and getattr(args, "Domain")) or
                    ("Network" in args and getattr(args, "Network"))):
                for item in items:
                    item = item.strip()
                    with open(item, "r") as file:
                        results.extend([line.strip() for line in file.readlines()])
            elif ("Add" in args and getattr(args, "Add")) or \
                    ("Scope" in args and getattr(args, "Scope")) or \
                    ("Delete" in args and getattr(args, "Delete")):
                for item in items:
                    item = item.strip()
                    with open(item, "r") as file:
                        results.extend([line.strip() for line in file.readlines()])
            else:
                results = items
        return results

    def execute(self, engine: Engine, args: argparse.Namespace, **kwargs):
        """
        Executes the given subcommand.
        """
        if args.module == "database":
            self._execute(engine=engine, args=args, **kwargs)
        elif args.module == self.name:
            with engine.session_scope() as session:
                if "workspace" in args:
                    workspace = self._domain_utils.get_workspace(session=session, name=args.workspace)
                    if not workspace:
                        raise WorkspaceNotFound(args.workspace)
                else:
                    workspace = None
                source_str = getattr(args, "source") if "source" in args and getattr(args, "source") else "user"
                source = self._domain_utils.add_source(session=session, name=source_str)
                self._execute(engine=engine, args=args, session=session, workspace=workspace, source=source, **kwargs)
        else:
            raise NotImplementedError()
