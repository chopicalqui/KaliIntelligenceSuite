#!/usr/bin/env python3

"""
allows importing scan results from filesystem
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
from database.model import ServiceState
from collectors.filesystem.nmap import DatabaseImporter as NmapDatabaseImporter
from collectors.filesystem.nessus import DatabaseImporter as NessusDatabaseImporter
from collectors.filesystem.masscan import DatabaseImporter as MasscanDatabaseImporter
from sqlalchemy.orm.session import Session
from .core import ManagerCommandBase


class Scan(ManagerCommandBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        parser = sub_parser.add_parser(self.name, help=__doc__.strip())
        parser.add_argument('FILE', type=str, nargs="+")
        parser.add_argument("-w", "--workspace",
                            metavar="WORKSPACE",
                            help="use the given workspace",
                            required=True,
                            type=str)
        parser.add_argument("-s",
                            dest="states",
                            choices=[item.name for item in ServiceState], nargs="*",
                            help="only import services that match one of the following Nmap states (per default only "
                                 "open and closed services are imported). this argument works only in combination "
                                 "with argument --nmap",
                            default=[ServiceState.Open.name, ServiceState.Closed.name])
        parser_group = parser.add_mutually_exclusive_group(required=True)
        parser_group.add_argument('--nmap',
                                  action="store_true",
                                  help="parse the given Nmap output file FILE (XML format) and add the containing "
                                       "information to workspace WORKSPACE")
        parser_group.add_argument('--nessus',
                                  action="store_true",
                                  help="parse the given Nessus output file FILE (XML format) and add the containing "
                                       "information to workspace WORKSPACE")
        parser_group.add_argument('--masscan',
                                  action="store_true",
                                  help="parse the given Masscan output file FILE (XML format) and add the containing "
                                       "information to workspace WORKSPACE")

    def _execute(self, args: argparse.Namespace, session: Session, workspace: Workspace, **kwargs):
        """
        Executes the given subcommand.
        """
        service_states = [ServiceState[item] for item in args.states]
        if args.nmap:
            NmapDatabaseImporter(session, workspace, args.FILE, service_states=service_states).run()
        elif args.nessus:
            NessusDatabaseImporter(session, workspace, args.FILE).run()
        elif args.masscan:
            MasscanDatabaseImporter(session, workspace, args.FILE).run()
