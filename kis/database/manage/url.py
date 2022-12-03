#!/usr/bin/env python3

"""
allows managing URLs
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
from database.model import Source
from sqlalchemy.orm.session import Session
from .core import ManagerCommandBase


class Url(ManagerCommandBase):

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
        parser.add_argument('URL', type=str, nargs="+")
        parser.add_argument('-a', '--add',
                            action="store_true",
                            help="create the given URL in the KIS database")

    def _execute(self, args: argparse.Namespace, session: Session, workspace: Workspace, source: Source, **kwargs):
        """
        Executes the given subcommand.
        """
        if args.add:
            for item in self._get_items(args=args, name="URL"):
                item = item.strip().lower()
                url = self._domain_utils.add_url(session=session,
                                                 workspace=workspace,
                                                 url=item,
                                                 source=source,
                                                 add_all=True)
                if not url:
                    raise ValueError("adding URL '{}' failed".format(item))
