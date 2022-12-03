#!/usr/bin/env python3

"""
allows managing emails
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


class Email(ManagerCommandBase):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        parser = sub_parser.add_parser(self.name, help=__doc__.strip())
        parser.add_argument('EMAIL', type=str, nargs="+")
        parser.add_argument("-w", "--workspace",
                            metavar="WORKSPACE",
                            help="use the given workspace",
                            required=True,
                            type=str)
        parser_group = parser.add_mutually_exclusive_group(required=True)
        parser_group.add_argument('-a', '--add',
                                  action="store_true",
                                  help="create the given email EMAIL in workspace WORKSPACE")
        parser_group.add_argument('-A', '--Add',
                                  action="store_true",
                                  help="read the given emails (one per line) from file EMAIL and add them "
                                       "to workspace WORKSPACE")
        parser_group.add_argument('-d', '--delete',
                                  action="store_true",
                                  help="delete the given email EMAIL from workspace WORKSPACE (use with caution)")
        parser_group.add_argument('-D', '--Delete',
                                  action="store_true",
                                  help="read the given emails (one per line) from file NETWORK and delete them "
                                       "from workspace WORKSPACE")
        parser_group.add_argument("--source", metavar="SOURCE", type=str,
                                  help="specify the source of the emails to be added")

    def _execute(self, args: argparse.Namespace, session: Session, workspace: Workspace, source: Source, **kwargs):
        """
        Executes the given subcommand.
        """
        for email in self._get_items(args=args, name="EMAIL"):
            email = email.strip()
            if args.add or args.Add:
                email_object = self._domain_utils.add_email(session=session,
                                                            workspace=workspace,
                                                            text=email,
                                                            source=source)
                if not email_object:
                    raise ValueError("adding email '{}' failed".format(email))
            elif args.delete or args.Delete:
                self._domain_utils.delete_email(session=session, workspace=workspace, email=email)
