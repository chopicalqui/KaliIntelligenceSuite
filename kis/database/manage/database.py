#!/usr/bin/env python3

"""
allows setting up and managing the database
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
import argparse
from database.utils import Engine
from database.utils import Setup
from database.config import BaseConfig
from .core import ManagerCommandBase


class Database(ManagerCommandBase):
    KIS_SCRIPTS = ["kiscollect.py", "kismanage.py", "kisreport.py"]
    GIT_REPOSITORIES = []
    KALI_PACKAGES = ["gobuster", "nfs-common", "ftp", "ntpdate", "csvkit", "wapiti",
                     "changeme", "theharvester", "sidguesser", "smtp-user-enum", "sublist3r",
                     "tcptraceroute", "crackmapexec", "dotdotpwn", "seclists", "smbclient", "enum4linux"]

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_arguments(self, sub_parser: argparse._SubParsersAction) -> None:
        """
        This method adds the subclasses specific command line arguments.
        """
        parser = sub_parser.add_parser(self.name, help=__doc__.strip())
        parser.add_argument("--init",
                            help="creates tables, views, functions, and triggers for the KIS database",
                            action="store_true")
        parser.add_argument("--drop",
                            help="drops tables, views, functions, and triggers in the KIS database",
                            action="store_true")
        parser.add_argument("--version", help="obtain version information", action="store_true")
        if not BaseConfig.is_docker():
            parser.add_argument("--backup", metavar="FILE", type=str, help="writes database backup to FILE")
            parser.add_argument("--restore", metavar="FILE", type=str, help="restores database backup from FILE")
            parser.add_argument("--setup",
                                action="store_true",
                                help="run initial setup for KIS")
            parser.add_argument("--setup-dbg",
                                action="store_true",
                                help="like --setup but just prints commands for initial setup for KIS")
        parser.add_argument("--test",
                            action="store_true",
                            help="test the existing KIS setup")

    def _execute(self, args: argparse.Namespace, engine: Engine, **kwargs):
        """
        Executes the given subcommand.
        """
        if os.geteuid() != 0:
            print("database commands must be executed as root", file=sys.stderr)
            sys.exit(1)
        if not BaseConfig.is_docker() and args.backup:
            engine.create_backup(args.backup)
        elif not BaseConfig.is_docker() and args.restore:
            engine.restore_backup(args.restore)
        elif not BaseConfig.is_docker() and (args.setup or args.setup_dbg):
            debug = args.setup_dbg
            Setup(engine=engine,
                  kis_scripts=Database.KIS_SCRIPTS,
                  kali_packages=Database.KALI_PACKAGES,
                  git_repositories=Database.GIT_REPOSITORIES,
                  debug=debug).execute()
        elif args.test:
            Setup(engine=engine,
                  kis_scripts=Database.KIS_SCRIPTS,
                  kali_packages=Database.KALI_PACKAGES,
                  git_repositories=Database.GIT_REPOSITORIES,
                  debug=True).test()
        elif args.version:
            engine.print_version_information()
        else:
            if args.drop:
                if BaseConfig.is_docker() or args.testing:
                    engine.drop()
                else:
                    engine.recreate_database()
            if args.init:
                engine.init(load_cipher_suites=True)
