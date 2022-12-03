#!/usr/bin/python3
"""
this file implements unittests for the kismanage script
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

import os
import tempfile
from database.model import Workspace
from database.utils import Setup
from database.config import BaseConfig
from database.manage.database import Database as ManageDatabase
from unittests.tests.core import KisCommandEnum
from unittests.tests.core import BaseTestKisCommand


class TestDatabase(BaseTestKisCommand):
    """
    This class implements checks for testing subcommand database
    """

    def __init__(self, test_name: str):
        super().__init__(command=KisCommandEnum.kismanage, test_name=test_name)

    def test_backup_restore(self):
        """
        This unittest tests creating and restoring a backup.
        """
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Backup and restore database
        if not BaseConfig.is_docker():
            with tempfile.TemporaryDirectory() as temp_dir:
                file_name = os.path.join(temp_dir, "backup.sql")
                self.execute(subcommand="database", arguments="--backup {}".format(file_name))
                self.execute(subcommand="database", arguments="--restore {}".format(file_name))
            # Test restore
            with self._engine.session_scope() as session:
                result = session.query(Workspace).filter_by(name=self._workspace).one()
                self.assertEqual(self._workspace, result.name)

    def test_setup_dbg(self):
        """
        This unittest tests the --setup-dbg argument.
        """
        if not BaseConfig.is_docker():
            self.execute(subcommand="database", arguments="--setup-dbg")

    def test_test(self):
        """
        This unittest tests the --test argument.
        """
        Setup(engine=self._engine,
              kis_scripts=ManageDatabase.KIS_SCRIPTS,
              kali_packages=ManageDatabase.KALI_PACKAGES,
              git_repositories=ManageDatabase.GIT_REPOSITORIES,
              debug=True).test(throw_exception=True)

    def test_version(self):
        """
        This unittest tests the --version argument.
        """
        self.execute(subcommand="database", arguments="--version")
