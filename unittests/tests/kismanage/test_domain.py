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
from database.model import ScopeType
from database.model import DomainName
from unittests.tests.core import KisCommandEnum
from unittests.tests.core import BaseTestKisCommand


class TestDomain(BaseTestKisCommand):
    """
    This class implements checks for testing subcommand domain
    """

    def __init__(self, test_name: str):
        super().__init__(command=KisCommandEnum.kismanage, test_name=test_name)

    def test_add_delete(self):
        """
        This unittest tests adding and deleting a company
        """
        source = " unittest "
        scope = ScopeType.exclude
        item = " unittest.local "
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new item to database
        self.execute(subcommand="domain",
                     arguments="-w {ws} --scope {scope} -a \"{item}\" --source \"{source}\"".format(ws=self._workspace,
                                                                                                    scope=scope.name,
                                                                                                    item=item,
                                                                                                    source=source))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name=item.strip().lower()).one()
            self.assertEqual(scope, result.scope)
            self.assertListEqual([source.strip()], [item.name for item in result.host_names[0].sources])
        # Delete item from database
        self.execute(subcommand="domain",
                     arguments="-w {ws} -d \"{item}\"".format(ws=self._workspace, item=item))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(DomainName).count()
            self.assertEqual(0, result)

    def test_Add_Delete(self):
        """
        This unittest tests adding and deleting networks via a file.
        """
        source = "unittest"
        scope = ScopeType.exclude
        items = ["unittest1.com", "unittest2.com"]
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {ws}".format(ws=self._workspace))
        # Initialize file
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "domains.txt")
            with open(file_name, "w") as file:
                file.writelines([item + os.linesep for item in items])
            # Add new item to database
            self.execute(subcommand="domain",
                         arguments="-w {ws} -A {item} --source {src} --scope {scope}".format(ws=self._workspace,
                                                                                             item=file_name,
                                                                                             src=source,
                                                                                             scope=scope.name))
            # Check database
            with self._engine.session_scope() as session:
                for item in items:
                    result = session.query(DomainName).filter_by(name=item).one()
                    self.assertEqual(scope, result.scope)
                    self.assertListEqual([source], [item.name for item in result.host_names[0].sources])
            # Delete items from database
            self.execute(subcommand="domain",
                         arguments="-w {ws} -D {item}".format(ws=self._workspace,
                                                              item=file_name,
                                                              src=source,
                                                              scope=scope.name))
            # Test network deletion
            with self._engine.session_scope() as session:
                result = session.query(DomainName).count()
                self.assertEqual(0, result)

    def test_set_scope(self):
        """
        This unittest tests the initialization of a workspace
        """
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {ws}".format(ws=self._workspace))
        # Add new item to database
        self.execute(subcommand="domain", arguments="-w {ws} -a unittest1.com".format(ws=self._workspace))
        self.execute(subcommand="domain", arguments="-w {ws} -a unittest2.com -s exclude".format(ws=self._workspace))
        self.execute(subcommand="domain", arguments="-w {ws} -a unittest3.com -s strict".format(ws=self._workspace))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name="unittest1.com").one()
            self.assertEqual(ScopeType.all, result.scope)
            self.assertTrue(result.host_names[0]._in_scope)
            result = session.query(DomainName).filter_by(name="unittest2.com").one()
            self.assertEqual(ScopeType.exclude, result.scope)
            self.assertFalse(result.host_names[0]._in_scope)
            result = session.query(DomainName).filter_by(name="unittest3.com").one()
            self.assertEqual(ScopeType.strict, result.scope)
            self.assertFalse(result.host_names[0]._in_scope)
        # Update scopes
        self.execute(subcommand="domain", arguments="-w {ws} unittest1.com -s strict".format(ws=self._workspace))
        self.execute(subcommand="domain", arguments="-w {ws} unittest2.com -s strict".format(ws=self._workspace))
        self.execute(subcommand="domain", arguments="-w {ws} -a unittest3.com -s all".format(ws=self._workspace))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(DomainName).filter_by(name="unittest1.com").one()
            self.assertEqual(ScopeType.strict, result.scope)
            self.assertFalse(result.host_names[0]._in_scope)
            result = session.query(DomainName).filter_by(name="unittest2.com").one()
            self.assertEqual(ScopeType.strict, result.scope)
            self.assertFalse(result.host_names[0]._in_scope)
            result = session.query(DomainName).filter_by(name="unittest3.com").one()
            self.assertEqual(ScopeType.strict, result.scope)
            self.assertTrue(result.host_names[0]._in_scope)
