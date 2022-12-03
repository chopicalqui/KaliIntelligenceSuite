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
from database.model import HostName
from database.model import ScopeType
from database.model import DomainName
from unittests.tests.core import KisCommandEnum
from unittests.tests.core import BaseTestKisCommand


class TestHostName(BaseTestKisCommand):
    """
    This class implements checks for testing subcommand hostname
    """

    def __init__(self, test_name: str):
        super().__init__(command=KisCommandEnum.kismanage, test_name=test_name)

    def test_add_host_name_without_domain(self):
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new item to database
        self.execute(subcommand="hostname",
                     arguments="-w {ws} -a \"{item}\"".format(ws=self._workspace, item="www.unittest.local"),
                     expected_return_code=1)

    def test_add_delete(self):
        """
        This unittest tests adding and deleting a hostname
        """
        source = " unittest "
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {}".format(self._workspace))
        # Add new item to database
        self.execute(subcommand="domain",
                     arguments="-w {ws} --scope {scope} -a \"{item}\"".format(ws=self._workspace,
                                                                              scope=ScopeType.exclude.name,
                                                                              item="exclude.local",
                                                                              source=source))
        self.execute(subcommand="hostname",
                     arguments="-w {ws} --scope {scope} -a \"{item}\" --source \"{src}\"".format(ws=self._workspace,
                                                                                                 scope="within",
                                                                                                 item="www.exclude.local",
                                                                                                 src=source))
        self.execute(subcommand="domain",
                     arguments="-w {ws} --scope {scope} -a \"{item}\"".format(ws=self._workspace,
                                                                              scope=ScopeType.all.name,
                                                                              item="all.local",
                                                                              source=source))
        self.execute(subcommand="hostname",
                     arguments="-w {ws} --scope {scope} -a \"{item}\" --source \"{src}\"".format(ws=self._workspace,
                                                                                                 scope="outside",
                                                                                                 item="www.all.local",
                                                                                                 src=source))
        self.execute(subcommand="domain",
                     arguments="-w {ws} --scope {scope} -a \"{item}\"".format(ws=self._workspace,
                                                                              scope=ScopeType.strict.name,
                                                                              item="strict.local",
                                                                              source=source))
        self.execute(subcommand="hostname",
                     arguments="-w {ws} -a \"{item}\" --source \"{src}\"".format(ws=self._workspace,
                                                                                 item="www1.strict.local",
                                                                                 src=source))
        self.execute(subcommand="hostname",
                     arguments="-w {ws} --scope {scope} -a \"{item}\" --source \"{src}\"".format(ws=self._workspace,
                                                                                                 scope="outside",
                                                                                                 item="www2.strict.local",
                                                                                                 src=source))
        # Check database
        with self._engine.session_scope() as session:
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="www.exclude.local")
            self.assertEqual(ScopeType.exclude, result.domain_name.scope)
            self.assertFalse(result._in_scope)
            self.assertListEqual([source.strip()], [item.name for item in result.sources])
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="www.all.local")
            self.assertEqual(ScopeType.all, result.domain_name.scope)
            self.assertTrue(result._in_scope)
            self.assertListEqual([source.strip()], [item.name for item in result.sources])
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="www1.strict.local")
            self.assertEqual(ScopeType.strict, result.domain_name.scope)
            self.assertTrue(result._in_scope)
            self.assertListEqual([source.strip()], [item.name for item in result.sources])
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="www2.strict.local")
            self.assertEqual(ScopeType.strict, result.domain_name.scope)
            self.assertFalse(result._in_scope)
            self.assertListEqual([source.strip()], [item.name for item in result.sources])
        # Update scopes
        self.execute(subcommand="domain",
                     arguments="-w {ws} --scope {scope} \"{item}\"".format(ws=self._workspace,
                                                                           scope=ScopeType.strict.name,
                                                                           item="all.local",
                                                                           source=source))
        self.execute(subcommand="hostname",
                     arguments="-w {ws} -s {scope} \"{item}\"".format(ws=self._workspace,
                                                                      item="www1.strict.local",
                                                                      scope="outside"))
        # Check database
        with self._engine.session_scope() as session:
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="www.all.local")
            self.assertEqual(ScopeType.strict, result.domain_name.scope)
            self.assertTrue(result._in_scope)
            result = self.query_hostname(session=session, workspace_str=self._workspace, host_name="www1.strict.local")
            self.assertEqual(ScopeType.strict, result.domain_name.scope)
            self.assertFalse(result._in_scope)
            self.assertListEqual([source.strip()], [item.name for item in result.sources])
        # Delete item from database
        self.execute(subcommand="hostname",
                     arguments="-w {ws} -d \"{item}\"".format(ws=self._workspace, item="www.exclude.local"))
        self.execute(subcommand="hostname",
                     arguments="-w {ws} -d \"{item}\"".format(ws=self._workspace, item="www.all.local"))
        self.execute(subcommand="hostname",
                     arguments="-w {ws} -d \"{item}\"".format(ws=self._workspace, item="www1.strict.local"))
        self.execute(subcommand="hostname",
                     arguments="-w {ws} -d \"{item}\"".format(ws=self._workspace, item="www2.strict.local"))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter(HostName.name.isnot(None)).count()
            self.assertEqual(0, result)

    def test_Add_Delete(self):
        """
        This unittest tests adding and deleting networks via a file.
        """
        source = "unittest"
        items = ["www.unittest.local", "www.unittest.local"]
        # Setup database and workspace
        self.execute(subcommand="database", arguments="--drop --init")
        self.execute(subcommand="workspace", arguments="-a {ws}".format(ws=self._workspace))
        self.execute(subcommand="domain",
                     arguments="-w {ws} -a \"{domain}\" --scope {scope}".format(ws=self._workspace,
                                                                                domain="unittest.local",
                                                                                scope="strict"))
        # Initialize file
        with tempfile.TemporaryDirectory() as temp_dir:
            file_name = os.path.join(temp_dir, "hostnames.txt")
            with open(file_name, "w") as file:
                file.writelines([item + os.linesep for item in items])
            # Add new item to database
            self.execute(subcommand="hostname",
                         arguments="-w {ws} -A {item} --source {src} --scope {scope}".format(ws=self._workspace,
                                                                                             item=file_name,
                                                                                             src=source,
                                                                                             scope="outside"))
            # Check database
            with self._engine.session_scope() as session:
                for item in items:
                    result = self.query_hostname(session=session, workspace_str=self._workspace,
                                                 host_name=item)
                    self.assertFalse(result._in_scope)
                    self.assertListEqual([source], [item.name for item in result.sources])
            # Update scopes
            self.execute(subcommand="hostname",
                         arguments="-w {ws} {item} -S {scope}".format(ws=self._workspace,
                                                                      item=file_name,
                                                                      scope="within"))
            # Check database
            with self._engine.session_scope() as session:
                for item in items:
                    result = self.query_hostname(session=session, workspace_str=self._workspace,
                                                 host_name=item)
                    self.assertTrue(result._in_scope)
                    self.assertListEqual([source], [item.name for item in result.sources])

            # Delete items from database
            self.execute(subcommand="hostname",
                         arguments="-w {ws} -D {item}".format(ws=self._workspace, item=file_name))
        # Check database
        with self._engine.session_scope() as session:
            result = session.query(HostName).filter(HostName.name.isnot(None)).count()
            self.assertEqual(0, result)
