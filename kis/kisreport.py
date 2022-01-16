#!/usr/bin/env python3

"""
this script can be used to implement custom operations like custom imports or custom operations
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2018 Lukas Reiter

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
import traceback
from collectors.core import DomainUtils
from database.model import WorkspaceNotFound
from database.model import DatabaseVersionMismatchError
from database.model import DatabaseUninitializationError
from database.report.core import ReportGenerator
from database.utils import Engine
from database.utils import DeclarativeBase


if __name__ == "__main__":
    # Create and parse arguments
    parser = ReportGenerator.get_report_argument_parser()
    sub_parser = ReportGenerator.add_sub_argument_parsers(parser)
    report_classes = ReportGenerator.add_argparser_arguments(sub_parser)
    args = parser.parse_args()

    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    try:
        engine = Engine(production=not args.testing)
        DeclarativeBase.metadata.bind = engine.engine
        # Check KIS' database status and version
        engine.perform_preflight_check()
        with engine.session_scope() as session:
            if args.workspaces:
                workspaces = []
                for item in args.workspaces:
                    workspace = DomainUtils.get_workspace(session=session, name=item)
                    if not workspace:
                        raise WorkspaceNotFound(item)
                    workspace = engine.get_workspace(session, item)
                    if workspace:
                        workspaces.append(workspace)
            else:
                workspaces = DomainUtils.get_workspaces(session=session)
            if workspaces:
                generator = ReportGenerator(report_classes=report_classes)
                generator.run(args=args, session=session, workspaces=workspaces)
    except DatabaseVersionMismatchError as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)
    except DatabaseUninitializationError as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)
    except WorkspaceNotFound as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)
    except NotImplementedError as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)
    except Exception as ex:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
