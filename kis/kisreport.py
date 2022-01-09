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
import argparse
import traceback
from collectors.core import DomainUtils
from database.model import VhostChoice
from database.model import WorkspaceNotFound
from database.model import ReportScopeType
from database.config import SortingHelpFormatter
from database.report.core import ReportGenerator
from database.report.core import ReportLanguage
from database.report.core import ExcelReport
from database.utils import Engine
from database.utils import DeclarativeBase


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=SortingHelpFormatter)
    parser.add_argument("--nocolor", action="store_true", help="disable colored output")
    parser.add_argument("-l", "--list", action='store_true', help="list existing workspaces")
    parser.add_argument('--testing',
                        action="store_true",
                        help="if specified, then KIS uses the testing instead of the production database")
    sub_parser = parser.add_subparsers(help='list of available database modules', dest="module")
    # setup excel parser
    parser_excel = sub_parser.add_parser('excel', help='allows writing all identified information into a '
                                                       'microsoft excel file')
    parser_excel.add_argument('FILE', type=str,
                              help="the path to the microsoft excel file")
    parser_excel.add_argument("-w", "--workspaces",
                              metavar="WORKSPACE",
                              help="query the given workspaces",
                              nargs="+",
                              type=str)
    parser_excel.add_argument('--filter', metavar='DOMAIN|HOSTNAME|IP|NETWORK|EMAIL', type=str, nargs='*',
                              help='list of second-level domains (e.g., megacorpone.com), host names '
                                   '(e.g., www.megacorpone.com), IP addresses (e.g., 192.168.1.1), networks (e.g., '
                                   '192.168.0.0/24), or email addresses (e.g., test@megacorpone.com) whose '
                                   'information shall be returned. per default, mentioned items are excluded. add + '
                                   'in front of each item (e.g., +192.168.0.1) to return only these items')
    parser_excel.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                              help='return only in scope (within) or out of scope (outside) items. per default, '
                                   'all information is returned')
    parser_excel.add_argument('--reports', choices=[item.name for item in ExcelReport],
                              nargs="+",
                              default=[item.name for item in ExcelReport],
                              help='import only the following reports into Microsoft Excel')
    parser_excel.add_argument("-r", "--report-level",
                              choices=[item.name for item in VhostChoice],
                              default=VhostChoice.all.name,
                              help="specifies the information that shall be displayed in the sheet 'service info'.")
    # setup final parser
    parser_final = sub_parser.add_parser('final', help='allows writing final report tables into microsoft excel file')
    parser_final.add_argument('FILE', type=str,
                              help="the path to the microsoft excel file")
    parser_final.add_argument("-w", "--workspaces",
                              metavar="WORKSPACE",
                              help="query the given workspaces",
                              nargs="+",
                              type=str)
    parser_final.add_argument('-l', '--language',
                              type=ReportLanguage.argparse,
                              choices=list(ReportLanguage),
                              default=ReportLanguage.en,
                              help="the final report's language")
    report_classes = ReportGenerator.add_argparser_arguments(sub_parser)
    args = parser.parse_args()
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    try:
        engine = Engine(production=not args.testing)
        DeclarativeBase.metadata.bind = engine.engine
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
    except WorkspaceNotFound as ex:
        print(ex, file=sys.stderr)
    except NotImplementedError as ex:
        print(ex, file=sys.stderr)
    except Exception as ex:
        traceback.print_exc(file=sys.stderr)
