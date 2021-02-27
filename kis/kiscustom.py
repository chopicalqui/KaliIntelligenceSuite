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

import argparse
import sys
import traceback
from configs.config import SortingHelpFormatter
from database.utils import Engine


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=SortingHelpFormatter)
    parser.add_argument("-w", "--workspace", metavar="WORKSPACE", help="use the given workspace", type=str)
    args = parser.parse_args()
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    try:
        engine = Engine()
        with engine.session_scope() as session:
            workspace = engine.get_workspace(session=session, name=args.workspace)
            # implement custom operations here
    except Exception as ex:
        traceback.print_exc(file=sys.stderr)
