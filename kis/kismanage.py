#!/usr/bin/env python3

"""
this script implements all functionalities to set up and manage the PostgreSql database. it allows performing the
initial setup; creating and restoring PostgreSql database backups as well as adding and deleting workspaces, networks,
IP addresses, second-level domains/host names, and emails. kismanage is also used by kiscollect to query APIs like
Builtwith.com, Censys.io, Hunter.io, etc.
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

from database.utils import LoadedClass
from database.manage.core import ManagerCommandBase

import sys
import os
import logging
import traceback
from database.utils import Engine
from database.utils import DeclarativeBase
from database.model import WorkspaceNotFound
from database.model import DatabaseVersionMismatchError
from database.model import DatabaseUninitializationError
from collectors.core import IpUtils
from collectors.core import DomainUtils
from collectors.apis.core import ApiCollectionFailed
from database.config import BaseConfig


if __name__ == "__main__":
    epilog='''---- USE CASES ----

use cases can be obtained from the following wiki page:

https://github.com/chopicalqui/KaliIntelligenceSuite/wiki/kismanage-Use-Cases
'''
    module_list = {}
    host_utils = IpUtils()
    domain_utils = DomainUtils()
    # Initialize argparse
    parser = ManagerCommandBase.get_report_argument_parser(description=__doc__,  epilog=epilog)
    parser.add_argument("--debug",
                        action="store_true",
                        help="prints extra information to log file")
    parser.add_argument("-l", "--list", action='store_true', help="list existing workspaces")
    parser.add_argument('--testing',
                        action="store_true",
                        help="if specified, then KIS uses the testing instead of the production database")
    sub_parser = ManagerCommandBase.add_subparsers(parser)
    # Add all manager classes
    manager_classes = LoadedClass.load_classes("database.manage.*", ManagerCommandBase)
    for item in manager_classes:
        instance = item.create_instance(name=item.package_name, domain_utils=domain_utils, host_utils=host_utils)
        instance.add_arguments(sub_parser=sub_parser)
        module_list[item.package_name] = instance
    args = parser.parse_args()
    # Establish logging
    if os.access(BaseConfig.get_log_file(), os.W_OK):
        log_level = logging.DEBUG if args.debug else logging.INFO
        logging.basicConfig(filename=BaseConfig.get_log_file(),
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S',
                            level=log_level)
        logger = logging.getLogger(sys.argv[0])
        logger.info(" ".join(sys.argv))
    else:
        logger = None
    # Check arguments
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    try:
        engine = Engine(production=not args.testing)
        DeclarativeBase.metadata.bind = engine.engine
        # Check KIS' database status and version
        if args.module != "database":
            engine.perform_preflight_check(appy_patches=True, ask_user=True)
        if args.list:
            engine.print_workspaces()
        else:
            instance = module_list[args.module]
            instance.execute(engine=engine, args=args)
    except DatabaseVersionMismatchError as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)
    except DatabaseUninitializationError as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)
    except WorkspaceNotFound as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)
    except ApiCollectionFailed as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
