#!/usr/bin/env python3

"""
this script implements a commandline interface to collect intelligence. the collection is performed by so called
collectors.

a collector is a Python module, which can operate on the IPv4/IPv6 address (e.g., collector shodanhost), IPv4/IPv6 network
(e.g., collector tcpnmap), service (e.g., collector ftphydra), or second-level domain (e.g., collector theharvester)
level. the collectors create these commands based on the data that is available in the KIS database and after each
execution, they perform the following tasks:

  * analyse the OS command's output
  * report any potential valuable information to the user
  * enrich the data (e.g., newly identified IPv4/IPv6 addresses, host names, URLs, credentials, etc.) in the database to
  ensure that subsequent collectors can re-use it

collectors are executed in a specific order to ensure that information required by one collector is already collected
by another.

Note: service-level collectors identify services from which they can collect intelligence by comparing the protocol
(TCP or UDP) and port number or by the nmap service name. the nmap service name is useful, if services are running on
non-standard ports. at the moment, only the service names of nmap are supported, which means that only from
nmap scan results, KIS is able to collect intel from services running on non-standard ports
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
__version__ = "0.3.0"

import os
import sys
import queue
import logging
import tempfile
import traceback
from database.config import Collector
from database.config import BaseConfig
from view.console import KisCollectConsole
from database.utils import Engine
from database.utils import DeclarativeBase
from collectors.os.collector import CollectorProducer
from database.model import DatabaseVersionMismatchError
from database.model import DatabaseUninitializationError


if __name__ == "__main__":
    try:
        engine = Engine()
        DeclarativeBase.metadata.bind = engine.engine
        commands_queue = queue.Queue()
        producer = CollectorProducer(engine, commands_queue)
        epilog='''---- USE CASES ----

use cases can be obtained from the following wiki page:

https://github.com/chopicalqui/KaliIntelligenceSuite/wiki/KIS-Use-Cases#kiscollect
'''
        parser = CollectorProducer.get_argument_parser(description=__doc__, epilog=epilog)
        collector_group = CollectorProducer.add_collector_argument_group(parser)
        producer.add_argparser_arguments(collector_group)

        args = parser.parse_args()
        # Check KIS' database status and version
        engine.perform_preflight_check(appy_patches=True, ask_user=True)
        if os.geteuid() != 0 and not args.print_commands:
            config = Collector()
            print("{} must be executed with root privileges. afterwards, it is possible to execute "
                  "individual commands with lower privileged users like 'nobody'".format(sys.argv[0]), file=sys.stderr)
            sys.exit(1)
        if args.list:
            engine.print_workspaces()
            sys.exit(1)
        with tempfile.TemporaryDirectory() as temp_dir:
            if args.testing:
                engine.production = False
            arguments = vars(args)
            if args.output_dir and not os.path.isdir(args.output_dir):
                print("output directory '{}' does not exist!".format(args.output_dir), file=sys.stderr)
                sys.exit(1)
            arguments["output_dir"] = args.output_dir if args.output_dir else temp_dir
            producer.init(arguments)
            with engine.session_scope() as session:
                if not engine.get_workspace(session, args.workspace):
                    sys.exit(1)
            if args.user and args.user_file:
                raise ValueError("option --user-file and --user cannot be used together.")
            if args.password and args.password_file:
                raise ValueError("option --password-file and --password cannot be used together.")
            if args.wordlist_files:
                for file in args.wordlist_files:
                    if not os.path.exists(file):
                        raise FileNotFoundError("wordlist '{}' not found.".format(file))
            if args.user_file and not os.path.exists(args.user_file):
                raise FileNotFoundError("user file '{}' not found.".format(args.user_file))
            if args.password_file and not os.path.exists(args.password_file):
                raise FileNotFoundError("password file '{}' not found.".format(args.password_file))
            if args.combo_file and not os.path.exists(args.combo_file):
                raise FileNotFoundError("combo file '{}' not found.".format(args.combo_file))
            log_level = logging.INFO
            if args.analyze:
                log_level = logging.WARNING
            if args.debug:
                log_level = logging.DEBUG
            if not args.print_commands:
                logging.basicConfig(filename=BaseConfig.get_log_file(),
                                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                                    datefmt='%Y-%m-%d %H:%M:%S',
                                    level=log_level)
                logger = logging.getLogger(sys.argv[0])
                logger.info("$ {}".format(" ".join(sys.argv)))

            # Let's get started
            if args.print_commands:
                producer.start()
                producer.join()
            else:
                KisCollectConsole(args=args, producer_thread=producer).cmdloop()
    except DatabaseVersionMismatchError as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)
    except DatabaseUninitializationError as ex:
        print(ex, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
