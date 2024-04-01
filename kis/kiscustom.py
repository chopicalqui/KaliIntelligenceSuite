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
import csv
import enum
import json
from database.config import SortingHelpFormatter
from database.utils import Engine
from collectors.os.modules.core import DomainUtils
from collectors.core import IpUtils
from database.model import ProtocolType
from database.model import ServiceState


class FileType(enum.Enum):
    qualys_hostname = enum.auto()
    qualys_services = enum.auto()
    confluence_networks = enum.auto()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=SortingHelpFormatter)
    parser.add_argument("-w", "--workspace", metavar="WORKSPACE", help="use the given workspace", type=str)
    parser.add_argument("-t", "--type",
                        metavar="TYPE",
                        choices=[item.name for item in FileType],
                        required=True,
                        help="use the given workspace",
                        type=str)
    parser.add_argument("FILE", help="import given JSON file", type=str)
    args = parser.parse_args()
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    try:
        file_type = FileType[args.type]
        domain_utils = DomainUtils()
        ip_utils = IpUtils()
        engine = Engine()
        with engine.session_scope() as session:
            workspace = engine.get_workspace(session=session, name=args.workspace)
            source_qualys = domain_utils.add_source(session=session, name="six(qualys20231209)")
            source_company_network = domain_utils.add_source(session=session, name="six(confluence)")
            # Read file content
            with open(args.FILE, "r") as file:
                content = file.read()
            json_object = json.loads(content)
            for item in json_object:
                if file_type == FileType.qualys_hostname:
                    host_name_str = item[0].strip()
                    host_name = domain_utils.add_domain_name(session=session,
                                                             workspace=workspace,
                                                             item=host_name_str,
                                                             source=source_qualys,
                                                             verify=False)
                    if not host_name:
                        raise ValueError(f"Hostname {host_name_str} could not be created.")
                elif file_type == FileType.qualys_services:
                    ip_address = item[0].strip()
                    protocol = item[1].strip()
                    port = int(item[2].strip())
                    # At the moment, we only import all TCP services and well-knwon UDP services (UDP port <= 1024)
                    if protocol == ProtocolType.tcp or (protocol == ProtocolType.udp and port <= 1024):
                        host = ip_utils.add_host(session=session,
                                                 workspace=workspace,
                                                 address=ip_address,
                                                 source=source_qualys)
                        if host:
                            # if service in ["http", "proxy_http"]:
                            #     service_name = "http"
                            #     confidence = 10
                            # else:
                            #     service_name = None
                            #     confidence = None
                            domain_utils.add_service(session=session,
                                                     port=port,
                                                     protocol_type=protocol,
                                                     state=ServiceState.Open,
                                                     host=host,
                                                     source=source_qualys)
                        else:
                            raise ValueError(f"Host {ip_address} could not be created.")
                elif file_type == FileType.confluence_networks:
                    network = ip_utils.add_network(session=session,
                                                   workspace=workspace,
                                                   network=item[0].strip(),
                                                   source=source_company_network)
                    if not network:
                        raise ValueError(f"Network {item[0].strip()} could not be created.")
                else:
                    raise NotImplementedError(file_type)
    except Exception as ex:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
