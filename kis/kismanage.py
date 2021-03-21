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

import argparse
import traceback
import ipaddress
import sys
import os
import json
import logging
from configs.config import SortingHelpFormatter
from database.utils import Engine
from database.utils import Setup
from database.utils import DeclarativeBase
from database.model import HostNotFound
from database.model import ScopeType
from database.model import ReportScopeType
from database.model import WorkspaceNotFound
from database.model import Workspace
from database.model import Source
from database.model import DomainName
from database.model import ProtocolType
from database.model import ServiceState
from collectors.core import IpUtils
from collectors.core import DomainUtils
from collectors.filesystem.nmap import DatabaseImporter as NmapDatabaseImporter
from collectors.filesystem.nessus import DatabaseImporter as NessusDatabaseImporter
from collectors.filesystem.masscan import DatabaseImporter as MasscanDatabaseImporter
from collectors.apis.core import ApiCollectionFailed
from collectors.apis.shodan import ShodanHost
from collectors.apis.shodan import ShodanNetwork
from collectors.apis.censys import CensysIpv4
from collectors.apis.censys import CensysCertificate
from collectors.apis.hunter import Hunter
from collectors.apis.dnsdumpster import DnsDumpster
from collectors.apis.securitytrails import SecurityTrails
from collectors.apis.haveibeenpwned import HaveIBeenPwnedBreachedAcccount
from collectors.apis.haveibeenpwned import HaveIBeenPwnedPasteAcccount
from collectors.apis.builtwith import BuiltWith
from collectors.apis.hostio import HostIo
from collectors.apis.burpsuite import BurpSuiteProfessional
from collectors.apis.virustotal import Virustotal
from collectors.apis.certspotter import Certspotter
from collectors.apis.crtsh import CrtshDomain
from collectors.apis.crtsh import CrtshCompany
from collectors.apis.viewdns import ViewDns
from configs.config import BaseConfig
from sqlalchemy.orm.session import Session
from typing import List


class KisImportArgumentParser(argparse.ArgumentParser):
    """
    Implements script specific argument parser
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.api_classes = {}
        self.file_classes = {}

    def add_all(self,
                parser,
                api_argument_name: str,
                file_argument_name: str,
                api_metavar: str,
                api_name: str,
                api_class: type):
        self.add_api_query_argument(parser=parser,
                                    argument_name=api_argument_name,
                                    metavar=api_metavar,
                                    api_name=api_name,
                                    api_class=api_class)
        self.add_api_file_argument(parser=parser,
                                   argument_name=file_argument_name,
                                   source_argument=api_argument_name,
                                   api_class=api_class)

    def add_api_query_argument(self, parser, argument_name: str, metavar: str, api_name: str, api_class: type):
        self.api_classes[argument_name.strip("-").replace("-", "_")] = api_class
        return parser.add_argument(argument_name, metavar=metavar, type=str,
                                   help='query information for the given IPv4 address from the {} API and '
                                        'add it to the given workspace (see argument -A or -w) in the KIS '
                                        'database. argument -O is mandatory and is used to store the raw '
                                        'data returned by the API in this output directory. this argument '
                                        'is usually only used by the script kiscollect'.format(api_name))

    def add_api_file_argument(self, parser, argument_name: str, source_argument: str, api_class: type):
        pass


class ManageDatabase:
    KIS_SCRIPTS = ["kiscollect.py", "kismanage.py", "kisreport.py"]
    GIT_REPOSITORIES = []
    KALI_PACKAGES = ["eyewitness", "gobuster", "nfs-common", "ftp", "ntpdate", "csvkit", "wapiti",
                     "changeme", "theharvester", "sidguesser", "smtp-user-enum", "sublist3r",
                     "tcptraceroute", "crackmapexec", "dotdotpwn", "seclists", "smbclient", "enum4linux"]

    def __init__(self, engine: Engine, arguments: argparse.Namespace, parser):
        self._parser = parser
        self._engine = engine
        self._arguments = arguments
        self._domain_utils = DomainUtils()
        self._ip_utils = IpUtils()

    def _manage_workspace(self, session: Session):
        if self._arguments.module == "workspace":
            if self._arguments.add:
                self._domain_utils.add_workspace(session, self._arguments.WORKSPACE)
            elif self._arguments.delete:
                self._domain_utils.delete_workspace(session, self._arguments.WORKSPACE)

    def _manage_database(self):
        if os.geteuid() != 0:
            print("database commands must be executed as root", file=sys.stderr)
            sys.exit(1)
        if self._arguments.backup:
            engine.create_backup(args.backup)
        elif self._arguments.restore:
            engine.restore_backup(args.restore)
        elif self._arguments.setup or self._arguments.setup_dbg:
            debug = args.setup_dbg
            Setup(kis_scripts=ManageDatabase.KIS_SCRIPTS,
                  kali_packages=ManageDatabase.KALI_PACKAGES,
                  git_repositories=ManageDatabase.GIT_REPOSITORIES,
                  debug=debug).execute()
        elif self._arguments.test:
            Setup(kis_scripts=ManageDatabase.KIS_SCRIPTS,
                  kali_packages=ManageDatabase.KALI_PACKAGES,
                  git_repositories=ManageDatabase.GIT_REPOSITORIES,
                  debug=True).test()
        else:
            if self._arguments.drop:
                self._engine.recreate_database()
            if self._arguments.init:
                self._engine.init(load_cipher_suites=True)

    def _get_items(self, name: str) -> List[str]:
        results = []
        if name in self._arguments:
            items = getattr(self._arguments, name) \
                if isinstance(getattr(self._arguments, name), list) else [getattr(self._arguments, name)]
            if name in ["Domain", "Network"] and (
                    ("Domain" in self._arguments and getattr(self._arguments, "Domain")) or
                    ("Network" in self._arguments and getattr(self._arguments, "Network"))):
                for item in items:
                    with open(item, "r") as file:
                        results.extend([line.strip() for line in file.readlines()])
            elif ("Add" in self._arguments and getattr(self._arguments, "Add")) or \
                    ("Delete" in self._arguments and getattr(self._arguments, "Delete")):
                for item in items:
                    with open(item, "r") as file:
                        results.extend([line.strip() for line in file.readlines()])
            else:
                results = items
        return results

    def _manage_network(self, session: Session, workspace: Workspace, source: Source):
        if self._arguments.module == "network":
            scope = ScopeType[self._arguments.scope] if self._arguments.scope != "vhost" else ScopeType.strict
            for network in self._get_items("NETWORK"):
                if self._arguments.add or self._arguments.Add:
                    ipv4_network = self._ip_utils.add_network(session=session,
                                                              workspace=workspace,
                                                              network=network,
                                                              scope=scope,
                                                              source=source)
                    if not ipv4_network:
                        raise ValueError("adding network '{}' failed".format(network))
                elif self._arguments.delete or self._arguments.Delete:
                    self._ip_utils.delete_network(session=session,
                                                  workspace=workspace,
                                                  network=network)
                elif self._arguments.scope:
                    result = self._ip_utils.get_network(session=session,
                                                        workspace=workspace,
                                                        network=network)
                    if not result:
                        raise ValueError("cannot set scope as network '{}' does not exist".format(network))
                    else:
                        result.scope = scope
                        if self._arguments.scope == "vhost":
                            for host in result.hosts:
                                if host.in_scope_host_name:
                                    host.in_scope = True
                if self._arguments.create_hosts:
                    ipv4_network = self._ip_utils.add_network(session=session,
                                                              workspace=workspace,
                                                              network=network,
                                                              scope=scope,
                                                              source=source)
                    if not ipv4_network:
                        raise ValueError("adding network '{}' failed".format(network))
                    for ipv4_address in ipaddress.ip_network(ipv4_network.network):
                        self._ip_utils.add_host(session=session,
                                                workspace=workspace,
                                                address=str(ipv4_address),
                                                source=source)

    def _manage_host(self, session: Session, workspace: Workspace, source: Source):
        if self._arguments.module == "host":
            in_scope = ReportScopeType[self._arguments.scope] == ReportScopeType.within
            for host in self._get_items("IP"):
                if self._arguments.add or self._arguments.Add:
                    host_object = self._ip_utils.add_host(session=session,
                                                          workspace=workspace,
                                                          address=host,
                                                          in_scope=in_scope,
                                                          source=source)
                    if not host_object:
                        raise ValueError("adding host with IP address '{}' failed".format(host))
                elif self._arguments.delete or self._arguments.Delete:
                    self._ip_utils.delete_host(session=session,
                                               workspace=workspace,
                                               address=host)
                else:
                    result = self._ip_utils.get_host(session=session, workspace=workspace, address=host)
                    if not result:
                        raise ValueError("cannot set scope as host '{}' does not exist".format(host))
                    else:
                        result.in_scope = in_scope

    def _manage_service(self, session: Session, workspace: Workspace, source: Source):
        if self._arguments.module == "service":
            type = ProtocolType[self._arguments.protocol]
            for host in self._arguments.host:
                host_object = self._ip_utils.get_host(session=session,
                                                      workspace=workspace,
                                                      address=host)
                if not host_object:
                    raise HostNotFound(host)
                if self._arguments.add:
                    self._domain_utils.add_service(session=session,
                                                   port=self._arguments.port,
                                                   protocol_type=type,
                                                   state=ServiceState.Open,
                                                   host=host_object,
                                                   nmap_service_name=self._arguments.service_name,
                                                   nmap_service_confidence=10,
                                                   nmap_tunnel="ssl" if self._arguments.tls else None,
                                                   source=source)
                elif self._arguments.delete:
                    self._domain_utils.delete_service(session=session,
                                                      port=self._arguments.port,
                                                      protocol_type=type,
                                                      host=host_object)

    def _manage_domain(self, session: Session, workspace: Workspace, source: Source):
        if self._arguments.module == "domain":
            scope = ScopeType[self._arguments.scope]
            for domain in self._get_items("DOMAIN"):
                if self._arguments.add or self._arguments.Add:
                    domain_object = self._domain_utils.add_sld(session=session,
                                                               workspace=workspace,
                                                               name=domain,
                                                               scope=scope,
                                                               source=source)
                    if not domain_object:
                        raise ValueError("adding domain '{}' failed".format(domain))
                elif self._arguments.delete or self._arguments.Delete:
                    self._domain_utils.delete_domain_name(session=session,
                                                          workspace=workspace,
                                                          domain_name=domain)
                elif self._arguments.scope:
                    result = session.query(DomainName) \
                        .join(Workspace) \
                        .filter(Workspace.id == workspace.id, DomainName.name == domain).one_or_none()
                    if not result:
                        raise ValueError("cannot set scope as second-level domain '{}' does not exist".format(domain))
                    elif result.scope != scope:
                        result.scope = scope

    def _manage_host_name(self, session: Session, workspace: Workspace, source: Source):
        if self._arguments.module == "hostname":
            scope = ReportScopeType[self._arguments.scope]
            in_scope = scope == ReportScopeType.within
            for host_name in self._get_items("HOSTNAME"):
                if self._arguments.add or self._arguments.Add:
                    host_name = self._domain_utils.add_host_name(session=session,
                                                                 workspace=workspace,
                                                                 name=host_name,
                                                                 in_scope=in_scope,
                                                                 source=source)
                    if not host_name:
                        raise ValueError("adding host name '{}' failed".format(host_name))
                elif self._arguments.sharphound:
                    with open(host_name, "rb") as file:
                        json_object = json.loads(file.read())
                        if "computers" in json_object and isinstance(json_object["computers"], list):
                            source = self._domain_utils.add_source(session=session, name="sharphound")
                            for item in json_object["computers"]:
                                if "Properties" in item and "name" in item["Properties"]:
                                    computer_name = item["Properties"]["name"]
                                    host_name = self._domain_utils.add_host_name(session=session,
                                                                                 workspace=workspace,
                                                                                 name=computer_name,
                                                                                 in_scope=in_scope,
                                                                                 source=source)
                                    if not host_name:
                                        raise ValueError("adding host name '{}' failed".format(host_name))
                                else:
                                    raise KeyError("invalid sharphound computer file. file does not contain "
                                                   "attribute 'Properties' and/or 'name'")
                        else:
                            raise KeyError("invalid sharphound computer file. file does not contain "
                                           "attribute 'computers'")
                elif self._arguments.delete or self._arguments.Delete:
                    self._domain_utils.delete_host_name(session=session,
                                                        workspace=workspace,
                                                        host_name=host_name)
                else:
                    result = self._domain_utils.get_host_name(session=session, workspace=workspace, host_name=host_name)
                    if not result:
                        raise ValueError("cannot set scope as host name '{}' does not exist".format(host_name))
                    elif result._in_scope != in_scope:
                        result._in_scope = in_scope

    def _manage_email(self, session: Session, workspace: Workspace, source: Source):
        if self._arguments.module == "email":
            for email in self._get_items("EMAIL"):
                if self._arguments.add or self._arguments.Add:
                    email_object = self._domain_utils.add_email(session=session,
                                                                workspace=workspace,
                                                                text=email,
                                                                source=source)
                    if not email_object:
                        raise ValueError("adding email '{}' failed".format(email))
                elif self._arguments.delete or self._arguments.Delete:
                    self._domain_utils.delete_email(session=session, workspace=workspace, email=email)

    def _manage_company(self, session: Session, workspace: Workspace, source: Source):
        if self._arguments.module == "company":
            in_scope = ReportScopeType[self._arguments.scope] == ReportScopeType.within \
                if self._arguments.scope else None
            for company in self._get_items("COMPANY"):
                if self._arguments.add:
                    company_object = self._domain_utils.add_company(session=session,
                                                                    workspace=workspace,
                                                                    name=company,
                                                                    in_scope=in_scope,
                                                                    source=source,
                                                                    verify=False)
                    if not company_object:
                        raise ValueError("adding company '{}' failed".format(company))
                    company_object.in_scope = True
                else:
                    company_object = self._domain_utils.get_company(session=session,
                                                                    workspace=workspace,
                                                                    name=company)
                    if not company_object:
                        raise ValueError("could not find company '{}' in database".format(company))
                    if in_scope:
                        company_object.in_scope = in_scope
                if "network" in self._arguments and self._arguments.network:
                    for network in self._arguments.network:
                        network_object = self._ip_utils.get_network(session=session,
                                                                    workspace=workspace,
                                                                    network=network)
                        if not network_object:
                            raise ValueError("could not find network '{}' in database".format(network))
                        else:
                            company_object.networks.append(network_object)
                if "Network" in self._arguments and self._arguments.Network:
                    for network in self._get_items("Network"):
                        network_object = self._ip_utils.get_network(session=session,
                                                                    workspace=workspace,
                                                                    network=network)
                        if not network_object:
                            raise ValueError("could not find network '{}' in database".format(network))
                        else:
                            company_object.networks.append(network_object)
                if "domain" in self._arguments and self._arguments.domain:
                    for domain in self._arguments.domain:
                        domain_object = self._domain_utils.get_host_name(session=session,
                                                                         workspace=workspace,
                                                                         host_name=domain)
                        if not domain_object:
                            raise ValueError("could not find domain '{}' in database".format(domain))
                        else:
                            company_object.domain_names.append(domain_object.domain_name)
                if "Domain" in self._arguments and self._arguments.Domain:
                    for domain in self._get_items("Domain"):
                        domain_object = self._domain_utils.get_host_name(session=session,
                                                                         workspace=workspace,
                                                                         host_name=domain)
                        if not domain_object:
                            raise ValueError("could not find domain '{}' in database".format(domain))
                        else:
                            company_object.domain_names.append(domain_object.domain_name)

    def _manage_scan(self, session: Session, workspace: Workspace):
        if self._arguments.module == "scan":
            service_states = [ServiceState[item] for item in self._arguments.states]
            if self._arguments.nmap:
                NmapDatabaseImporter(session, workspace, self._arguments.FILE, service_states=service_states).run()
            elif self._arguments.nessus:
                NessusDatabaseImporter(session, workspace, self._arguments.FILE).run()
            elif self._arguments.masscan:
                MasscanDatabaseImporter(session, workspace, self._arguments.FILE).run()

    def _manage_kiscollect(self, session: Session, workspace: Workspace):
        if self._arguments.module == "kiscollect":
            for name in self._parser.api_classes:
                if name in self._arguments and getattr(self._arguments, name):
                    api = self._parser.api_classes[name](session=session,
                                                         workspace=workspace,
                                                         command_id=self._arguments.id)
                    api.collect_api(getattr(self._arguments, name),
                                    output_directory=self._arguments.output_dir)
            for name in self._parser.file_classes:
                if name in self._arguments and getattr(self._arguments, name):
                    api = self._parser.api_classes[name](session=session,
                                                         workspace=workspace,
                                                         command_id=self._arguments.id)
                    api.collect_filesystem(json_files=getattr(self._arguments, name),
                                           output_directory=self._arguments.output_dir)

    def run(self):
        if self._arguments.list:
            self._engine.print_workspaces()
        else:
            if self._arguments.module == "database":
                self._manage_database()
            else:
                with self._engine.session_scope() as session:
                    if "workspace" in self._arguments:
                        workspace = self._domain_utils.get_workspace(session=session, name=self._arguments.workspace)
                        if not workspace:
                            raise WorkspaceNotFound(self._arguments.workspace)
                    else:
                        workspace = None
                    source_str = getattr(self._arguments, "source") if "source" in self._arguments and \
                        getattr(self._arguments, "source") else "user"
                    source = self._domain_utils.add_source(session=session, name=source_str)
                    self._manage_workspace(session=session)
                    self._manage_network(session=session, workspace=workspace, source=source)
                    self._manage_host(session=session, workspace=workspace, source=source)
                    self._manage_service(session=session, workspace=workspace, source=source)
                    self._manage_domain(session=session, workspace=workspace, source=source)
                    self._manage_host_name(session=session, workspace=workspace, source=source)
                    self._manage_email(session=session, workspace=workspace, source=source)
                    self._manage_company(session=session, workspace=workspace, source=source)
                    self._manage_scan(session=session, workspace=workspace)
                    self._manage_kiscollect(session=session, workspace=workspace)


if __name__ == "__main__":
    epilog='''---- USE CASES ----

- I. initialize the database for the first time

$ kismanage database --init

- II. create backup of the entire KIS database and store it in file $backup

$ kismanage database --backup $backup

- III. drop existing database and restore KIS database backup, which is stored in file $backup

$ kismanage database --drop --restore $backup

- IV. re-initialize KIS database

$ kismanage database --drop --init

- V. list of existing workspaces

$ kismanage -l

- IV. add new workspace $workspace

$ kismanage workspace --add $workspace
'''
    parser = KisImportArgumentParser(description=__doc__, formatter_class=SortingHelpFormatter, epilog=epilog)
    parser.add_argument("--debug",
                        action="store_true",
                        help="prints extra information to log file")
    parser.add_argument("-l", "--list", action='store_true', help="list existing workspaces")
    sub_parser = parser.add_subparsers(help='list of available database modules', dest="module")
    parser_kiscollect = sub_parser.add_parser('kiscollect', help='contains functionality used by kiscollect')
    parser_scan = sub_parser.add_parser('scan', help='allows importing scan results from filesystem')
    parser_database = sub_parser.add_parser('database', help='allows setting up and managing the database')
    parser_workspace = sub_parser.add_parser('workspace', help='allows managing workspaces')
    parser_network = sub_parser.add_parser('network', help='allows managing networks')
    parser_host = sub_parser.add_parser('host', help='allows managing hosts')
    parser_service = sub_parser.add_parser('service', help='allows managing services')
    parser_domain = sub_parser.add_parser('domain', help='allows managing second-level domains')
    parser_host_name = sub_parser.add_parser('hostname', help='allows managing host names (sub-domains of second-level'
                                                              'domains')
    parser_email = sub_parser.add_parser('email', help='allows managing emails')
    parser_company = sub_parser.add_parser('company', help='allows managing companies')
    # setup workspace parser
    parser_workspace.add_argument('WORKSPACE', type=str)
    parser_workspace_group = parser_workspace.add_mutually_exclusive_group(required=True)
    parser_workspace_group.add_argument('-a', '--add',
                                        action="store_true",
                                        help="create the given workspace WORKSPACE in KIS database")
    parser_workspace_group.add_argument('-d', '--delete',
                                        action="store_true",
                                        help="delete the given workspace WORKSPACE together with all associated "
                                             "information from KIS database (use with caution)")
    # setup database parser
    parser_database.add_argument('-a', '--add',
                                 action="store_true",
                                 help="create the given workspace WORKSPACE in KIS database")
    parser_database.add_argument("--init",
                                 help="creates tables, views, functions, and triggers for the KIS database",
                                 action="store_true")
    parser_database.add_argument("--drop",
                                 help="drops tables, views, functions, and triggers in the KIS database",
                                 action="store_true")
    parser_database.add_argument("--backup", metavar="FILE", type=str, help="writes database backup to FILE")
    parser_database.add_argument("--restore", metavar="FILE", type=str, help="restores database backup from FILE")
    parser_database.add_argument("--setup",
                                 action="store_true",
                                 help="run initial setup for KIS")
    parser_database.add_argument("--setup-dbg",
                                 action="store_true",
                                 help="like --setup but just prints commands for initial setup for KIS")
    parser_database.add_argument("--test",
                                 action="store_true",
                                 help="test the existing KIS setup")
    # setup network parser
    parser_network.add_argument('NETWORK', type=str, nargs="+")
    parser_network.add_argument("-w", "--workspace",
                                metavar="WORKSPACE",
                                help="use the given workspace",
                                required=True,
                                type=str)
    parser_network_group = parser_network.add_mutually_exclusive_group()
    parser_network_group.add_argument('-a', '--add',
                                      action="store_true",
                                      help="create the given network NETWORK in workspace WORKSPACE")
    parser_network_group.add_argument('-A', '--Add',
                                      action="store_true",
                                      help="read the given networks (one per line) from file NETWORK and add them to "
                                           "workspace WORKSPACE")
    parser_network_group.add_argument('-d', '--delete',
                                      action="store_true",
                                      help="delete the given networks NETWORK together with all associated host "
                                           "information in workspace WORKSPACE (use with caution)")
    parser_network_group.add_argument('-D', '--Delete',
                                      action="store_true",
                                      help="read the given networks (one per line) from file NETWORK and delete them "
                                           "from workspace WORKSPACE. Note that only the given NETWORK but no "
                                           "associated host information is deleted")
    options = [item.name for item in ScopeType]
    options.append("vhost")
    parser_network.add_argument('-s', '--scope', choices=options,
                                type=str,
                                help="set only the given networks in scope and exclude all IP addresses (option "
                                     "explicit). set the given networks including all IP addresses in scope (option "
                                     "all). exclude the given networks including all IP addresses from scope. set "
                                     "only those IP addresses (option vhost) in scope to which an in-scope host "
                                     "name resolves to. note that KIS only actively collects information from "
                                     "in-scope hosts and networks",
                                default=ScopeType.all.name)
    parser_network.add_argument('-c', '--create-hosts',
                                action="store_true",
                                help="add the given networks NETWORK to workspace WORKSPACE and add all IP "
                                     "addresses of these networks to hosts table")
    parser_network.add_argument("--source", metavar="SOURCE", type=str,
                                help="specify the source of the networks to be added")
    # setup host parser
    parser_host.add_argument('IP', type=str, nargs="+")
    parser_host.add_argument("-w", "--workspace",
                             metavar="WORKSPACE",
                             help="use the given workspace",
                             required=True,
                             type=str)
    parser_host_group = parser_host.add_mutually_exclusive_group()
    parser_host_group.add_argument('-a', '--add',
                                   action="store_true",
                                   help="create the given host with IP address IP in workspace WORKSPACE")
    parser_host_group.add_argument('-A', '--Add',
                                   action="store_true",
                                   help="read the given IP addresses (one per line) from file IP and add them to "
                                        "workspace WORKSPACE")
    parser_host_group.add_argument('-d', '--delete',
                                   action="store_true",
                                   help="delete the given host with address IP together with all associated host "
                                        "information in workspace WORKSPACE (use with caution)")
    parser_host_group.add_argument('-D', '--Delete',
                                   action="store_true",
                                   help="read the given IP addresses (one per line) from file IP and delete them "
                                        "together with all associated host information from workspace WORKSPACE")
    parser_host.add_argument('-s', '--scope', choices=[item.name for item in ReportScopeType],
                             help="set the given hosts IP in or out of scope. note that KIS only "
                                  "actively collects information from in-scope hosts and networks ",
                             default=ReportScopeType.within.name)
    parser_host_group.add_argument("--source", metavar="SOURCE", type=str,
                                   help="specify the source of the hosts to be added")
    # setup domain parser
    parser_domain.add_argument('DOMAIN', type=str, nargs="+")
    parser_domain.add_argument("-w", "--workspace",
                               metavar="WORKSPACE",
                               help="use the given workspace",
                               required=True,
                               type=str)
    parser_domain_group = parser_domain.add_mutually_exclusive_group()
    parser_domain_group.add_argument('-a', '--add',
                                     action="store_true",
                                     help="create the given second-level domain DOMAIN in workspace WORKSPACE")
    parser_domain_group.add_argument('-A', '--Add',
                                     action="store_true",
                                     help="read the given second-level domain (one per line) from file DOMAIN and "
                                          "add them to workspace WORKSPACE")
    parser_domain_group.add_argument('-d', '--delete',
                                     action="store_true",
                                     help="delete the given second-level domain DOMAIN together with all associated "
                                          "host names and email addresses from workspace WORKSPACE (use with caution)")
    parser_domain_group.add_argument('-D', '--Delete',
                                     action="store_true",
                                     help="read the given second-level domain (one per line) from file DOMAIN and "
                                          "delete them together with all associated host names and emails from "
                                          "workspace WORKSPACE")
    parser_domain.add_argument('-s', '--scope', choices=[item.name for item in ScopeType],
                               type=str,
                               help="set only the given domains in scope and exclude all other sub-domains (option "
                                    "explicit). set the given domains including all other sub-domains in scope "
                                    "(option all). set only those sub-domains (option vhost) in scope that resolve "
                                    "to an in-scope IP address. exclude the given domains (option exclude). "
                                    "including all other sub-domains from scope. note that KIS only actively "
                                    "collects information from in-scope second-level domain/host name",
                               default=ScopeType.all.name)
    parser_domain.add_argument("--source", metavar="SOURCE", type=str,
                               help="specify the source of the second-level-domains to be added")
    # setup host name parser
    parser_host_name.add_argument('HOSTNAME', type=str, nargs="+")
    parser_host_name.add_argument("-w", "--workspace",
                                  metavar="WORKSPACE",
                                  help="use the given workspace",
                                  required=True,
                                  type=str)
    parser_host_name_group = parser_host_name.add_mutually_exclusive_group()
    parser_host_name_group.add_argument('-a', '--add',
                                        action="store_true",
                                        help="create the given host name in workspace WORKSPACE")
    parser_host_name_group.add_argument('-A', '--Add',
                                        action="store_true",
                                        help="read the given host names (one per line) from file HOSTNAME and add "
                                             "them to workspace WORKSPACE")
    parser_host_name_group.add_argument('-d', '--delete',
                                        action="store_true",
                                        help="delete the given host name HOSTNAME together with all associated email "
                                             "addresses in workspace WORKSPACE (use with caution)")
    parser_host_name_group.add_argument('-D', '--Delete',
                                        action="store_true",
                                        help="read the given host names (one per line) from file HOSTNAME and delete "
                                             "them together with all associated email addresses from workspace "
                                             "WORKSPACE")
    parser_host_name_group.add_argument('--sharphound',
                                        action="store_true",
                                        help="read the given computer.json file created by sharphound and import all "
                                             "computer names into KIS for further intel collection")
    parser_host_name.add_argument('-s', '--scope', choices=[item.name for item in ReportScopeType],
                                  help="set the given host names HOSTNAME in or out of scope. note that KIS only "
                                       "actively collects information from in-scope host names",
                                  default=ReportScopeType.within.name)
    parser_host_name_group.add_argument("--source", metavar="SOURCE", type=str,
                                        help="specify the source of the host name to be added")
    # setup email parser
    parser_email.add_argument('EMAIL', type=str, nargs="+")
    parser_email.add_argument("-w", "--workspace",
                              metavar="WORKSPACE",
                              help="use the given workspace",
                              required=True,
                              type=str)
    parser_email_group = parser_email.add_mutually_exclusive_group(required=True)
    parser_email_group.add_argument('-a', '--add',
                                    action="store_true",
                                    help="create the given email EMAIL in workspace WORKSPACE")
    parser_email_group.add_argument('-A', '--Add',
                                    action="store_true",
                                    help="read the given emails (one per line) from file EMAIL and add them "
                                         "to workspace WORKSPACE")
    parser_email_group.add_argument('-d', '--delete',
                                    action="store_true",
                                    help="delete the given email EMAIL from workspace WORKSPACE (use with caution)")
    parser_email_group.add_argument('-D', '--Delete',
                                    action="store_true",
                                    help="read the given emails (one per line) from file NETWORK and delete them "
                                         "from workspace WORKSPACE")
    parser_email_group.add_argument("--source", metavar="SOURCE", type=str,
                                    help="specify the source of the emails to be added")
    # setup service parser
    parser_service.add_argument("-w", "--workspace",
                                metavar="WORKSPACE",
                                help="use the given workspace",
                                required=True,
                                type=str)
    parser_service_group = parser_service.add_mutually_exclusive_group(required=True)
    parser_service_group.add_argument('-a', '--add',
                                      action="store_true",
                                      help="create the given service in workspace WORKSPACE")
    parser_service_group.add_argument('-d', '--delete',
                                      action="store_true",
                                      help="delete the given service from workspace WORKSPACE (use with caution)")
    parser_service.add_argument("--host",
                                metavar="IP",
                                nargs="+",
                                help="add the service to this host",
                                required=True,
                                type=str)
    parser_service.add_argument("--port",
                                metavar="PORT",
                                help="the service's port number",
                                required=True,
                                type=int)
    parser_service.add_argument("--protocol",
                                choices=[item.name for item in ProtocolType],
                                help="the service's layer 4 protocol",
                                required=True)
    parser_service.add_argument("--service-name",
                                type=str,
                                metavar="NMAP",
                                help="the nmap service name (refer to first column of file "
                                     "/usr/share/nmap/nmap-services)")
    parser_service.add_argument('--tls',
                                action="store_true",
                                help="if set, then the service uses TLS for secure communication")
    parser_service.add_argument("--source", metavar="SOURCE", type=str,
                                help="specify the source of the service to be added")
    # setup company parser
    parser_company.add_argument('COMPANY', type=str, nargs="+")
    parser_company.add_argument("-w", "--workspace",
                                metavar="WORKSPACE",
                                help="use the given workspace",
                                required=True,
                                type=str)
    parser_company_group = parser_company.add_mutually_exclusive_group()
    parser_company_group.add_argument('-a', '--add',
                                      action="store_true",
                                      help="create the given company COMPANY in workspace WORKSPACE")
    parser_company_group.add_argument('-d', '--delete',
                                      action="store_true",
                                      help="delete the given company COMPANY from workspace WORKSPACE "
                                           "(use with caution)")
    parser_company_group.add_argument('--network',
                                      type=str,
                                      nargs="+",
                                      metavar="NETWORK",
                                      help="assign the company COMPANY to the given network NETWORK")
    parser_company_group.add_argument('--Network',
                                      type=str,
                                      nargs="+",
                                      metavar="NETWORK",
                                      help="read the given networks (one per line) from file NETWORK and add them to "
                                           "the company COMPANY")
    parser_company_group.add_argument('--domain',
                                      type=str,
                                      nargs="+",
                                      metavar="DOMAIN",
                                      help="assign the company COMPANY to the given domain DOMAIN")
    parser_company_group.add_argument('--Domain',
                                      type=str,
                                      nargs="+",
                                      metavar="DOMAIN",
                                      help="read the given domains (one per line) from file DOMAIN and add them to "
                                           "the company COMPANY")
    parser_company_group.add_argument('-s', '--scope', choices=[item.name for item in ReportScopeType],
                                      help="set the given company COMPANY in or out of scope. note that KIS only "
                                           "actively collects information from in-scope hosts and networks ")
    parser_company.add_argument("--source", metavar="SOURCE", type=str,
                                help="specify the source of the company to be added")
    # setup scan parser
    parser_scan.add_argument('FILE', type=str, nargs="+")
    parser_scan.add_argument("-w", "--workspace",
                             metavar="WORKSPACE",
                             help="use the given workspace",
                             required=True,
                             type=str)
    parser_scan.add_argument("-s",
                             dest="states",
                             choices=[item.name for item in ServiceState], nargs="*",
                             help="only import services that match one of the following Nmap states (per default only "
                                  "open and closed services are imported). this argument works only in combination "
                                  "with argument --nmap",
                             default=[ServiceState.Open.name, ServiceState.Closed.name])
    parser_scan_group = parser_scan.add_mutually_exclusive_group(required=True)
    parser_scan_group.add_argument('--nmap',
                                   action="store_true",
                                   help="parse the given Nmap output file FILE (XML format) and add the containing "
                                        "information to workspace WORKSPACE")
    parser_scan_group.add_argument('--nessus',
                                   action="store_true",
                                   help="parse the given Nessus output file FILE (XML format) and add the containing "
                                        "information to workspace WORKSPACE")
    parser_scan_group.add_argument('--masscan',
                                   action="store_true",
                                   help="parse the given Masscan output file FILE (XML format) and add the containing "
                                        "information to workspace WORKSPACE")
    # setup kiscollect parser
    parser_kiscollect.add_argument("-w", "--workspace",
                                   metavar="WORKSPACE",
                                   help="use the given workspace",
                                   required=True,
                                   type=str)
    parser_kiscollect.add_argument('-O',
                                   '--output-dir',
                                   metavar='DIR',
                                   required=True,
                                   type=str,
                                   help='output directory for storing intermediate results')
    parser_kiscollect.add_argument("--id",
                                   metavar="ID",
                                   required=True,
                                   help="represents the internal database ID for the command that executes the command",
                                   type=int)
    parser_kiscollect_group = parser_kiscollect.add_mutually_exclusive_group(required=True)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--shodan-host',
                   file_argument_name='--shodan-host-files',
                   api_metavar='IP',
                   api_name='shodan.io',
                   api_class=ShodanHost)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--shodan-network',
                   file_argument_name='--shodan-network-files',
                   api_metavar='NETWORK',
                   api_name='shodan.io',
                   api_class=ShodanNetwork)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--censys-host',
                   file_argument_name='--censys-host-files',
                   api_metavar='IP',
                   api_name='censys.io',
                   api_class=CensysIpv4)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--censys-domain',
                   file_argument_name='--censys-domain-files',
                   api_metavar='DOMAIN',
                   api_name='censys.io',
                   api_class=CensysCertificate)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--hunter',
                   file_argument_name='--hunter-files',
                   api_metavar='DOMAIN',
                   api_name='hunter.io',
                   api_class=Hunter)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--securitytrails',
                   file_argument_name='--securitytrails-files',
                   api_metavar='DOMAIN',
                   api_name='securitytrails.com',
                   api_class=SecurityTrails)
    parser.add_api_query_argument(parser_kiscollect_group,
                                  argument_name='--dnsdumpster',
                                  metavar='DOMAIN',
                                  api_name='dnsdumpster.com',
                                  api_class=DnsDumpster)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--haveibeenbreach',
                   file_argument_name='--haveibeenbreach-files',
                   api_metavar='EMAIL',
                   api_name='haveibeenpwned.com',
                   api_class=HaveIBeenPwnedBreachedAcccount)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--haveibeenpaste',
                   file_argument_name='--haveibeenpaste-files',
                   api_metavar='EMAIL',
                   api_name='haveibeenpwned.com',
                   api_class=HaveIBeenPwnedPasteAcccount)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--builtwith',
                   file_argument_name='--builtwith-files',
                   api_metavar='DOMAIN',
                   api_name='builtwith.com',
                   api_class=BuiltWith)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--hostio',
                   file_argument_name='--hostio-files',
                   api_metavar='DOMAIN',
                   api_name='host.io',
                   api_class=HostIo)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--virustotal',
                   file_argument_name='--virustotal-files',
                   api_metavar='DOMAIN',
                   api_name='virustotal.com',
                   api_class=Virustotal)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--certspotter',
                   file_argument_name='--certspotter-files',
                   api_metavar='DOMAIN',
                   api_name='certspotter.com',
                   api_class=Certspotter)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--crtshdomain',
                   file_argument_name='--crtshdomain-files',
                   api_metavar='DOMAIN',
                   api_name='crt.sh',
                   api_class=CrtshDomain)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--crtshcompany',
                   file_argument_name='--crtshcompany-files',
                   api_metavar='DOMAIN',
                   api_name='crt.sh',
                   api_class=CrtshCompany)
    parser.add_all(parser=parser_kiscollect_group,
                   api_argument_name='--reversewhois',
                   file_argument_name='--reversewhois-files',
                   api_metavar='COMPANY',
                   api_name='viewdns.info',
                   api_class=ViewDns)
    parser.add_api_query_argument(parser_kiscollect_group,
                                  argument_name='--burpsuitepro',
                                  metavar='WEBSITE',
                                  api_name='Burp Suite Professional REST API',
                                  api_class=BurpSuiteProfessional)
    args = parser.parse_args()
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
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    try:
        exit_code = 0
        engine = Engine()
        domain_utils = DomainUtils()
        ipv4_address_utils = IpUtils()
        DeclarativeBase.metadata.bind = engine.engine
        ManageDatabase(engine=engine, arguments=args, parser=parser).run()
    except WorkspaceNotFound as ex:
        print(ex, file=sys.stderr)
        exit_code = 1
    except ApiCollectionFailed as ex:
        print(ex, file=sys.stderr)
        exit_code = 1
    except Exception as e:
        traceback.print_exc(file=sys.stderr)
        exit_code = 1
    sys.exit(exit_code)
