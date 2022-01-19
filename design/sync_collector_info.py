#!/usr/bin/python3

"""
this script updates the collector source code to the latest execution priorities based on the collector table in
README.md
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

import os
import re
import fnmatch
import sys
import argparse


class ReadmeEntry:
    def __init__(self, collector_name: str, priority: int):
        self.collector_name = collector_name
        self.priority = priority


class ReadmeParser(dict):
    def __init__(self):
        super().__init__()
        self._readme_path = os.path.abspath("../README.md")
        self._re_entry = re.compile("^\|\s*(?P<priority>[0-9]+)\s*\|\s*(?P<collector_name>[a-zA-Z0-9]+)\s*\|.+$")
        self._parse()

    def _parse(self):
        with open(self._readme_path, "r") as file:
            for line in file.readlines():
                line = line.strip()
                match = self._re_entry.match(line)
                if match:
                    collector_name = match.group("collector_name")
                    priority = int(match.group("priority"))
                    if collector_name not in self:
                        self[collector_name] = ReadmeEntry(collector_name, priority)
                    else:
                        raise ValueError("collector '{}' exists already".format(collector_name))


class AnalyzerBase(dict):

    def __init__(self):
        super().__init__()
        self._home_dir = os.path.abspath("../kis/collectors/os/modules/")

    def _get_collector_files(self, pattern: str = "*.py") -> list:
        for root, dirs, files in os.walk(self._home_dir):
            for basename in files:
                if fnmatch.fnmatch(basename, pattern):
                    filename = os.path.join(root, basename)
                    yield filename


class CollectorFileUpdater(AnalyzerBase):

    def __init__(self, readme_parser: ReadmeParser):
        super().__init__()
        self._readme_parser = readme_parser
        self._load_modules()

    def _load_modules(self):
        for file in self._get_collector_files():
            collector = os.path.splitext(os.path.basename(file))[0]
            if collector in self._readme_parser:
                if collector not in self:
                    self[collector] = file
                else:
                    raise ValueError("collector name '{}' is not unique".format(collector))
            elif collector not in ["core", "__init__"]:
                print("ignoring file: {}".format(file), file=sys.stderr)

    @staticmethod
    def _replace(path: str, priority: int) -> None:
        with open(path, "r") as file:
            content = file.read()
        new_content = re.sub("priority=[0-9]+", "priority={}".format(priority), content)
        if new_content != content:
            with open(path, "w") as file:
                file.write(new_content)

    def run(self):
        for collector, value in self._readme_parser.items():
            file = self[collector]
            self._replace(file, value.priority)


class AnalyzeCollectorTableUpdates(AnalyzerBase):
    def __init__(self):
        super().__init__()
        self._method_table_mapping = {"add_additional_info": ["additional_info", "source"],
                                      "add_certificate": ["domain_name",
                                                          "host_name",
                                                          "source",
                                                          "file",
                                                          "company",
                                                          "email"],
                                      "add_company": ["company", "source"],
                                      "add_credential": ["credential"],
                                      "add_domain_name": ["domain_name", "host_name", "source"],
                                      "add_email": ["email", "domain_name", "host_name", "source"],
                                      "add_execution_info_enum": ["command"],
                                      "add_execution_info_str": ["command"],
                                      "add_file_content": ["file"],
                                      "add_hint": ["command"],
                                      "add_host_host_name_mapping": ["host_host_name_mapping", "source"],
                                      "add_host_name": ["domain_name", "host_name", "source"],
                                      "add_host_name_host_name_mapping": ["host_name_host_name_mapping", "source"],
                                      "add_ipv4_address": ["host", "source"],
                                      "add_ipv4_network": ["network", "source"],
                                      "add_path": ["path", "source", "query"],
                                      "add_query": ["query"],
                                      "add_robots_txt": ["path", "source"],
                                      "add_service": ["service", "source"],
                                      "add_service_method": ["service_method", "source"],
                                      "add_source": ["source"],
                                      "add_url": ["path", "source"]}
        self._collector_methods = {"ftpdotdotpwn": ["add_path"],
                                   "httpdotdotpwn": ["add_path"],
                                   "rdphydra": ["add_credential"],
                                   "smbhydra": ["add_credential"],
                                   "sshhydra": ["add_credential"],
                                   "ftphydra": ["add_credential"],
                                   "mssqlhydra": ["add_credential"],
                                   "pgsqlhydra": ["add_credential"],
                                   "rdphydra": ["add_credential"],
                                   "httphydra": ["add_credential"],
                                   "mysqlhydra": ["add_credential"],
                                   "smbmedusa": ["add_credential"],
                                   "securitytrails": ["add_domain_name"],
                                   "hunter": ["add_email"],
                                   "haveibeenbreach": ["add_additional_info"],
                                   "haveibeenpaste": ["add_additional_info"],
                                   "tcpnmapnetwork": ["add_ipv4_address",
                                                      "add_service",
                                                      "add_domain_name",
                                                      "add_additional_info",
                                                      "add_path",
                                                      "add_service_method",
                                                      "add_certificate"],
                                   "tcpnmapdomain": ["add_ipv4_address",
                                                     "add_service",
                                                     "add_domain_name",
                                                     "add_additional_info",
                                                     "add_path",
                                                     "add_service_method",
                                                     "add_certificate"],
                                   "udpnmapnetwork": ["add_ipv4_address",
                                                      "add_service",
                                                      "add_domain_name",
                                                      "add_additional_info",
                                                      "add_path",
                                                      "add_service_method",
                                                      "add_certificate"],
                                   "udpnmapdomain": ["add_ipv4_address",
                                                     "add_service",
                                                     "add_domain_name",
                                                     "add_additional_info",
                                                     "add_path",
                                                     "add_service_method",
                                                     "add_certificate"],
                                   "mssqlnmap": ["add_service"],
                                   "smbnmap": ["add_path", "add_additional_info", "add_domain_name"],
                                   "smtpnmap": ["add_service_method", "add_domain_name"],
                                   "rpcnmap": ["add_service", "add_domain_name"],
                                   "msrpcenum": ["add_path", "add_additional_info", "add_domain_name"],
                                   "sshnmap": ["add_additional_info"],
                                   "tftpnmap": ["add_path"],
                                   "certnmap": ["add_certificate"],
                                   "httpnmap": ["add_source",
                                                "add_additional_info",
                                                "add_url",
                                                "add_service_method"],
                                   "tcpmasscannetwork": ["add_ipv4_address", "add_service"],
                                   "tcptraceroute": ["add_ipv4_address", "add_host_name"],
                                   "sshchangeme": ["add_credential"],
                                   "httpchangeme": ["add_credential", "add_path"]
                                   }
        self._re_method = re.compile("^.*\.(?P<method>add_.+?)\(.*$")

    def _analyze(self, collector: str, path: str):
        if collector not in self:
            self[collector] = {}
        if collector in self._collector_methods:
            for method in self._collector_methods[collector]:
                for item in self._method_table_mapping[method]:
                    self[collector][item] = None
        else:
            with open(path, "r") as file:
                content = file.readlines()
            for line in content:
                line = line.strip()
                line = line.split("#")[0]
                if line:
                    match = self._re_method.match(line)
                    if match:
                        method = match.group("method")
                        if method in self._method_table_mapping:
                            for item in self._method_table_mapping[method]:
                                self[collector][item] = None

    def run(self):
        # analyze
        for file in self._get_collector_files():
            collector = os.path.splitext(os.path.basename(file))[0]
            if collector not in ["core", "__init__"]:
                self._analyze(collector, file)
        # report
        for collector, methods in self.items():
            print("{}:{}".format(collector, ", ".join(methods.keys())))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mutex_group = parser.add_mutually_exclusive_group(required=True)
    mutex_group.add_argument("-u", "--update",
                             action='store_true',
                             help="update collector priorities based on README.md")
    mutex_group.add_argument("-a", "--analyze",
                             action='store_true',
                             help="report which collectors use which update methods")
    args = parser.parse_args()
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    if args.update:
        parser = ReadmeParser()
        updater = CollectorFileUpdater(parser)
        updater.run()
    elif args.analyze:
        analyzer = AnalyzeCollectorTableUpdates()
        analyzer.run()
