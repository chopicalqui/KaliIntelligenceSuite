# -*- coding: utf-8 -*-
""""This file contains common functionality to access configuration files."""

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
import json
import configparser
from argparse import RawDescriptionHelpFormatter
from operator import attrgetter
from typing import List


class SortingHelpFormatter(RawDescriptionHelpFormatter):
    def add_arguments(self, actions):
        actions = sorted(actions, key=attrgetter('option_strings'))
        super(SortingHelpFormatter, self).add_arguments(actions)


class MissingApiCredentialsError(Exception):
    """
    This exception shall be used by API classes if the API credentials are not set in the configuration file
    kis/configs/api.config
    """

    def __init__(self, message: str):
        super().__init__(message)


class BaseConfig:
    """This class implements common functionality to access configuration files."""

    ENV_USER = "KIS_DB_USER"
    ENV_PASSWORD_FILE = "KIS_DB_PASSWORD_FILE"
    ENV_HOST = "KIS_DB_HOST"
    ENV_PORT = "KIS_DB_PORT"
    ENV_DB_NAME = "KIS_DB_NAME"
    ENV_LOG_PATH = "KIS_LOG_PATH"

    def __init__(self, config_file: str):
        self._config_file = config_file
        self._repo_home = BaseConfig.get_repo_home()
        self._script_home = BaseConfig.get_script_home()
        self._config_dir = os.path.dirname(__file__)
        self.full_path = os.path.join(self._config_dir, config_file)
        if not os.path.exists(self.full_path):
            raise FileNotFoundError("The database configuration file  \"{}\" does not exist!".format(self.full_path))
        self._config = configparser.ConfigParser()
        self._config.read(self.full_path)

    @staticmethod
    def get_log_file() -> str:
        path = BaseConfig.get_script_home()
        if BaseConfig.ENV_LOG_PATH in os.environ:
            path = os.environ[BaseConfig.ENV_LOG_PATH]
        return os.path.join(path, "kaliintelsuite.log")

    @staticmethod
    def get_script_home() -> str:
        return os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))

    @staticmethod
    def get_repo_home() -> str:
        return os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", ".."))

    @property
    def config(self):
        return self._config

    def get_config_str(self, section: str, name: str) -> str:
        return self._config[section][name].format(repo_home=self._repo_home,
                                                  script_home=self._script_home)

    def get_config_int(self, section: str, name: str) -> int:
        return self._config[section].getint(name)

    def write(self) -> None:
        with open(self.full_path, "w") as file:
            self._config.write(file)\

    @staticmethod
    def is_docker():
        return os.path.exists("/.dockerenv")


class Database(BaseConfig):
    """This class contains the ConfigParser object for the database"""

    def __init__(self, production: bool = True):
        super().__init__("database.config")
        self._production = production

    @property
    def dialect(self) -> str:
        return self.get_config_str("production", "dialect")

    @property
    def db_envs(self) -> dict:
        result = {}
        if self.is_docker():
            result = {Database.ENV_PORT: self.env_port,
                      Database.ENV_HOST: self.env_host,
                      Database.ENV_DB_NAME: self.env_database,
                      Database.ENV_USER: self.env_username,
                      Database.ENV_PASSWORD_FILE: self.env_password_file}
        return result

    @property
    def env_host(self) -> str:
        result = None
        if Database.ENV_HOST in os.environ:
            result = os.environ[Database.ENV_HOST]
        return result

    @property
    def host(self) -> str:
        result = self.env_host
        if not result:
            result = self.get_config_str("production", "host")
        return result

    @property
    def env_port(self) -> int:
        result = None
        if Database.ENV_PORT in os.environ:
            result = int(os.environ[Database.ENV_PORT])
        return result

    @property
    def port(self) -> int:
        result = self.env_port
        if not result:
            result = self.get_config_int("production", "port")
        return result

    @property
    def env_username(self) -> str:
        result = None
        if Database.ENV_USER in os.environ:
            result = os.environ[Database.ENV_USER]
        return result

    @property
    def username(self) -> str:
        result = self.env_username
        if not result:
            result = self.get_config_str("production", "username")
        return result

    @property
    def env_password_file(self) -> str:
        result = None
        if Database.ENV_PASSWORD_FILE in os.environ:
            result = os.environ[Database.ENV_PASSWORD_FILE]
        return result

    @property
    def password(self) -> str:
        password_file = self.env_password_file
        if password_file:
            with open(password_file, "r") as file:
                content = file.readlines()
            if len(content) != 1:
                raise ValueError("the password file '{}' should only contain one line.".format(password_file))
            result = content[0].strip()
        else:
            result = self.get_config_str("production", "password")
        return result

    @password.setter
    def password(self, value: str) -> None:
        self._config["production"]["password"] = value

    @property
    def env_database(self) -> str:
        result = None
        if Database.ENV_DB_NAME in os.environ:
            result = os.environ[Database.ENV_DB_NAME]
        return result

    @property
    def production_database(self) -> str:
        result = self.env_database
        if not result:
            result = self.get_config_str("production", "database")
        return result

    @property
    def test_database(self) -> str:
        return self.get_config_str("unittesting", "database")

    @property
    def database(self) -> str:
        return self.production_database if self._production else self.test_database

    @property
    def connection_string(self):
        return "{}://{}:{}@{}:{}/{}".format(self.dialect,
                                            self.username,
                                            self.password,
                                            self.host,
                                            self.port,
                                            self.database)


class Collector(BaseConfig):
    """This class contains the ConfigParser object for the database."""

    def __init__(self):
        super().__init__("collectors.config")
        self._default_user_agent_string = self.get_config_str("general", "user_agent_string")
        self._default_dns_server = self.get_config_str("general", "default_dns_server")
        self._path_proxychains = self.get_config_str("file_paths", "proxychains")
        self._path_smb4linux = self.get_config_str("file_paths", "enum4linux")
        self._path_gobuster = self.get_config_str("file_paths", "gobuster")
        self._path_wpscan = self.get_config_str("file_paths", "wpscan")
        self._path_medusa = self.get_config_str("file_paths", "medusa")
        self._path_hydra = self.get_config_str("file_paths", "hydra")
        self._path_nikto = self.get_config_str("file_paths", "nikto")
        self._path_eyewitness = self.get_config_str("file_paths", "eyewitness")
        self._path_showmount = self.get_config_str("file_paths", "showmount")
        self._path_onesixtyone = self.get_config_str("file_paths", "onesixtyone")
        self._path_snmpcheck = self.get_config_str("file_paths", "snmpcheck")
        self._path_snmpwalk = self.get_config_str("file_paths", "snmpwalk")
        self._path_nmap = self.get_config_str("file_paths", "nmap")
        self._path_smtpusername = self.get_config_str("file_paths", "smtpuserenum")
        self._path_smbclient = self.get_config_str("file_paths", "smbclient")
        self._path_dotdotpwn = self.get_config_str("file_paths", "dotdotpwn")
        self._path_host = self.get_config_str("file_paths", "host")
        self._path_openssl = self.get_config_str("file_paths", "openssl")
        self._path_dnsrecon = self.get_config_str("file_paths", "dnsrecon")
        self._path_dnsenum = self.get_config_str("file_paths", "dnsenum")
        self._path_nbtscan = self.get_config_str("file_paths", "nbtscan")
        self._path_sqlmap = self.get_config_str("file_paths", "sqlmap")
        self._path_msfconsole = self.get_config_str("file_paths", "msfconsole")
        self._path_ikescan = self.get_config_str("file_paths", "ikescan")
        self._path_finger = self.get_config_str("file_paths", "finger")
        self._path_rpcinfo = self.get_config_str("file_paths", "rpcinfo")
        self._path_rpcclient = self.get_config_str("file_paths", "rpcclient")
        self._path_dig = self.get_config_str("file_paths", "dig")
        self._path_vncviewer = self.get_config_str("file_paths", "vncviewer")
        self._path_sidguess = self.get_config_str("file_paths", "sidguess")
        self._path_ntpdate = self.get_config_str("file_paths", "ntpdate")
        self._path_ldapsearch = self.get_config_str("file_paths", "ldapsearch")
        self._path_tcptraceroute = self.get_config_str("file_paths", "tcptraceroute")
        self._path_whois = self.get_config_str("file_paths", "whois")
        self._path_theharvester = self.get_config_str("file_paths", "theharvester")
        self._path_ping = self.get_config_str("file_paths", "ping")
        self._path_ntpq = self.get_config_str("file_paths", "ntpq")
        self._path_slurp = self.get_config_str("file_paths", "slurp")
        self._path_python3 = self.get_config_str("file_paths", "python3")
        self._path_davtest = self.get_config_str("file_paths", "davtest")
        self._path_whatweb = self.get_config_str("file_paths", "whatweb")
        self._path_smbmap = self.get_config_str("file_paths", "smbmap")
        self._path_curl = self.get_config_str("file_paths", "curl")
        self._path_sslyze = self.get_config_str("file_paths", "sslyze")
        self._path_sslscan = self.get_config_str("file_paths", "sslscan")
        self._path_kisimport = self.get_config_str("file_paths", "kisimport")
        self._path_sublist3r = self.get_config_str("file_paths", "sublist3r")
        self._path_wapiti = self.get_config_str("file_paths", "wapiti")
        self._path_changeme = self.get_config_str("file_paths", "changeme")
        self._path_masscan = self.get_config_str("file_paths", "masscan")
        self._path_crackmapexec = self.get_config_str("file_paths", "crackmapexec")
        self._path_amass = self.get_config_str("file_paths", "amass")
        self._path_crobat = self.get_config_str("file_paths", "crobat")
        self._path_kiterunner = self.get_config_str("file_paths", "kiterunner")
        self._eyewitness_proxy_ip = self.get_config_str("eyewitness", "proxy_ip")
        self._eyewitness_proxy_port = self.get_config_str("eyewitness", "proxy_port")
        self._wordlist_gobuster_dir = self.get_config_str("default_wordlists", "gobuster_dir")
        self._wordlist_gobuster_dns = self.get_config_str("default_wordlists", "gobuster_dns")
        self._wordlist_kiterunner = self.get_config_str("default_wordlists", "kiterunner_file")
        self._ftp_default_credentials = self.get_config_str("default_wordlists", "ftp_default_credentials")
        self._mssql_default_credentials = self.get_config_str("default_wordlists", "mssql_default_credentials")
        self._mysql_default_credentials = self.get_config_str("default_wordlists", "mysql_default_credentials")
        self._pgsql_default_credentials = self.get_config_str("default_wordlists", "pgsql_default_credentials")
        self._snmp_default_credentials = self.get_config_str("default_wordlists", "snmp_default_credentials")
        self._vnc_default_credentials = self.get_config_str("default_wordlists", "vnc_default_credentials")
        self._http_default_passwords = self.get_config_str("default_wordlists", "http_default_passwords")
        self._apache_tomcat_default_passwords = self.get_config_str("default_wordlists",
                                                                    "apache_tomcat_default_passwords")
        self._slurp_permutations_file = self.get_config_str("default_wordlists", "slurp_permutations_file")
        self._sidguess_default_wordlist = self.get_config_str("default_wordlists", "sidguess_default")
        self._apache_tomcat_default_users = self.get_config_str("default_wordlists", "apache_tomcat_default_users")
        self._http_default_users = self.get_config_str("default_wordlists", "http_default_users")
        self._webserver_apache = self.get_config_str("default_wordlists", "webserver_apache")
        self._webserver_apache_tomcat = self.get_config_str("default_wordlists", "webserver_apache_tomcat")
        self._webserver_microsoft_iis = self.get_config_str("default_wordlists", "webserver_microsoft_iis")
        self._webserver_netware = self.get_config_str("default_wordlists", "webserver_netware")
        self._webserver_nginx = self.get_config_str("default_wordlists", "webserver_nginx")
        self._webserver_php = self.get_config_str("default_wordlists", "webserver_php")
        self._webserver_sap = self.get_config_str("default_wordlists", "webserver_sap")
        self._webserver_weblogic = self.get_config_str("default_wordlists", "webserver_weblogic")
        self._webserver_websphere = self.get_config_str("default_wordlists", "webserver_websphere")
        self._legal_entities = json.loads(self.get_config_str("company", "entities"))
        self._re_legal_entities = "\s(({}))(([\s\.])|($))".format(")|(".join(self._legal_entities))
        self._irrelevant_http_files = json.loads(self.get_config_str("http", "irrelevant_files"))

    @property
    def default_user_agent(self) -> str:
        return self._default_user_agent_string

    @property
    def legal_entities(self) -> List[str]:
        return self._legal_entities

    @property
    def re_legal_entities(self) -> str:
        return self._re_legal_entities

    @property
    def irrelevant_http_files(self) -> str:
        return self._irrelevant_http_files

    def get_organization_re(self, whois_attributes: list = None) -> re.Pattern:
        """
        This method compiles the regular expression to extract company information from whois entries
        """
        if whois_attributes:
            result = re.compile("^\\s*(({}))\\s*:\\s*(?P<name>.+?{}).*$".format(")|(".join(whois_attributes),
                                                                                self._re_legal_entities),
                                re.IGNORECASE)
        else:
            result = re.compile("^\\s*(?P<name>.+?{}).*$".format(self._re_legal_entities), re.IGNORECASE)
        return result


class ApiConfig(BaseConfig):
    """This class contains the config parser object for APIs"""

    def __init__(self):
        super().__init__("api.config")

    @property
    def proxy_settings(self) -> dict:
        result = None
        proxy_ip = self.get_config_str("http-proxy", "proxy_ip")
        proxy_port = self.get_config_str("http-proxy", "proxy_port")
        if proxy_ip and proxy_port:
            result = {"http": "http://{}:{}".format(proxy_ip, proxy_port),
                      "https": "https://{}:{}".format(proxy_ip, proxy_port)}
        return result


class ScannerConfig(BaseConfig):
    """This class contains the config parser object for APIs"""

    def __init__(self):
        super().__init__("scanner.config")

    def _split_ports(self, ports: List[str]) -> List[str]:
        return_value = []
        for item in list(ports):
            tmp = [i.strip() for i in item.split(",")] if "," in item else item.split()
            return_value.extend(tmp)
        return return_value

    @property
    def tcp_interesting_ports(self) -> List[str]:
        return self._split_ports(self._config["InterestingTcpPorts"].values())

    @property
    def udp_interesting_ports(self) -> List[str]:
        return self._split_ports(self._config["InterestingUdpPorts"].values())

    @property
    def tcp_nse_scripts(self) -> List[str]:
        return [item.strip() for item in self.get_config_str("NMmapScripts", "tcp").split(",")]

    @property
    def udp_nse_scripts(self) -> List[str]:
        return [item.strip() for item in self.get_config_str("NMmapScripts", "udp").split(",")]

    @property
    def nmap_tcp_options(self) -> List[str]:
        return [item.strip() for item in self.get_config_str("NmapSettings", "tcp_options").split(" ")]

    @property
    def nmap_udp_options(self) -> List[str]:
        return [item.strip() for item in self.get_config_str("NmapSettings", "udp_options").split(" ")]

    @property
    def nmap_general_settings(self) -> List[str]:
        return self.get_config_str("NmapSettings", "default_options").split(" ")

    @property
    def masscan_general_settings(self) -> List[str]:
        return self.get_config_str("MasscanSettings", "default_options").split(" ")


class DomainConfig(BaseConfig):
    """This class contains the config parser object for domains"""

    def __init__(self):
        super().__init__("domain.config")
        self.environments = {}
        raw_config = json.loads(self.config.get("general", "environment_wordlist"))
        for key, values in raw_config.items():
            self.environments[key] = []
            for item in values:
                self.environments[key].append(re.compile(item, re.IGNORECASE))

    def get_environment(self, host_name) -> str:
        """
        This method takes the given host name object and determines the environment.
        """
        result = "Production"
        full_name = host_name.full_name
        for key, values in self.environments.items():
            for item in values:
                if item.match(full_name):
                    result = key
                    break
        return result
