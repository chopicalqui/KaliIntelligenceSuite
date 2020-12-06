#!/usr/bin/python3

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

collectors are executed in a specific order to ensure that information required by one collector (e.g., httpeyewitness)
is already collected by another (e.g., httpgobuster).

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
__version__ = 0.1

import argparse
import sys
import queue
import traceback
import os
import logging
import tempfile
from configs.config import SortingHelpFormatter
from configs.config import BaseConfig
from configs.config import Collector
from collectors.os.collector import CollectorProducer
from collectors.os.collector import CollectorConsumer
from view.curses import CursesUiManager
from view.core import PrintCommmandUi
from database.model import CommandStatus
from database.model import VhostChoice
from database.utils import Engine
from database.utils import DeclarativeBase


if __name__ == "__main__":
    ui_manager = CursesUiManager()
    try:
        engine = Engine()
        DeclarativeBase.metadata.bind = engine.engine
        commands_queue = queue.Queue()
        producer = CollectorProducer(engine, commands_queue, ui_manager)
        epilog='''---- USE CASES ----

- I. http directory brute-force and screenshoting

identify subdomains for a given second-level domain using gobuster, crts.sh, and sublist3r; scan the identified host 
names for web services (TCP ports 80, 443, 8080, and 8443) using nmap; do a directory brute force on each identified 
web service using gobuster; and create screenshots for each identified URL using eyewitness

before starting, specify a workspace $ws (e.g., ws=test) as well as a domain/host name (e.g., 
domains=megacorpone.com or domains=www.megacorpone.com). in addition, all IPv4/IPv6 addresses to which host 
names resolve (0.0.0.0/0) are in scope

import networks into database and execute collection
$ kismanage workspace --add $ws
$ kismanage domain -w $ws --add $domain
$ kismanage network -w $ws --add 0.0.0.0/0     # Any IPv4 address is in scope
$ kiscollect -w $ws -t4 --debug --vhost domain --dnshost --dnssublist3r --crtshdomain --dnsgobuster \\ 
    --tcpnmapdomain 80 443 8080 8443 --httpmsfrobotstxt --httpgobuster --httpeyewitness --crtshcompany

obtain CSV list of identified IPv4/IPv6 addresses and services
$ kisreport host -w $ws --csv

obtain list of identified paths
$ kisreport path -w $ws --csv

obtain report about all executed httpgobuster commands (option -I)
$ kisreport host -w $ws --text -I httpgobuster

export screenshots to $workdir for manual review
$ kisreport file -w $ws --type screenshot -O $workdir

- II. semi-passive subdomain gathering

conservatively collect information (e.g., subdomains, email addresses, IPv4/IPv6 addresses, or IPv4/IPv6 address 
ownerships) about second-level domains using whois, theharvester, and sublist3r as well as via the APIs provided by 
censys.io, dnsdumpster.com, builtwith.com, host.io, and securitytrails.com. in addition, obtain whois information 
for each host name and IPv4/IPv6 address

before you  start: specify a workspace $ws (e.g., ws=osint) and the list of public domains $domains to 
investigate (e.g., domains=megacorpone.com or domains=www.megacorpone.com)

import domains into database and execute collection
$ kismanage workspace --add $ws
$ kismanage domain -w $ws --add $domains
$ kiscollect -w $ws --debug --whoisdomain --whoishost --theharvester --dnsdumpster --reversewhois \\
    --securitytrails --censysdomain --hunter --haveibeenbreach --haveibeenpaste --builtwith --crtshdomain \\
    --virustotal --certspotter --dnssublist3r --dnsspf --dnsdkim --dnsdmark --hostio --dnshostpublic --awsslurp \\
    --crtshcompany

obtain CSV list of identified host names
$ kisreport domain -w $ws --csv

obtain CSV list of identified IPv4/IPv6 addresses
$ kisreport host -w $ws --csv

- III. passive information gathering using censys.io and shodan.io

passively collect information (e.g., subdomains from certificates or service information) about IPv4/IPv6 networks/
addresses using the APIs provided by censys.io and shodan.io

before the start: specify a workspace $ws (e.g., ws=osint) and the list of public 
IPv4/IPv6 networks/addresses $networks to investigate

import IPv4/IPv6 networks/addresses into database and execute collection

$ kismanage workspace --add $ws
$ kismanage network -w $ws --add $networks
$ kiscollect -w $ws --debug --censyshost --shodannetwork

export collected information into microsoft excel
$ kisreport excel /tmp/kis-scan-results.xlsx -w $ws

review scan results of all hosts
$ kisreport host -w $ws --text | less -R

- IV. active intel gathering during penetration test

check services (e.g., FTP, SNMP, MSSQL, etc.) for default credentials using hydra; check access to file sharing 
services (e.g., NFS and SMB) using smbclient, enum4linux, or showmount; check web applications using gobuster, nikto, 
davtest, and eyewitness; obtain TLS information using sslscan, sslyze, and nmap. the collection is performed on 
previously executed nmap scans and a list of in-scope IPv4/IPv6 networks/addresses

before you  start: specify a workspace $ws (e.g., ws=pentest), the paths to the nmap XML files 
(e.g., nmap_paths=/tmp/scan1/*.xml /tmp/scan2/*.xml or nmap_paths=/tmp/scan1/nmap-tcp-all.xml 
/tmp/scan1/nmap-udp-top100.xml) as well as a list of in-scope $networks (e.g., networks=192.168.0.0/24, 
networks=192.168.1.0/24 192.168.1.0/24, networks=192.168.0.1, or networks=192.168.0.1 192.168.0.2)

import nmap scan results as well as in-scope IPv4/IPv6 networks/addresses into database and execute collection
$ kismanage workspace --add $ws
$ kismanage network -w $ws --add $networks
$ kismanage scan -w $ws --nmap $nmap_paths
$ kiscollect -w $ws --debug --strict -t5 --ftphydra --snmphydra --snmpcheck --onesixtyone --showmount --ipmi \\
--nbtscan --ikescan --ldapsearch --oraclesidguess --ntpq --sshnmap --httpgobuster --httpnikto --httphydra --smtpnmap \\
--mysqlhydra --pgsqlhydra --smbnmap --smbmap --smbclient --rpcclient --rpcnmap --rpcinfo --mssqlhydra --mssqlnmap \\
--finger --httpnmap --pop3nmap --imapnmap --tftpnmap --nfsnmap --x11nmap --msrpcenum --mysqlnmap --rdpnmap \\
--httpdavtest --httpwhatweb --httpeyewitness --tlsnmap --smbfilelist --sslyze --sslscan --sshchangeme --httpchangeme \\
--httpmsfrobotstxt --certnmap --ftpnmap --ldapnmap --dnsnmap --ldapnmap --snmpnmap --telnetnmap --vncnmap \\
--ftpfilelist --certopenssl --httpntlmnmap --ikescan --anyservicenmap --smbcme

export collected information into microsoft excel
$ kisreport excel /tmp/kis-scan-results.xlsx -w $ws

export screenshots to $workdir for manual review
$ kisreport file -w $ws --file screenshot -O $workdir

review scan results of hosts with IPv4/IPv6 addresses $ip1 and $ip2
$ kisreport host -w $ws --text --filter +$ip1 +$ip2

review scan results of all hosts except hosts with IPv4/IPv6 addresses $ip1 and $ip2
$ kisreport host -w $ws --text --filter $ip1 $ip2

review scan results of collectors httpnikto and httpgobuster
$ kisreport host -w $ws --text -I httpnikto httpgobuster

review scan results of all collectors except httpnikto and httpgobuster
$ kisreport host -w $ws --text -X httpnikto httpgobuster
'''
        parser = argparse.ArgumentParser(description=__doc__, formatter_class=SortingHelpFormatter, epilog=epilog)
        collector_group = parser.add_argument_group('collectors', 'use the following arguments to collect intelligence')
        ogroup = parser.add_argument_group('general options', 'use the following arguments to specify how intelligence '
                                                              'is collected')
        producer.add_argparser_arguments(collector_group)
        ogroup.add_argument("--http-proxy",
                            type=str,
                            help="specify an HTTP(S) proxy that shall be used by collectors in the format "
                                 "https://$ip:$port")
        ogroup.add_argument("-S", "--print-commands",
                            action="store_true",
                            help="print commands to be executed in console instead of executing them. use this option "
                                 "to see how tools (e.g., dnsenum) are executed")
        ogroup.add_argument("--vhost", choices=[item.name for item in VhostChoice],
                            help="per default all HTTP(S) collectors (e.g., httpnikto, httpgobuster) use the IPv4/IPv6 "
                                 "address to scan the target web application. virtual hosts, which are not accessible "
                                 "via this IPv4/IPv6 address are not scanned. if this argument is specified, then the "
                                 "HTTP(S) service intelligence gathering is performed on all known in-scope host "
                                 "names. use choice 'domain' if you want to collect intel just on the host names or "
                                 "use choice 'all' to collect intel based on both - IPv4/IPv6 addresses and host names")
        ogroup.add_argument("--debug",
                            action="store_true",
                            help="prints extra information to log file")
        ogroup.add_argument("-B", "--batch-mode",
                            action="store_true",
                            help="automatically start, execute, and stop the application without user interaction")
        ogroup.add_argument("--strict",
                            action="store_true",
                            help="collect information only from services that are definitely open (nmap state is "
                                 "open). ports with nmap status 'open|filtered' are ignored. this option decreases the "
                                 "intel collection time but might not be as comprehensive")
        ogroup.add_argument("--restart", choices=[CommandStatus.failed.name,
                                                  CommandStatus.terminated.name,
                                                  CommandStatus.completed.name], nargs='+',
                            help="per default, kiscollect continues the collection from the last interruption point, "
                                 "and ignores all previously failed or terminated commands. With this option the "
                                 "collection of commands with statuses failed, terminated, or completed can be "
                                 "restarted.")
        ogroup.add_argument("-A", "--analyze",
                            action="store_true",
                            help="re-analyze the already collected information. use this option if you updated the "
                                 "verify_results method of a collector and you want to import the update into the "
                                 "database")
        ogroup.add_argument("--filter",
                            type=str,
                            metavar="IP|NETWORK|HOST",
                            nargs='+',
                            help='list of IPv4/IPv6 networks/addresses or domain/host names that shall be processed.'
                                 'per default, mentioned items are excluded. add + in front of item (e.g., +127.0.0.1) '
                                 ' to process only these items')
        ogroup.add_argument("-t", "--threads",
                            type=int,
                            default=1,
                            help="number of threads that execute collection")
        ogroup.add_argument("-w", "--workspace",
                            type=str,
                            required=True,
                            default=1,
                            help="the workspace within the collection is executed")
        ogroup.add_argument("-l", "--list", action='store_true', help="list existing workspaces")
        ogroup.add_argument("-o", dest="output_dir",
                            type=str,
                            help="KIS uses a temporary working directory to store all temporary files. this working "
                                 "directory is deleted when KIS quits. use this argument to specify an alternative "
                                 "working directory, which must be manually deleted. this argument is usually useful "
                                 "during debugging")
        ogroup.add_argument('--cookies', metavar='N', type=str, nargs='+',
                            help='list of cookies that shall be used by collectors (e.g. "Cookie: JSESSION=123")')
        ogroup.add_argument('--user-agent', metavar='AGENT', type=str,
                            help='set a user agent string')
        ogroup.add_argument('-C', '--combo-file', type=str,
                            help='user name password combo files that shall be used by collectors. the internal '
                                 'structure of the combo file varies depending on the used collectors. for example, '
                                 'hydra collectors have a different structure than medusa collectors')
        ogroup.add_argument("-P","--password-file",
                            type=str,
                            help="file containing passwords that shall be used by collectors")
        ogroup.add_argument("-U", "--user-file",
                            type=str,
                            help="file containing user names that shall be used by collectors")
        ogroup.add_argument("-u", "--user",
                            type=str,
                            help="username that shall be used by collectors")
        ogroup.add_argument("-d", "--domain",
                            type=str,
                            help="domain or workgroup that shall be used by collectors")
        ogroup.add_argument("-p", "--password",
                            type=str,
                            help="password that shall be used by collectors")
        ogroup.add_argument("--hashes",
                            action="store_true",
                            help="if specified, then the passwords specified via arguments -p or -P are interpreted as "
                                 "hashes (this adds arguments -m 'LocalHash' to hydra and -m PASS:HASH to medusa)")
        ogroup.add_argument("-L", "--wordlist-files",
                            type=str, nargs='+',
                            help="list of files containing words (e.g., host names or URLs) that shall be used by "
                                 "collectors. usually KIS creates one command per specified word list")
        ogroup.add_argument("-D", "--delay-min", metavar='MIN', dest="force-delay-min",
                            type=int,
                            help="minimum number of seconds between each operating system command executions. if "
                                 "specified together with option -M, then KIS randomly computes a delay between MIN "
                                 "and MAX per execution else, the delay is always MIN")
        ogroup.add_argument("-M", "--delay-max", metavar='MAX', dest="force-delay-max",
                            type=int,
                            help="maximum number of seconds between each operating system command executions. if "
                                 "specified together with option -D, then KIS randomly computes a delay between MIN "
                                 "and MAX per execution else, the delay is always MAX")
        ogroup.add_argument("--dns-server", metavar='SERVER',
                            type=str,
                            help="DNS server (e.g., 8.8.8.8) that shall be used by collectors to query DNS "
                                 "information. otherwise, the system's DNS server is used")
        ogroup.add_argument("--proxychains",
                            action="store_true",
                            help="perform all collections via proxychains")
        ogroup.add_argument("--continue",
                            action="store_true",
                            help="indefinitely repeat the execution of selected collectors")
        if os.geteuid() != 0:
            config = Collector()
            print("{} must be executed with root privileges. afterwards, it is possible to execute "
                  "individual commands with lower privileged users like 'nobody'".format(sys.argv[0]), file=sys.stderr)
            sys.exit(1)
        args = parser.parse_args()
        if args.list:
            engine.print_workspaces()
            sys.exit(1)
        with tempfile.TemporaryDirectory() as temp_dir:
            arguments = vars(args)
            if args.output_dir and not os.path.isdir(args.output_dir):
                ui_manager.set_message("output directory '{}' does not exist!".format(args.output_dir),
                                       file=sys.stderr)
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
            logging.basicConfig(filename=BaseConfig.get_log_file(),
                                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                                datefmt='%Y-%m-%d %H:%M:%S',
                                level=log_level)
            logger = logging.getLogger(sys.argv[0])
            logger.info(" ".join(sys.argv))
            # We start our daemon consumer threads
            if args.print_commands:
                ui_manager = PrintCommmandUi()
                producer.ui_manager = ui_manager
            producer.ui_manager.init_windows()
            for i in range(0, producer.number_of_threads):
                cc = CollectorConsumer(engine,
                                       commands_queue,
                                       producer)
                cc.start()
            producer.start()
            ui_manager.process_user_input()
            producer.join()
            producer.ui_manager.end_window()
    except Exception as e:
        ui_manager.end_window()
        traceback.print_exc(file=sys.stderr)
        ui_manager.log_exception(e)

