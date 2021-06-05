#!/usr/bin/env python3

"""
this script implements all functionalities to query the KIS database and analyze\nthe information gathering results
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
import sys
from collectors.core import DomainUtils
from database.model import FileType
from database.model import PathType
from database.model import ReportScopeType
from database.model import ReportVisibility
from database.model import WorkspaceNotFound
from database.model import ScopeType
from configs.config import SortingHelpFormatter
from database.utils import Engine
from database.report import ReportGenerator
from database.report import ReportLanguage
from database.report import ExcelReport
from database.utils import DeclarativeBase


if __name__ == "__main__":
    epilog = '''---- USE CASES ----

- I. export all structured information to a microsoft excel file

the following command queries all structured information about all 
positional arguments from workspace $ws and exports it to the 
microsoft excel file /tmp/report.xlsx

the icrosoft excel file can then be used for further analyses or reporting

$ kisreport excel /tmp/report.xlsx -w $ws

- II. obtain list of in-scope host names

the following command returns a unique list of in-scope host names from 
workspace $ws. the returned list could be used as input for other 
external intelligence gathering tools

$ kisreport domain -w $ws --csv --scope within | csvcut -c "Host Name"

alternatively, you could query all second-level domains from workspace 
$ws to identify those domains that are relevant for the assessment. 

$ kisreport domain -w $ws --csv | csvcut -c "Second-Level Domain"

the relevant domains can then be set in-scope using the script kismanage. 
after setting them in-scope, it is possible to perform active intelligence 
gathering on them using script kiscollect

- III. obtain list of URLs

the following command returns a unique list of host names from workspace 
$ws. the returned list could be used as input for other external 
intelligence gathering tools

the following command returns a unique list of URLs, which could be used as 
input for other external intelligence gathering tools (e.g., aquatone)

$ kisreport path -w $ws --scope within --type Http --csv | csvcut -H -c 15 | sed -e 's/^"//' -e 's/"$//' | sort -u

- IV. obtain all hosts/services where the collector http was executed

the following command returns all IPv4/IPv6 addresses on which the collector  
httpnikto was executed. the text output also includes the output of httpnikto

$ kisreport host -w $ws --text -I httpnikto | less -R

the following command returns all virtual hosts/services on which the 
collector httpnikto was executed. the text output also includes the output of 
httpnikto

$ kisreport vhost -w $ws --text -I httpnikto | less -R

- V. show all results for a specific IPv4 address or host name

the following command returns all gathered information from workspace $ws 
for IPv4 address $ip

$ kisreport host -w $ws --text --filter +$ip | less -R

the following command returns all gathered information from workspace $ws 
for host name $hostname

$ kisreport vhost -w $ws --text --filter +$hostname | less -R

- VI. search all collector raw outputs for a specific key word

the following command searches all command outputs of $ws for the 
keyword $keyword

$ kisreport command -w $ws --text | grep $keyword

the following command searches all httpnikto outputs of $ws for the 
keyword $keyword

$ kisreport command -w $ws --text -I httpnikto | grep $keyword

- VII. export raw scan results

the following command exports all screenshots located in workspace $ws and
taken by collector httpeyewitness to the output directory $outdir

$ kisreport file -w $ws --type screenshot -I httpeyewitness -o $outdir

the following command exports all raw xml scan files of collector tcpnmap located 
in workspace $ws to the output directory $outdir

$ kisreport file -w $ws --type xml -I tcpnmap -o $outdir
'''
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=SortingHelpFormatter, epilog=epilog)
    parser.add_argument("--nocolor", action="store_true", help="disable colored output")
    parser.add_argument("-l", "--list", action='store_true', help="list existing workspaces")
    sub_parser = parser.add_subparsers(help='list of available database modules', dest="module")
    parser_additional_info = sub_parser.add_parser('additional-info', help='allows querying additional information '
                                                                           '(e.g., HTTP headers)')
    parser_breach = sub_parser.add_parser('breach', help='allows querying information about identified breaches '
                                                         '(e.g., via haveibeenpwned.com)')
    parser_credential = sub_parser.add_parser('credential', help='allows querying information about identified '
                                                                 'credentials (e.g., ftp or snmp)')
    parser_command = sub_parser.add_parser('command', help='allows querying information about executed '
                                                           'OS commands')
    parser_domain = sub_parser.add_parser('domain', help='allows querying information about second-level domains and '
                                                         'host names')
    parser_cname = sub_parser.add_parser('cname', help='allows querying DNS canonical names (CNAMES). this report can '
                                                       'be used to identify potential subdomain takeovers')
    parser_email = sub_parser.add_parser('email', help='allows querying information about emails')
    parser_company = sub_parser.add_parser('company', help='allows querying information about companies')
    parser_excel = sub_parser.add_parser('excel', help='allows writing all identified information into a '
                                                       'microsoft excel file')
    parser_final = sub_parser.add_parser('final', help='allows writing final report tables into microsoft excel file')
    parser_file = sub_parser.add_parser('file', help='allows querying information about collected files (e.g., raw '
                                                     'scan results, certificates, etc.)')
    parser_host = sub_parser.add_parser('host', help='allows querying information about hosts')
    parser_network = sub_parser.add_parser('network', help='allows querying information about networks')
    parser_path = sub_parser.add_parser('path', help='allows querying information about identified paths (e.g., urls)')
    parser_vhost = sub_parser.add_parser('vhost', help='allows querying information about virtual hosts (vhost)')
    parser_vulnerability = sub_parser.add_parser('vulnerability', help='allows querying information about identified '
                                                                       'vulnerabilities (e.g., via shodan.io or '
                                                                       'nessus)')
    parser_tls = sub_parser.add_parser('tls', help='allows querying information about identified tls configurations')
    parser_cert = sub_parser.add_parser('cert', help='allows querying information about identified certificates')
    # setup host parser
    parser_host.add_argument("-w", "--workspaces",
                             metavar="WORKSPACE",
                             help="query the given workspaces",
                             nargs="+",
                             required=True,
                             type=str)
    parser_host_group = parser_host.add_mutually_exclusive_group(required=True)
    parser_host_group.add_argument('--text', action='store_true',
                                   help='returns gathered information including all collector outputs as text')
    parser_host_group.add_argument('--csv', action='store_true',
                                   help='returns gathered information in csv format')
    parser_host_group.add_argument('--igrep', type=str, nargs='+', metavar="REGEX",
                                   help="print command outputs that match the given string or Python3 regular "
                                        "expressions REGEX. matching is case insensitive. use named group 'output' "
                                        "to just capture the content of this named group")
    parser_host_group.add_argument('--grep', type=str, nargs='+', metavar="REGEX",
                                   help="print command outputs that match the given string or Python3 regular "
                                        "expressions REGEX. matching is case sensitive. use named group 'output' "
                                        "to just capture the content of this named group")
    parser_host.add_argument('--not', dest="grep_not", action='store_true',
                             help='negate the filter logic and only show those IP addresses that do not match the '
                                  '--igrep or --grep argument.')
    parser_host.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                             help='list of IP addresses, IP networks, second-level domains (e.g., megacorpone.com), or '
                                  'host names (e.g., www.megacorpone.com) whose information shall be returned.'
                                  'per default, mentioned items are excluded. add + in front of each item '
                                  '(e.g., +192.168.0.1) to return only these items')
    parser_host.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                             help='return only networks or hosts that are in scope (within) or out of scope '
                                  '(outside). per default, all information is returned')
    parser_host.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                             help='return only relevant (relevant) or potentially irrelevant (irrelevant) information '
                                  'in text output (argument --text). examples of potentially irrelevant information '
                                  'are hosts with no open ports or operating system commands that did not return '
                                  'any results. per default, all information is returned')
    parser_host.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                             help='list of collector names (e.g., httpnikto) whose outputs should not be returned in '
                                  'text mode (see argument --text). use argument value "all" to exclude all '
                                  'collectors. per default, no collectors are excluded')
    parser_host.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                             help='list of collector names whose outputs should be returned in text mode (see '
                                  'argument --text). per default, all collector information is returned')
    # setup domain parser
    parser_domain.add_argument("-w", "--workspaces",
                               metavar="WORKSPACE",
                               help="query the given workspaces",
                               nargs="+",
                               required=True,
                               type=str)
    parser_domain_group = parser_domain.add_mutually_exclusive_group(required=True)
    parser_domain_group.add_argument('--text', action='store_true',
                                     help='returns gathered information including all collector outputs as text')
    parser_domain_group.add_argument('--csv', action='store_true',
                                     help='returns gathered information in csv format')
    parser_domain_group.add_argument('--igrep', type=str, nargs='+', metavar="REGEX",
                                     help="print command outputs that match the given string or Python3 regular "
                                          "expressions REGEX. matching is case insensitive. use named group 'output' "
                                          "to just capture the content of this named group")
    parser_domain_group.add_argument('--grep', type=str, nargs='+', metavar="REGEX",
                                     help="print command outputs that match the given string or Python3 regular "
                                          "expressions REGEX. matching is case sensitive. use named group 'output' "
                                          "to just capture the content of this named group")
    parser_domain.add_argument('--not', dest="grep_not", action='store_true',
                               help='negate the filter logic and only show those domain names that do not match the '
                                    '--igrep or --grep argument.')
    parser_domain.add_argument('--filter', metavar='IP|DOMAIN', type=str, nargs='*',
                               help='list of IP addresses or second-level domains (e.g., megacorpone.com) whose '
                                    'information shall be returned. per default, mentioned items are excluded. '
                                    'add + in front of each item (e.g., +megacorpone.com) to return only these items')
    parser_domain.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                               help='return only second-level domains that are in scope (within) or out of scope '
                                    '(outside). per default, all information is returned')
    parser_domain.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                               help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                    'information (e.g., executed commands that did not return any information) in text '
                                    'output (argument --text). per default, all information is returned')
    parser_domain.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                               help='list of collector names (e.g., dnshost) whose outputs should not be returned in '
                                    'text mode (see argument --text). use argument value "all" to exclude all '
                                    'collectors. per default, no collectors are excluded')
    parser_domain.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                               help='list of collector names whose outputs should be returned in text mode (see '
                                    'argument --text). per default, all collector information is returned')
    # setup cname parser
    parser_cname.add_argument("-w", "--workspaces",
                              metavar="WORKSPACE",
                              help="query the given workspaces",
                              nargs="+",
                              required=True,
                              type=str)
    parser_cname.add_argument('--csv',
                              required=True,
                              action='store_true',
                              help='returns gathered information in csv format')
    parser_cname.add_argument('--filter', metavar='IP|DOMAIN', type=str, nargs='*',
                              help='list of IP addresses or second-level domains (e.g., megacorpone.com) whose '
                                   'information shall be returned. per default, mentioned items are excluded. '
                                   'add + in front of each item (e.g., +megacorpone.com) to return only these items')
    parser_cname.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                              help='return only second-level domains that are in scope (within) or out of scope '
                                   '(outside). per default, all information is returned')
    # setup network parser
    parser_network.add_argument("-w", "--workspaces",
                                metavar="WORKSPACE",
                                help="query the given workspaces",
                                nargs="+",
                                required=True,
                                type=str)
    parser_network_group = parser_network.add_mutually_exclusive_group(required=True)
    parser_network_group.add_argument('--text', action='store_true',
                                      help='returns gathered information including all collector outputs as text')
    parser_network_group.add_argument('--csv', action='store_true',
                                      help='returns gathered information in csv format')
    parser_network_group.add_argument('--igrep', type=str, nargs='+', metavar="REGEX",
                                      help="print command outputs that match the given string or Python3 regular "
                                           "expressions REGEX. matching is case insensitive. use named group 'output' "
                                           "to just capture the content of this named group")
    parser_network_group.add_argument('--grep', type=str, nargs='+', metavar="REGEX",
                                      help="print command outputs that match the given string or Python3 regular "
                                           "expressions REGEX. matching is case sensitive. use named group 'output' "
                                           "to just capture the content of this named group")
    parser_network.add_argument('--not', dest="grep_not", action='store_true',
                                help='negate the filter logic and only show those IP networks that do not match the '
                                     '--igrep or --grep argument.')
    parser_network.add_argument('--filter', metavar='NETWORK', type=str, nargs='*',
                                help='list of IPv4 networks (e.g., 192.168.0.0/24) whose information shall be '
                                     'returned. per default, mentioned items are excluded. add + in front of each '
                                     'item (e.g., +192.168.0.0/24) to return only these items')
    parser_network.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                help='return only networks that are in scope (within) or out of scope (outside). '
                                     'per default, all information is returned')
    parser_network.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                                help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                     'information (e.g., executed commands that did not return any information) in '
                                     'text output (argument --text) per default, all information is returned')
    parser_network.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                help='list of collector names (e.g., tcpnmap) whose outputs should not be returned in '
                                     'text mode (see argument --text). use argument value "all" to exclude all '
                                     'collectors. per default, no collectors are excluded')
    parser_network.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                help='list of collector names whose outputs should be returned in text mode (see '
                                     'argument --text). per default, all collector information is returned')
    # setup path parser
    parser_path.add_argument("-w", "--workspaces",
                             metavar="WORKSPACE",
                             help="query the given workspaces",
                             nargs="+",
                             required=True,
                             type=str)
    parser_path.add_argument('--csv',
                             required=True,
                             action='store_true',
                             help='returns gathered information in csv format')
    parser_path.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                             help='list of IP addresses, IP networks, second-level domains (e.g., megacorpone.com), or '
                                  'host names (e.g., www.megacorpone.com) whose information shall be returned.'
                                  'per default, mentioned items are excluded. add + in front of each item '
                                  '(e.g., +192.168.0.1) to return only these items')
    parser_path.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                             help='return only information about in scope (within) or out of scope (outside) items. '
                                  'per default, all information is returned')
    parser_path.add_argument('--type',
                             choices=[item.name for item in PathType],
                             nargs="+",
                             help='return only path items of the given type. per default, all information is returned')
    # setup credential parser
    parser_credential.add_argument("-w", "--workspaces",
                                   metavar="WORKSPACE",
                                   help="query the given workspaces",
                                   nargs="+",
                                   required=True,
                                   type=str)
    parser_credential.add_argument('--csv',
                                   required=True,
                                   action='store_true',
                                   help='returns gathered information in csv format')
    parser_credential.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME|EMAIL', type=str, nargs='*',
                                   help='list of IP addresses, IP networks, second-level domains (e.g., '
                                        'megacorpone.com), email address, or host names (e.g., www.megacorpone.com) '
                                        'whose information shall be returned.per default, mentioned items are. '
                                        'excluded add + in front of each item (e.g., +192.168.0.1) to return only '
                                        'these items')
    parser_credential.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                   help='return only information about in scope (within) or out of scope (outside) '
                                        'items. per default, all information is returned')
    # setup email parser
    parser_email.add_argument("-w", "--workspaces",
                              metavar="WORKSPACE",
                              help="query the given workspaces",
                              nargs="+",
                              required=True,
                              type=str)
    parser_email_group = parser_email.add_mutually_exclusive_group(required=True)
    parser_email_group.add_argument('--text', action='store_true',
                                    help='returns gathered information including all collector outputs as text')
    parser_email_group.add_argument('--csv', action='store_true',
                                    help='returns gathered information in csv format')
    parser_email.add_argument('--filter', metavar='DOMAIN|HOSTNAME|EMAIL', type=str, nargs='*',
                              help='list of second-level domains (e.g., megacorpone.com), host names (e.g., '
                                   'www.megacorpone.com), or email addresses whose information shall be returned. '
                                   'per default, mentioned items are excluded. add + in front of each item '
                                   '(e.g., +megacorpone.com) to return only these items')
    parser_email.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                              help='return only in scope (within) or out of scope (outside) items. '
                                   'per default, all information is returned')
    parser_email.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                              help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                   'information (e.g., executed commands that did not return any information) in text '
                                   'output (argument --text). per default, all information is returned')
    parser_email.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                               help='list of collector names (e.g., haveibeenbreach) whose outputs should not be '
                                    'returned in text mode (see argument --text). use argument value "all" to '
                                    'exclude all collectors. per default, no collectors are excluded')
    parser_email.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                               help='list of collector names whose outputs should be returned in text mode (see '
                                    'argument --text). per default, all collector information is returned')
    # setup company parser
    parser_company.add_argument("-w", "--workspaces",
                                metavar="WORKSPACE",
                                help="query the given workspaces",
                                nargs="+",
                                required=True,
                                type=str)
    parser_company_group = parser_company.add_mutually_exclusive_group(required=True)
    parser_company_group.add_argument('--text', action='store_true',
                                      help='returns gathered information including all collector outputs as text')
    parser_company_group.add_argument('--csv', action='store_true',
                                      help='returns gathered information in csv format')
    parser_company.add_argument('--filter', metavar='COMPANY', type=str, nargs='*',
                                help='list of company names whose information shall be returned. '
                                     'per default, mentioned items are excluded. add + in front of each item '
                                     '(e.g., +"test llc") to return only these items')
    parser_company.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                help='return only in scope (within) or out of scope (outside) items. '
                                     'per default, all information is returned')
    parser_company.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                                help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                     'information (e.g., executed commands that did not return any information) in '
                                     'text output (argument --text). per default, all information is returned')
    parser_company.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                help='list of collector names (e.g., reversewhois) whose outputs should not be '
                                     'returned in text mode (see argument --text). use argument value "all" to '
                                     'exclude all collectors. per default, no collectors are excluded')
    parser_company.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                help='list of collector names whose outputs should be returned in text mode (see '
                                     'argument --text). per default, all collector information is returned')
    # setup breach parser
    parser_breach.add_argument("-w", "--workspaces",
                               metavar="WORKSPACE",
                               help="query the given workspaces",
                               nargs="+",
                               required=True,
                               type=str)
    parser_breach.add_argument('--csv', action='store_true',
                               required=True,
                               help='returns gathered information in csv format')
    parser_breach.add_argument('--filter', metavar='DOMAIN|HOSTNAME|EMAIL', type=str, nargs='*',
                               help='list of second-level domains (e.g., megacorpone.com), host names (e.g., '
                                    'www.megacorpone.com), or email addresses whose information shall be returned. '
                                    'per default, mentioned items are excluded. add + in front of each item '
                                    '(e.g., +megacorpone.com) to return only these items')
    parser_breach.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                               help='return only in scope (within) or out of scope (outside) items. '
                                    'per default, all information is returned')
    parser_breach.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                               help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                    'information (e.g., executed commands that did not return any information) in text '
                                    'output (argument --text) per default, all information is returned')
    # setup vhost parser
    parser_vhost.add_argument("-w", "--workspaces",
                              metavar="WORKSPACE",
                              help="query the given workspaces",
                              nargs="+",
                              required=True,
                              type=str)
    parser_vhost_group = parser_vhost.add_mutually_exclusive_group(required=True)
    parser_vhost_group.add_argument('--text', action='store_true',
                                    help='returns gathered information including all collector outputs as text')
    parser_vhost_group.add_argument('--csv', action='store_true',
                                    help='returns gathered information in csv format')
    parser_vhost_group.add_argument('--igrep', type=str, nargs='+', metavar="REGEX",
                                    help="print command outputs that match the given string or Python3 regular "
                                         "expressions REGEX. matching is case insensitive. use named group 'output' "
                                         "to just capture the content of this named group")
    parser_vhost_group.add_argument('--grep', type=str, nargs='+', metavar="REGEX",
                                    help="print command outputs that match the given string or Python3 regular "
                                         "expressions REGEX. matching is case sensitive. use named group 'output' "
                                         "to just capture the content of this named group")
    parser_vhost.add_argument('--not', dest="grep_not", action='store_true',
                              help='negate the filter logic and only show those vhost information that do not match '
                                   'the --igrep or --grep argument.')
    parser_vhost.add_argument('--filter', metavar='DOMAIN|HOSTNAME|IP', type=str, nargs='*',
                              help='list of second-level domains (e.g., megacorpone.com), host names '
                                   '(e.g., www.megacorpone.com), or IP addresses whose information shall be returned.'
                                   'per default, mentioned items are excluded. add + in front of each item '
                                   '(e.g., +192.168.0.1) to return only these items')
    parser_vhost.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                              help='return only in scope (within) or out of scope (outside) items. per default, '
                                   'all information is returned')
    parser_vhost.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                              help='return only relevant (relevant) or potentially irrelevant (irrelevant) information '
                                   'in text output (argument --text). examples of potentially irrelevant information '
                                   'are hosts with no open ports or operating system commands that did not return '
                                   'any results. per default, all information is returned')
    parser_vhost.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                              help='list of collector names (e.g., httpnikto) whose outputs should not be returned in '
                                   'text mode (see argument --text). use argument value "all" to exclude all '
                                   'collectors. per default, no collectors are excluded')
    parser_vhost.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                              help='list of collector names whose outputs should be returned in text mode (see '
                                   'argument --text). per default, all collector information is returned')
    # setup additional info parser
    parser_additional_info.add_argument("-w", "--workspaces",
                                        metavar="WORKSPACE",
                                        help="query the given workspaces",
                                        nargs="+",
                                        required=True,
                                        type=str)
    parser_additional_info.add_argument('--csv',
                                        required=True,
                                        action='store_true',
                                        help='returns gathered information in csv format')
    parser_additional_info.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                                        help='list of IP addresses (e.g., 192.168.1.1), IP networks (e.g., '
                                             '192.168.1.0/24), second-level domains (e.g., megacorpone.com), or '
                                             'host names (e.g., www.megacorpone.com) whose information shall be '
                                             'returned.per default, mentioned items are excluded. add + in front of '
                                             'each item (e.g., +192.168.0.1) to return only these items')
    parser_additional_info.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                        help='return only information about in scope (within) or out of scope '
                                             '(outside) items. per default, all information is returned')
    # setup vulnerability parser
    parser_vulnerability.add_argument("-w", "--workspaces",
                                      metavar="WORKSPACE",
                                      help="query the given workspaces",
                                      nargs="+",
                                      required=True,
                                      type=str)
    parser_vulnerability.add_argument('--csv',
                                      required=True,
                                      action='store_true',
                                      help='returns gathered information in csv format')
    parser_vulnerability.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                                      help='list of IP addresses (e.g., 192.168.1.1), IP networks (e.g., '
                                           '192.168.1.0/24), second-level domains (e.g., megacorpone.com), or '
                                           'host names (e.g., www.megacorpone.com) whose information shall be '
                                           'returned.per default, mentioned items are excluded. add + in front of '
                                           'each item (e.g., +192.168.0.1) to return only these items')
    parser_vulnerability.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                      help='return only information about in scope (within) or out of scope '
                                           '(outside) items. per default, all information is returned')
    # setup command parser
    parser_command.add_argument("-w", "--workspaces",
                                metavar="WORKSPACE",
                                help="query the given workspaces",
                                nargs="+",
                                required=True,
                                type=str)
    parser_command_group = parser_command.add_mutually_exclusive_group(required=True)
    parser_command_group.add_argument('--text', action='store_true',
                                      help='returns gathered information including all collector outputs as text')
    parser_command_group.add_argument('--csv', action='store_true',
                                      help='returns gathered information in csv format')
    parser_command.add_argument('--filter', metavar='DOMAIN|HOSTNAME|IP|NETWORK|EMAIL', type=str, nargs='*',
                                help='list of second-level domains (e.g., megacorpone.com), host names '
                                     '(e.g., www.megacorpone.com), IP addresses (e.g., 192.168.1.1), networks (e.g., '
                                     '192.168.0.0/24), or email addresses (e.g., test@megacorpone.com) whose '
                                     'information shall be returned. per default, mentioned items are excluded. add + '
                                     'in front of each item (e.g., +192.168.0.1) to return only these items')
    parser_command.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                                help='return only in scope (within) or out of scope (outside) items. per default, '
                                     'all information is returned')
    parser_command.add_argument('--visibility', choices=[item.name for item in ReportVisibility],
                                help='return only relevant (relevant) or potentially irrelevant (irrelevant) '
                                     'information (e.g., executed commands that did not return any '
                                     'information) in text output (argument --text). per default, all information '
                                     'is returned')
    parser_command.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                help='list of collector names (e.g., httpnikto) whose outputs should not be returned '
                                     'in text mode (see argument --text). use argument value "all" to exclude all '
                                     'collectors. per default, no collectors are excluded')
    parser_command.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                                help='list of collector names whose outputs should be returned in text mode (see '
                                     'argument --text). per default, all collector information is returned')
    # setup file parser
    parser_file.add_argument("-w", "--workspaces",
                             metavar="WORKSPACE",
                             help="query the given workspaces",
                             nargs="+",
                             required=True,
                             type=str)
    parser_file_group = parser_file.add_mutually_exclusive_group(required=True)
    parser_file_group.add_argument('--csv',
                                   action='store_true',
                                   help='returns gathered information in csv format')
    parser_file_group.add_argument('-o', '--export-path',
                                   type=str,
                                   metavar="DIR",
                                   help='exports files to output directory DIR')
    parser_file.add_argument('--type',
                             choices=[item.name for item in FileType] + ["all"],
                             required=True,
                             nargs='+',
                             help='return only files of type TYPE (e.g., screenshot or certificate). file types json, '
                                  'xml, binary, or text contain the raw scan results returned by the respective '
                                  'collector command')
    parser_file.add_argument('--filter', metavar='DOMAIN|HOSTNAME|IP|NETWORK|EMAIL', type=str, nargs='*',
                             help='list of second-level domains (e.g., megacorpone.com), host names '
                                  '(e.g., www.megacorpone.com), IP addresses (e.g., 192.168.1.1), networks (e.g., '
                                  '192.168.0.0/24), or email addresses (e.g., test@megacorpone.com) whose '
                                  'information shall be returned. per default, mentioned items are excluded. add + '
                                  'in front of each item (e.g., +192.168.0.1) to return only these items')
    parser_file.add_argument('--scope', choices=[item.name for item in ReportScopeType],
                             help='return only in scope (within) or out of scope (outside) items. per default, '
                                  'all information is returned')
    parser_file.add_argument('-X', '--exclude', metavar='COLLECTOR', type=str, nargs='+', default=[],
                             help='list of collector names (e.g., httpnikto) whose outputs should not be returned in '
                                  'CSV (see argument --csv) or export (see argument -o) mode. use argument value "all" '
                                  'to exclude all collectors. per default, no collectors are excluded')
    parser_file.add_argument('-I', '--include', metavar='COLLECTOR', type=str, nargs='+', default=[],
                             help='list of collector names whose outputs should be returned in CSV (see argument '
                                  '--csv) or export (see argument -o) mode. per default, all collector information is '
                                  'returned')
    # setup excel parser
    parser_excel.add_argument('FILE', type=str,
                              help="the path to the microsoft excel file")
    parser_excel.add_argument("-w", "--workspaces",
                              metavar="WORKSPACE",
                              help="query the given workspaces",
                              nargs="+",
                              required=True,
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
    # setup final parser
    parser_final.add_argument('FILE', type=str,
                              help="the path to the microsoft excel file")
    parser_final.add_argument("-w", "--workspaces",
                              metavar="WORKSPACE",
                              help="query the given workspaces",
                              nargs="+",
                              required=True,
                              type=str)
    parser_final.add_argument('-l', '--language',
                              type=ReportLanguage.argparse,
                              choices=list(ReportLanguage),
                              default=ReportLanguage.en,
                              help="the final report's language")
    # setup tls parser
    parser_tls.add_argument("-w", "--workspaces",
                            metavar="WORKSPACE",
                            help="query the given workspaces",
                            nargs="+",
                            required=True,
                            type=str)
    parser_tls.add_argument('--csv',
                            required=True,
                            action='store_true',
                            help='returns gathered information in csv format')
    parser_tls.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                            help='list of IP addresses, IP networks, second-level domains (e.g., megacorpone.com), or '
                                 'host names (e.g., www.megacorpone.com) whose information shall be returned.'
                                 'per default, mentioned items are excluded. add + in front of each item '
                                 '(e.g., +192.168.0.1) to return only these items')
    parser_tls.add_argument('--scope', choices=[item.name for item in ScopeType],
                            help='return only information about in scope (within) or out of scope (outside) items. '
                                 'per default, all information is returned')
    # setup cert parser
    parser_cert.add_argument("-w", "--workspaces",
                             metavar="WORKSPACE",
                             help="query the given workspaces",
                             nargs="+",
                             required=True,
                             type=str)
    parser_cert.add_argument('--csv',
                             required=True,
                             action='store_true',
                             help='returns gathered information in csv format')
    parser_cert.add_argument('--filter', metavar='IP|NETWORK|DOMAIN|HOSTNAME', type=str, nargs='*',
                             help='list of IP addresses, IP networks, second-level domains (e.g., megacorpone.com), or '
                                  'host names (e.g., www.megacorpone.com) whose information shall be returned.'
                                  'per default, mentioned items are excluded. add + in front of each item '
                                  '(e.g., +192.168.0.1) to return only these items')
    parser_cert.add_argument('--scope', choices=[item.name for item in ScopeType],
                             help='return only information about in scope (within) or out of scope (outside) items. '
                                  'per default, all information is returned')
    args = parser.parse_args()
    if len(sys.argv) <= 1:
        parser.print_help()
        sys.exit(1)
    try:
        engine = Engine()
        if args.list:
            engine.print_workspaces()
            sys.exit(1)
        DeclarativeBase.metadata.bind = engine.engine
        with engine.session_scope() as session:
            workspaces = []
            for item in args.workspaces:
                workspace = DomainUtils.get_workspace(session=session, name=item)
                if not workspace:
                    raise WorkspaceNotFound(item)
                workspace = engine.get_workspace(session, item)
                if workspace:
                    workspaces.append(workspace)
            if workspaces:
                rg = ReportGenerator(args, session, workspaces)
                rg.run()
    except WorkspaceNotFound as ex:
        print(ex, file=sys.stderr)
    except NotImplementedError as ex:
        print(ex, file=sys.stderr)
    except Exception as ex:
        traceback.print_exc(file=sys.stderr)
