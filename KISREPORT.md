# kisreport

This script implements all functionalities to query the KIS database and analyze the information gathering results

```bash
root@kali: ~ $ kisreport -h
usage: kisreport [-h] [--nocolor] [-l]
                 {additional-info,breach,credential,command,domain,cname,email,company,excel,file,host,network,path,vhost,vulnerability,tls,cert}
                 ...

this script implements all functionalities to query the KIS database and analyze
the information gathering results

positional arguments:
  {additional-info,breach,credential,command,domain,cname,email,company,excel,file,host,network,path,vhost,vulnerability,tls,cert}
                        list of available database modules
    additional-info     allows querying additional information (e.g., HTTP
                        headers)
    breach              allows querying information about identified breaches
                        (e.g., via haveibeenpwned.com)
    credential          allows querying information about identified
                        credentials (e.g., ftp or snmp)
    command             allows querying information about executed OS commands
    domain              allows querying information about second-level domains
                        and host names
    cname               allows querying DNS canonical names (CNAMES). this
                        report can be used to identify potential subdomain
                        takeovers
    email               allows querying information about emails
    company             allows querying information about companies
    excel               allows writing all identified information into a
                        microsoft excel file
    file                allows querying information about collected files
                        (e.g., raw scan results, certificates, etc.)
    host                allows querying information about hosts
    network             allows querying information about networks
    path                allows querying information about identified paths
                        (e.g., urls)
    vhost               allows querying information about virtual hosts
                        (vhost)
    vulnerability       allows querying information about identified
                        vulnerabilities (e.g., via shodan.io or nessus)
    tls                 allows querying information about identified tls
                        configurations
    cert                allows querying information about identified
                        certificates

optional arguments:
  --nocolor             disable colored output
  -h, --help            show this help message and exit
  -l, --list            list existing workspaces

---- USE CASES ----

- I. export all structured information to a microsoft excel file

the following command queries all structured information about all 
positional arguments from workspace $workspace and exports it to the 
microsoft excel file /tmp/report.xlsx

the icrosoft excel file can then be used for further analyses or reporting

$ kisreport excel /tmp/report.xlsx -w $workspace

- II. obtain list of in-scope host names

the following command returns a unique list of in-scope host names from 
workspace $workspace. the returned list could be used as input for other 
external intelligence gathering tools

$ kisreport domain -w $workspace --csv --scope within | csvcut -c "Host Name"

alternatively, you could query all second-level domains from workspace 
$workspace to identify those domains that are relevant for the assessment. 

$ kisreport domain -w $workspace --csv | csvcut -c "Second-Level Domain"

the relevant domains can then be set in-scope using the script kismanage. 
after setting them in-scope, it is possible to perform active intelligence 
gathering on them using script kiscollect

- III. obtain list of URLs

the following command returns a unique list of host names from workspace 
$workspace. the returned list could be used as input for other external 
intelligence gathering tools

the following command returns a unique list of URLs, which could be used as 
input for other external intelligence gathering tools (e.g., aquatone)

$ kisreport path -w $workspace --csv | grep ,http, | csvcut -c 10 | sed -e 's/^"//' -e 's/"$//' | sort -u

- IV. obtain all hosts/services where the collector http was executed

the following command returns all IPv4/IPv6 addresses on which the collector  
httpnikto was executed. the text output also includes the output of httpnikto

$ kisreport host -w $workspace --text -I httpnikto | less -R

the following command returns all virtual hosts/services on which the 
collector httpnikto was executed. the text output also includes the output of 
httpnikto

$ kisreport vhost -w $workspace --text -I httpnikto | less -R

- V. show all results for a specific IPv4 address or host name

the following command returns all gathered information from workspace $workspace 
for IPv4 address $ip

$ kisreport host -w $workspace --text --filter +$ip | less -R

the following command returns all gathered information from workspace $workspace 
for host name $hostname

$ kisreport vhost -w $workspace --text --filter +$hostname | less -R

- VI. search all collector raw outputs for a specific key word

the following command searches all command outputs of $workspace for the 
keyword $keyword

$ kisreport command -w $workspace --text | grep $keyword

the following command searches all httpnikto outputs of $workspace for the 
keyword $keyword

$ kisreport command -w $workspace --text -I httpnikto | grep $keyword

- VII. export raw scan results

the following command exports all screenshots located in workspace $workspace and
taken by collector httpeyewitness to the output directory $outdir

$ kisreport file -w $workspace --type screenshot -I httpeyewitness -o $outdir

the following command exports all raw xml scan files of collector tcpnmap located 
in workspace $workspace to the output directory $outdir

$ kisreport file -w $workspace --type xml -I tcpnmap -o $outdir

kisreport domain -w maurer --csv --scope within | csvcut -c 6,13,16 | csvlook

Process finished with exit code 1

```
