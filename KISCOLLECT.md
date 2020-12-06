# kiscollect

This script implements a commandline interface to collect intelligence. The collection is performed by so called
collectors.

A collector is a Python module, which can operate on the IP address (e.g., collector shodanhost), IP network
(e.g., collector tcpnmap), service (e.g., collector ftphydra), or second-level domain (e.g., collector theharvester)
level. The collectors create these commands based on the data that is available in the KIS database and after each
execution, they perform the following tasks:

  * Analyse the OS command's output
  * Report any potential valuable information to the user
  * Enrich the data (e.g., newly identified IPv4 addresses, host names, URLs, credentials, etc.) in the database to
  ensure that subsequent collectors can re-use it

Collectors are executed in a specific order to ensure that information required by one collector (e.g., httpeyewitness)
is already collected by another (e.g., httpgobuster).

Note: service-level collectors identify services from which they can collect intelligence by comparing the protocol
(TCP or UDP) and port number or by the nmap service name. the nmap service name is useful, if services are running on
non-standard ports. at the moment, only the service names of nmap are supported, which means that only from
nmap scan results, KIS is able to collect intel from services running on non-standard ports.

The script provides the following functionalities and some case studies are provided at the end of kiscollect's help.


```bash
root@kali: ~ $ kiscollect -h
usage: kiscollect [-h] [--finger] [--ipmi] [--tcptraceroute] [--rdphydra]
                  [--rdpnmap] [--awsslurp] [--anyservicenmap]
                  [--icmpnmapnetwork] [--tcpmasscannetwork TYPE [TYPE ...]]
                  [--tcpnmapdomain TYPE [TYPE ...]]
                  [--tcpnmapnetwork TYPE [TYPE ...]]
                  [--udpnmapdomain TYPE [TYPE ...]]
                  [--udpnmapnetwork TYPE [TYPE ...]] [--pgsqlhydra]
                  [--tftpdotdotpwn] [--tftpnmap] [--certnmap]
                  [--certopenssl] [--sslscan] [--sslyze] [--tlsnmap]
                  [--oraclesidguess] [--builtwith] [--censysdomain]
                  [--censyshost] [--certspotter] [--crtshcompany]
                  [--crtshdomain] [--dnsdumpster] [--haveibeenbreach]
                  [--haveibeenpaste] [--hostio] [--hunter] [--reversewhois]
                  [--securitytrails] [--shodanhost] [--shodannetwork]
                  [--theharvester] [--virustotal] [--whoisdomain]
                  [--whoishost] [--whoisnetwork] [--h323version] [--sipmsf]
                  [--sipnmap] [--stunnmap] [--mssqlhydra] [--mssqlnmap]
                  [--sshchangeme] [--sshhydra] [--sshnmap] [--x11nmap]
                  [--imapnmap] [--pop3nmap] [--smtpnmap] [--smtpuserenum]
                  [--rpcclient] [--rpcinfo] [--rpcnmap] [--vncnmap]
                  [--vncviewer] [--dnsdkim] [--dnsdmark] [--dnsenum]
                  [--dnsgobuster] [--dnshost] [--dnshostpublic] [--dnsnmap]
                  [--dnsrecon] [--dnsreverselookup] [--dnsspf]
                  [--dnssublist3r] [--dnstakeover] [--dnszonetransfer]
                  [--ftpdotdotpwn] [--ftpfilelist] [--ftphydra] [--ftpnmap]
                  [--ldapnmap] [--ldapsearch] [--mysqlhydra] [--mysqlnmap]
                  [--nfsnmap] [--showmount] [--ntpdate] [--ntpq]
                  [--enum4linux] [--msrpcenum] [--smbclient] [--smbcme]
                  [--smbfilelist] [--smbhydra] [--smbmap] [--smbmedusa]
                  [--smbnmap] [--telnetnmap] [--onesixtyone] [--snmpcheck]
                  [--snmphydra] [--snmpnmap] [--snmpwalk] [--nbtscan]
                  [--httpburpsuitepro] [--httpchangeme] [--httpdavtest]
                  [--httpdotdotpwn] [--httpeyewitness] [--httpgobuster]
                  [--httphydra [PATHS [PATHS ...]]] [--httpmsfrobotstxt]
                  [--httpnikto] [--httpnmap] [--httpntlmnmap]
                  [--httpsqlmap] [--httpwapiti] [--httpwhatweb]
                  [--httpwpscan] [--vhostgobuster] [--ikescan]
                  [--http-proxy HTTP_PROXY] [-S] [--vhost {all,domain}]
                  [--debug] [-B] [--strict]
                  [--restart {failed,terminated,completed} [{failed,terminated,completed} ...]]
                  [-A] [--filter IP|NETWORK|HOST [IP|NETWORK|HOST ...]]
                  [-t THREADS] -w WORKSPACE [-l] [-o OUTPUT_DIR]
                  [--cookies N [N ...]] [--user-agent AGENT]
                  [-C COMBO_FILE] [-P PASSWORD_FILE] [-U USER_FILE]
                  [-u USER] [-d DOMAIN] [-p PASSWORD] [--hashes]
                  [-L WORDLIST_FILES [WORDLIST_FILES ...]] [-D MIN]
                  [-M MAX] [--dns-server SERVER] [--proxychains]
                  [--continue]

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

optional arguments:
  -h, --help            show this help message and exit

collectors:
  use the following arguments to collect intelligence

  --anyservicenmap      run tool nmap on any open in-scope service to obtain
                        additional intelligence. this collector useful after
                        importing masscan scan results or after executing
                        collector tcpmasscannetwork. with this collector, nmap
                        obtains the service name (e.g, ssh or http) from non-
                        standard ports, which allows subsequently executed
                        collectors to determine whether they apply
  --awsslurp            run tool slurp on each in-scope second-level domain
                        (e.g., megacorpone.com) to perform S3 bucket
                        enumeration for AWS
  --builtwith           run tool kismanage on each identified in-scope second-
                        level domain to identify relationships to other
                        second-level domains via builtwith.com. depending on
                        the number of domains in the current workspace, it
                        might be desired to limit the number of OS commands by
                        using the optional argument --filter
  --censysdomain        run tool kismanage on each identified in-scope second-
                        level domain to obtain domain information via
                        censys.io. depending on the number of domains in the
                        current workspace, it might be desired to limit the
                        number of OS commands by using the optional argument
                        --filter
  --censyshost          run tool kismanage on each identified in-scope and
                        non-private IPv4 address to obtain host information
                        via censys.io. depending on the number of IP addresses
                        in the current workspace, it might be desired to limit
                        the number of OS commands by using the optional
                        argument --filter
  --certnmap            run tool nmap with all safe NSE scripts on all
                        identified in-scope TLS services to obtain certificate
                        information
  --certopenssl         run tool nmap with all safe NSE scripts on all
                        identified in-scope TLS services to obtain certificate
                        information
  --certspotter         run tool kismanage on each identified in-scope second-
                        level domain to obtain domain information via
                        certspotter.com. depending on the number of domains in
                        the current workspace, it might be desired to limit
                        the number of OS commands by using the optional
                        argument --filter
  --crtshcompany        run tool kismanage on each company of an identified
                        in-scope second-level domain or network to obtain
                        additional host names via the crt.sh web site.
                        depending on the number of certificates the company
                        has registered. note that this command might take a
                        long time to complete as between each certificate
                        request, the command sleeps between 2 and 5 seconds
  --crtshdomain         run tool kismanage on each identified in-scope second-
                        level domain to obtain domain information via crt.sh.
                        depending on the number of domains in the current
                        workspace, it might be desired to limit the number of
                        OS commands by using the optional argument --filter
  --dnsdkim             run tool dig on each in-scope second-level domain
                        (e.g., megacorpone.com) using the operating system's
                        DNS server to obtain DKIM information. use optional
                        argument --dns-server to explicitly specify another
                        DNS server
  --dnsdmark            run tool dig on each in-scope second-level domain
                        (e.g., megacorpone.com) using the operating system's
                        DNS server to obtain DMARK information. use optional
                        argument --dns-server to explicitly specify another
                        DNS server
  --dnsdumpster         run tool kismanage on each identified in-scope second-
                        level domain to obtain domain information via
                        dnsdumpster.com. depending on the number of domains in
                        the current workspace, it might be desired to limit
                        the number of OS commands by using the optional
                        argument --filter
  --dnsenum             run tool dnsenum on each in-scope second-level domain
                        (e.g., megacorpone.com) using the operating system's
                        DNS server. use optional argument --dns-server to
                        explicitly specify another DNS server
  --dnsgobuster         run tool gobuster on each in-scope second-level domain
                        (e.g., megacorpone.com) using the operating system's
                        DNS server to enumerate subdomains. use optional
                        argument -L to specify word lists containing the host
                        names to enumerate. without argument -L, the default
                        word list is used
  --dnshost             run tool host on each collected in-scope host name
                        (e.g., www.megacorpone.com) and second-level domain
                        (e.g., megacorpone.com) to resolve their IPv4/IPv6
                        addresses using the operating system's DNS server. use
                        optional argument --dns-server to explicitly specify
                        another DNS server
  --dnshostpublic       run tool host on all collected host names (e.g.,
                        www.megacorpone.com) and second-level domains (e.g.,
                        megacorpone.com) to resolve their IPv4/IPv6 addresses
                        using the public DNS server 8.8.8.8. alternatively,
                        you can use a different DNS server by using optional
                        argument --dns-server
  --dnsnmap             run tool nmap with all safe NSE scripts on all
                        identified in-scope DNS services
  --dnsrecon            run tool dnsrecon on each in-scope second-level domain
                        (e.g., megacorpone.com) using the operating system's
                        DNS server. use optional argument --dns-server to
                        explicitly specify another DNS server
  --dnsreverselookup    run tool host on each in-scope IPv4/v6 address to
                        reverse lookup their DNS names using the operating
                        system's DNS server. use optional argument --dns-
                        server to explicitly specify another DNS server
  --dnsspf              run tool dig on each in-scope second-level domain
                        (e.g., megacorpone.com) using the operating system's
                        DNS server to obtain SPF information. use optional
                        argument --dns-server to explicitly specify another
                        DNS server
  --dnssublist3r        run sublist3r on each in-scope second-level domain to
                        passively collect host names
  --dnstakeover         run tool dig on each in-scope second-level domain
                        (e.g., megacorpone.com) using the operating system's
                        DNS server to obtain DNS resource records NS and
                        CNAME. use optional argument --dns-server to
                        explicitly specify another DNS server
  --dnszonetransfer     run tool dig on each in-scope second-level domain
                        (e.g., megacorpone.com) using the operating system's
                        DNS server to test for DNS zone transfers.
  --enum4linux          run tool enum4linux on each identified in-scope SMB
                        service
  --finger              run tool finger on each identified in-scope finger
                        service (TCP)
  --ftpdotdotpwn        run tool dotdotpwn on each identified in-scope FTP
                        service where access credentials are known to KIS.
                        alternatively, use optional arguments -u and -p to
                        specify a user name and password. note, this collector
                        only works in combination with argument -S as
                        dotdotpwn requires user interaction. argument -S
                        prints the commands and then you have to execute them
                        manually
  --ftpfilelist         run tool curl on each identified in-scope FTP service
                        where access credentials are known to KIS (use
                        ftphydra to brute- force credentials). alternatively,
                        use optional arguments -u and -p to specify a user
                        name and password
  --ftphydra            run tool hydra on each identified in-scope FTP service
                        to brute-force user accounts. per default, the brute-
                        force is performed using a default word list (use
                        argument -S to figure out which one). alternatively,
                        use optional arguments -p and -u; -P and -U; or -C to
                        specify other access credentials
  --ftpnmap             run tool nmap with all safe NSE scripts on all
                        identified in-scope FTP services
  --h323version         run Metasploit auxiliary module h323_version on each
                        identified in-scope H323 service.
  --haveibeenbreach     run tool kismanage on each identified in-scope email
                        address to determine breaches (using
                        haveibeenpwned.com) in which the email address
                        appears. depending on the number of email addresses in
                        the current workspace, it might be desired to limit
                        the number of OS commands by using the optional
                        argument --filter
  --haveibeenpaste      run tool kismanage on each identified in-scope email
                        address to determine pastes (using haveibeenpwned.com)
                        in which the email address appears. depending on the
                        number of email addresses in the current workspace, it
                        might be desired to limit the number of OS commands by
                        using the optional argument --filter
  --hostio              run tool kismanage on each identified in-scope second-
                        level domain to identify relationships to other
                        second-level domains via host.io. depending on the
                        number of domains in the current workspace, it might
                        be desired to limit the number of OS commands by using
                        the optional argument --filter
  --httpburpsuitepro    submit in-scope web applications to Burp Suite
                        Professional for scanning via Burp's REST API. use
                        this collector with caution as these scans are
                        aggressive and therefore, might case damage.
                        therefore, it might be desired to limit the number of
                        OS commands by using the optional argument --filter.
                        note that Burp's scan results are not fed back into
                        KIS
  --httpchangeme        run tool changeme on each identified in-scope HTTP(S)
                        service to test service for default credentials. use
                        optional argument --user-agent to specify a different
                        user agent string, or optional argument --http-proxy
                        to specify an HTTP proxy
  --httpdavtest         run tool davtest on each identified in-scope HTTP(S)
                        service that support HTTP method PUT (use collector
                        httpnmap to identify the supported HTTP methods). if
                        credentials for basic authentication are known to KIS,
                        then they will be automatically used. alternatively,
                        use optional arguments -u and -p to provide a user
                        name and password for basic authentication
  --httpdotdotpwn       run dotdotpwn on each identified in-scope HTTP(S)
                        service. if credentials for basic authentication are
                        known to KIS, then they will be automatically used.
                        alternatively, use optional arguments -u and -p to
                        provide a user name and password for basic
                        authentication. note, this collector only works in
                        combination with argument -S as dotdotpwn requires
                        user interaction. argument -S prints the commands and
                        then you have to execute them manually
  --httpeyewitness      run tool eyewitness on each identified in-scope
                        HTTP(S) service path to create screenshots. use
                        optional argument --user-agent to specify a different
                        user agent string or optional argument --http-proxy to
                        specify an HTTP proxy
  --httpgobuster        run tool gobuster on each identified in-scope HTTP(S)
                        service to enumerate existing URIs. if credentials for
                        basic authentication are known to KIS, then they will
                        be automatically used. alternatively, use optional
                        arguments -u and -p to provide a user name and
                        password for basic authentication. use optional
                        argument --cookies to specify a list of cookies,
                        optional argument --user-agent to specify a different
                        user agent string, or optional argument --http-proxy
                        to specify an HTTP proxy
  --httphydra [PATHS [PATHS ...]]
                        (INCOMPLETE) check given HTACCESS protected paths for
                        known credentials using hydra. the option's argument
                        is either - or a list of paths. use options -p and -u;
                        -P and -U; or -C to test for known user names and
                        password. if the option's value is -, then httphydra,
                        searches the already identified paths for paths which
                        have known default credentials
  --httpmsfrobotstxt    run Metasploit auxiliary module robots_txt on each
                        identified in-scope HTTP(S) service to enumerate
                        existing URIs. use optional argument --http-proxy to
                        specify an HTTP proxy
  --httpnikto           run tool nikto on each identified in-scope HTTP(S)
                        service to enumerate existing URIs. if credentials for
                        basic authentication are known to KIS, then they will
                        be automatically used. alternatively, use optional
                        arguments -u and -p to provide a user name and
                        password for basic authentication. use optional
                        argument --user-agent to specify a different user
                        agent string, or optional argument --http-proxy to
                        specify an HTTP proxy
  --httpnmap            run tool nmap with all safe NSE scripts on all
                        identified in-scope HTTP(S) services
  --httpntlmnmap        run tool nmap with NSE script http-ntlm-info on all
                        identified in-scope HTTP(S) services
  --httpsqlmap          run tool sqlmap in batch mode on all identified in-
                        scope HTTP(S) services. if credentials for basic
                        authentication are known to KIS, then they will be
                        automatically used. alternatively, use optional
                        arguments -u and -p to provide a user name and
                        password for basic authentication. use optional
                        argument --cookies to specify a list of cookies,
                        optional argument --user-agent to specify a different
                        user agent string, or optional argument --http-proxy
                        to specify a HTTP proxy
  --httpwapiti          run tool wapiti on each identified in-scope HTTP(S)
                        service. if credentials for basic authentication are
                        known to KIS, then they will be automatically used.
                        alternatively, use optional arguments -u and -p to
                        provide a user name and password for basic
                        authentication. use optional argument --user-agent to
                        specify a different user agent string or optional
                        argument --http-proxy to specify an HTTP proxy
  --httpwhatweb         run tool whatweb on each identified in-scope HTTP(S)
                        service. if credentials for basic authentication are
                        known to KIS, then they will be automatically used.
                        alternatively, use optional arguments -u and -p to
                        provide a user name and password for basic
                        authentication. use optional argument --cookies to
                        specify a cookie, optional argument --user-agent to
                        specify a different user agent string, or optional
                        argument --http-proxy to specify an HTTP proxy
  --httpwpscan          run tool wpscan on each identified in-scope HTTP(S)
                        service. if credentials for basic authentication are
                        known to KIS, then they will be automatically used.
                        alternatively, use optional arguments -u and -p to
                        provide a user name and password for basic
                        authentication. use optional argument --cookies to
                        specify a cookie, optional argument --user-agent to
                        specify a different user agent string, or optional
                        argument --http-proxy to specify an HTTP proxy
  --hunter              run tool kismanage on each identified in-scope second-
                        level domain to obtain emails via hunter.io. depending
                        on the number of domains in the current workspace, it
                        might be desired to limit the number of OS commands by
                        using the optional argument --filter
  --icmpnmapnetwork     run a ping scan on all identified in-scope IPv4/IPv6
                        networks using nmap
  --ikescan             run tool ike-scan on each identified in-scope ISAKMP
                        service
  --imapnmap            run tool nmap with all safe NSE scripts on all
                        identified in-scope IMAP services
  --ipmi                run Metasploit auxiliary module ipmi_dumphashes on
                        each identified in-scope IPMI 2.0-compatible system
                        and attempts to retrieve the HMAC-SHA1 password hashes
                        of default usernames.
  --ldapnmap            run tool nmap with all safe NSE scripts on all
                        identified in-scope LDAP services
  --ldapsearch          run ldapsearch on each identified in-scope LDAP(S)
                        service. if credentials for user authentication are
                        known to KIS, then they will be automatically used.
                        alternatively, use optional arguments -u and -p to
                        provide a user name and password for user
                        authentication.
  --msrpcenum           run tool nmap on each identified in-scope SMB services
                        to query an MSRPC endpoint mapper for a list of mapped
                        services. if credentials for SMB authentication are
                        known to KIS, then they will be automatically used.
                        alternatively, use optional arguments -u, -p, and -d
                        to provide a user name, a password/NTLM hash, and
                        domain/workgroup for authentication
  --mssqlhydra          run tool hydra on each identified in-scope MS-SQL
                        service to brute-force user accounts. per default, the
                        brute-force is performed using a default word list
                        (use argument -S to figure out which one).
                        alternatively, use optional arguments -p and -u; -P
                        and -U; or -C to specify other access credentials
  --mssqlnmap           run tool nmap with all safe NSE scripts on all
                        identified in-scope MS-SQL services
  --mysqlhydra          run tool hydra on each identified in-scope MySQL
                        service to brute-force user accounts. per default, the
                        brute-force is performed using a default word list
                        (use argument -S to figure out which one).
                        alternatively, use optional arguments -p and -u; -P
                        and -U; or -C to specify other access credentials
  --mysqlnmap           run tool nmap with all safe NSE scripts on all
                        identified in-scope MySQL services
  --nbtscan             run tool nbtscan on each identified in-scope NBT
                        service
  --nfsnmap             run tool nmap with all safe NSE scripts on all
                        identified in-scope NFS services
  --ntpdate             run tool ntpdate on each identified NTP service to
                        determine the remote system time
  --ntpq                run tool ntpq on each identified in-scope NTP service
                        to determine whether the NTP service responds to mode
                        6 queries and thus can be exploited for NTP
                        amplification attacks
  --onesixtyone         run tool onesixtyone on each identified in-scope SNMP
                        service where access credentials are known to KIS (use
                        snmphydra to brute-force credentials). alternatively,
                        use optional arguments -p to specify a community
                        string
  --oraclesidguess      run tool sidguess on oracle databases to determine
                        valid SIDs
  --pgsqlhydra          run tool hydra on each identified in-scope PostgreSQL
                        service to brute-force user accounts. per default, the
                        brute- force is performed using a default word list
                        (use argument -S to figure out which one).
                        alternatively, use optional arguments -p and -u; -P
                        and -U; or -C to specify other access credentials
  --pop3nmap            run tool nmap with all safe NSE scripts on all
                        identified in-scope POP3 services
  --rdphydra            run tool hydra on each identified in-scope RDP service
                        to brute-force user accounts. use arguments -p and -u;
                        -P and -U; or -C to specify access credentials
  --rdpnmap             run tool nmap with all safe NSE scripts on all
                        identified in-scope RDP services
  --reversewhois        run tool kismanage on each company of an identified
                        in-scope second-level domain or network to obtain
                        additional domain names via the viewdns.info web site.
                        depending on the number of domains in the current
                        workspace, it might be desired to limit the number of
                        OS commands by using the optional argument --filter
  --rpcclient           run tool rpcclient on each identified in-scope RPCBIND
                        or SMB service. if credentials are known to KIS, then
                        they will be automatically used. alternatively, use
                        optional arguments -u and -p to provide a user name
                        and password
  --rpcinfo             run tool rpcinfo on all identified in-scope RPCBIND
                        service
  --rpcnmap             run tool nmap with all safe NSE scripts on all
                        identified in-scope RPCBIND services
  --securitytrails      run tool kismanage on each identified in-scope second-
                        level domain to obtain domain information via
                        securitytrails.com. depending on the number of domains
                        in the current workspace, it might be desired to limit
                        the number of OS commands by using the optional
                        argument --filter
  --shodanhost          run tool kisimport on each identified in-scope and
                        non-private IPv4/IPv6 address to obtain host
                        information via shodan.io. depending on the number IP
                        addresses in the current workspace, it might be
                        desired to limit the number of OS commands by using
                        the optional argument --filter
  --shodannetwork       run tool kismanage on each identified in-scope and
                        non-private IPv4/IPv6 network to obtain host
                        information via shodan.io
  --showmount           run tool showmount on each identified in-scope NFS
                        service to determine network shares
  --sipmsf              run Metasploit auxiliary module enumerator on each
                        identified in-scope SIP service.
  --sipnmap             run tool nmap with all safe NSE scripts on all
                        identified in-scope SIP services
  --smbclient           run tool pth-smbclient on each identified in-scope SMB
                        service. per default this collector tests SMB services
                        for NULL sessions. alternatively, use optional
                        arguments -u, -p, and -d to provide a user name,
                        password/NTLM hash, and domain/ workgroup for
                        authentication
  --smbcme              run tool crackmapexec on each identified in-scope SMB
                        service to obtain general SMB information
  --smbfilelist         run smbclient on each identified in-scope SMB network
                        share to get a directory listing. per default this
                        collector tests SMB services for NULL sessions.
                        alternatively, use optional arguments -u, -p, and -d
                        to provide a user name, a password/NTLM hash, and
                        domain/workgroup for authentication
  --smbhydra            run tool hydra on each identified in-scope SMB service
                        to brute-force user accounts. use arguments -p and -u;
                        -P and -U; or -C to specify other access credentials.
                        use optional argument --hash, if the provided
                        passwords are hashes
  --smbmap              run tool smbmap on each identified in-scope SMB
                        services. if credentials for SMB authentication are
                        known to KIS, then they will be automatically used.
                        alternatively, use optional arguments -u, -p, and -d
                        to provide a user name, a password/NTLM hash, and
                        domain/workgroup for authentication
  --smbmedusa           run tool medusa on each identified in-scope SMB
                        service to brute-force user accounts. use arguments -p
                        and -u; -P and -U; or -C to specify other access
                        credentials. use optional argument --hash, if the
                        provided passwords are hashes
  --smbnmap             run tool nmap with all safe and discovery NSE scripts
                        on all identified in-scope SMB services. if
                        credentials for SMB authentication are known to KIS,
                        then they will be automatically used. alternatively,
                        use optional arguments -u, -p, and -d to provide a
                        user name, a password/NTML hash, and a
                        domain/workgroup for authentication
  --smtpnmap            run tool nmap with all safe NSE scripts on all
                        identified in-scope SMTP services
  --smtpuserenum        run tool smtpuserenum on each identified in-scope SMTP
                        service to brute-force valid user names. use the
                        mandatory argument -L to specify a file containing
                        user names to enumerate
  --snmpcheck           run tool snmpcheck on each identified in-scope SNMP
                        service where access credentials are known to KIS (use
                        snmphydra to brute-force credentials). alternatively,
                        use optional arguments -p to specify a community
                        string
  --snmphydra           run tool hydra on each identified in-scope SNMP
                        service to brute-force user accounts. per default, the
                        brute-force is performed using a default word list
                        (use argument -S to figure out which one).
                        alternatively, use optional arguments -p and -u; -P
                        and -U; or -C to specify other access credentials
  --snmpnmap            run tool nmap with all safe NSE scripts on all
                        identified in-scope SNMP services
  --snmpwalk            run tool snmpwalk on each identified in-scope SNMP
                        service where access credentials are known to KIS (use
                        snmphydra to brute-force credentials). alternatively,
                        use optional arguments -p to specify a community
                        string
  --sshchangeme         run tool changeme on each identified in-scope SSH
                        service to test for default credentials and weak SSH
                        keys
  --sshhydra            run tool hydra on each identified in-scope SSH service
                        to brute-force user accounts. use arguments -p and -u;
                        -P and -U; or -C to specify other access credentials
  --sshnmap             run tool nmap with all safe NSE scripts on all
                        identified in-scope SSH services
  --sslscan             run tool sslscan on each identified in-scope TLS
                        service to obtain information about the TLS
                        configuration as well as the certificate
  --sslyze              run tool sslyze on each identified in-scope TLS
                        service to obtain information about the TLS
                        configuration as well as the certificate
  --stunnmap            run tool nmap with all safe NSE scripts on all
                        identified in-scope STUN services
  --tcpmasscannetwork TYPE [TYPE ...]
                        run tool masscan on all in-scope IPv4 networks. valid
                        parameters for this argument are: topX for scanning
                        top X TCP ports; interesting for scanning interesting
                        TCP ports; all for scanning all TCP ports; or a list
                        of port numbers/ranges (e.g., 0-1024 8080) to scan
                        just those TCP ports
  --tcpnmapdomain TYPE [TYPE ...]
                        run tool nmap on all in-scope second-level domains and
                        host names. valid parameters for this argument are:
                        topX for scanning top X TCP ports; interesting for
                        scanning interesting TCP ports; all for scanning all
                        TCP ports; or a list of port numbers/ranges (e.g.,
                        0-1024 8080) to scan just those TCP ports
  --tcpnmapnetwork TYPE [TYPE ...]
                        run tool nmap on all in-scope IPv4/IPv6 networks.
                        valid parameters for this argument are: topX for
                        scanning top X TCP ports; interesting for scanning
                        interesting TCP ports; all for scanning all TCP ports;
                        or a list of port numbers/ranges (e.g., 0-1024 8080)
                        to scan just those TCP ports
  --tcptraceroute       run tool traceroute on the first open in-scope TCP
                        service to determine the communication path the target
                        host
  --telnetnmap          run tool nmap with all safe NSE scripts on all
                        identified in-scope telnet services
  --tftpdotdotpwn       run dotdotpwn on each identified in-scope TFTP
                        service. note, this collector only works in
                        combination with argument -S as dotdotpwn requires
                        user interaction. argument -S prints the commands and
                        then you have to execute them manually
  --tftpnmap            run tool nmap with all safe NSE scripts on all
                        identified in-scope TFTP services
  --theharvester        run tool theharvester on each identified in-scope
                        second-level domain
  --tlsnmap             run tool nmap with all safe NSE scripts on all
                        identified in-scope TLS services to obtain information
                        about the TLS configuration
  --udpnmapdomain TYPE [TYPE ...]
                        run tool nmap on all in-scope second-level domains and
                        host names. valid parameters for this argument are:
                        topX for scanning top X UDP ports; interesting for
                        scanning interesting UDP ports; all for scanning all
                        UDP ports; or a list of port numbers/ranges (e.g.,
                        0-1024 8080) to scan just those UDP ports
  --udpnmapnetwork TYPE [TYPE ...]
                        run tool nmap on all in-scope IPv4/IPv6 networks.
                        valid parameters for this argument are: topX for
                        scanning top X UDP ports; interesting for scanning
                        interesting UDP ports; all for scanning all UDP ports;
                        or a list of port numbers/ ranges (e.g., 0-1024 8080)
                        to scan just those UDP ports
  --vhostgobuster       run tool gobuster on each identified in-scope HTTP(S)
                        service to enumerate existing URIs. if credentials for
                        basic authentication are known to KIS, then they will
                        be automatically used. alternatively, use optional
                        arguments -u and -p to provide a user name and
                        password for basic authentication. use optional
                        argument --cookies to specify a list of cookies,
                        optional argument --user-agent to specify a different
                        user agent string, or optional argument --http-proxy
                        to specify an HTTP proxy
  --virustotal          run tool kismanage on each identified in-scope second-
                        level domain to obtain domain information via
                        virustotal.com. depending on the number of domains in
                        the current workspace, it might be desired to limit
                        the number of OS commands by using the optional
                        argument --filter
  --vncnmap             run tool nmap with all safe NSE scripts on all
                        identified in-scope VNC services
  --vncviewer           connect to VNC services via vncviewer application
                        (only one thread is allowed). use option -P to provide
                        a list of password files
  --whoisdomain         run tool whois on all identified in- and out-of-scope
                        second-level domains. depending on the number of
                        domains in the current workspace, it might be desired
                        to limit the number of OS commands by using the
                        optional argument --filter
  --whoishost           run tool whois on all identified in- and out-of-scope
                        global IPv4/IPv6 addresses. depending on the number of
                        hosts in the current workspace, it might be desired to
                        limit the number of OS commands by using the optional
                        argument --filter. note that in order to reduce the
                        number of whois requests, KIS only queries one
                        IPv4/IPv6 address per network range returned by whois
                        and all remaining queries are ignored
  --whoisnetwork        run tool whois on all identified in- and out-of-scope
                        global IPv4/IPv6 networks. depending on the number of
                        networks in the current workspace, it might be desired
                        to limit the number of OS commands by using the
                        optional argument --filter. note that in order to
                        reduce the number of whois requests, KIS only queries
                        one IPv4/IPv6 address per network range returned by
                        whois and all remaining queries are ignored
  --x11nmap             run tool nmap with all safe NSE scripts on all
                        identified in-scope X11 services

general options:
  use the following arguments to specify how intelligence is collected

  --continue            indefinitely repeat the execution of selected
                        collectors
  --cookies N [N ...]   list of cookies that shall be used by collectors (e.g.
                        "Cookie: JSESSION=123")
  --debug               prints extra information to log file
  --dns-server SERVER   DNS server (e.g., 8.8.8.8) that shall be used by
                        collectors to query DNS information. otherwise, the
                        system's DNS server is used
  --filter IP|NETWORK|HOST [IP|NETWORK|HOST ...]
                        list of IPv4/IPv6 networks/addresses or domain/host
                        names that shall be processed.per default, mentioned
                        items are excluded. add + in front of item (e.g.,
                        +127.0.0.1) to process only these items
  --hashes              if specified, then the passwords specified via
                        arguments -p or -P are interpreted as hashes (this
                        adds arguments -m 'LocalHash' to hydra and -m
                        PASS:HASH to medusa)
  --http-proxy HTTP_PROXY
                        specify an HTTP(S) proxy that shall be used by
                        collectors in the format https://$ip:$port
  --proxychains         perform all collections via proxychains
  --restart {failed,terminated,completed} [{failed,terminated,completed} ...]
                        per default, kiscollect continues the collection from
                        the last interruption point, and ignores all
                        previously failed or terminated commands. With this
                        option the collection of commands with statuses
                        failed, terminated, or completed can be restarted.
  --strict              collect information only from services that are
                        definitely open (nmap state is open). ports with nmap
                        status 'open|filtered' are ignored. this option
                        decreases the intel collection time but might not be
                        as comprehensive
  --user-agent AGENT    set a user agent string
  --vhost {all,domain}  per default all HTTP(S) collectors (e.g., httpnikto,
                        httpgobuster) use the IPv4/IPv6 address to scan the
                        target web application. virtual hosts, which are not
                        accessible via this IPv4/IPv6 address are not scanned.
                        if this argument is specified, then the HTTP(S)
                        service intelligence gathering is performed on all
                        known in-scope host names. use choice 'domain' if you
                        want to collect intel just on the host names or use
                        choice 'all' to collect intel based on both -
                        IPv4/IPv6 addresses and host names
  -A, --analyze         re-analyze the already collected information. use this
                        option if you updated the verify_results method of a
                        collector and you want to import the update into the
                        database
  -B, --batch-mode      automatically start, execute, and stop the application
                        without user interaction
  -C COMBO_FILE, --combo-file COMBO_FILE
                        user name password combo files that shall be used by
                        collectors. the internal structure of the combo file
                        varies depending on the used collectors. for example,
                        hydra collectors have a different structure than
                        medusa collectors
  -D MIN, --delay-min MIN
                        minimum number of seconds between each operating
                        system command executions. if specified together with
                        option -M, then KIS randomly computes a delay between
                        MIN and MAX per execution else, the delay is always
                        MIN
  -L WORDLIST_FILES [WORDLIST_FILES ...], --wordlist-files WORDLIST_FILES [WORDLIST_FILES ...]
                        list of files containing words (e.g., host names or
                        URLs) that shall be used by collectors. usually KIS
                        creates one command per specified word list
  -M MAX, --delay-max MAX
                        maximum number of seconds between each operating
                        system command executions. if specified together with
                        option -D, then KIS randomly computes a delay between
                        MIN and MAX per execution else, the delay is always
                        MAX
  -P PASSWORD_FILE, --password-file PASSWORD_FILE
                        file containing passwords that shall be used by
                        collectors
  -S, --print-commands  print commands to be executed in console instead of
                        executing them. use this option to see how tools
                        (e.g., dnsenum) are executed
  -U USER_FILE, --user-file USER_FILE
                        file containing user names that shall be used by
                        collectors
  -d DOMAIN, --domain DOMAIN
                        domain or workgroup that shall be used by collectors
  -l, --list            list existing workspaces
  -o OUTPUT_DIR         KIS uses a temporary working directory to store all
                        temporary files. this working directory is deleted
                        when KIS quits. use this argument to specify an
                        alternative working directory, which must be manually
                        deleted. this argument is usually useful during
                        debugging
  -p PASSWORD, --password PASSWORD
                        password that shall be used by collectors
  -t THREADS, --threads THREADS
                        number of threads that execute collection
  -u USER, --user USER  username that shall be used by collectors
  -w WORKSPACE, --workspace WORKSPACE
                        the workspace within the collection is executed

---- USE CASES ----

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
$ kiscollect -w $ws -t4 --debug --vhost domain --dnshost --dnssublist3r --crtshdomain --dnsgobuster \ 
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
$ kiscollect -w $ws --debug --whoisdomain --whoishost --theharvester --dnsdumpster --reversewhois \
    --securitytrails --censysdomain --hunter --haveibeenbreach --haveibeenpaste --builtwith --crtshdomain \
    --virustotal --certspotter --dnssublist3r --dnsspf --dnsdkim --dnsdmark --hostio --dnshostpublic --awsslurp \
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
$ kiscollect -w $ws --debug --strict -t5 --ftphydra --snmphydra --snmpcheck --onesixtyone --showmount --ipmi \
--nbtscan --ikescan --ldapsearch --oraclesidguess --ntpq --sshnmap --httpgobuster --httpnikto --httphydra --smtpnmap \
--mysqlhydra --pgsqlhydra --smbnmap --smbmap --smbclient --rpcclient --rpcnmap --rpcinfo --mssqlhydra --mssqlnmap \
--finger --httpnmap --pop3nmap --imapnmap --tftpnmap --nfsnmap --x11nmap --msrpcenum --mysqlnmap --rdpnmap \
--httpdavtest --httpwhatweb --httpeyewitness --tlsnmap --smbfilelist --sslyze --sslscan --sshchangeme --httpchangeme \
--httpmsfrobotstxt --certnmap --ftpnmap --ldapnmap --dnsnmap --ldapnmap --snmpnmap --telnetnmap --vncnmap \
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
```

If kiscollect is started, then the user is presented with a user interface like the following:

![User interface after starting kiscollect](images/kiscollector_01.png "User interface after starting kiscollect")

The user interface is divided into the following three sections:

  1. **Collector list**: Provides you an overview of the collection status per collector. The numbers tell you how
  many Kali commands are pending, failed, or succeeded. The order of the collectors in this list is also the order of
  execution.
  2. **Thread info**: Shows you which thread runs which collector on which host, service, or domain for how long. Note
  that only the Kali commands of one collector are executed at a time and all Kali commands of the collector must be
  finished before continuing the execution of Kali commands of the next collector. Why? Subsequent collectors might depend
  on the information identified by the current collector. In addition, you might see several threads working on the same
  service. That's intended as one collector can create several commands, which are then executed by different threads in
  parallel.
  3. **Report items**: If a collector finds interesting information (e.g., credentials), then this information is shown
  in this area. This allows the immediate analysis of the identified information. In addition, this information is 
  also logged in log file `/opt/kaliintelsuite/kis/kaliintelsuite.log`. Note that this section is not scrollable. If 
  you want to access the data, then open the log file `/opt/kaliintelsuite/kis/kaliintelsuite.log`, which is located 
  in the output directory.

You can interact with `kiscollect` using the following commands. Each command is executed after you hit the enter key.

  * **s** starts the collection
  * **k** followed by the thread ID shown in the **Thread info** section, will kill the thread. `k1` will for example
  kill the first thread in the **Thread info** section.
  * **t** followed by the thread ID shown in the **Thread info** section, will terminate the thread. `t5` will for
  example terminate the fifth thread in the **Thread info** section.
  * **n** terminates all commands of the current collector and continues with the commands of the next collector.
  * **q** terminates all commands and quits the application.

If you add argument `-S` (show) to any `kiscollect` command, then KIS just prints the created OS commands. This helps in
  * gaining a better understanding of what the commands are actually doing or
  * in executing a single command manually for testing purposes.

Per default, when KIS is restarted, it does not execute OS commands that have successfully completed again. If you want
to force re-execution, then you have to add argument `-I` (ignore status).

**Note 1**: Make sure that the terminal where you start this command is in full screen mode and do not resize it.

**Note 2**: Do not start more than one process of `kiscollect` in parallel as `kiscollect` performs a cleanup during
the startup phase. Thereby, it deletes all commands whose execution have not been started. Consequently, the
kiscollect process that was started first, won't be able to find its commands anymore. As a result, you will find a
lot of exceptions in the `/opt/kaliintelsuite/kis/kaliintelsuite.log` file.
