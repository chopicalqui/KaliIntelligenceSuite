# Kali Intelligence Suite

Kali Intelligence Suite (KIS) shall aid in the fast, autonomous, central, and comprehensive collection of intelligence 
by automatically:

 -  executing Kali Linux tools (e.g., dnsrecon, gobuster, hydra, nmap, etc.)
 -  querying publicly available APIs (e.g., Censys.io, Haveibeenpwned.com, Hunter.io, Securitytrails.com,
 DNSdumpster.com, Shodan.io, etc.)
 -  storing the collected data in a central rational database (see next section)
 -  providing an interface to query and analyze the gathered intelligence

After the execution of each Kali Linux tools or querying APIs, KIS analyses the collected information and extracts
as well as reports interesting information like newly identified user credentials, hosts/domains, TCP/UDP services,
HTTP directories, etc. The extracted information is then internally stored in different PostgreSql database tables,
which enables the continuous, structured enhancement and re-use of the collected intelligence by subsequently
executed Kali Linux tools.

Additional features are:

 -  pre-defined dependencies between Kali Linux tools ensure that relevant information like SNMP default community
  strings or default credentials is known to KIS before trying to access the respective services

 -  remembering the execution status of each Kali Linux tool and API query ensures that already executed OS commands
  are not automatically executed again

 -  data imports of scan results of external scanners like Masscan, Nessus, or Nmap

 -  supporting the intelligence collection based on virtual hosts (vhost)

 -  using a modular approach that allows the fast integration of new Kali Linux tools

 -  parallel Kali Linux command execution by using a specifiable number of threads

 -  allowing users to kill Kali commands via the KIS user interface in case they take too long

## KIS' Data and Collection Model

The following figure illustrates KIS' data and collection model. Thereby, each node represents a table in the rational 
database and each solid line between the nodes documents the corresponding relationship. The dashed directed graphs 
document based on which already collected intelligence (source node) KIS is able to collect further information 
(destination node). The labels of the directed graphs document the techniques used by KIS to perform the collection.

![KIS' data and collection model](images/data-collection-model.png "KIS' data and collection model")

## Scoping the Engagement
Scoping is an essential feature of KIS, which specifies on which IP networks, IP addresses, host names, etc.,  
KIS is allowed to collect data (e.g., via OSINT or active scans) from. Before diving into scoping, it is important to 
understand the following collection types, which are supported by KIS:

 -  **Passive**: Passive collections do not directly interact with the targets but obtain the information from
 third-party sources like whois. Per default, KIS automatically executes these collections and, thereby, no scoping is 
 required.
 -  **Active**: Active collections directly interact with the targets by for example actively scanning them. Thus, in
 contrast to passive collections, these type of collection requires permission from the target's owner and, therefore,
 KIS does not automatically perform active collections unless the targets are explicitly marked as in scope.
 -  **Active***: Active* collections are actually passive collections. Nevertheless, as accessing some third-party
 sources is somehow limited (e.g., querying certain sources like Shodan.io cost credits), they are treated like active 
 collectors, and, as a result, targets must be marked as in scope in order to perform active* collections on them.

Scopes can be set on the following items by using the script
[kismanage](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/KISMANAGE.md):

 - **IP networks** and **IP addresses**: For IP networks the following scope types can be set:
    * `all`: Sets the given IP network (e.g., 192.168.1.0/24) together with all IP addresses (e.g., 192.168.1.1) that 
    are within this network range in scope. As a result, KIS automatically executes any active and active* collectors 
    on such IP networks and IP addresses.
    
      This type is useful during penetration tests where the scope is limited to certain IP networks and all their IP 
    addresses.
    
      The following listing provides an example on how this scope type is set during the initial intel collection setup:
      ```bash
      # create a new workspace example
      root@kali: ~ $ kismanage workspace -a example
      # add the network 192.168.1.0/24 to workspace example and set the scope to all (default)
      root@kali: ~ $ kismanage network -w example -a 192.168.1.0/24
      # add new IP address 192.168.1.1 to workspace example. IP address is automatically in scope due to the network's scope all
      root@kali: ~ $ kismanage host -w example -a 192.168.1.1
      ```
    * `strict`: Sets the given IP network (e.g., 192.168.1.0/24) in scope. In contrast to type `all`, IP addresses 
    (e.g., 192.168.1.1), which are within this network range, are not automatically in scope, unless they are explicitly 
    added. As a result, KIS automatically executes any active or active* collectors on such in-scope IP networks and 
    additionally on those IP addresses that are explicitly added to the scope.
    
      This type is useful during penetration tests where the scope is limited to certain IP networks and some (not all) 
    of their IP addresses. For example, the network-level collector `tcpnmapnetwork` performs an Nmap SYN scan on all 
    in-scope IP networks but excludes all IP addresses that are out-of-scope.
    
      The following listing provides an example on how this scope type is set during the initial intel collection setup:
      ```bash
      # create a new workspace example
      root@kali: ~ $ kismanage workspace -a example
      # add the network 192.168.1.0/24 to workspace example and set the scope to strict
      root@kali: ~ $ kismanage network -w example -a 192.168.1.0/24 -s strict
      # add new IP address 192.168.1.1 to workspace example and set it in scope (default)
      root@kali: ~ $ kismanage host -w example -a 192.168.1.1
      ```
    * `exclude`: Sets the given IP network (e.g., 192.168.1.0/24) together with all IP addresses (e.g., 192.168.1.1) 
    that are within this network range out of scope. As a result, KIS does not execute any active and active* 
    collectors on this IP network and its IP addresses.
    
      This scope type is the default type for all IP networks and IP addresses that are automatically identified by KIS 
    (e.g., via whois, DNS resolution, etc.). Thus, it is not necessary to explicitly set this scope type.
 - **Second-level domain** and **host names**: For second-level domains (e.g., megacorpone.com), the same scope types 
 as for IP networks (see above) exist. Their mode of operation is described below:
    * `all`: Sets the given second-level domain (e.g., megacorpone.com) together with all sub-domains (e.g. 
    www.megacorpone.com) in scope. As a result, KIS automatically executes any active and active* collectors 
    on such host names.
    
      This type is useful during penetration tests where the scope is limited to certain second-level domains and 
    all their sub-level domains.
    
      The following listing provides an example on how this scope type is set during the initial intel collection setup:
      ```bash
      # create a new workspace example
      root@kali: ~ $ kismanage workspace -a example
      # add the second-level domain megacorpone.com to workspace example and set the scope to all (default)
      root@kali: ~ $ kismanage domain -w example -a megacorpone.com
      ```
    * `strict`: Sets the given second-level domains (e.g., megacorpone.com) in scope. In contrast to type `all`, any 
    sub-level domains (e.g., www.megacorpone.com) are not automatically in scope, unless they are explicitly added.
    As a result, KIS automatically executes any active or active* collectors on such in-scope second-level domains 
    and additionally on those sub-level domains that are explicitly added to the scope.
    
      This type is useful during penetration tests where the scope is limited to certain sub-level domains.
    
      The following listing provides an example on how this scope type is set during the initial intel collection setup:
      ```bash
      # create a new workspace example
      root@kali: ~ $ kismanage workspace -a example
      # add the network 192.168.1.0/24 to workspace example and set the scope to strict
      root@kali: ~ $ kismanage domain -w example -a www.megacorpone.com ftp.megacorpone.com -s strict
      ```
    * `exclude`: Sets the given second-level domains (e.g., megacorpone.com) together with all sub-level domains 
    out of scope. As a result, KIS does not execute any active and active* collectors on these second-level domains.
    
      This scope type is the default type for all second-level domains and their sub-level domains that are 
    automatically identified by KIS (e.g., via extraction from certificates, etc.). Thus, it is not necessary to 
    explicitly set this scope type.
 - **Virtual hosts (vhost)**: KIS supports scanning vhosts (https://httpd.apache.org/docs/2.4/vhosts/) by using tools 
 like Nikto or Burp Suite Professional (see argument `--vhost` of script
 [kiscollect](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/KISCOLLECT.md)). Which vhosts are in scope and
 which are not is indirectly specified by scoping **IP networks** and **IP addresses** (see above) together with 
 **Second-level domain** and **host names** (see above). Below are two examples to demonstrate how it works:
 
   * Example 1: Let's assume the second-level domain google.com together with all sub-level domains that resolve to a 
   network range within 172.217.0.0/16 are in scope. In this case, the top-level domain google.com is added to the KIS 
   database with scope type `all` as documented below:
   
     ```bash
     # create a new workspace example
     root@kali: ~ $ kismanage workspace -a example
     # add the second-level domain google.com to workspace example and set the scope to all (default)
     root@kali: ~ $ kismanage domain -w example -a google.com
     ```
     
     In this case, KIS is able to, among other things, enumerate any sub-level domains as well as resolve their 
     corresponding IP addresses. In addition, to ensure that KIS scans any host with an IP address within the IP 
     network range 172.217.0.0/16, this network range must be added to KIS with scope type `all` as well:
     
     ```bash
     # add the network 172.217.0.0/16 to workspace example and set the scope to all (default)
     root@kali: ~ $ kismanage network -w example -a 172.217.0.0/16
     ```
     
   * Example 2: Let's assume the second-level domain google.com together with all sub-level domains that resolve to 
   any network range are in scope. In this case, the top-level domain google.com is added to the KIS database with 
   scope type `all` as documented below:
     
     ```bash
     # create a new workspace example
     root@kali: ~ $ kismanage workspace -a example
     # add the second-level domain google.com to workspace example and set the scope to all (default)
     root@kali: ~ $ kismanage domain -w example -a google.com
     ```
     
     In this case, KIS is able to, among other things, enumerate any sub-level domains as well as resolve their 
     corresponding IP addresses. In addition, to ensure that KIS scans any host, the network range 0.0.0.0/0 must 
     be added to KIS with scope type `all` as well:
     
     ```bash
     # add network 0.0.0.0/0 to workspace example and set the scope to all (default)
     root@kali: ~ $ kismanage network -w example -a 0.0.0.0/0
     ```


 -  Networks: By setting a certain network (e.g., 192.168.0.0/24) in scope, this network together with all IP addresses within
 this network become in scope for active and active* collections. In other words, KIS is allowed to perform active
 scans on these network and IP addresses.
 -  Second-level domains: By setting a certain second-level domain (e.g., google.com) in scope, this second-level
 domain as well as all sub domains (e.g., www.google.com) become in scope for active and active* collections.
 Note: If scans shall be performed on virtual hosts (VHOST), then the second-level domain as well as the IP
 addresses to which the virtual host resolves must be set in scope.


## List of KIS Collectors

The following table shows the list of existing collectors that are supported by KIS. These collectors are executed by
the script [kiscollect](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/KISCOLLECT.md) to create and execute
actual OS commands.

The **Priority** column provides information about the order of execution; the lower the number, the earlier the
respective OS commands are created and executed and subsequent collectors can profit from the already collected
information. Collectors with a priority of `-` are not automatically executed as they either require user interaction
or additional information (e.g., domain credentials) for execution.

The **Name** column contains the name of the collector. These names can be added as command arguments to
[kiscollect](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/KISCOLLECT.md) (e.g. `--nikto`). The name also
indicates, which underlying OS command is executed. Column **Level** specifies whether the collector is operating on:
  - services: Scans services by using IPv4 addresses and UDP/TCP port numbers
  - vhosts: Scans web services by using host names and TCP port numbers
  - hosts: Obtains information based on IPv4/IPv6 addresses
  - domains: Obtains information based on second-level domains and optionally sub-level domains
  - networks: Obtains information based on IPv4/IPv6 network ranges
  - emails: Obtains information based on emails
  - companies: Obtains information based on companies
Column **Type** specifies whether the collector actively approaches the target (`active`) or obtains the information 
from third-party sources (`passive` and `active*`).

The **IP Support** column specifies the IP versions, which are supported by the underlying Kali tool (e.g., gobuster).
Kali uses this information to decide which operating systems commands can be created and successfully executed. This
column is only relevant for host, network, service, and vhost (see column Level) collectors.

Column **Timeout** specifies the number of seconds after which the collector is automatically terminated.

The column **User** specifies the user with which the respective operating system commands are executed.

| Priority | Name              | Level           | Type     | IP Support | Timeout | User   |
| --------:| ----------------- |:---------------:|:--------:| ---------- | ------- | ------ |
| -        | ftpdotdotpwn      | service         | Active   | IPv4       | -       | nobody |
| -        | httpdotdotpwn     | service         | Active   | IPv4, IPv6 | -       | nobody |
| -        | httphydra         | service         | Active   | IPv4, IPv6 | -       | nobody |
| -        | rdphydra          | service         | Active   | IPv4, IPv6 | -       | nobody |
| -        | smbhydra          | service         | Active   | IPv4, IPv6 | -       | nobody |
| -        | smbmedusa         | service         | Active   | IPv4       | -       | nobody |
| -        | sshhydra          | service         | Active   | IPv4, IPv6 | -       | nobody |
| 125      | builtwith         | domain          | Active*  | -          | -       | nobody |
| 127      | hostio            | domain          | Active*  | -          | -       | nobody |
| 130      | censysdomain      | domain          | Active*  | -          | -       | kali   |
| 131      | securitytrails    | domain          | Active*  | -          | -       | nobody |
| 132      | dnsdumpster       | domain          | Active*  | -          | -       | nobody |
| 133      | certspotter       | domain          | Active*  | -          | -       | nobody |
| 134      | crtshdomain       | domain          | Active*  | -          | -       | nobody |
| 135      | virustotal        | domain          | Active*  | -          | -       | nobody |
| 140      | dnssublist3r      | domain          | Active   | -          | -       | nobody |
| 150      | theharvester      | domain          | Passive  | -          | -       | kali   |
| 155      | awsslurp          | domain          | Active   |            | -       | nobody |
| 160      | dnsenum           | domain          | Active   | -          | -       | nobody |
| 170      | dnsgobuster       | domain          | Active   | -          | -       | nobody |
| 210      | whoisdomain       | domain          | Active   | -          | 10      | nobody |
| 215      | dnsspf            | domain          | Active   | -          | -       | nobody |
| 220      | dnsdmark          | domain          | Active   | -          | -       | nobody |
| 235      | dnsdkim           | domain          | Active   | -          | -       | nobody |
| 240      | dnstakeover       | domain          | Active   | -          | -       | nobody |
| 310      | dnshost           | domain          | Active   | -          | -       | nobody |
| 312      | dnshostpublic     | domain          | Passive  | -          | -       | nobody |
| 320      | dnsreverselookup  | host            | Active   | IPv4, IPv6 | -       | nobody |
| 410      | hunter            | domain          | Active*  | -          | -       | nobody |
| 420      | haveibeenbreach   | email           | Active*  | -          | -       | nobody |
| 430      | haveibeenpaste    | email           | Active*  | -          | -       | nobody |
| 510      | whoishost         | host            | Passive  | IPv4, IPv6 | -       | nobody |
| 512      | whoisnetwork      | network         | Passive  | IPv4, IPv6 | -       | nobody |
| 515      | reversewhois      | company         | Active*  | -          | -       | nobody |
| 520      | shodanhost        | host            | Active*  | IPv4, IPv6 | -       | nobody |
| 521      | shodannetwork     | network         | Active*  | IPv4, IPv6 | -       | nobody |
| 530      | censyshost        | host            | Active*  | IPv4       | -       | nobody |
| 540      | crtshcompany      | company         | Active*  | -          | -       | root   |
| 1100     | tcpnmapnetwork    | network         | Active   | IPv4, IPv6 | -       | root   |
| 1150     | tcpnmapdomain     | domain          | Active   | IPv4, IPv6 | -       | root   |
| 1200     | udpnmapnetwork    | network         | Active   | IPv4, IPv6 | -       | root   |
| 1250     | udpnmapdomain     | domain          | Active   | IPv4, IPv6 | -       | root   |
| 1270     | icmpnmapnetwork   | network         | Active   | IPv4, IPv6 | -       | root   |
| 1300     | tcpmasscannetwork | network         | Active   | IPv4       | -       | root   |
| 1350     | anyservicenmap    | service         | Active   | IPv4, IPv6 | -       | root   |
| 1820     | tcptraceroute     | host            | Active   | IPv4, IPv6 | -       | nobody |
| 1900     | httpmsfrobotstxt  | service, vhost  | Active   | IPv4, IPv6 | -       | kali   |
| 2000     | dnsnmap           | service         | Active   | IPv4, IPv6 | -       | root   |
| 2020     | telnetnmap        | service         | Active   | IPv4, IPv6 | -       | root   |
| 2040     | vncnmap           | service         | Active   | IPv4, IPv6 | -       | root   |
| 2100     | mssqlnmap         | service         | Active   | IPv4, IPv6 | -       | root   |
| 2150     | mysqlnmap         | service         | Active   | IPv4, IPv6 | -       | root   |
| 2200     | smbnmap           | service         | Active   | IPv4, IPv6 | -       | root   |
| 2250     | ftpnmap           | service         | Active   | IPv4, IPv6 | -       | root   |
| 2300     | smtpnmap          | service         | Active   | IPv4, IPv6 | -       | root   |
| 2400     | rpcnmap           | service         | Active   | IPv4, IPv6 | -       | root   |
| 2500     | rdpnmap           | service         | Active   | IPv4, IPv6 | -       | root   |
| 2700     | pop3nmap          | service         | Active   | IPv4, IPv6 | -       | root   |
| 2750     | msrpcenum         | service         | Active   | IPv4, IPv6 | -       | root   |
| 2800     | imapnmap          | service         | Active   | IPv4, IPv6 | -       | root   |
| 2850     | x11nmap           | service         | Active   | IPv4, IPv6 | -       | root   |
| 2900     | tftpnmap          | service         | Active   | IPv4, IPv6 | -       | root   |
| 2950     | nfsnmap           | service         | Active   | IPv4, IPv6 | -       | root   |
| 3100     | finger            | service         | Active   | IPv4       | -       | nobody |
| 3200     | ntpdate           | service         | Active   | IPv4, IPv6 | -       | nobody |
| 3300     | ntpq              | service         | Active   | IPv4, IPv6 | -       | nobody |
| 4000     | h323version       | service         | Active   | IPv4, IPv6 | -       | kali   |
| 4100     | sipnmap           | service         | Active   | IPv4, IPv6 | -       | root   |
| 4120     | sipmsf            | service         | Active   | IPv4, IPv6 | -       | kali   |
| 4200     | stunnmap          | service         | Active   | IPv4, IPv6 | -       | root   |
| 11100    | ftphydra          | service         | Active   | IPv4, IPv6 | -       | nobody |
| 11200    | mssqlhydra        | service         | Active   | IPv4, IPv6 | -       | nobody |
| 11400    | pgsqlhydra        | service         | Active   | IPv4, IPv6 | -       | nobody |
| 11500    | snmphydra         | service         | Active   | IPv4, IPv6 | -       | nobody |
| 11600    | sshchangeme       | service         | Active   | IPv4, IPv6 | -       | kali   |
| 11700    | ipmi              | service         | Active   | IPv4, IPv6 | -       | kali   |
| 12100    | ftpfilelist       | service         | Active   | IPv4, IPv6 | -       | nobody |
| 13000    | showmount         | service         | Active   | IPv4, IPv6 | 300     | nobody |
| 13090    | smbcme            | service         | Active   | IPv4       | -       | kali   |
| 13100    | smbclient         | service         | Active   | IPv4, IPv6 | -       | nobody |
| 13200    | smbfilelist       | service         | Active   | IPv4, IPv6 | -       | nobody |
| 13210    | smbmap            | service         | Active   | IPv4       | -       | nobody |
| 21500    | nbtscan           | service         | Active   | IPv4       | -       | nobody |
| 21600    | ldapsearch        | service         | Active   | IPv4, IPv6 | -       | nobody |
| 21610    | ldapnmap          | service         | Active   | IPv4, IPv6 | -       | root   |
| 31100    | snmpcheck         | service         | Active   | IPv4       | 300     | nobody |
| 31110    | snmpnmap          | service         | Active   | IPv4, IPv6 | -       | root   |
| 31200    | onesixtyone       | service         | Active   | IPv4       | 60      | nobody |
| 31300    | snmpwalk          | service         | Active   | IPv4       | -       | nobody |
| 31400    | oraclesidguess    | service         | Active   | IPv4       | -       | nobody |
| 41100    | sslyze            | service, vhost  | Active   | IPv4       | -       | nobody |
| 41200    | sshnmap           | service         | Active   | IPv4, IPv6 | -       | root   |
| 41300    | certnmap          | service, vhost  | Active   | IPv4, IPv6 | -       | root   |
| 41305    | certopenssl       | service, vhost  | Active   | IPv4, IPv6 | 120     | nobody |
| 41310    | tlsnmap           | service, vhost  | Active   | IPv4, IPv6 | -       | root   |
| 41400    | sslscan           | service, vhost  | Active   | IPv4, IPv6 | -       | nobody |
| 51100    | httpgobuster      | service, vhost  | Active   | IPv4, IPv6 | -       | nobody |
| 51200    | httpnmap          | service, vhost  | Active   | IPv4, IPv6 | -       | root   |
| 51205    | httpntlmnmap      | service, vhost  | Active   | IPv4, IPv6 | -       | root   |
| 61400    | rpcclient         | service         | Active   | IPv4, IPv6 | -       | nobody |
| 61500    | rpcinfo           | service         | Active   | IPv4, IPv6 | -       | nobody |
| 71100    | ikescan           | service         | Active   | IPv4       | -       | root   |
| 91050    | httpwpscan        | service         | Active   | IPv4, IPv6 | -       | nobody |
| 91100    | enum4linux        | service         | Active   | IPv4       | -       | nobody |
| 91150    | httpchangeme      | service, vhost  | Active   | IPv4, IPv6 | -       | kali   |
| 91200    | httpnikto         | service, vhost  | Active   | IPv4       | -       | nobody |
| 91225    | httpburpsuitepro  | domain, host    | Active   | IPv4, IPv6 | -       | nobody |
| 91250    | httpdavtest       | service, vhost  | Active   | IPv4, IPv6 | -       | nobody |
| 91250    | httpwhatweb       | service         | Active   | IPv4, IPv6 | -       | nobody |
| 91300    | httpsqlmap        | service, vhost  | Active   | IPv4, IPv6 | -       | nobody |
| 91400    | smtpuserenum      | service         | Active   | IPv4       | -       | nobody |
| 91600    | mysqlhydra        | service         | Active   | IPv4, IPv6 | -       | nobody |
| 92200    | httpwapiti        | service, vhost  | Active   | IPv4, IPv6 | -       | nobody |
| 100000   | vncviewer         | service         | Active   | IPv4       | -       | nobody |
| 100100   | httpeyewitness    | service, vhost  | Active   | IPv4, IPv6 | 3600    | kali   |
| 114200   | dnsrecon          | domain          | Active   | -          | -       | nobody |


## Installing KIS

Note that KIS is only tested on Kali Linux and it has the following minimum system requirements:
 - 2 CPUs
 - 2048 MB RAM

In order to use KIS, the following configuration steps must be successfully accomplished beforehand:

 -  [mandatory] Clone the repository to a directory you prefere. Depending on your location preference, you might have 
    to execute this clone with root privileges.

    ```bash
    kali@kali: ~ $ sudo git clone https://github.com/chopicalqui/KaliIntelligenceSuite.git /opt/kaliintelsuite
    ```

 -  [mandatory] Install required Python3 packages

    ```bash
    kali@kali: ~ $ sudo pip3 install -r /opt/kaliintelsuite/requirements.txt
    ```

 -  [mandatory] Run the setup script: Use argument `--setup-dbg` instead of `--setup` to review the setup
    OS commands first

    ```bash
    root@kali: ~ $ sudo /opt/kaliintelsuite/kis/kismanage.py database --setup
    ```

 - [optional] Setup connection to APIs: In order to access the APIs of censys.io, hunter.io, securitytrails.com, or
   shodan.io, you must have an existing account for those services. Obtain the respective API keys and store them in
   the configuration file `kis/configs/api.conf` sections `[censys]`, `[hunter]`, `[securitytrails]`, or `[shodan]`.
   
 - [optional] Setup slurp (Amazon S3 bucket enumeration): Install slurp (https://github.com/0xbharath/slurp). Per 
   default, the slurp executable and the permutation file should be located in the following locations:
   
   `/home/kali/go/bin/slurp`
   `/home/kali/go/src/github.com/0xbharath/slurp/permutations.json`
   
   If, the slurp location is different, then update the file path in
   [collectors.config](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/kis/configs/collectors.config), 
   section `[file_paths]`, entry `slurp`. In addition, make sure that slurp's permutations file (`permutations.json`) is
   correctly set in 
   [collectors.config](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/kis/configs/collectors.config), 
   section `[default_wordlists]`, entry `slurp_permutations_file`.

 - [mandatory] Check KIS setup to determine potential issues

    ```bash
    kali@kali: ~ $ sudo pip3 install -r /opt/kaliintelsuite/requirements.txt
    check os
    Linux kali 5.8.0-kali2-amd64 #1 SMP Debian 5.8.10-1kali1 (2020-09-22) x86_64     [supported]
    
    check tools (see section 'file_paths' in: /opt/kaliintelsuite/kis/configs/collectors.config)
    postgresql                                                                       [installed]
    kiscollect                                                                       [installed]
    kisreport                                                                        [installed]
    enum4linux                                                                       [installed]
    gobuster                                                                         [installed]
    medusa                                                                           [installed]
    [...]
    ```
    Review the above output; there should not be any red entries.

## Usage

After the setup, the following KIS commands are available.

 - [kismanage](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/KISMANAGE.md): This tool allows:
    * managing the database (re-creation, creating backups, restoring backups, etc.)
    * creating workspaces, networks, host names, emails, and companies
    * importing Nmap, Nessus, and Masscan scan results
    * defining the scope

   For more information refer to [kismanage](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/KISMANAGE.md)
 - [kiscollect](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/KISCOLLECT.md): This tool performs the
 automated intelligence collection based on the already collected data. For more information refer to
 [kiscollect](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/KISCOLLECT.md)
 - [kisreport](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/KISREPORT.md): This tool allows the analysis
 of the collected data via various filtering options. Supported report formats are:
    * Character-separated values (CSV): Export of the collected intelligence format in the structured CSV format.
    This allows further processing via tools like `grep` or `csvcut`
    * Microsoft Excel: Export of all collected intelligence into a Microsoft Excel file.
    * Text: Export of the collected raw text intelligence (e.g., text output of tool Nikto)
    * Raw: Export of additionally collected files like JSON objects from APIs like Shodan.io, certificate files,
    or screenshots made by screenshotting tools like Eyewitness.

   For more information refer to [kisreport](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/KISREPORT.md)

   
## Author

**Lukas Reiter** (@chopicalquy) - [Kali Intelligence Suite](https://github.com/chopicalqui/KaliIntelligenceSuite)

## License

This project is licensed under the GPLv3 License - see the
[license](https://github.com/chopicalqui/KaliIntelligenceSuite/blob/master/LICENSE) file for details.
