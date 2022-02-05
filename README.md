# Kali Intelligence Suite

Kali Intelligence Suite (KIS) is an intelligence gathering and data mining tool for penetration testers. It shall aid
in the fast, autonomous, central, and comprehensive collection of intelligence by automatically:

 -  executing Kali Linux tools (e.g., dnsrecon, gobuster, hydra, nmap, etc.)
 -  querying publicly available APIs (e.g., Censys.io, Haveibeenpwned.com, Hunter.io, Securitytrails.com, Shodan.io, etc.)
 -  sending data to third-party applications like Burp Suite Professional or Aquatone
 -  storing the collected data in a central PostgreSQL database (see next section)
 -  providing an interface to query and analyze the gathered intelligence

After the execution of each Kali Linux tool or querying APIs, KIS analyses the collected information and extracts
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

 -  enables users to kill Kali commands via the KIS user interface in case they take too long

 -  access public APIs to enhance data with OSINT


## Setup and Installation

The latest version of KIS is available at
[Docker.com](https://hub.docker.com/r/chopicalqui/kali-intelligence-suite). Follow the installation and update
instructions [there](https://hub.docker.com/r/chopicalqui/kali-intelligence-suite).

Information about manual installations can be obtained from the wiki page
[Installing KIS](https://github.com/chopicalqui/KaliIntelligenceSuite/wiki/Installing-KIS).


## KIS' Data and Collection Model

The following figure illustrates KIS' data and collection model. Thereby, each node represents a table in the rational 
database and each solid line between the nodes documents the corresponding relationship. The dashed directed graphs 
document based on which already collected intelligence (source node) KIS is able to collect further information 
(destination node). The labels of the directed graphs document the techniques used by KIS to perform the collection.

![KIS' data and collection model](images/data-collection-model.png "KIS' data and collection model")


## Scoping the Engagement

Scoping is an essential feature of KIS, which is important to know about in order to use KIS effectively.

Therefore, information about scoping can be obtained from the wiki page
[Scoping in KIS](https://github.com/chopicalqui/KaliIntelligenceSuite/wiki/Scoping-in-KIS).


## List of KIS Collectors

For a complete list of available collector, refer to the wiki page
[KIS Collectors](https://github.com/chopicalqui/KaliIntelligenceSuite/wiki/KIS-Collectors).


## Usage

After the setup, the following KIS commands are available.

### kismanage

This script allows:
  - setting up and testing KIS
  - managing the database (re-creation, creating backups, restoring backups, etc.)
  - creating workspaces, networks, host names, emails, companies, etc.
  - importing Nmap, Nessus, and Masscan scan results
  - defining the scope

Run the following command to obtain more information and examples:
```bash
docker exec -it kaliintelsuite kismanage -h
```

### kiscollect

This script implements a commandline interface to collect the intelligence.

Run the following command to obtain more information and examples:
```bash
docker exec -it kaliintelsuite kiscollect -h
```

### kisreport

This script allows the analysis of the collected data via various filtering options. Supported report formats are:
  - Character-separated values (CSV): Export of the collected intelligence in the structured CSV format. This allows
  further processing via tools like grep, csvcut, or Aquatone
  - Microsoft Excel: Export of all collected intelligence into a Microsoft Excel file.
  - Text: Export of the collected raw text intelligence (e.g., text output of tool Nikto).
  - Raw: Export of additionally collected files like JSON objects from APIs like Shodan.io, or certificate files.

Run the following command to obtain more information and examples:
```bash
docker exec -it kaliintelsuite kisreport -h
```

## Author

**Lukas Reiter** ([@chopicalquy](https://twitter.com/chopicalquy)) - 
[Kali Intelligence Suite](https://github.com/chopicalqui/KaliIntelligenceSuite)

## License

This project is licensed under the GPLv3 License - see the [license](LICENSE) file for details.
