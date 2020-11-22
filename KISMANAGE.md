# kismanage

This script implements all functionalities to set up and manage the PostgreSql database. It allows performing the
initial setup; creating and restoring PostgreSql database backups as well as adding and deleting workspaces, networks,
IP addresses, second-level domains/host names, and emails. kismanage is also used by kiscollect to query APIs like
Builtwith.com, Censys.io, Hunter.io, etc. The script provides the following functionalities.

```bash
root@kali: ~ $ kismanage -h
usage: kismanage [-h] [--debug] [-l] {kiscollect,scan,database,workspace,network,host,service,domain,email,company} ...

this script implements all functionalities to set up and manage the PostgreSql database. it allows performing the
initial setup; creating and restoring PostgreSql database backups as well as adding and deleting workspaces, networks,
IP addresses, second-level domains/host names, and emails. kismanage is also used by kiscollect to query APIs like
Builtwith.com, Censys.io, Hunter.io, etc.

positional arguments:
  {kiscollect,scan,database,workspace,network,host,service,domain,email,company}
                        list of available database modules
    kiscollect          contains functionality used by kiscollect
    scan                allows importing scan results from filesystem
    database            allows setting up and managing the database
    workspace           allows managing workspaces
    network             allows managing networks
    host                allows managing hosts
    service             allows managing services
    domain              allows managing second-level-domains and host names
    email               allows managing emails
    company             allows managing companies

optional arguments:
  --debug               prints extra information to log file
  -h, --help            show this help message and exit
  -l, --list            list existing workspaces

---- USE CASES ----

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
```

