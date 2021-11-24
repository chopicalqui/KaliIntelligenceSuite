# Installation

Note that Kali Intelligence Suite (KIS) only runs on official releases of Kali Linux. Before you start, clone the KIS
repository to the directory `/opt/kaliintelsuite`:

```bash
sudo git clone https://github.com/chopicalqui/KaliIntelligenceSuite.git /opt/kaliintelsuite
```

## Docker Installation (recommended)

In order to use KIS in a Docker environment, follow the following configuration steps:

 - **[mandatory]** After cloning the KIS repository (see above), create and store a secret in the file
   `/opt/kaliintelsuite/postgres.txt`:

    ```bash
    sudo su -
    pwgen -s 30 -N1 > /opt/kaliintelsuite/postgres.txt
    chmod 400 /opt/kaliintelsuite/postgres.txt
    ```

    This file is used by [docker-compose.yml](docker-compose.yml) to set the password for the PostgresSQL user.

 - **[optional]** Specify your API keys of Burp Suite Professional, censys.io, hunter.io, etc. in
   the respective sections of the configuration file [api.config](kis/configs/api.config).

 - **[mandatory]** Navigate to the local KIS Git repository, pull/build the Docker images, and launch the Docker
   containers postgres and kaliintelsuite:

    ```bash
    cd /opt/kaliintelsuite
    docker-compose run -d --name kaliintelsuite kaliintelsuite
    ```

 - **[mandatory]** Initialize the database.

    ```bash
    docker exec -it kaliintelsuite kismanage database --init --drop
    ```

 - **[optional]** Check KIS setup to determine potential issues:

    ```bash
    docker exec -it kaliintelsuite kismanage database --test
    check os
    Linux 161047b3acca 5.10.0-kali8-amd64 #1 SMP Debian 5.10.40-1kali1 (2021-05-31) x86_64    [supported]

    check tools (see section 'file_paths' in: /opt/kaliintelsuite/configs/collectors.config)
    postgresql                                                                                [installed]
    kiscollect                                                                                [installed]
    kisreport                                                                                 [installed]
    enum4linux                                                                                [installed]
    gobuster                                                                                  [installed]
    medusa                                                                                    [installed]
    [...]
    ```

    Review the command's output; there should not be any red entries marked as `[missing]` or `[unsupported]`.

 - **[optional]** Remove unused Docker data to free up space:

    ```bash
    docker system prune
    ```

## Manual Installation (not officially supported)

This setup requires an official
[Kali Linux](https://www.kali.org/docs/introduction/download-official-kali-linux-images/) release with the following
minimum system requirements:
 - 2 CPUs
 - 4096 MB RAM

In order to manually install KIS, the following configuration steps must be executed:

 -  **[mandatory]** After cloning the SFH repository (see above), navigate to the local KIS Git repository, install
    the required Python3 packages, and launch a virtual environment:

    ```bash
    kali@kali: ~ $ sudo su -
    root@kali: ~ # cd /opt/kaliintelsuite
    root@kali: /opt/kaliintelsuite # export POETRY_VIRTUALENVS_IN_PROJECT=true
    root@kali: /opt/kaliintelsuite # export POETRY_VIRTUALENVS_PATH=/opt/kaliintelsuite/.venv/
    root@kali: /opt/kaliintelsuite # poetry install --no-root --no-dev
    root@kali: /opt/kaliintelsuite # poetry shell
    ```

    Note that it is important that the virutal environment is created in directory `/opt/kaliintelsuite/.venv/` as
    KIS uses this full path to access Python3.

 -  **[mandatory]** Run the setup script:

    ```bash
    root@kali: /opt/kaliintelsuite # /opt/kaliintelsuite/kis/kismanage.py database --setup
    ```

    Use argument `--setup-dbg` instead of `--setup` to review the setup OS commands first.

 - **[optional]** Specify your API keys of Burp Suite Professional, censys.io, hunter.io, etc. in
   the respective sections of the configuration file [api.config](kis/configs/api.config).

 - **[optional]** Manually install Aquatone, Crobat, Kiterunner, and Slurp as they are not part of the Kali Linux
   distribution (refer to the [Dockerfile](Dockerfile) for additional information):

 - **[mandatory]** Check KIS setup to determine potential issues:

    ```bash
    root@kali: /opt/kaliintelsuite # kismanage database --test
    check os
    Linux kali 5.8.0-kali2-amd64 #1 SMP Debian 5.8.10-1kali1 (2020-09-22) x86_64              [supported]

    check tools (see section 'file_paths' in: /opt/kaliintelsuite/kis/configs/collectors.config)
    postgresql                                                                                [installed]
    kiscollect                                                                                [installed]
    kisreport                                                                                 [installed]
    enum4linux                                                                                [installed]
    gobuster                                                                                  [installed]
    medusa                                                                                    [installed]
    [...]
    ```

    Review the command's output; there should not be any red entries marked as `[missing]` or `[unsupported]`.
