FROM kalilinux/kali-last-release as base

ENV LD_LIBRARY_PATH=/usr/local/lib \
    PYTHONFAULTHANDLER=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    PATH="/opt/kaliintelsuite/.venv/bin:${PATH}" \
    VIRTUAL_ENV="/opt/kaliintelsuite/.venv/"

# Create kali user
RUN useradd kali && \
    mkdir /home/kali && \
    chown kali:kali /home/kali

# Do base installation
WORKDIR /opt/kaliintelsuite
RUN apt-get update && \
    apt-get install -y ca-certificates openssl apt-transport-https && \
    echo "deb https://http.kali.org/kali kali-rolling main non-free contrib" >> /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y amass \
                       bind9-dnsutils \
                       bind9-host \
                       changeme \
                       chromium \
                       crackmapexec \
                       csvkit \
                       davtest \
                       dirb \
                       dnsenum \
                       dnsrecon \
                       dotdotpwn \
                       enum4linux \
                       finger \
                       ftp \
                       gobuster \
                       hydra \
                       ike-scan \
                       iputils-ping \
                       ldap-utils \
                       masscan \
                       metasploit-framework \
                       medusa \
                       nbtscan \
                       nfs-common \
                       nikto \
                       nmap \
                       ntp \
                       ntpdate \
                       onesixtyone \
                       passing-the-hash \
                       proxychains4 \
                       python3-minimal \
                       postgresql-client-14 \
                       rpcbind \
                       sidguesser \
                       smbclient \
                       smbmap \
                       smtp-user-enum \
                       snmp \
                       snmpcheck \
                       seclists \
                       sqlmap \
                       sslscan \
                       sslyze \
                       sublist3r \
                       theharvester \
                       tcptraceroute \
                       vim \
                       wapiti \
                       whatweb \
                       whois \
                       wpscan

# Setup container
FROM base as builder

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    GOPATH=/opt/go

# Install required packages for building process
RUN apt install -y git golang-go wget zip

# Prepare Aquatone
WORKDIR /tmp/
RUN wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip -O /tmp/aquatone.zip && \
    unzip /tmp/aquatone.zip

# Prepare Crobat
RUN go install github.com/cgboal/sonarsearch/cmd/crobat@latest

# Prepare Kiterunner
RUN wget https://github.com/assetnote/kiterunner/releases/download/v1.0.2/kiterunner_1.0.2_linux_amd64.tar.gz -O /tmp/kiterunner.tar.gz && \
    tar --extract -f /tmp/kiterunner.tar.gz -C /tmp/ && \
    wget -qO- https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz | tar -xvz -C /tmp/ && \
    wget -qO- https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite.tar.gz | tar -xvz -C /tmp/

# Prepare Slurp
RUN wget https://github.com/0xbharath/slurp/releases/download/1.1.0/slurp-1.1.0-linux-amd64 -O /tmp/slurp && \
    wget https://github.com/0xbharath/slurp/archive/refs/tags/1.1.0.tar.gz -O /tmp/1.1.0.tar.gz && \
    tar --extract -f /tmp/1.1.0.tar.gz -C /tmp/ && \
    chmod +x /tmp/slurp

# Obtain SNMP default password wordlist
RUN wget https://raw.githubusercontent.com/SECFORCE/sparta/master/wordlists/snmp-default.txt -O /tmp/snmp-default.txt

# Setup and install Poetry
RUN apt install -y python3-pip python2
ENV POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    POETRY_VERSION=1.1.8

RUN pip install "poetry==$POETRY_VERSION"
COPY pyproject.toml /opt/kaliintelsuite/
WORKDIR /opt/kaliintelsuite/
RUN ln -sT python2 /usr/bin/python && poetry install --no-root --no-dev


# Setup and deploy Kali Intelligence Suite
FROM base as final

# Deploy Aquatone
COPY --from=builder /tmp/aquatone /usr/local/bin/

# Deploy Crobat
COPY --from=builder /opt/go/bin/crobat /usr/local/bin/

# Deploy Kiterunner
COPY --from=builder /tmp/kr /usr/local/bin/
COPY --from=builder /tmp/routes-large.kite /usr/share/kiterunner/
COPY --from=builder /tmp/routes-small.kite /usr/share/kiterunner/

# Deploy Slurp
COPY --from=builder /tmp/slurp /usr/local/bin/
COPY --from=builder /tmp/slurp-1.1.0/permutations.json /usr/share/slurp/

# Deploy Python3 virtual environment
COPY --from=builder /opt/kaliintelsuite/.venv /opt/kaliintelsuite/.venv/

RUN ln -sT /opt/kaliintelsuite/kis/kiscollect.py /usr/bin/kiscollect && \
    ln -sT /opt/kaliintelsuite/kis/kismanage.py /usr/bin/kismanage && \
    ln -sT /opt/kaliintelsuite/kis/kisreport.py /usr/bin/kisreport && \
    ln -sT /opt/kaliintelsuite/kis/kiscustom.py /usr/bin/kiscustom

# Deploy SNMP default password wordlist
COPY --from=builder /tmp/snmp-default.txt /usr/share/legion/wordlists/

# This is the build stage label for unittests
FROM final as test

# Deploy KIS including unittests
COPY ./ /opt/kaliintelsuite/

ENV PYTHONPATH=/opt/kaliintelsuite/:/opt/kaliintelsuite/kis/

RUN ["bash"]
# RUN ["pytest", "--log-file", "/kis/unittests.log"]


# This is the build stage label for production
FROM final as production

# Modify .bashrc to prevent copy&paste issues
COPY .bashrc /root/.bashrc

# Deploy KIS
COPY ./kis /opt/kaliintelsuite/kis/

WORKDIR /opt/kaliintelsuite/kis
