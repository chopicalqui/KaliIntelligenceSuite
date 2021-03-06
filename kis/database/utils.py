# -*- coding: utf-8 -*-
""""This file contains general functionality for database communication."""

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

import sqlalchemy
import sys
import passgen
import shutil
from sqlalchemy import create_engine
from configs import config
from configs.config import Database as DatabaseConfig
from configs.config import Collector as CollectorConfig
from configs.config import ApiConfig
from collectors.os.core import SetupCommand
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import scoped_session
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager

DeclarativeBase = declarative_base()
Session = sessionmaker()

from database.model import *

logger = logging.getLogger('database')


class Engine:
    """This class implements general methods to interact with the underlying database."""

    def __init__(self, production: bool = True):
        self.production = production
        self._config = config.Database(production)
        self._engine = create_engine(self._config.connection_string)
        self._session_factory = sessionmaker(bind=self._engine)
        self._Session = scoped_session(self._session_factory)

    @property
    def engine(self):
        return self._engine

    @contextmanager
    def session_scope(self):
        """Provide a transactional scope around a series of operations."""
        session = self.get_session()
        try:
            yield session
            session.commit()
        except Exception as ex:
            logger.exception(ex)
            session.rollback()
            raise
        finally:
            session.close()

    def get_workspace(self, session, name: str) -> Workspace:
        try:
            workspace = session.query(Workspace).filter(Workspace.name == name).one()
        except sqlalchemy.orm.exc.NoResultFound:
            print("Only the following workspaces exist:", file=sys.stderr)
            self.list_workspaces()
            workspace = None
        return workspace

    def print_workspaces(self):
        with self.session_scope() as session:
            workspaces = session.query(Workspace).all()
            if workspaces:
                print("the following workspaces exist:")
                for workspace in workspaces:
                    print("- {}".format(workspace.name))
            else:
                print("database does not contain any workspaces")

    def get_session(self):
        return self._Session()

    def list_workspaces(self):
        with self.session_scope() as session:
            for workspace in session.query(Workspace).all():
                print(workspace.name)

    def create_backup(self, file: str) -> None:
        """
        This method creates a backup of the KIS database into the given file
        :param file:
        :return:
        """
        if os.path.exists(file):
            raise FileExistsError("the file '{}' exists.".format(file))
        with open(file, "wb") as file:
            rvalue = subprocess.Popen(['sudo', '-u', 'postgres', 'pg_dump', self._config.database],
                                      stdout=file, stderr=subprocess.DEVNULL).wait()
        if rvalue != 0:
            raise subprocess.CalledProcessError("creating backup failed with return code {}".format(rvalue))

    def restore_backup(self, file: str) -> None:
        """
        This method restores a backup of the KIS database from the given file
        :param file:
        :return:
        """
        if not os.path.exists(file):
            raise FileExistsError("the file '{}' does not exist.".format(file))
        self.drop()
        with open(file, "rb") as file:
            rvalue = subprocess.Popen(['sudo', '-u', 'postgres', 'psql', self._config.database],
                                      stdin=file, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).wait()
        if rvalue != 0:
            raise subprocess.CalledProcessError("creating backup failed with return code {}".format(rvalue))

    def set_commands_incomplete(self, workspace: str, collector_name: str=None) -> None:
        """
        This method sets all pending OS commands to status execution terminated
        :param command_name: If specified the status for all commands with the same command_name are update
        """
        with self.session_scope() as session: \
            # todo: update for new collector
            commands_host = session.query(Command.id) \
                .join((CollectorName, Command.collector_name)) \
                .join((Host, Command.host)) \
                .join((Workspace, Host.workspace)) \
                .filter(Workspace.name == workspace, Command.status == CommandStatus.pending)
            commands_host_name = session.query(Command.id) \
                .join((CollectorName, Command.collector_name)) \
                .join((HostName, Command.host_name)) \
                .join((DomainName, HostName.domain_name)) \
                .join((Workspace, DomainName.workspace)) \
                .filter(Workspace.name == workspace, Command.status == CommandStatus.pending)
            commands_ipv4_network = session.query(Command.id) \
                .join((CollectorName, Command.collector_name)) \
                .join((Network, Command.ipv4_network)) \
                .join((Workspace, Network.workspace)) \
                .filter(Workspace.name == workspace, Command.status == CommandStatus.pending)
            commands_email = session.query(Command.id) \
                .join((CollectorName, Command.collector_name)) \
                .join((Email, Command.email)) \
                .join((HostName, Email.host_name)) \
                .join((DomainName, HostName.domain_name)) \
                .join((Workspace, DomainName.workspace)) \
                .filter(Workspace.name == workspace, Command.status == CommandStatus.pending)
            command_ids = commands_host.union(commands_host_name) \
                .union(commands_ipv4_network) \
                .union(commands_email).all()
            for command in session.query(Command).filter(Command.id.in_(command_ids)):
                if collector_name == command.collector_name.name or not collector_name:
                    command.status = CommandStatus.terminated

    def delete_incomplete_commands(self, workspace: str) -> None:
        """This method resets all status that have not successfully completed to status pending"""
        with self.session_scope() as session:
            # todo: update for new collector
            commands_host = session.query(Command.id)\
                .join((Host, Command.host))\
                .join((Workspace, Host.workspace))\
                .filter(Workspace.name == workspace, Command.status.in_([CommandStatus.pending,
                                                                        CommandStatus.collecting])).subquery()
            session.query(Command).filter(Command.id.in_(commands_host)).delete(synchronize_session='fetch')
            commands_host_name = session.query(Command.id)\
                .join((HostName, Command.host_name))\
                .join((DomainName, HostName.domain_name))\
                .join((Workspace, DomainName.workspace))\
                .filter(Workspace.name == workspace, Command.status.in_([CommandStatus.pending,
                                                                        CommandStatus.collecting])).subquery()
            session.query(Command).filter(Command.id.in_(commands_host_name)).delete(synchronize_session='fetch')
            commands_ipv4_network = session.query(Command.id)\
                .join((Network, Command.ipv4_network))\
                .join((Workspace, Network.workspace))\
                .filter(Workspace.name == workspace, Command.status.in_([CommandStatus.pending,
                                                                        CommandStatus.collecting])).subquery()
            session.query(Command).filter(Command.id.in_(commands_ipv4_network)).delete(synchronize_session='fetch')
            commands_email = session.query(Command.id)\
                .join((Email, Command.email))\
                .join((HostName, Email.host_name))\
                .join((DomainName, HostName.domain_name))\
                .join((Workspace, DomainName.workspace))\
                .filter(Workspace.name == workspace, Command.status.in_([CommandStatus.pending,
                                                                        CommandStatus.collecting])).subquery()
            session.query(Command).filter(Command.id.in_(commands_email)).delete(synchronize_session='fetch')

    def init(self, load_cipher_suites: bool):
        """This method initializes the database."""
        self._create_tables()
        self._create_views()
        self._create_functions()
        self._create_triggers()
        if load_cipher_suites:
            self._add_cipher_suites()

    def recreate_database(self):
        """
        This method drops the databases
        """
        """This method drops all views and tables in the database."""
        for database in [self._config.production_database, self._config.test_database]:
            # drop database
            result = subprocess.Popen(['sudo', '-u', 'postgres', 'dropdb', database],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL).wait()
            if result != 0:
                raise subprocess.CalledProcessError("dropping database '{}' failed with return code {}".format(database,
                                                                                                               result))
            # create database
            result = subprocess.Popen(['sudo', '-u', 'postgres', 'createdb', database],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL).wait()
            if result != 0:
                raise subprocess.CalledProcessError("creating database '{}' failed with return code {}".format(database,
                                                                                                               result))
            # assign privileges to database
            result = subprocess.Popen(['sudo', '-u', 'postgres', 'psql',
                                       '-c', 'grant all privileges on database {} to {}'.format(database,
                                                                                                self._config.username)],
                                      stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL).wait()
            if result != 0:
                raise subprocess.CalledProcessError("assigning privileges on database '{}' for '{}' "
                                                    "failed with return code {}".format(database,
                                                                                        self._config.username,
                                                                                        result))

    def drop(self):
        """This method drops all views and tables in the database."""
        self._drop_views()
        self._drop_tables()

    def _create_tables(self) -> None:
        """This method creates all tables."""
        DeclarativeBase.metadata.create_all(self._engine, checkfirst=True)

    def _create_views(self) -> None:
        """This method creates all views."""
        pass

    def _drop_tables(self) -> None:
        """This method drops all tables in the database."""
        DeclarativeBase.metadata.drop_all(self._engine, checkfirst=True)

    def _drop_views(self) -> None:
        """This method drops all views"""
        pass

    def _create_functions(self) -> None:
        """This method creates all functions"""
        # Triggers for setting host_names in or out of scope
        # update_host_names_after_domain_name_changes
        self._engine.execute("""CREATE OR REPLACE FUNCTION update_host_names_after_domain_name_changes() 
        RETURNS TRIGGER AS $$
        BEGIN
            IF (TG_OP = 'INSERT') THEN
                -- Set the scope of the host name that represents the second-level domain
                UPDATE host_name
                SET in_scope = (NEW.scope = 'strict' OR NEW.scope = 'all')
                WHERE domain_name_id = NEW.id AND name IS NULL;
            ELSIF (TG_OP = 'UPDATE' AND OLD.scope <> NEW.scope) THEN
                -- Update scope of all sub-domains if the scope of the second-level domain is updated
                UPDATE host_name
                SET in_scope = (NEW.scope = 'all')
                WHERE domain_name_id = NEW.id AND name IS NOT NULL;
                
                UPDATE host_name
                SET in_scope = (NEW.scope = 'strict' OR NEW.scope = 'all')
                WHERE domain_name_id = NEW.id AND name IS NULL;
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # update_host_names_after_host_names_changes
        self._engine.execute("""CREATE OR REPLACE FUNCTION update_host_names_after_host_names_changes() 
        RETURNS TRIGGER AS $$
        BEGIN
            -- automatically set host_name's in_scope attribute to true, if domain_name scope is all
            IF (EXISTS(SELECT * FROM domain_name n 
                       WHERE n.id = NEW.domain_name_id AND n.scope = 'all') AND NOT NEW.in_scope) THEN
                UPDATE host_name
                SET in_scope = True
                WHERE id = NEW.id;
            ELSIF (EXISTS(SELECT * FROM domain_name n 
                          WHERE n.id = NEW.domain_name_id AND n.scope = 'exclude') AND NEW.in_scope) THEN
                UPDATE host_name
                SET in_scope = False
                WHERE id = NEW.id;
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # Triggers for setting hosts in or out of scope
        # update_hosts_after_ipv4network_changes
        self._engine.execute("""CREATE OR REPLACE FUNCTION update_hosts_after_ipv4network_changes() 
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        -- update the scope of the current network
        IF (EXISTS(SELECT * FROM network 
                   WHERE address >> NEW.address and workspace_id = NEW.workspace_id AND scope = 'all')) THEN
            UPDATE network
            SET scope = 'all'
            WHERE id = NEW.id;
        END IF;
        
        -- update the scope of all networks within the newly added network
        -- we only update the scope if the new network has scope all. in this case we know that the scope was set by
        -- a user and not a collector
        IF (NEW.scope = 'all') THEN
            UPDATE network n
            SET scope = NEW.scope
            WHERE n.address << NEW.address AND n.workspace_id = NEW.workspace_id;
        END IF;
        
        -- update the scope of all hosts
        UPDATE host h
        SET in_scope = (NEW.scope = 'all')
        WHERE h.address <<= NEW.address AND h.workspace_id = NEW.workspace_id;
        
        -- the new network is the smallest network in the network table. in this case, we assign hosts to this
        -- network
        IF (NOT EXISTS(SELECT * FROM network WHERE address << NEW.address AND workspace_id = NEW.workspace_id)) THEN
            UPDATE host h
            SET network_id = NEW.id
            WHERE h.address <<= NEW.address and h.workspace_id = NEW.workspace_id;
        END IF;
    ELSIF (TG_OP = 'UPDATE' AND NEW.scope <> OLD.scope) THEN
        -- update the scope
        UPDATE host h
        SET in_scope = (NEW.scope = 'all')
        WHERE h.address <<= NEW.address AND h.workspace_id = NEW.workspace_id;
    ELSIF (TG_OP = 'DELETE') THEN
        -- re-assign network
        UPDATE host h
        SET network_id = n.id
        FROM network n
        WHERE h.address <<= n.address AND h.workspace_id = n.workspace_id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE PLPGSQL;""")
        # update_hosts_after_host_changes
        self._engine.execute("""CREATE OR REPLACE FUNCTION update_hosts_after_host_changes() 
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'INSERT') THEN
        -- assign hosts to network
        UPDATE host h
        SET network_id = n.id
        FROM network n
        WHERE h.address <<= n.address and h.workspace_id = n.workspace_id;
    ELSIF (TG_OP = 'UPDATE' AND abbrev(OLD.address) <> abbrev(NEW.address)) THEN
        -- remove all previous assignments
        UPDATE host h
        SET network_id = NULL
        FROM network n
        WHERE h.id = NEW.id;
        -- re-assign hosts to network
        UPDATE host h
        SET network_id = n.id
        FROM network n
        WHERE h.address <<= n.address and h.id = NEW.id;
    END IF;
    -- automatically set host's in_scope attribute to true, if network scope is all
    IF (EXISTS(SELECT * FROM network n 
               WHERE n.id = NEW.network_id AND n.scope = 'all') AND NOT NEW.in_scope) THEN
        UPDATE host
        SET in_scope = True
        WHERE id = NEW.id;
    ELSIF (EXISTS(SELECT * FROM network n 
                  WHERE n.id = NEW.network_id AND n.scope = 'exclude') AND NEW.in_scope) THEN
        UPDATE host
        SET in_scope = False
        WHERE id = NEW.id;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE PLPGSQL;""")
        # assign_services_to_host_name
        self._engine.execute("""CREATE OR REPLACE FUNCTION assign_services_to_host_name() 
RETURNS TRIGGER AS $$
DECLARE
service_cursor CURSOR(id_host integer) FOR SELECT * FROM service WHERE service.host_id = id_host;
current_row service%%ROWTYPE;
BEGIN
    IF (new.type & 1) < 3  THEN
        OPEN service_cursor(NEW.host_id);
        LOOP
            FETCH service_cursor INTO current_row;
            EXIT WHEN NOT FOUND;
            IF (NOT EXISTS(SELECT * FROM service WHERE protocol = current_row.protocol AND port = current_row.port AND host_name_id = NEW.host_name_id)) THEN
                INSERT INTO service (host_name_id,
                                     protocol, 
                                     port, 
                                     nmap_service_name, 
                                     nessus_service_name, 
                                     nmap_service_confidence, 
                                     nessus_service_confidence, 
                                     nmap_service_name_original,
                                     state,
                                     nmap_service_state_reason, 
                                     nmap_product,
                                     nmap_version,
                                     nmap_tunnel, 
                                     nmap_os_type, 
                                     creation_date) VALUES (NEW.host_name_id,
                                                            current_row.protocol,
                                                            current_row.port,
                                                            current_row.nmap_service_name,
                                                            current_row.nessus_service_name,
                                                            current_row.nmap_service_confidence,
                                                            current_row.nessus_service_confidence,
                                                            current_row.nmap_service_name_original,
                                                            current_row.state,
                                                            current_row.nmap_service_state_reason,
                                                            current_row.nmap_product,
                                                            current_row.nmap_version,
                                                            current_row.nmap_tunnel,
                                                            current_row.nmap_os_type,
                                                            NOW());
            END IF;
        END LOOP;
        CLOSE service_cursor;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE PLPGSQL;""")
        # add_services_to_host_name
        self._engine.execute("""CREATE OR REPLACE FUNCTION add_services_to_host_name() 
RETURNS TRIGGER AS $$
DECLARE
mapping_host_name_cursor CURSOR(id_service integer) FOR SELECT host_host_name_mapping.host_name_id FROM 
    host_host_name_mapping 
    INNER JOIN host ON host.id = host_host_name_mapping.host_id
    INNER JOIN service ON service.host_id = host.id
    INNER JOIN host_name ON host_name.id = host_host_name_mapping.host_name_id
    WHERE host_host_name_mapping.type < 3 AND service.id = id_service;
id_host_name integer;
mapping_host_cursor CURSOR(id_service integer) FOR SELECT host_host_name_mapping.host_id FROM 
    host_host_name_mapping 
    INNER JOIN host_name ON host_name.id = host_host_name_mapping.host_name_id
    INNER JOIN service ON service.host_name_id = host_name.id
    INNER JOIN host ON host.id = host_host_name_mapping.host_id
    WHERE host_host_name_mapping.type < 3 AND service.id = id_service;
id_host integer;
BEGIN
    IF (pg_trigger_depth() = 1) THEN
        IF (NEW.host_id IS NOT NULL) THEN
            OPEN mapping_host_name_cursor(NEW.id);
            LOOP
                FETCH mapping_host_name_cursor INTO id_host_name;
                EXIT WHEN NOT FOUND;
                IF (NOT EXISTS(SELECT * FROM service WHERE protocol = NEW.protocol AND port = NEW.port AND host_name_id = id_host_name)) THEN
                    INSERT INTO service (host_name_id,
                                         protocol,
                                         port,
                                         nmap_service_name,
                                         nessus_service_name,
                                         nmap_service_confidence,
                                         nessus_service_confidence,
                                         nmap_service_name_original,
                                         state,
                                         nmap_service_state_reason,
                                         nmap_product,
                                         nmap_version,
                                         nmap_tunnel,
                                         nmap_os_type,
                                         creation_date) SELECT id_host_name,
                                                               protocol,
                                                               port,
                                                               nmap_service_name,
                                                               nessus_service_name,
                                                               nmap_service_confidence,
                                                               nessus_service_confidence,
                                                               nmap_service_name_original,
                                                               state,
                                                               nmap_service_state_reason,
                                                               nmap_product,
                                                               nmap_version,
                                                               nmap_tunnel,
                                                               nmap_os_type,
                                                               NOW() FROM service WHERE id = NEW.id;
                ELSIF (NEW.host_id = OLD.host_id AND NEW.protocol = OLD.protocol AND NEW.port = OLD.port) THEN
                    UPDATE service
                    SET protocol = t.protocol,
                        port = t.port,
                        nmap_service_name = t.nmap_service_name,
                        nessus_service_name = t.nessus_service_name,
                        nmap_service_confidence = t.nmap_service_confidence,
                        nessus_service_confidence = t.nessus_service_confidence,
                        nmap_service_name_original = t.nmap_service_name_original,
                        state = t.state,
                        nmap_service_state_reason = t.nmap_service_state_reason,
                        nmap_product = t.nmap_product,
                        nmap_version = t.nmap_version,
                        nmap_tunnel = t.nmap_tunnel,
                        nmap_os_type = t.nmap_os_type
                    FROM service AS s
                    JOIN (SELECT id_host_name AS host_name_id,
                                 protocol,
                                 port,
                                 nmap_service_name,
                                 nessus_service_name,
                                 nmap_service_confidence,
                                 nessus_service_confidence,
                                 nmap_service_name_original,
                                 state,
                                 nmap_service_state_reason,
                                 nmap_product,
                                 nmap_version,
                                 nmap_tunnel,
                                 nmap_os_type FROM service WHERE id = NEW.id) AS t ON t.host_name_id = s.host_name_id AND
                                                                                      t.port = s.port AND
                                                                                      t.protocol = s.protocol
                    WHERE service.id = s.id;
                END IF;
            END LOOP;
            CLOSE mapping_host_name_cursor;
        ELSIF (NEW.host_name_id IS NOT NULL) THEN
            OPEN mapping_host_cursor(NEW.id);
            LOOP
                FETCH mapping_host_cursor INTO id_host;
                EXIT WHEN NOT FOUND;
                IF (NOT EXISTS(SELECT * FROM service WHERE protocol = NEW.protocol AND port = NEW.port AND host_id = id_host)) THEN 
                    INSERT INTO service (host_id,
                                         protocol,
                                         port,
                                         nmap_service_name,
                                         nessus_service_name,
                                         nmap_service_confidence,
                                         nessus_service_confidence,
                                         nmap_service_name_original,
                                         state,
                                         nmap_service_state_reason,
                                         nmap_product,
                                         nmap_version,
                                         nmap_tunnel,
                                         nmap_os_type,
                                         creation_date) SELECT id_host,
                                                               protocol,
                                                               port,
                                                               nmap_service_name,
                                                               nessus_service_name,
                                                               nmap_service_confidence,
                                                               nessus_service_confidence,
                                                               nmap_service_name_original,
                                                               state,
                                                               nmap_service_state_reason,
                                                               nmap_product,
                                                               nmap_version,
                                                               nmap_tunnel,
                                                               nmap_os_type,
                                                               NOW() FROM service WHERE id = NEW.id;
                ELSIF (NEW.host_name_id = OLD.host_name_id AND NEW.protocol = OLD.protocol AND NEW.port = OLD.port) THEN
                    UPDATE service
                    SET protocol = t.protocol,
                        port = t.port,
                        nmap_service_name = t.nmap_service_name,
                        nessus_service_name = t.nessus_service_name,
                        nmap_service_confidence = t.nmap_service_confidence,
                        nessus_service_confidence = t.nessus_service_confidence,
                        nmap_service_name_original = t.nmap_service_name_original,
                        state = t.state,
                        nmap_service_state_reason = t.nmap_service_state_reason,
                        nmap_product = t.nmap_product,
                        nmap_version = t.nmap_version,
                        nmap_tunnel = t.nmap_tunnel,
                        nmap_os_type = t.nmap_os_type
                    FROM service AS s
                    JOIN (SELECT id_host AS host_id,
                                 protocol,
                                 port,
                                 nmap_service_name,
                                 nessus_service_name,
                                 nmap_service_confidence,
                                 nessus_service_confidence,
                                 nmap_service_name_original,
                                 state,
                                 nmap_service_state_reason,
                                 nmap_product,
                                 nmap_version,
                                 nmap_tunnel,
                                 nmap_os_type FROM service WHERE id = NEW.id) AS t ON t.host_id = s.host_id AND
                                                                                      t.port = s.port AND
                                                                                      t.protocol = s.protocol
                    WHERE service.id = s.id;
                END IF;
            END LOOP;
            CLOSE mapping_host_cursor;
        END IF;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE PLPGSQL;""")
        self._engine.execute("""CREATE OR REPLACE FUNCTION reassign_hosts_to_network() 
RETURNS TEXT AS $$
DECLARE
network_cursor CURSOR FOR SELECT * FROM network;
current_row network%%ROWTYPE;
BEGIN
  OPEN network_cursor;
  LOOP
    FETCH network_cursor INTO current_row;
    EXIT WHEN NOT FOUND;
    -- the new network is the smallest network in the network table. in this case, we assign hosts to this
    -- network
    IF (NOT EXISTS(SELECT * FROM network WHERE address << current_row.address AND workspace_id = current_row.workspace_id)) THEN
      UPDATE host h
      SET network_id = current_row.id
      WHERE h.address <<= current_row.address and h.workspace_id = current_row.workspace_id;
    END IF;
  END LOOP;
  CLOSE network_cursor;
  RETURN NULL;
END;
$$ LANGUAGE PLPGSQL;""")

    def _drop_functions(self) -> None:
        """This method drops all functions"""
        self._engine.execute("""DROP FUNCTION update_host_names_after_domain_name_changes;""")
        self._engine.execute("""DROP FUNCTION update_host_names_after_host_names_changes;""")
        self._engine.execute("""DROP FUNCTION update_hosts_after_ipv4network_changes;""")
        self._engine.execute("""DROP FUNCTION update_hosts_after_host_changes;""")
        self._engine.execute("""DROP FUNCTION assign_services_to_host_name;""")
        self._engine.execute("""DROP FUNCTION add_services_to_host_name;""")
        self._engine.execute("""DROP FUNCTION reassign_hosts_to_network;""")

    def _create_triggers(self) -> None:
        """This method creates all triggers."""
        # Triggers on host_name and domain_name tables
        self._engine.execute("""CREATE TRIGGER after_domain_name_changes AFTER INSERT OR UPDATE ON domain_name
 FOR EACH ROW EXECUTE PROCEDURE update_host_names_after_domain_name_changes();""")
        self._engine.execute("""CREATE TRIGGER after_host_name_changes AFTER INSERT OR UPDATE ON host_name
 FOR EACH ROW EXECUTE PROCEDURE update_host_names_after_host_names_changes();""")
        # Triggers on host and network tables
        self._engine.execute("""CREATE TRIGGER after_network_changes AFTER INSERT OR UPDATE OR DELETE ON network
 FOR EACH ROW EXECUTE PROCEDURE update_hosts_after_ipv4network_changes();""")
        self._engine.execute("""CREATE TRIGGER after_host_changes AFTER INSERT OR UPDATE ON host
 FOR EACH ROW EXECUTE PROCEDURE update_hosts_after_host_changes();""")
        self._engine.execute("""CREATE TRIGGER host_host_name_mapping_insert AFTER INSERT OR UPDATE ON host_host_name_mapping
 FOR EACH ROW EXECUTE PROCEDURE assign_services_to_host_name();""")
        self._engine.execute("""CREATE TRIGGER service_insert AFTER INSERT OR UPDATE ON service
 FOR EACH ROW EXECUTE PROCEDURE add_services_to_host_name();""")

    def _drop_trigger(self) -> None:
        """This method drops all triggers."""
        self._engine.execute("""DROP TRIGGER after_domain_name_changes ON domain_name""")
        self._engine.execute("""DROP TRIGGER after_host_name_changes ON host_name""")
        self._engine.execute("""DROP TRIGGER after_network_changes ON network""")
        self._engine.execute("""DROP TRIGGER after_host_changes ON host""")
        self._engine.execute("""DROP TRIGGER host_name_mapping_insert ON host_name_mapping""")
        self._engine.execute("""DROP TRIGGER service_insert ON service""")

    @staticmethod
    def get_or_create(session, model, one_or_none=True, **kwargs):
        """
        This method queries the given model based on the filter kwargs or creates a new instance

        The method queries, the given model (e.g. Host) for existing entries based on the filter stored in kwargs. If
        argument one_or_none is set to true, then the query must return one argument, else an exception is thrown. If
        the argument is false, then the first value returned by the filter is returned. If no object is identified, then
        a new entry is created and added to the session.

        :param session: The database session used to query the database and eventually add a new object.
        :param model: The class that is queried (e.g., Task or Project).
        :param one_or_none: Specifies whether an exception shall be thrown if the query returns more than one result.
        :param kwargs: The filter to query for entries in the model.
        :return: An instance of type model.
        """
        if one_or_none:
            instance = session.query(model).filter_by(**kwargs).one_or_none()
        else:
            instance = session.query(model).filter_by(**kwargs).first()
        if not instance:
            instance = model(**kwargs)
            session.add(instance)
            session.flush()
        return instance

    def _add_cipher_suites(self):
        with self.session_scope() as session:
            session.add(CipherSuite(iana_name='TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA', gnutls_name=None, byte_1=0x00,
                                    byte_2=0x19, protocol_version=CipherSuiteProtocolVersion.tls_export,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.des40_cbc, enc_algorithm_bits=40, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_EXPORT_WITH_RC4_40_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x17,
                            protocol_version=CipherSuiteProtocolVersion.tls_export,
                            kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.rc4_40, enc_algorithm_bits=40, aead=False,
                            hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_3DES_EDE_CBC_SHA', gnutls_name='ADH-DES-CBC3-SHA', byte_1=0x00,
                            byte_2=0x1B, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_AES_128_CBC_SHA', gnutls_name='ADH-AES128-SHA', byte_1=0x00,
                            byte_2=0x34, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_anon_WITH_AES_128_CBC_SHA256', gnutls_name='ADH-AES128-SHA256',
                                    byte_1=0x00, byte_2=0x6C, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_AES_128_GCM_SHA256', gnutls_name='ADH-AES128-GCM-SHA256',
                            byte_1=0x00, byte_2=0xA6, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_AES_256_CBC_SHA', gnutls_name='ADH-AES256-SHA', byte_1=0x00,
                            byte_2=0x3A, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_anon_WITH_AES_256_CBC_SHA256', gnutls_name='ADH-AES256-SHA256',
                                    byte_1=0x00, byte_2=0x6D, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_AES_256_GCM_SHA384', gnutls_name='ADH-AES256-GCM-SHA384',
                            byte_1=0x00, byte_2=0xA7, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_anon_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x46, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.aria128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_anon_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x5A, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.aria128_gcm, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_anon_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x47, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.aria256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_anon_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x5B, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.aria256_gcm, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA', gnutls_name='ADH-CAMELLIA128-SHA',
                            byte_1=0x00, byte_2=0x46, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256', gnutls_name='ADH-CAMELLIA128-SHA256',
                            byte_1=0x00, byte_2=0xBF, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x84, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA', gnutls_name='ADH-CAMELLIA256-SHA',
                            byte_1=0x00, byte_2=0x89, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256', gnutls_name='ADH-CAMELLIA256-SHA256',
                            byte_1=0x00, byte_2=0xC5, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x85, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_DES_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x1A,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.anon, enc_algorithm=SymmetricAlgorithm.des_cbc,
                            enc_algorithm_bits=56, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_anon_WITH_RC4_128_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x18,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.anon, enc_algorithm=SymmetricAlgorithm.rc4_128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.md5,
                            security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_anon_WITH_SEED_CBC_SHA', gnutls_name='ADH-SEED-SHA', byte_1=0x00,
                                    byte_2=0x9B, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.seed_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA', gnutls_name=None, byte_1=0x00,
                                    byte_2=0x0B, protocol_version=CipherSuiteProtocolVersion.tls_export,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.des40_cbc, enc_algorithm_bits=40, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_DSS_WITH_DES_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x0C,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.des_cbc, enc_algorithm_bits=56, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA', gnutls_name=None, byte_1=0x00,
                                    byte_2=0x11, protocol_version=CipherSuiteProtocolVersion.tls_export,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.des40_cbc, enc_algorithm_bits=40, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_DSS_WITH_DES_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x12,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dhe,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.des_cbc,
                            enc_algorithm_bits=56, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_NULL_SHA', gnutls_name='DHE-PSK-NULL-SHA', byte_1=0x00,
                                    byte_2=0x2D, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_PSK_WITH_NULL_SHA256', gnutls_name='DHE-PSK-NULL-SHA256', byte_1=0x00,
                            byte_2=0xB4, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_PSK_WITH_NULL_SHA384', gnutls_name='DHE-PSK-NULL-SHA384', byte_1=0x00,
                            byte_2=0xB5, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_PSK_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x8E,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dhe,
                            auth_algorithm=AuthenticationAlgorithm.psk, enc_algorithm=SymmetricAlgorithm.rc4_128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA', gnutls_name=None, byte_1=0x00,
                                    byte_2=0x14, protocol_version=CipherSuiteProtocolVersion.tls_export,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.des40_cbc, enc_algorithm_bits=40, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_DES_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x15,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dhe,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.des_cbc,
                            enc_algorithm_bits=56, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA', gnutls_name=None, byte_1=0x00,
                                    byte_2=0x0E, protocol_version=CipherSuiteProtocolVersion.tls_export,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.des40_cbc, enc_algorithm_bits=40, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_DH_RSA_WITH_DES_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x0F,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.des_cbc, enc_algorithm_bits=56, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA', gnutls_name='AECDH-DES-CBC3-SHA',
                                    byte_1=0xC0, byte_2=0x17, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.anon,
                                    enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168,
                                    aead=False, hash_algorithm=HashAlgorithm.sha1,
                                    security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_anon_WITH_AES_128_CBC_SHA', gnutls_name='AECDH-AES128-SHA', byte_1=0xC0,
                            byte_2=0x18, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_anon_WITH_AES_256_CBC_SHA', gnutls_name='AECDH-AES256-SHA', byte_1=0xC0,
                            byte_2=0x19, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.anon,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_ECDH_anon_WITH_NULL_SHA', gnutls_name='AECDH-NULL-SHA', byte_1=0xC0,
                                    byte_2=0x15, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.anon, enc_algorithm=SymmetricAlgorithm.null,
                                    enc_algorithm_bits=None, aead=False, hash_algorithm=HashAlgorithm.sha1,
                                    security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_anon_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x16,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdh,
                            auth_algorithm=AuthenticationAlgorithm.anon, enc_algorithm=SymmetricAlgorithm.rc4_128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_NULL_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x01,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdh,
                            auth_algorithm=AuthenticationAlgorithm.ecdsa, enc_algorithm=SymmetricAlgorithm.null,
                            enc_algorithm_bits=None, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x02,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdh,
                            auth_algorithm=AuthenticationAlgorithm.ecdsa, enc_algorithm=SymmetricAlgorithm.rc4_128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_NULL_SHA', gnutls_name='ECDHE-ECDSA-NULL-SHA', byte_1=0xC0,
                            byte_2=0x06, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x07,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                            auth_algorithm=AuthenticationAlgorithm.ecdsa, enc_algorithm=SymmetricAlgorithm.rc4_128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_NULL_SHA', gnutls_name='ECDHE-PSK-NULL-SHA', byte_1=0xC0,
                            byte_2=0x39, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_NULL_SHA256', gnutls_name='ECDHE-PSK-NULL-SHA256',
                                    byte_1=0xC0, byte_2=0x3A, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk, enc_algorithm=SymmetricAlgorithm.null,
                                    enc_algorithm_bits=None, aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_NULL_SHA384', gnutls_name='ECDHE-PSK-NULL-SHA384',
                                    byte_1=0xC0, byte_2=0x3B, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk, enc_algorithm=SymmetricAlgorithm.null,
                                    enc_algorithm_bits=None, aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x33,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                            auth_algorithm=AuthenticationAlgorithm.psk, enc_algorithm=SymmetricAlgorithm.rc4_128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_NULL_SHA', gnutls_name='ECDHE-RSA-NULL-SHA', byte_1=0xC0,
                            byte_2=0x10, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x11,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.rc4_128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_ECDH_RSA_WITH_NULL_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x0B,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_RSA_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x0C,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.rc4_128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x29,
                            protocol_version=CipherSuiteProtocolVersion.tls_export,
                            kex_algorithm=KeyExchangeAlgorithm.krb5, auth_algorithm=AuthenticationAlgorithm.krb5,
                            enc_algorithm=SymmetricAlgorithm.des_cbc_40, enc_algorithm_bits=40, aead=False,
                            hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x26,
                            protocol_version=CipherSuiteProtocolVersion.tls_export,
                            kex_algorithm=KeyExchangeAlgorithm.krb5, auth_algorithm=AuthenticationAlgorithm.krb5,
                            enc_algorithm=SymmetricAlgorithm.des_cbc_40, enc_algorithm_bits=40, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x2A,
                            protocol_version=CipherSuiteProtocolVersion.tls_export,
                            kex_algorithm=KeyExchangeAlgorithm.krb5, auth_algorithm=AuthenticationAlgorithm.krb5,
                            enc_algorithm=SymmetricAlgorithm.rc2_cbc_40, enc_algorithm_bits=40, aead=False,
                            hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x27,
                            protocol_version=CipherSuiteProtocolVersion.tls_export,
                            kex_algorithm=KeyExchangeAlgorithm.krb5, auth_algorithm=AuthenticationAlgorithm.krb5,
                            enc_algorithm=SymmetricAlgorithm.rc2_cbc_40, enc_algorithm_bits=40, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_KRB5_EXPORT_WITH_RC4_40_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x2B,
                            protocol_version=CipherSuiteProtocolVersion.tls_export,
                            kex_algorithm=KeyExchangeAlgorithm.krb5, auth_algorithm=AuthenticationAlgorithm.krb5,
                            enc_algorithm=SymmetricAlgorithm.rc4_40, enc_algorithm_bits=40, aead=False,
                            hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_KRB5_EXPORT_WITH_RC4_40_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x28,
                            protocol_version=CipherSuiteProtocolVersion.tls_export,
                            kex_algorithm=KeyExchangeAlgorithm.krb5, auth_algorithm=AuthenticationAlgorithm.krb5,
                            enc_algorithm=SymmetricAlgorithm.rc4_40, enc_algorithm_bits=40, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_KRB5_WITH_3DES_EDE_CBC_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x23,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.krb5,
                            auth_algorithm=AuthenticationAlgorithm.krb5,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_KRB5_WITH_DES_CBC_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x22,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.krb5,
                                    auth_algorithm=AuthenticationAlgorithm.krb5,
                                    enc_algorithm=SymmetricAlgorithm.des_cbc, enc_algorithm_bits=56, aead=False,
                                    hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_KRB5_WITH_DES_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x1E,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.krb5,
                                    auth_algorithm=AuthenticationAlgorithm.krb5,
                                    enc_algorithm=SymmetricAlgorithm.des_cbc, enc_algorithm_bits=56, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_KRB5_WITH_IDEA_CBC_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x25,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.krb5,
                                    auth_algorithm=AuthenticationAlgorithm.krb5,
                                    enc_algorithm=SymmetricAlgorithm.idea_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_KRB5_WITH_RC4_128_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x24,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.krb5,
                                    auth_algorithm=AuthenticationAlgorithm.krb5,
                                    enc_algorithm=SymmetricAlgorithm.rc4_128, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_KRB5_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x20,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.krb5,
                                    auth_algorithm=AuthenticationAlgorithm.krb5,
                                    enc_algorithm=SymmetricAlgorithm.rc4_128, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_NULL_WITH_NULL_NULL', gnutls_name=None, byte_1=0x00, byte_2=0x00,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.null,
                                    auth_algorithm=AuthenticationAlgorithm.null, enc_algorithm=SymmetricAlgorithm.null,
                                    enc_algorithm_bits=None, aead=False, hash_algorithm=HashAlgorithm.null,
                                    security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_NULL_SHA', gnutls_name='PSK-NULL-SHA', byte_1=0x00, byte_2=0x2C,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.psk,
                            auth_algorithm=AuthenticationAlgorithm.psk, enc_algorithm=SymmetricAlgorithm.null,
                            enc_algorithm_bits=None, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_NULL_SHA256', gnutls_name='PSK-NULL-SHA256', byte_1=0x00,
                                    byte_2=0xB0, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_NULL_SHA384', gnutls_name='PSK-NULL-SHA384', byte_1=0x00,
                                    byte_2=0xB1, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x8A,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.rc4_128, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x08,
                            protocol_version=CipherSuiteProtocolVersion.tls_export,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.des40_cbc, enc_algorithm_bits=40, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x06,
                            protocol_version=CipherSuiteProtocolVersion.tls_export,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.rc2_cbc_40, enc_algorithm_bits=40, aead=False,
                            hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_EXPORT_WITH_RC4_40_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x03,
                            protocol_version=CipherSuiteProtocolVersion.tls_export,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.rc4_40, enc_algorithm_bits=40, aead=False,
                            hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_NULL_SHA', gnutls_name='RSA-PSK-NULL-SHA', byte_1=0x00,
                                    byte_2=0x2E, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_PSK_WITH_NULL_SHA256', gnutls_name='RSA-PSK-NULL-SHA256', byte_1=0x00,
                            byte_2=0xB8, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_PSK_WITH_NULL_SHA384', gnutls_name='RSA-PSK-NULL-SHA384', byte_1=0x00,
                            byte_2=0xB9, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_PSK_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x92,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.psk, enc_algorithm=SymmetricAlgorithm.rc4_128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_DES_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x09,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.des_cbc, enc_algorithm_bits=56, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_NULL_MD5', gnutls_name='NULL-MD5', byte_1=0x00, byte_2=0x01,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                                    hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_NULL_SHA', gnutls_name='NULL-SHA', byte_1=0x00, byte_2=0x02,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.null, enc_algorithm_bits=None, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_NULL_SHA256', gnutls_name='NULL-SHA256', byte_1=0x00, byte_2=0x3B,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.null,
                            enc_algorithm_bits=None, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_RC4_128_MD5', gnutls_name=None, byte_1=0x00, byte_2=0x04,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.rc4_128, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.md5, security=CipherSuiteSecurity.insecure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_RC4_128_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x05,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.rc4_128, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.insecure))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x0D,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_AES_128_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x30,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.aes128_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_AES_128_CBC_SHA256', gnutls_name=None, byte_1=0x00, byte_2=0x3E,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.aes128_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_AES_128_GCM_SHA256', gnutls_name=None, byte_1=0x00, byte_2=0xA4,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.aes128_gcm,
                            enc_algorithm_bits=128, aead=True, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_AES_256_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x36,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.aes256_cbc,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_AES_256_CBC_SHA256', gnutls_name=None, byte_1=0x00, byte_2=0x68,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.aes256_cbc,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_AES_256_GCM_SHA384', gnutls_name=None, byte_1=0x00, byte_2=0xA5,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.aes256_gcm,
                            enc_algorithm_bits=256, aead=True, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0, byte_2=0x3E,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.aria128_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0, byte_2=0x58,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.aria128_gcm,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0, byte_2=0x3F,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.aria256_cbc,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0, byte_2=0x59,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.aria256_gcm,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA', gnutls_name=None, byte_1=0x00,
                                    byte_2=0x42, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256', gnutls_name=None, byte_1=0x00,
                                    byte_2=0xBB, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x82, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA', gnutls_name=None, byte_1=0x00,
                                    byte_2=0x85, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256', gnutls_name=None, byte_1=0x00,
                                    byte_2=0xC1, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x83, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_DSS_WITH_SEED_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x97,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.dss, enc_algorithm=SymmetricAlgorithm.seed_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA', gnutls_name='DHE-DSS-DES-CBC3-SHA',
                                    byte_1=0x00, byte_2=0x13, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168,
                                    aead=False, hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA', gnutls_name='DHE-PSK-3DES-EDE-CBC-SHA',
                            byte_1=0x00, byte_2=0x8F, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', gnutls_name='DHE-RSA-DES-CBC3-SHA',
                                    byte_1=0x00, byte_2=0x16, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168,
                                    aead=False, hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x10,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_AES_128_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x31,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes128_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_AES_128_CBC_SHA256', gnutls_name=None, byte_1=0x00, byte_2=0x3F,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes128_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_AES_128_GCM_SHA256', gnutls_name=None, byte_1=0x00, byte_2=0xA0,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes128_gcm,
                            enc_algorithm_bits=128, aead=True, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_AES_256_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x37,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes256_cbc,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_AES_256_CBC_SHA256', gnutls_name=None, byte_1=0x00, byte_2=0x69,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes256_cbc,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_AES_256_GCM_SHA384', gnutls_name=None, byte_1=0x00, byte_2=0xA1,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes256_gcm,
                            enc_algorithm_bits=256, aead=True, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0, byte_2=0x40,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aria128_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0, byte_2=0x54,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aria128_gcm,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0, byte_2=0x41,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aria256_cbc,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0, byte_2=0x55,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aria256_gcm,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA', gnutls_name=None, byte_1=0x00,
                                    byte_2=0x43, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256', gnutls_name=None, byte_1=0x00,
                                    byte_2=0xBC, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x7E, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA', gnutls_name=None, byte_1=0x00,
                                    byte_2=0x86, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256', gnutls_name=None, byte_1=0x00,
                                    byte_2=0xC2, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x7F, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DH_RSA_WITH_SEED_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x98,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.dh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.seed_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x03, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168,
                                    aead=False, hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x04,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdh,
                            auth_algorithm=AuthenticationAlgorithm.ecdsa, enc_algorithm=SymmetricAlgorithm.aes128_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x25, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x2D, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x05,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdh,
                            auth_algorithm=AuthenticationAlgorithm.ecdsa, enc_algorithm=SymmetricAlgorithm.aes256_cbc,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x26, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x2E, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x4A, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aria128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x5E, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aria128_gcm, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x4B, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aria256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x5F, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aria256_gcm, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x74, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x88, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x75, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x89, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', gnutls_name='ECDHE-ECDSA-DES-CBC3-SHA',
                            byte_1=0xC0, byte_2=0x08, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA', gnutls_name='ECDHE-PSK-3DES-EDE-CBC-SHA',
                            byte_1=0xC0, byte_2=0x34, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', gnutls_name='ECDHE-RSA-DES-CBC3-SHA',
                            byte_1=0xC0, byte_2=0x12, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x0D,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdh,
                            auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_RSA_WITH_AES_128_CBC_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x0E,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes128_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x29, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x31, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_RSA_WITH_AES_256_CBC_SHA', gnutls_name=None, byte_1=0xC0, byte_2=0x0F,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.ecdh,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes256_cbc,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x2A, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x32, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x4E, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x62, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria128_gcm, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x4F, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x63, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria256_gcm, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x78, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x8C, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x79, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x8D, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdh, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_KRB5_WITH_3DES_EDE_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x1F,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.krb5,
                            auth_algorithm=AuthenticationAlgorithm.krb5,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_3DES_EDE_CBC_SHA', gnutls_name='PSK-3DES-EDE-CBC-SHA', byte_1=0x00,
                            byte_2=0x8B, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA', gnutls_name='RSA-PSK-3DES-EDE-CBC-SHA',
                            byte_1=0x00, byte_2=0x93, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_3DES_EDE_CBC_SHA', gnutls_name='DES-CBC3-SHA', byte_1=0x00,
                                    byte_2=0x0A, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168,
                                    aead=False, hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA', gnutls_name='SRP-DSS-3DES-EDE-CBC-SHA',
                            byte_1=0xC0, byte_2=0x1C, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.srp, auth_algorithm=AuthenticationAlgorithm.sha_dss,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA', gnutls_name='SRP-DSS-AES-128-CBC-SHA',
                            byte_1=0xC0, byte_2=0x1F, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.srp, auth_algorithm=AuthenticationAlgorithm.sha_dss,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA', gnutls_name='SRP-DSS-AES-256-CBC-SHA',
                            byte_1=0xC0, byte_2=0x22, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.srp, auth_algorithm=AuthenticationAlgorithm.sha_dss,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA', gnutls_name='SRP-RSA-3DES-EDE-CBC-SHA',
                            byte_1=0xC0, byte_2=0x1B, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.srp, auth_algorithm=AuthenticationAlgorithm.sha_rsa,
                            enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA', gnutls_name='SRP-RSA-AES-128-CBC-SHA',
                            byte_1=0xC0, byte_2=0x1E, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.srp, auth_algorithm=AuthenticationAlgorithm.sha_rsa,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA', gnutls_name='SRP-RSA-AES-256-CBC-SHA',
                            byte_1=0xC0, byte_2=0x21, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.srp, auth_algorithm=AuthenticationAlgorithm.sha_rsa,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA', gnutls_name='SRP-3DES-EDE-CBC-SHA',
                                    byte_1=0xC0, byte_2=0x1A, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.srp, auth_algorithm=AuthenticationAlgorithm.sha,
                                    enc_algorithm=SymmetricAlgorithm.tripledes_ede_cbc, enc_algorithm_bits=168,
                                    aead=False, hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_SRP_SHA_WITH_AES_128_CBC_SHA', gnutls_name='SRP-AES-128-CBC-SHA',
                                    byte_1=0xC0, byte_2=0x1D, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.srp, auth_algorithm=AuthenticationAlgorithm.sha,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(CipherSuite(iana_name='TLS_SRP_SHA_WITH_AES_256_CBC_SHA', gnutls_name='SRP-AES-256-CBC-SHA',
                                    byte_1=0xC0, byte_2=0x20, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.srp, auth_algorithm=AuthenticationAlgorithm.sha,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.weak))
            session.add(
                CipherSuite(iana_name='TLS_DHE_DSS_WITH_AES_128_CBC_SHA', gnutls_name='DHE-DSS-AES128-SHA', byte_1=0x00,
                            byte_2=0x32, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', gnutls_name='DHE-DSS-AES128-SHA256',
                            byte_1=0x00, byte_2=0x40, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_DSS_WITH_AES_256_CBC_SHA', gnutls_name='DHE-DSS-AES256-SHA', byte_1=0x00,
                            byte_2=0x38, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_DSS_WITH_AES_256_CBC_SHA256', gnutls_name='DHE-DSS-AES256-SHA256',
                            byte_1=0x00, byte_2=0x6A, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x42, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.aria128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x43, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.aria256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA', gnutls_name='DHE-DSS-CAMELLIA128-SHA',
                            byte_1=0x00, byte_2=0x44, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                            enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
                                    gnutls_name='DHE-DSS-CAMELLIA128-SHA256', byte_1=0x00, byte_2=0xBD,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA', gnutls_name='DHE-DSS-CAMELLIA256-SHA',
                            byte_1=0x00, byte_2=0x87, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                            enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
                                    gnutls_name='DHE-DSS-CAMELLIA256-SHA256', byte_1=0x00, byte_2=0xC3,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_DSS_WITH_SEED_CBC_SHA', gnutls_name='DHE-DSS-SEED-SHA', byte_1=0x00,
                            byte_2=0x99, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                            enc_algorithm=SymmetricAlgorithm.seed_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_AES_128_CBC_SHA', gnutls_name='DHE-PSK-AES128-CBC-SHA',
                                    byte_1=0x00, byte_2=0x90, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_PSK_WITH_AES_128_CBC_SHA256', gnutls_name='DHE-PSK-AES128-CBC-SHA256',
                            byte_1=0x00, byte_2=0xB2, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_PSK_WITH_AES_128_CCM', gnutls_name='DHE-PSK-AES128-CCM', byte_1=0xC0,
                            byte_2=0xA6, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes128, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.ccm, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_AES_256_CBC_SHA', gnutls_name='DHE-PSK-AES256-CBC-SHA',
                                    byte_1=0x00, byte_2=0x91, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_PSK_WITH_AES_256_CBC_SHA384', gnutls_name='DHE-PSK-AES256-CBC-SHA384',
                            byte_1=0x00, byte_2=0xB3, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_PSK_WITH_AES_256_CCM', gnutls_name='DHE-PSK-AES256-CCM', byte_1=0xC0,
                            byte_2=0xA7, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes256, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.ccm, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x66, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aria128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x67, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aria256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
                                    gnutls_name='DHE-PSK-CAMELLIA128-SHA256', byte_1=0xC0, byte_2=0x96,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
                                    gnutls_name='DHE-PSK-CAMELLIA256-SHA384', byte_1=0xC0, byte_2=0x97,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_AES_128_CBC_SHA', gnutls_name='DHE-RSA-AES128-SHA', byte_1=0x00,
                            byte_2=0x33, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', gnutls_name='DHE-RSA-AES128-SHA256',
                            byte_1=0x00, byte_2=0x67, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_AES_128_CCM', gnutls_name='DHE-RSA-AES128-CCM', byte_1=0xC0,
                            byte_2=0x9E, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes128, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.ccm, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_AES_256_CBC_SHA', gnutls_name='DHE-RSA-AES256-SHA', byte_1=0x00,
                            byte_2=0x39, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', gnutls_name='DHE-RSA-AES256-SHA256',
                            byte_1=0x00, byte_2=0x6B, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_AES_256_CCM', gnutls_name='DHE-RSA-AES256-CCM', byte_1=0xC0,
                            byte_2=0x9F, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes256, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.ccm, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x44, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x45, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA', gnutls_name='DHE-RSA-CAMELLIA128-SHA',
                            byte_1=0x00, byte_2=0x45, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                                    gnutls_name='DHE-RSA-CAMELLIA128-SHA256', byte_1=0x00, byte_2=0xBE,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', gnutls_name='DHE-RSA-CAMELLIA256-SHA',
                            byte_1=0x00, byte_2=0x88, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
                                    gnutls_name='DHE-RSA-CAMELLIA256-SHA256', byte_1=0x00, byte_2=0xC4,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_SEED_CBC_SHA', gnutls_name='DHE-RSA-SEED-SHA', byte_1=0x00,
                            byte_2=0x9A, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.seed_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_ECCPWD_WITH_AES_128_CCM_SHA256', gnutls_name=None, byte_1=0xC0, byte_2=0xB2,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.eccpwd,
                            auth_algorithm=AuthenticationAlgorithm.eccpwd, enc_algorithm=SymmetricAlgorithm.aes128_ccm,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_ECCPWD_WITH_AES_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0, byte_2=0xB0,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.eccpwd,
                            auth_algorithm=AuthenticationAlgorithm.eccpwd, enc_algorithm=SymmetricAlgorithm.aes128_gcm,
                            enc_algorithm_bits=128, aead=True, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_ECCPWD_WITH_AES_256_CCM_SHA384', gnutls_name=None, byte_1=0xC0, byte_2=0xB3,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.eccpwd,
                            auth_algorithm=AuthenticationAlgorithm.eccpwd, enc_algorithm=SymmetricAlgorithm.aes256_ccm,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_ECCPWD_WITH_AES_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0, byte_2=0xB1,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.eccpwd,
                            auth_algorithm=AuthenticationAlgorithm.eccpwd, enc_algorithm=SymmetricAlgorithm.aes256_gcm,
                            enc_algorithm_bits=256, aead=True, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', gnutls_name='ECDHE-ECDSA-AES128-SHA',
                            byte_1=0xC0, byte_2=0x09, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
                                    gnutls_name='ECDHE-ECDSA-AES128-SHA256', byte_1=0xC0, byte_2=0x23,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_AES_128_CCM', gnutls_name='ECDHE-ECDSA-AES128-CCM',
                                    byte_1=0xC0, byte_2=0xAC, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aes128, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.ccm, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', gnutls_name='ECDHE-ECDSA-AES256-SHA',
                            byte_1=0xC0, byte_2=0x0A, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
                                    gnutls_name='ECDHE-ECDSA-AES256-SHA384', byte_1=0xC0, byte_2=0x24,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_AES_256_CCM', gnutls_name='ECDHE-ECDSA-AES256-CCM',
                                    byte_1=0xC0, byte_2=0xAD, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aes256, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.ccm, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x48, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aria128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x49, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aria256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
                                    gnutls_name='ECDHE-ECDSA-CAMELLIA128-SHA256', byte_1=0xC0, byte_2=0x72,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
                                    gnutls_name='ECDHE-ECDSA-CAMELLIA256-SHA384', byte_1=0xC0, byte_2=0x73,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA', gnutls_name='ECDHE-PSK-AES128-CBC-SHA',
                            byte_1=0xC0, byte_2=0x35, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
                                    gnutls_name='ECDHE-PSK-AES128-CBC-SHA256', byte_1=0xC0, byte_2=0x37,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA', gnutls_name='ECDHE-PSK-AES256-CBC-SHA',
                            byte_1=0xC0, byte_2=0x36, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
                                    gnutls_name='ECDHE-PSK-AES256-CBC-SHA384', byte_1=0xC0, byte_2=0x38,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x70, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aria128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x71, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aria256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
                                    gnutls_name='ECDHE-PSK-CAMELLIA128-SHA256', byte_1=0xC0, byte_2=0x9A,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
                                    gnutls_name='ECDHE-PSK-CAMELLIA256-SHA384', byte_1=0xC0, byte_2=0x9B,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', gnutls_name='ECDHE-RSA-AES128-SHA',
                                    byte_1=0xC0, byte_2=0x13, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', gnutls_name='ECDHE-RSA-AES128-SHA256',
                            byte_1=0xC0, byte_2=0x27, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', gnutls_name='ECDHE-RSA-AES256-SHA',
                                    byte_1=0xC0, byte_2=0x14, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', gnutls_name='ECDHE-RSA-AES256-SHA384',
                            byte_1=0xC0, byte_2=0x28, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x4C, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x4D, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
                                    gnutls_name='ECDHE-RSA-CAMELLIA128-SHA256', byte_1=0xC0, byte_2=0x76,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
                                    gnutls_name='ECDHE-RSA-CAMELLIA256-SHA384', byte_1=0xC0, byte_2=0x77,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_KRB5_WITH_IDEA_CBC_SHA', gnutls_name=None, byte_1=0x00, byte_2=0x21,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.krb5,
                                    auth_algorithm=AuthenticationAlgorithm.krb5,
                                    enc_algorithm=SymmetricAlgorithm.idea_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_DHE_WITH_AES_128_CCM_8', gnutls_name='DHE-PSK-AES128-CCM8', byte_1=0xC0,
                            byte_2=0xAA, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.dhe,
                            enc_algorithm=SymmetricAlgorithm.aes128, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.ccm8, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_DHE_WITH_AES_256_CCM_8', gnutls_name='DHE-PSK-AES256-CCM8', byte_1=0xC0,
                            byte_2=0xAB, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.dhe,
                            enc_algorithm=SymmetricAlgorithm.aes256, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.ccm8, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_AES_128_CBC_SHA', gnutls_name='PSK-AES128-CBC-SHA', byte_1=0x00,
                            byte_2=0x8C, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_AES_128_CBC_SHA256', gnutls_name='PSK-AES128-CBC-SHA256',
                                    byte_1=0x00, byte_2=0xAE, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_AES_128_CCM', gnutls_name='PSK-AES128-CCM', byte_1=0xC0,
                                    byte_2=0xA4, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes128, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.ccm, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_AES_128_CCM_8', gnutls_name='PSK-AES128-CCM8', byte_1=0xC0,
                                    byte_2=0xA8, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes128, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.ccm8, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_AES_128_GCM_SHA256', gnutls_name='PSK-AES128-GCM-SHA256',
                                    byte_1=0x00, byte_2=0xA8, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_AES_256_CBC_SHA', gnutls_name='PSK-AES256-CBC-SHA', byte_1=0x00,
                            byte_2=0x8D, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_AES_256_CBC_SHA384', gnutls_name='PSK-AES256-CBC-SHA384',
                                    byte_1=0x00, byte_2=0xAF, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_AES_256_CCM', gnutls_name='PSK-AES256-CCM', byte_1=0xC0,
                                    byte_2=0xA5, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes256, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.ccm, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_AES_256_CCM_8', gnutls_name='PSK-AES256-CCM8', byte_1=0xC0,
                                    byte_2=0xA9, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes256, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.ccm8, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_AES_256_GCM_SHA384', gnutls_name='PSK-AES256-GCM-SHA384',
                                    byte_1=0x00, byte_2=0xA9, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0, byte_2=0x64,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.psk,
                            auth_algorithm=AuthenticationAlgorithm.psk, enc_algorithm=SymmetricAlgorithm.aria128_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0, byte_2=0x6A,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.psk,
                            auth_algorithm=AuthenticationAlgorithm.psk, enc_algorithm=SymmetricAlgorithm.aria128_gcm,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0, byte_2=0x65,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.psk,
                            auth_algorithm=AuthenticationAlgorithm.psk, enc_algorithm=SymmetricAlgorithm.aria256_cbc,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0, byte_2=0x6B,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.psk,
                            auth_algorithm=AuthenticationAlgorithm.psk, enc_algorithm=SymmetricAlgorithm.aria256_gcm,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256', gnutls_name='PSK-CAMELLIA128-SHA256',
                            byte_1=0xC0, byte_2=0x94, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x8E, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384', gnutls_name='PSK-CAMELLIA256-SHA384',
                            byte_1=0xC0, byte_2=0x95, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x8F, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_PSK_WITH_CHACHA20_POLY1305_SHA256', gnutls_name='PSK-CHACHA20-POLY1305',
                            byte_1=0xCC, byte_2=0xAB, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.psk, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.chacha20_poly1305, enc_algorithm_bits=256, aead=True,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_AES_128_CBC_SHA', gnutls_name='RSA-PSK-AES128-CBC-SHA',
                                    byte_1=0x00, byte_2=0x94, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_PSK_WITH_AES_128_CBC_SHA256', gnutls_name='RSA-PSK-AES128-CBC-SHA256',
                            byte_1=0x00, byte_2=0xB6, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_PSK_WITH_AES_128_GCM_SHA256', gnutls_name='RSA-PSK-AES128-GCM-SHA256',
                            byte_1=0x00, byte_2=0xAC, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_AES_256_CBC_SHA', gnutls_name='RSA-PSK-AES256-CBC-SHA',
                                    byte_1=0x00, byte_2=0x95, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_PSK_WITH_AES_256_CBC_SHA384', gnutls_name='RSA-PSK-AES256-CBC-SHA384',
                            byte_1=0x00, byte_2=0xB7, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_PSK_WITH_AES_256_GCM_SHA384', gnutls_name='RSA-PSK-AES256-GCM-SHA384',
                            byte_1=0x00, byte_2=0xAD, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x68, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aria128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x6E, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aria128_gcm, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x69, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aria256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x6F, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aria256_gcm, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
                                    gnutls_name='RSA-PSK-CAMELLIA128-SHA256', byte_1=0xC0, byte_2=0x98,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x92, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
                                    gnutls_name='RSA-PSK-CAMELLIA256-SHA384', byte_1=0xC0, byte_2=0x99,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x93, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256',
                                    gnutls_name='RSA-PSK-CHACHA20-POLY1305', byte_1=0xCC, byte_2=0xAE,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.chacha20_poly1305, enc_algorithm_bits=256,
                                    aead=True, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_AES_128_CBC_SHA', gnutls_name='AES128-SHA', byte_1=0x00,
                                    byte_2=0x2F, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_AES_128_CBC_SHA256', gnutls_name='AES128-SHA256', byte_1=0x00,
                            byte_2=0x3C, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_AES_128_CCM', gnutls_name='AES128-CCM', byte_1=0xC0, byte_2=0x9C,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.ccm,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_AES_128_CCM_8', gnutls_name='AES128-CCM8', byte_1=0xC0, byte_2=0xA0,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes128,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.ccm8,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_AES_128_GCM_SHA256', gnutls_name='AES128-GCM-SHA256', byte_1=0x00,
                            byte_2=0x9C, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_AES_256_CBC_SHA', gnutls_name='AES256-SHA', byte_1=0x00,
                                    byte_2=0x35, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_AES_256_CBC_SHA256', gnutls_name='AES256-SHA256', byte_1=0x00,
                            byte_2=0x3D, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_AES_256_CCM', gnutls_name='AES256-CCM', byte_1=0xC0, byte_2=0x9D,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes256,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.ccm,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_AES_256_CCM_8', gnutls_name='AES256-CCM8', byte_1=0xC0, byte_2=0xA1,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aes256,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.ccm8,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_AES_256_GCM_SHA384', gnutls_name='AES256-GCM-SHA384', byte_1=0x00,
                            byte_2=0x9D, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_ARIA_128_CBC_SHA256', gnutls_name=None, byte_1=0xC0, byte_2=0x3C,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aria128_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0, byte_2=0x50,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aria128_gcm,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_ARIA_256_CBC_SHA384', gnutls_name=None, byte_1=0xC0, byte_2=0x3D,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aria256_cbc,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0, byte_2=0x51,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.aria256_gcm,
                            enc_algorithm_bits=256, aead=False, hash_algorithm=HashAlgorithm.sha384,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_CAMELLIA_128_CBC_SHA', gnutls_name='CAMELLIA128-SHA', byte_1=0x00,
                            byte_2=0x41, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256', gnutls_name='CAMELLIA128-SHA256',
                                    byte_1=0x00, byte_2=0xBA, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_cbc, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x7A, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', gnutls_name='CAMELLIA256-SHA', byte_1=0x00,
                            byte_2=0x84, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha1, security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256', gnutls_name='CAMELLIA256-SHA256',
                                    byte_1=0x00, byte_2=0xC0, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_cbc, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x7B, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.rsa, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_IDEA_CBC_SHA', gnutls_name='IDEA-CBC-SHA', byte_1=0x00, byte_2=0x07,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.idea_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.secure))
            session.add(
                CipherSuite(iana_name='TLS_RSA_WITH_SEED_CBC_SHA', gnutls_name='SEED-SHA', byte_1=0x00, byte_2=0x96,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=KeyExchangeAlgorithm.rsa,
                            auth_algorithm=AuthenticationAlgorithm.rsa, enc_algorithm=SymmetricAlgorithm.seed_cbc,
                            enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha1,
                            security=CipherSuiteSecurity.secure))
            session.add(CipherSuite(iana_name='TLS_AES_128_CCM_8_SHA256', gnutls_name=None, byte_1=0x13, byte_2=0x05,
                                    protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=None,
                                    auth_algorithm=None, enc_algorithm=SymmetricAlgorithm.aes128_ccm_8,
                                    enc_algorithm_bits=128, aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_AES_128_CCM_SHA256', gnutls_name='TLS_AES_128_CCM_SHA256', byte_1=0x13,
                            byte_2=0x04, protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=None,
                            auth_algorithm=None, enc_algorithm=SymmetricAlgorithm.aes128_ccm, enc_algorithm_bits=128,
                            aead=False, hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_AES_128_GCM_SHA256', gnutls_name='TLS_AES_128_GCM_SHA256', byte_1=0x13,
                            byte_2=0x01, protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=None,
                            auth_algorithm=None, enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128,
                            aead=True, hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_AES_256_GCM_SHA384', gnutls_name='TLS_AES_256_GCM_SHA384', byte_1=0x13,
                            byte_2=0x02, protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=None,
                            auth_algorithm=None, enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256,
                            aead=True, hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_CHACHA20_POLY1305_SHA256', gnutls_name=None, byte_1=0x13, byte_2=0x03,
                            protocol_version=CipherSuiteProtocolVersion.tls, kex_algorithm=None, auth_algorithm=None,
                            enc_algorithm=SymmetricAlgorithm.chacha20_poly1305, enc_algorithm_bits=256, aead=True,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_DHE_DSS_WITH_AES_128_GCM_SHA256', gnutls_name='DHE-DSS-AES128-GCM-SHA256',
                            byte_1=0x00, byte_2=0xA2, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                            enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_DHE_DSS_WITH_AES_256_GCM_SHA384', gnutls_name='DHE-DSS-AES256-GCM-SHA384',
                            byte_1=0x00, byte_2=0xA3, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                            enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x56, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.aria128_gcm, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x57, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.aria256_gcm, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x80, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x81, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.dss,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_DHE_PSK_WITH_AES_128_GCM_SHA256', gnutls_name='DHE-PSK-AES128-GCM-SHA256',
                            byte_1=0x00, byte_2=0xAA, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_DHE_PSK_WITH_AES_256_GCM_SHA384', gnutls_name='DHE-PSK-AES256-GCM-SHA384',
                            byte_1=0x00, byte_2=0xAB, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                            enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x6C, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aria128_gcm, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x6D, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aria256_gcm, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x90, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x91, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
                                    gnutls_name='DHE-PSK-CHACHA20-POLY1305', byte_1=0xCC, byte_2=0xAD,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.chacha20_poly1305, enc_algorithm_bits=256,
                                    aead=True, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_AES_128_CCM_8', gnutls_name='DHE-RSA-AES128-CCM8', byte_1=0xC0,
                            byte_2=0xA2, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes128, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.ccm8, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', gnutls_name='DHE-RSA-AES128-GCM-SHA256',
                            byte_1=0x00, byte_2=0x9E, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_AES_256_CCM_8', gnutls_name='DHE-RSA-AES256-CCM8', byte_1=0xC0,
                            byte_2=0xA3, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes256, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.ccm8, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', gnutls_name='DHE-RSA-AES256-GCM-SHA384',
                            byte_1=0x00, byte_2=0x9F, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x52, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria128_gcm, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x53, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria256_gcm, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x7C, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128,
                                    aead=False, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x7D, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256,
                                    aead=False, hash_algorithm=HashAlgorithm.sha384,
                                    security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
                                    gnutls_name='DHE-RSA-CHACHA20-POLY1305', byte_1=0xCC, byte_2=0xAA,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.dhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.chacha20_poly1305, enc_algorithm_bits=256,
                                    aead=True, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8', gnutls_name='ECDHE-ECDSA-AES128-CCM8',
                            byte_1=0xC0, byte_2=0xAE, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.aes128, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.ccm8, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                                    gnutls_name='ECDHE-ECDSA-AES128-GCM-SHA256', byte_1=0xC0, byte_2=0x2B,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8', gnutls_name='ECDHE-ECDSA-AES256-CCM8',
                            byte_1=0xC0, byte_2=0xAF, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.aes256, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.ccm8, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                                    gnutls_name='ECDHE-ECDSA-AES256-GCM-SHA384', byte_1=0xC0, byte_2=0x2C,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x5C, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aria128_gcm, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x5D, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.aria256_gcm, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x86, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x87, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.ecdsa,
                            enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
                                    gnutls_name='ECDHE-ECDSA-CHACHA20-POLY1305', byte_1=0xCC, byte_2=0xA9,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.ecdsa,
                                    enc_algorithm=SymmetricAlgorithm.chacha20_poly1305, enc_algorithm_bits=256,
                                    aead=True, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256', gnutls_name=None, byte_1=0xD0,
                                    byte_2=0x03, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes128_ccm_8, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256', gnutls_name=None, byte_1=0xD0,
                                    byte_2=0x05, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes128_ccm, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256', gnutls_name=None, byte_1=0xD0,
                                    byte_2=0x01, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384', gnutls_name=None, byte_1=0xD0,
                                    byte_2=0x02, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256',
                                    gnutls_name='ECDHE-PSK-CHACHA20-POLY1305', byte_1=0xCC, byte_2=0xAC,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.psk,
                                    enc_algorithm=SymmetricAlgorithm.chacha20_poly1305, enc_algorithm_bits=256,
                                    aead=True, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                                    gnutls_name='ECDHE-RSA-AES128-GCM-SHA256', byte_1=0xC0, byte_2=0x2F,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aes128_gcm, enc_algorithm_bits=128, aead=True,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                                    gnutls_name='ECDHE-RSA-AES256-GCM-SHA384', byte_1=0xC0, byte_2=0x30,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aes256_gcm, enc_algorithm_bits=256, aead=True,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x60, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria128_gcm, enc_algorithm_bits=128, aead=False,
                                    hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                                    byte_2=0x61, protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.aria256_gcm, enc_algorithm_bits=256, aead=False,
                                    hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x8A, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.camellia128_gcm, enc_algorithm_bits=128, aead=False,
                            hash_algorithm=HashAlgorithm.sha256, security=CipherSuiteSecurity.recommended))
            session.add(
                CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384', gnutls_name=None, byte_1=0xC0,
                            byte_2=0x8B, protocol_version=CipherSuiteProtocolVersion.tls,
                            kex_algorithm=KeyExchangeAlgorithm.ecdhe, auth_algorithm=AuthenticationAlgorithm.rsa,
                            enc_algorithm=SymmetricAlgorithm.camellia256_gcm, enc_algorithm_bits=256, aead=False,
                            hash_algorithm=HashAlgorithm.sha384, security=CipherSuiteSecurity.recommended))
            session.add(CipherSuite(iana_name='TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
                                    gnutls_name='ECDHE-RSA-CHACHA20-POLY1305', byte_1=0xCC, byte_2=0xA8,
                                    protocol_version=CipherSuiteProtocolVersion.tls,
                                    kex_algorithm=KeyExchangeAlgorithm.ecdhe,
                                    auth_algorithm=AuthenticationAlgorithm.rsa,
                                    enc_algorithm=SymmetricAlgorithm.chacha20_poly1305, enc_algorithm_bits=256,
                                    aead=True, hash_algorithm=HashAlgorithm.sha256,
                                    security=CipherSuiteSecurity.recommended))


class Setup:
    """
    This class implements the initial setup for KIS
    """
    def __init__(self,
                 kis_scripts: List[str],
                 kali_packages: List[str],
                 git_repositories: List[str],
                 debug: bool = False):
        self._debug = debug
        self._db_config = DatabaseConfig()
        self._databases = [self._db_config.config.get("production", "database"),
                           self._db_config.config.get("unittesting", "database")]
        self._git_repositories = git_repositories
        self._setup_commands = []
        self._db_config.password = passgen.passgen(30)
        if not self._debug:
            self._db_config.write()
        for file in kis_scripts:
            base_name = os.path.splitext(file)[0]
            real_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            python_script = os.path.join(real_path, file)
            os_command = ["ln", "-sT", python_script, os.path.join("/usr/bin", base_name)]
            self._setup_commands.append(SetupCommand(description="creating link file for {}".format(python_script),
                                                     command=os_command))
        self._setup_commands.append(SetupCommand(description="adding PostgresSql database to auto start",
                                                 command=["update-rc.d", "postgresql", "enable"],
                                                 return_code=0))
        self._setup_commands.append(SetupCommand(description="starting PostgreSql database",
                                                 command=["service", "postgresql", "start"],
                                                 return_code=0))
        self._setup_commands.append(SetupCommand(description="adding PostgreSql database user '{}'"
                                                 .format(self._db_config.username),
                                                 command=["sudo", "-u", "postgres", "createuser",
                                                          self._db_config.username]))
        self._setup_commands.append(SetupCommand(description="setting PostgreSql database user '{}' password"
                                                 .format(self._db_config.username),
                                                 command=["sudo", "-u", "postgres", "psql", "-c",
                                                          "alter user {} with encrypted password '{}'"
                                                          .format(self._db_config.database, self._db_config.password)]))
        for database in self._databases:
            self._setup_commands.append(SetupCommand(description=
                                                     "creating PostgreSql database '{}'".format(database),
                                                     command=["sudo", "-u", "postgres", "createdb", database]))
            self._setup_commands.append(SetupCommand(description="setting PostgreSql database user '{}' "
                                                                 "permissions on database '{}'"
                                                     .format(self._db_config.username, database),
                                                     command=["sudo", "-u", "postgres", "psql", "-c",
                                                              "grant all privileges on database {} to {}"
                                                              .format(database, self._db_config.username)],
                                                     return_code=0))
        self._setup_commands.append(SetupCommand(description="creating the tables, triggers, views, etc. in database {}"
                                                 .format(self._db_config.database),
                                                 command=["kismanage", "database", "--drop", "--init"]))
        if kali_packages:
            apt_command = ["apt-get", "install", "-q", "--yes"]
            apt_command.extend(kali_packages)
            self._setup_commands.append(SetupCommand(description="installing additional Kali packages",
                                                     command=apt_command,
                                                     return_code=0))
        for repo in self._git_repositories:
            repo_name = repo.split("/")[-1]
            repo_name = os.path.splitext(repo_name)[0]
            git_command = ["git", "clone", repo, os.path.join(self._db_config.get_repo_home(), repo_name)]
            self._setup_commands.append(SetupCommand(description="clone git repository: {}".format(repo_name),
                                                     command=git_command,
                                                     return_code=0))

    def execute(self) -> None:
        """Executes the setup"""
        ok = True
        for command in self._setup_commands:
            if ok:
                ok = command.execute(self._debug)

    def _print(self, message: str, status: str = None, color: FontColor = None, throw_exception: bool = False):
        """
        Prints the given message to stdout
        :param message: The message to be printed.
        :param status: The message's status.
        :param color: The font color of the status.
        :return:
        """
        if not throw_exception:
            columns, _ = shutil.get_terminal_size()
            if status:
                status = "{}[{}]{}".format(color, status, FontColor.END)
                spaces = columns - len(message) - len(status)
                spaces = spaces if spaces > 0 else 1
                print("{}{}{}".format(message, " " * spaces, status))
            else:
                print(message)

    def _check_exists(self, path: str, text: str = None, throw_exception: bool = False):
        """
        This method checks whether the given path exists. Depending on whether it exists or not it prints a message or
        throws an exception.
        :param path: The path that shall be checked.
        :param text: The message that shall be printed for the check. If None, then the path is printed.
        :param throw_exception: If True, then an exception is thrown instead of a message is printed.
        :return:
        """

        message = text if text else path
        full_path = str(path)
        status_text = "installed"
        status_color = FontColor.GREEN
        if not os.path.exists(full_path):
            full_path = shutil.which(full_path)
            if not full_path:
                if throw_exception:
                    raise ModuleNotFoundError("{} not found".format(message))
                status_text = "missing"
                status_color = FontColor.RED
        self._print(message, status_text, status_color, throw_exception=throw_exception)

    def test(self, throw_exception: bool = False) -> None:
        """This method tests the setup"""
        api_config = ApiConfig()
        collector_config = CollectorConfig()
        os_info = os.uname()
        self._print("check os", throw_exception=throw_exception)
        os_info_str = " ".join([item for item in os_info])
        if not os_info.nodename or os_info.nodename.lower() != "kali":
            if throw_exception:
                raise NotImplementedError("The used operating system is unspported.")
            self._print(os_info_str, "unsupported", FontColor.RED, throw_exception=throw_exception)
        else:
            self._print(os_info_str, "supported", FontColor.GREEN, throw_exception=throw_exception)
        self._print("", throw_exception=throw_exception)
        self._print("check tools (see section 'file_paths' in: {})".format(collector_config.full_path),
                    throw_exception=throw_exception)
        # manually check tools
        self._check_exists("psql", "postgresql", throw_exception=throw_exception)
        self._check_exists("kiscollect", throw_exception=throw_exception)
        self._check_exists("kisreport", throw_exception=throw_exception)
        # check tool paths
        for tool, path in collector_config.config.items("file_paths"):
            self._check_exists(collector_config.get_config_str("file_paths", tool),
                               tool,
                               throw_exception=throw_exception)
        # check default wordlist paths
        self._print("", throw_exception=throw_exception)
        self._print("check default wordlists (see section 'default_wordlists' in: {})"
                    .format(collector_config.full_path), throw_exception=throw_exception)
        for wordlist, path in collector_config.config.items("default_wordlists"):
            self._check_exists(collector_config.get_config_str("default_wordlists", wordlist),
                               throw_exception=throw_exception)
        # check API
        self._print("", throw_exception=throw_exception)
        self._print("check API settings (see sections in: {})".format(api_config.full_path),
                    throw_exception=throw_exception)
        for section in api_config.config.sections():
            complete = True
            if section == "http-proxy":
                continue
            for _, value in api_config.config.items(section):
                complete = complete and value.split("#")[0].strip()
                if not complete:
                    break
            if complete:
                self._print(section, "complete", FontColor.GREEN, throw_exception=throw_exception)
            else:
                self._print(section, "missing", FontColor.ORANGE, throw_exception=throw_exception)
