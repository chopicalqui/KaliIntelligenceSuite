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
__version__ = "0.3.0"

import sys
import grp
import passgen
import shutil
import tempfile
import sqlalchemy
from sqlalchemy import create_engine
from database import config
from database.config import Database as DatabaseConfig
from database.config import Collector as CollectorConfig
from database.config import ApiConfig
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
        self._production = production
        self._config = config.Database(self._production)
        self._engine = create_engine(self._config.connection_string)
        self._session_factory = sessionmaker(bind=self._engine)
        self._Session = scoped_session(self._session_factory)
        self.production = production

    @property
    def production(self) -> bool:
        return self._production

    @production.setter
    def production(self, value) -> bool:
        self._production = value
        self._config = config.Database(self._production)
        self._engine = create_engine(self._config.connection_string)
        self._session_factory = sessionmaker(bind=self._engine)
        self._Session = scoped_session(self._session_factory)

    @property
    def engine(self):
        return self._engine

    @property
    def config(self):
        return self._config

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

    def _set_commands_incomplete(self, query: sqlalchemy.orm.query.Query, collector_name: str = None) -> None:
        """
        This method sets all commands of the given query to incomplete.
        """
        for command in query.all():
            if collector_name == command.collector_name.name or not collector_name:
                command.status = CommandStatus.terminated

    def set_commands_incomplete(self, workspace: str, collector_name: str = None) -> None:
        """
        This method sets all pending OS commands to status execution terminated
        :param command_name: If specified the status for all commands with the same command_name are update
        """
        with self.session_scope() as session: \
            # todo: update for new collector
            self._set_commands_incomplete(session.query(Command)
                                          .join((CollectorName, Command.collector_name))
                                          .join((Host, Command.host))
                                          .join((Workspace, Host.workspace))
                                          .filter(Workspace.name == workspace,
                                                  Command.status == CommandStatus.pending), collector_name)
            self._set_commands_incomplete(session.query(Command)
                                          .join((CollectorName, Command.collector_name))
                                          .join((HostName, Command.host_name))
                                          .join((DomainName, HostName.domain_name))
                                          .join((Workspace, DomainName.workspace))
                                          .filter(Workspace.name == workspace,
                                                  Command.status == CommandStatus.pending), collector_name)
            self._set_commands_incomplete(session.query(Command)
                                          .join((CollectorName, Command.collector_name))
                                          .join((Network, Command.ipv4_network))
                                          .join((Workspace, Network.workspace))
                                          .filter(Workspace.name == workspace,
                                                  Command.status == CommandStatus.pending), collector_name)
            self._set_commands_incomplete(session.query(Command)
                                          .join((CollectorName, Command.collector_name))
                                          .join((Email, Command.email))
                                          .join((HostName, Email.host_name))
                                          .join((DomainName, HostName.domain_name))
                                          .join((Workspace, DomainName.workspace))
                                          .filter(Workspace.name == workspace,
                                                  Command.status == CommandStatus.pending), collector_name)

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

    def perform_preflight_check(self, test_version: str = None):
        """
        This method shall be called during startup to check KIS' data model.
        :param test_version: This parameter is only used by unittests.
        """
        current_kis_version = Version(test_version if test_version else str(__version__))
        result = self._engine.execute("SELECT * FROM information_schema.tables WHERE table_name = 'workspace';")
        if result.rowcount != 1:
            raise DatabaseUninitializationError()
        # If the version table is missing, then we are definitely dealing with an outdated version
        result = self._engine.execute("SELECT * FROM information_schema.tables WHERE table_name = 'version';")
        if result.rowcount != 1:
            raise DatabaseVersionMismatchError(reason=DatabaseVersionMismatchEnum.model_outdated)
        with self.session_scope() as session:
            database_version = session.query(Version).one()
            if database_version < current_kis_version:
                raise DatabaseVersionMismatchError(reason=DatabaseVersionMismatchEnum.model_outdated)
            elif database_version > current_kis_version:
                raise DatabaseVersionMismatchError(reason=DatabaseVersionMismatchEnum.model_newer)

    def print_version_information(self):
        """
        This method returns the version of the currently deployed database.
        """
        with self.session_scope() as session:
            try:
                result = self._engine.execute("SELECT * FROM information_schema.tables WHERE table_name = 'workspace';")
                if result.rowcount != 1:
                    print("database has not been initialized.")
                else:
                    database_version = session.query(Version).one()
                    print("Deployed database version: {:>10}".format(str(database_version)))
            except Exception as e:
                if 'relation "version" does not exist' in str(e):
                    database_version = Version("0.3.0")
                    print("Deployed database version: {:>10}".format("< " + str(database_version)))
                else:
                    raise e

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
        with tempfile.TemporaryDirectory() as temp:
            uid = pwd.getpwnam("postgres").pw_uid
            gid = grp.getgrnam("postgres").gr_gid
            os.chown(temp, uid, gid)
            for database in [self._config.production_database, self._config.test_database]:
                # drop database
                subprocess.check_output("sudo -u postgres dropdb {}".format(database), shell=True, cwd=temp)
                # create database
                subprocess.check_output("sudo -u postgres createdb {}".format(database), shell=True, cwd=temp)
                # assign privileges to database
                subprocess.check_output("sudo -u postgres psql -c 'grant all privileges on database {} to {}'".format(database,
                                                                                                                      self._config.username),
                                        shell=True, cwd=temp)

    def drop(self):
        """This method drops all views and tables in the database."""
        self._drop_views()
        self._drop_tables()

    def _create_tables(self) -> None:
        """This method creates all tables."""
        DeclarativeBase.metadata.create_all(self._engine, checkfirst=True)
        # Record the database model's current version
        with self.session_scope() as session:
            versions = session.query(Version).all()
            if len(versions) == 0:
                session.add(Version(str(__version__)))

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
        # Note: For debugging triggers, you can use the following command:
        # RAISE NOTICE 'Hello World!';
        # This might not show Hello World in the logs but will only display it in the psql console

        # Triggers for setting host_names in or out of scope
        # pre_update_domain_name_scope_changes
        # todo: update pre_command_changes for new collector
        self._engine.execute("""CREATE OR REPLACE FUNCTION pre_command_changes()
        RETURNS TRIGGER AS $$
        BEGIN
            IF (TG_OP = 'INSERT') THEN
                IF (NEW.host_id IS NOT NULL) THEN
                    SELECT w.id INTO NEW.workspace_id FROM workspace w
                    INNER JOIN host h ON h.workspace_id = w.id AND h.id = NEW.host_id;
                ELSIF (NEW.host_name_id IS NOT NULL) THEN
                    SELECT w.id INTO NEW.workspace_id FROM workspace w
                    INNER JOIN domain_name d ON d.workspace_id = w.id
                    INNER JOIN host_name hn ON hn.domain_name_id = d.id AND hn.id = NEW.host_name_id;
                ELSIF (NEW.network_id IS NOT NULL) THEN
                    SELECT w.id INTO NEW.workspace_id FROM workspace w
                    INNER JOIN network n ON n.workspace_id = w.id AND n.id = NEW.network_id;
                ELSIF (NEW.email_id IS NOT NULL) THEN
                    SELECT w.id INTO NEW.workspace_id FROM workspace w
                    INNER JOIN domain_name d ON d.workspace_id = w.id
                    INNER JOIN host_name hn ON hn.domain_name_id = d.id
                    INNER JOIN email e ON e.host_name_id = hn.id AND e.id = NEW.email_id;
                ELSIF (NEW.company_id IS NOT NULL) THEN
                    SELECT w.id INTO NEW.workspace_id FROM workspace w
                    INNER JOIN company c ON c.workspace_id = w.id AND c.id = NEW.company_id;
                ELSE
                    RAISE EXCEPTION 'this case has not been implemented';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # pre_update_domain_name_scope_changes
        self._engine.execute("""CREATE OR REPLACE FUNCTION pre_update_domain_name_scope_changes()
        RETURNS TRIGGER AS $$
        BEGIN
            IF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') AND
                COALESCE(NEW.scope, 'exclude') = 'vhost' AND
                EXISTS(SELECT * FROM network
                        WHERE workspace_id = NEW.workspace_id AND
                              COALESCE(scope, 'exclude') = 'vhost') THEN
                    RAISE EXCEPTION 'scope vhost cannot be set at domain and network level at the same time';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # This trigger ensures that updating the service's port or protocol cannot be updated.
        self._engine.execute("""CREATE OR REPLACE FUNCTION update_service_check()
        RETURNS TRIGGER AS $$
        BEGIN
            IF (TG_OP = 'UPDATE' AND (OLD.protocol <> NEW.protocol OR OLD.port <> NEW.port)) THEN
                    RAISE EXCEPTION 'the service port or protocol cannot be updated as they are part of the primary key. delete service and create a new one.';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # post_update_host_names_after_domain_name_scope_changes
        self._engine.execute("""CREATE OR REPLACE FUNCTION post_update_host_names_after_domain_name_scope_changes()
        RETURNS TRIGGER AS $$
        BEGIN
            IF (TG_OP = 'UPDATE' AND COALESCE(OLD.scope, 'exclude') <> COALESCE(NEW.scope, 'exclude')) THEN
                -- Update scope of all sub-domains if the scope of the second-level domain is updated
                IF (COALESCE(NEW.scope, 'exclude') = 'all') THEN
                    UPDATE host_name
                        SET in_scope = True
                        WHERE domain_name_id = NEW.id;
                ELSIF (COALESCE(NEW.scope, 'exclude') = 'exclude') THEN
                    UPDATE host_name
                        SET in_scope = False
                        WHERE domain_name_id = NEW.id;
                ELSIF (COALESCE(NEW.scope, 'exclude') = 'vhost') THEN
                    -- We only have to set all host names out of scope. The corresponding host name trigger will then
                    -- automatically update the scope.
                    UPDATE host_name
                        SET in_scope = False
                        WHERE domain_name_id = NEW.id;
                END IF;
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # pre_update_host_name_scope
        self._engine.execute("""CREATE OR REPLACE FUNCTION pre_update_host_name_scope()
        RETURNS TRIGGER AS $$
        DECLARE
            domain_scope scopetype;
        BEGIN
            -- automatically set host_name's in_scope attribute to true, if domain_name scope is all
            domain_scope := (SELECT scope FROM domain_name WHERE id = NEW.domain_name_id);
            IF (domain_scope = 'all' OR
                (domain_scope = 'vhost' AND
                 EXISTS(SELECT hn.id FROM host_name hn
                        INNER JOIN host_host_name_mapping m ON m.host_name_id = hn.id AND
                                                               hn.id = NEW.id AND
                                                               COALESCE(m.type, 4) < 3
                        INNER JOIN host h ON h.id = m.host_id AND
                                             COALESCE(h.in_scope, False)))) THEN
                 NEW.in_scope := True;
            ELSIF (domain_scope = 'exclude') THEN
                NEW.in_scope := False;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # post_update_scopes_after_host_host_name_mapping_update
        self._engine.execute("""CREATE OR REPLACE FUNCTION post_update_scopes_after_host_host_name_mapping_update()
        RETURNS TRIGGER AS $$
        DECLARE
            current_host_name_id INTEGER;
            current_host_id INTEGER;
            current_type INTEGER;
            domain_scope scopetype;
            network_scope scopetype;
            host_name_record_count INTEGER;
            host_record_count INTEGER;
        BEGIN
            IF TG_OP = 'DELETE' THEN
                current_host_id = OLD.host_id;
                current_host_name_id = OLD.host_name_id;
                current_type = OLD.type;
            ELSE
                current_host_id = NEW.host_id;
                current_host_name_id = NEW.host_name_id;
                current_type = NEW.type;
            END IF;
            -- RAISE NOTICE 'BEGIN POST HOST_HOST_NAME_MAPPING: TG_OP = %%, host_id = %%, host_name_id = %%', TG_OP, current_host_id, current_host_name_id;
            IF COALESCE(current_type, 4) < 3 THEN
                -- Determine the domain scope settings
                SELECT d.scope INTO domain_scope FROM domain_name d
                    INNER JOIN host_name h ON d.id = h.domain_name_id AND h.id = current_host_name_id;
                -- Determine the host scope settings
                SELECT n.scope INTO network_scope FROM host h
                    INNER JOIN network n ON n.id = h.network_id AND h.id = current_host_id;
                   
                -- Determine if the current host name still has an A or AAAA relationship to a in scope host.
                host_name_record_count := (SELECT COUNT(*) FROM host_name hn
                    INNER JOIN host_host_name_mapping m ON hn.id = m.host_name_id AND
                                                           hn.id = current_host_name_id AND
                                                           COALESCE(m.type, 4) < 3
                    INNER JOIN domain_name dn ON dn.scope = 'vhost' AND dn.id = hn.domain_name_id
                    INNER JOIN host h ON h.id = m.host_id AND h.in_scope IS NOT NULL AND h.in_scope);
                -- Determine if the current host still has an A or AAAA relationship to a in scope host.
                host_record_count := (SELECT COUNT(*) FROM host h
                    INNER JOIN host_host_name_mapping m ON h.id = m.host_id AND
                                                           h.id = current_host_id AND
                                                           COALESCE(m.type, 4) < 3
                    INNER JOIN network n ON n.scope = 'vhost' AND n.id = h.network_id
                    INNER JOIN host_name hn ON hn.id = m.host_name_id AND COALESCE(hn.in_scope, False));
                -- RAISE NOTICE '  network_scope = %%, host_record_count = %%', network_scope, COALESCE(host_record_count, 0);
                
                -- If we have a domain scope of type vhost and an in scope host, then we have to put the host_name in scope
                IF COALESCE(domain_scope, 'exclude') = 'vhost' THEN
                    UPDATE host_name SET in_scope = COALESCE(host_name_record_count, 0) > 0
                        WHERE id = current_host_name_id;
                END IF;
                IF COALESCE(network_scope, 'exclude') = 'vhost' THEN
                    UPDATE host SET in_scope = COALESCE(host_record_count, 0) > 0
                        WHERE id = current_host_id;
                END IF;
                -- RAISE NOTICE 'END POST HOST_HOST_NAME_MAPPING: TG_OP = %%, host_id = %%, host_name_id = %%', TG_OP, current_host_id, current_host_name_id;
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # Triggers for setting hosts in or out of scope
        # pre_update_network_scopes_after_network_changes
        self._engine.execute("""CREATE OR REPLACE FUNCTION pre_update_network_scopes_after_network_changes()
        RETURNS TRIGGER AS $$
        DECLARE
            network inet;
            scope scopetype;
            net_id integer;
        BEGIN
            -- RAISE NOTICE 'BEGIN PRE NETWORK: TG_OP = %%, address = %%, new scope = %% old scope = %%', TG_OP, NEW.address, NEW.scope, OLD.scope;
            -- This trigger performs consistency checks as well as updates the scope of the current network
            -- accordingly.
            IF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') THEN
                IF COALESCE(NEW.scope, 'exclude') = 'vhost' AND
                   EXISTS(SELECT * FROM domain_name d
                            WHERE d.workspace_id = NEW.workspace_id AND
                                  COALESCE(d.scope, 'exclude') = 'vhost') THEN
                    RAISE EXCEPTION 'scope vhost cannot be set at domain and network level at the same time';
                ELSIF (TG_OP = 'UPDATE' AND OLD.address <> NEW.address) THEN
                    RAISE EXCEPTION 'changing the networks address (%%) is not allowed as it might make scoping
                                     inconsistent.', OLD.address;
                ELSIF (NEW.scope IS NOT NULL) THEN
                    -- If the current networks scope is explicitly set (NEW.scope IS NOT NULL), then check whether
                    -- there is a scope contradiction with a parent network.
                    SELECT n.address, n.scope INTO network, scope FROM network n
                        WHERE n.workspace_id = NEW.workspace_id AND
                              n.address >> NEW.address AND
                              n.scope IS NOT NULL AND
                              n.scope <> 'strict' AND -- inserting strict and exclude as parent networks is valid
                              n.scope <> 'exclude' AND
                              n.scope <> NEW.scope
                        LIMIT 1;
                    IF network IS NOT NULL THEN
                        -- If a scope contradiction exists, then raise an exception
                        RAISE EXCEPTION 'insert failed because there is the following scope contradiction: Current
                                         network (%%) with scope %% cannot be inserted as it has a different
                                         scope than the parent network %% with scope %%. update the scope of the
                                         parent network first or use the same scope as the
                                         parent network.', NEW.address, NEW.scope, network, scope;
                    END IF;
                ELSE
                    -- If NEW.scope is NULL, then the network was automatically added. In this case, we have to
                    -- determine whether there is already a parent network with a predefined scope. If there is such a
                    -- network, then we update NEW.scope.
                    SELECT n.scope INTO scope FROM network n
                        WHERE n.workspace_id = NEW.workspace_id AND
                              n.address >> NEW.address AND
                              n.scope IS NOT NULL
                        LIMIT 1;
                    IF (scope IS NOT NULL) THEN
                        NEW.scope = scope;
                    END IF;
                END IF;
                RETURN NEW;
                -- RAISE NOTICE 'END PRE NETWORK: TG_OP = %%, address = %%, new scope = %% old scope = %%', TG_OP, NEW.address, NEW.scope, OLD.scope;
            ELSIF (TG_OP = 'DELETE') THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # post_update_network_scopes_after_network_changes
        self._engine.execute("""CREATE OR REPLACE FUNCTION post_update_network_scopes_after_network_changes()
        RETURNS TRIGGER AS $$
        DECLARE
            sub_net inet;
        BEGIN
            -- This trigger updates all networks and hosts based on the current network's scope
            -- RAISE NOTICE 'BEGIN POST NETWORK: TG_OP = %%, address = %%, new scope = %% old scope = %%', TG_OP, NEW.address, NEW.scope, OLD.scope;
            IF (NEW.scope IS NOT NULL) THEN
                -- Check whether all child networks have already the same scope. If they don't, then we update their
                -- scope as well.
                IF (NOT EXISTS(SELECT n.id FROM network n
                                WHERE n.workspace_id = NEW.workspace_id AND
                                      n.address >> NEW.address AND
                                      n.scope IS NOT NULL AND NEW.scope IS NOT NULL
                                      AND n.scope = NEW.scope)) THEN
                    UPDATE network n
                        SET scope = NEW.scope
                        WHERE n.workspace_id = NEW.workspace_id AND
                            n.address << NEW.address AND
                            ((NEW.scope = 'strict' AND n.scope IS NULL) OR NEW.scope <> 'strict');
                END IF;
            END IF;
        
            IF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') THEN
                -- Check whether the network is the smallest network in the network table.
                SELECT address INTO sub_net FROM network
                    WHERE address << NEW.address AND
                          workspace_id = NEW.id
                    ORDER BY masklen(address) ASC LIMIT 1;
                IF (sub_net IS NULL) THEN
                    -- If this is the case, then we assign all hosts within this network to this network.
                    UPDATE host
                        SET network_id = NEW.id
                        WHERE workspace_id = NEW.workspace_id AND address <<= NEW.address;
                ELSE
                    -- If not, then we have to assign all hosts that are within the current network and the next
                    -- closest subnetwork, to the current network.
                    UPDATE host
                        SET network_id = NEW.id
                    WHERE workspace_id = NEW.workspace_id AND
                        NOT address << sub_net AND
                        address <<= NEW.address;
                END IF;
            END IF;
            IF TG_OP = 'UPDATE' AND COALESCE(OLD.scope, 'exclude') <> COALESCE(NEW.scope, 'exclude') THEN
                -- Update scope of all hosts if the scope of the network is updated
                IF NEW.scope = 'all' THEN
                    UPDATE host
                        SET in_scope = True
                        WHERE network_id = NEW.id;
                ELSIF COALESCE(NEW.scope, 'exclude') = 'exclude' OR COALESCE(NEW.scope, 'exclude') = 'vhost' THEN
                    -- In case of vhost, we only have to set all hosts out of scope. The corresponding trigger
                    -- will then automatically update the scope.
                    UPDATE host
                        SET in_scope = False
                        WHERE network_id = NEW.id;
                END IF;
            END IF;
            -- RAISE NOTICE 'END POST NETWORK: TG_OP = %%, address = %%, new scope = %% old scope = %%', TG_OP, NEW.address, NEW.scope, OLD.scope;
            RETURN NULL;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # pre_update_hosts_after_host_changes
        self._engine.execute("""CREATE OR REPLACE FUNCTION pre_update_hosts_after_host_changes()
        RETURNS TRIGGER AS $$
        DECLARE
            network_scope scopetype;
        BEGIN
            -- RAISE NOTICE 'BEGIN PRE HOST: TG_OP = %%, address = %%, new scope = %%, old scope = %%, network_id = %%', TG_OP, NEW.address, NEW.in_scope, OLD.in_scope, NEW.network_id;
            IF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') THEN
                -- Usually network assignments are performed when a new network is inserted or updated. If all
                -- networks, however, are already inserted, then this case ensures that it is inserted to the smallest
                -- network.
                SELECT id, scope INTO NEW.network_id, network_scope FROM network
                    WHERE address >>= NEW.address AND
                          workspace_id = NEW.workspace_id
                    ORDER BY masklen(address) DESC
                    LIMIT 1;

                IF network_scope IS NOT NULL THEN
                    IF network_scope = 'all' OR 
                       (network_scope = 'vhost' AND
                        EXISTS(SELECT * FROM host h
                                   INNER JOIN host_host_name_mapping m ON m.host_id = h.id AND
                                                                          h.id = NEW.id AND
                                                                          COALESCE(m.type, 4) < 3
                                   INNER JOIN host_name hn ON m.host_name_id = hn.id AND
                                                              hn.in_scope IS NOT NULL AND
                                                              hn.in_scope)) THEN
                        NEW.in_scope = True;
                    ELSIF network_scope = 'exclude' THEN
                        NEW.in_scope = False;
                    END IF;
                ELSE
                    NEW.in_scope = False;
                END IF;
            END IF;
            -- RAISE NOTICE 'END PRE HOST: TG_OP = %%, address = %%, new scope = %%, old scope = %%, network_id = %%', TG_OP, NEW.address, NEW.in_scope, OLD.in_scope, NEW.network_id;
            RETURN NEW;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # assign_services_to_host_name
        self._engine.execute("""CREATE OR REPLACE FUNCTION assign_services_to_host_name()
        RETURNS TRIGGER AS $$
        DECLARE
        host_service_cursor CURSOR(id_host integer) FOR SELECT * FROM service WHERE service.host_id = id_host;
        host_name_service_cursor CURSOR(id_host_name integer) FOR SELECT * FROM service WHERE service.host_name_id = id_host_name;
        current_row service%%ROWTYPE;
        BEGIN
            IF (NEW.type & 1) = 1 OR (NEW.type & 2) = 2 THEN
                -- 1. Sync host services to host name
                OPEN host_service_cursor(NEW.host_id);
                LOOP
                    FETCH host_service_cursor INTO current_row;
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
                CLOSE host_service_cursor;

                -- 2. Sync host name services to host
                OPEN host_name_service_cursor(NEW.host_name_id);
                LOOP
                    FETCH host_name_service_cursor INTO current_row;
                    EXIT WHEN NOT FOUND;
                    IF (NOT EXISTS(SELECT * FROM service WHERE protocol = current_row.protocol AND port = current_row.port AND host_id = NEW.host_id)) THEN
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
                                             creation_date) VALUES (NEW.host_id,
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
                CLOSE host_name_service_cursor;
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE PLPGSQL;""")
        # add_services_to_host_name
        self._engine.execute("""CREATE OR REPLACE FUNCTION add_services_to_host_name() 
        RETURNS TRIGGER AS $$
        DECLARE
        mapping_host_name_cursor CURSOR(id_service integer) FOR SELECT hhnm.host_name_id FROM
            host_host_name_mapping hhnm
            INNER JOIN host ON host.id = hhnm.host_id
            INNER JOIN service ON service.host_id = host.id
            INNER JOIN host_name ON host_name.id = hhnm.host_name_id
            WHERE ((hhnm.type & 1) = 1 OR (hhnm.type & 2) = 2) AND service.id = id_service;
        id_host_name integer;
        mapping_host_cursor CURSOR(id_service integer) FOR SELECT hhnm.host_id FROM
            host_host_name_mapping hhnm
            INNER JOIN host_name ON host_name.id = hhnm.host_name_id
            INNER JOIN service ON service.host_name_id = host_name.id
            INNER JOIN host ON host.id = hhnm.host_id
            WHERE ((hhnm.type & 1) = 1 OR (hhnm.type & 2) = 2) AND service.id = id_service;
        id_host integer;
        BEGIN
            IF (pg_trigger_depth() = 1) THEN
                IF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') THEN
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
                                                     nmap_extra_info,
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
                                                                           nmap_extra_info,
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
                                    nmap_extra_info = t.nmap_extra_info,
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
                                             nmap_extra_info,
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
                                                     nmap_extra_info,
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
                                                                           nmap_extra_info,
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
                                    nmap_extra_info = t.nmap_extra_info,
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
                                             nmap_extra_info,
                                             nmap_os_type FROM service WHERE id = NEW.id) AS t ON t.host_id = s.host_id AND
                                                                                                  t.port = s.port AND
                                                                                                  t.protocol = s.protocol
                                WHERE service.id = s.id;
                            END IF;
                        END LOOP;
                        CLOSE mapping_host_cursor;
                    END IF;

                    -- If web service, then add the default path '/' to the path table
                    IF (NEW.state = 'Open' AND NEW.protocol = 'tcp' AND
                        (NEW.nmap_service_name IN ('ssl|http', 'http', 'https', 'http-alt', 'https-alt', 'http-proxy', 'https-proxy', 'sgi-soap', 'caldav') OR
                         NEW.nessus_service_name IN ('www', 'http', 'https', 'http-alt', 'https-alt', 'pcsync-http', 'pcsync-https', 'homepage', 'greenbone-administrator', 'openvas-administrator') OR
                         NEW.port = 80 OR NEW.port = 443) AND
                        NOT EXISTS(SELECT * FROM path WHERE service_id = NEW.id AND name = '/')) THEN
                        INSERT INTO path (service_id, name, type, creation_date) VALUES (NEW.id, '/', 'http', NOW());
                    END IF;
                ELSIF (TG_OP = 'DELETE') THEN
                    RAISE NOTICE 'DELETE';
                    IF (OLD.host_id IS NOT NULL) THEN
                        RAISE NOTICE 'DELETE host name service';
                        -- Check if a host's service was deleted. If so, then delete the corresponding host name service
                        DELETE FROM service
                        WHERE id IN (SELECT s.id FROM service s
                                     INNER JOIN host_name hn ON s.host_name_id = hn.id
                                     INNER JOIN host_host_name_mapping hhnm ON hhnm.host_name_id = hn.id AND ((hhnm.type & 1) = 1 OR (hhnm.type & 2) = 2)
                                     INNER JOIN host h ON hhnm.host_id = h.id
                                     WHERE s.protocol = OLD.protocol AND s.port = OLD.port AND h.id = OLD.host_id);
                    ELSIF (OLD.host_name_id IS NOT NULL) THEN
                        RAISE NOTICE 'DELETE host name service';
                        -- Check if a host's service was deleted. If so, then delete the corresponding host name service
                        DELETE FROM service
                        WHERE id IN (SELECT s.id FROM service s
                                     INNER JOIN host h ON s.host_id = h.id
                                     INNER JOIN host_host_name_mapping hhnm ON hhnm.host_id = h.id AND ((hhnm.type & 1) = 1 OR (hhnm.type & 2) = 2)
                                     INNER JOIN host_name hn ON hhnm.host_name_id = hn.id
                                     WHERE s.protocol = OLD.protocol AND s.port = OLD.port AND hn.id = OLD.host_name_id);
                    END IF;
                END IF;
            END IF;
            RETURN NULL;
        END;
        $$ LANGUAGE PLPGSQL;""")

    def _drop_functions(self) -> None:
        """This method drops all functions"""
        self._engine.execute("""DROP FUNCTION pre_command_changes;""")
        self._engine.execute("""DROP FUNCTION pre_update_domain_name_scope_changes;""")
        self._engine.execute("""DROP FUNCTION post_update_host_names_after_domain_name_scope_changes;""")
        self._engine.execute("""DROP FUNCTION pre_update_host_name_scope;""")
        self._engine.execute("""DROP FUNCTION pre_update_network_scopes_after_network_changes;""")
        self._engine.execute("""DROP FUNCTION post_update_network_scopes_after_network_changes;""")
        self._engine.execute("""DROP FUNCTION pre_update_hosts_after_host_changes;""")
        self._engine.execute("""DROP FUNCTION assign_services_to_host_name;""")
        self._engine.execute("""DROP FUNCTION add_services_to_host_name;""")
        self._engine.execute("""DROP FUNCTION update_service_check;""")

    def _create_triggers(self) -> None:
        """This method creates all triggers."""
        # Triggers on command table to automatically populate the workspace_id
        self._engine.execute("""CREATE TRIGGER pre_command_changes BEFORE INSERT ON command
 FOR EACH ROW EXECUTE PROCEDURE pre_command_changes();""")
        # Triggers on host_name and domain_name tables
        self._engine.execute("""CREATE TRIGGER pre_update_domain_name_scope_trigger BEFORE INSERT OR UPDATE ON domain_name
 FOR EACH ROW EXECUTE PROCEDURE pre_update_domain_name_scope_changes();""")
        self._engine.execute("""CREATE TRIGGER post_update_domain_name_scope_trigger AFTER INSERT OR UPDATE ON domain_name
 FOR EACH ROW EXECUTE PROCEDURE post_update_host_names_after_domain_name_scope_changes();""")
        self._engine.execute("""CREATE TRIGGER pre_update_host_name_scope_trigger BEFORE INSERT OR UPDATE ON host_name
 FOR EACH ROW EXECUTE PROCEDURE pre_update_host_name_scope();""")
        # Trigger to update host/host names scopes when A, AAAA records are updated
        self._engine.execute("""CREATE TRIGGER post_update_host_host_name_mapping_trigger AFTER INSERT OR DELETE OR UPDATE ON host_host_name_mapping
 FOR EACH ROW EXECUTE PROCEDURE post_update_scopes_after_host_host_name_mapping_update();""")
        # Triggers on network tables
        self._engine.execute("""CREATE TRIGGER pre_update_network_scope_trigger BEFORE INSERT OR UPDATE OR DELETE ON network
 FOR EACH ROW EXECUTE PROCEDURE pre_update_network_scopes_after_network_changes();""")
        self._engine.execute("""CREATE TRIGGER post_update_network_scope_trigger AFTER INSERT OR UPDATE OR DELETE ON network
 FOR EACH ROW EXECUTE PROCEDURE post_update_network_scopes_after_network_changes();""")
        # Triggers on hosts
        self._engine.execute("""CREATE TRIGGER pre_update_host_scope_trigger BEFORE INSERT OR UPDATE ON host
 FOR EACH ROW EXECUTE PROCEDURE pre_update_hosts_after_host_changes();""")
        self._engine.execute("""CREATE TRIGGER host_host_name_mapping_insert AFTER INSERT OR UPDATE ON host_host_name_mapping
 FOR EACH ROW EXECUTE PROCEDURE assign_services_to_host_name();""")
        self._engine.execute("""CREATE TRIGGER service_insert AFTER UPDATE OR INSERT OR DELETE ON service
 FOR EACH ROW EXECUTE PROCEDURE add_services_to_host_name();""")
        self._engine.execute("""CREATE TRIGGER check_service_update BEFORE UPDATE ON service
 FOR EACH ROW EXECUTE PROCEDURE update_service_check();""")

    def _drop_trigger(self) -> None:
        """This method drops all triggers."""
        self._engine.execute("""DROP TRIGGER post_update_domain_name_scope_trigger ON domain_name""")
        self._engine.execute("""DROP TRIGGER pre_update_host_name_scope_trigger ON host_name""")
        self._engine.execute("""DROP TRIGGER post_update_host_host_name_mapping_trigger ON host_host_name_mapping""")
        self._engine.execute("""DROP TRIGGER pre_update_network_scope_trigger ON network""")
        self._engine.execute("""DROP TRIGGER post_update_network_scope_trigger ON network""")
        self._engine.execute("""DROP TRIGGER pre_update_host_scope_trigger ON host""")
        self._engine.execute("""DROP TRIGGER host_name_mapping_insert ON host_name_mapping""")
        self._engine.execute("""DROP TRIGGER service_insert ON service""")
        self._engine.execute("""DROP TRIGGER check_service_update ON service""")

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
        """
        This method imports all cipher suites into the database.
        """
        cipher_suites = CipherSuites()
        with self.session_scope() as session:
            for cipher_suite in cipher_suites:
                session.add(cipher_suite)


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
        if not os_info.release and "-kali8-" in os_info.release:
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
            if self._db_config.is_docker() and tool == "vncviewer":
                continue
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
