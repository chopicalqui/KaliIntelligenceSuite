--
-- PostgreSQL database dump
--

-- Dumped from database version 14.4 (Debian 14.4-1+b1)
-- Dumped by pg_dump version 14.4 (Debian 14.4-1+b1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: certtype; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.certtype AS ENUM (
    'identity',
    'intermediate',
    'root'
);


ALTER TYPE public.certtype OWNER TO kis;

--
-- Name: ciphersuitesecurity; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.ciphersuitesecurity AS ENUM (
    'insecure',
    'weak',
    'secure',
    'recommended'
);


ALTER TYPE public.ciphersuitesecurity OWNER TO kis;

--
-- Name: collectortype; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.collectortype AS ENUM (
    'host_service',
    'host',
    'domain',
    'network',
    'vhost_service',
    'email',
    'company'
);


ALTER TYPE public.collectortype OWNER TO kis;

--
-- Name: commandstatus; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.commandstatus AS ENUM (
    'pending',
    'collecting',
    'terminated',
    'failed',
    'not_found',
    'completed',
    'skipped'
);


ALTER TYPE public.commandstatus OWNER TO kis;

--
-- Name: credentialtype; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.credentialtype AS ENUM (
    'cleartext',
    'hash',
    'oracle_tns_sid'
);


ALTER TYPE public.credentialtype OWNER TO kis;

--
-- Name: filetype; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.filetype AS ENUM (
    'screenshot',
    'certificate',
    'json',
    'xml',
    'text',
    'binary',
    'other'
);


ALTER TYPE public.filetype OWNER TO kis;

--
-- Name: keyexchangealgorithm; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.keyexchangealgorithm AS ENUM (
    'dh',
    'dhe',
    'ecdh',
    'ecdhe',
    'krb5',
    'null',
    'psk',
    'rsa',
    'srp',
    'eccpwd',
    'dh512',
    'dh1024',
    'dh2048',
    'dh2240',
    'dh3072',
    'dh4096',
    'rsa512',
    'rsa1024',
    'rsa2048',
    'rsa3072',
    'rsa4096',
    'p_256',
    'p_384',
    'p_521',
    'ecdh_x25519',
    'secp256r1',
    'secp384r1',
    'secp521r1',
    'anonymous'
);


ALTER TYPE public.keyexchangealgorithm OWNER TO kis;

--
-- Name: pathtype; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.pathtype AS ENUM (
    'http',
    'smb_share',
    'nfs_export',
    'filesystem'
);


ALTER TYPE public.pathtype OWNER TO kis;

--
-- Name: protocoltype; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.protocoltype AS ENUM (
    'udp',
    'tcp'
);


ALTER TYPE public.protocoltype OWNER TO kis;

--
-- Name: scopetype; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.scopetype AS ENUM (
    'all',
    'strict',
    'exclude',
    'vhost',
    'ignore'
);


ALTER TYPE public.scopetype OWNER TO kis;

--
-- Name: servicestate; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.servicestate AS ENUM (
    'Open',
    'Internal',
    'Open_Filtered',
    'Closed_Filtered',
    'Filtered',
    'Closed'
);


ALTER TYPE public.servicestate OWNER TO kis;

--
-- Name: tlspreference; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.tlspreference AS ENUM (
    'server',
    'client',
    'indeterminate'
);


ALTER TYPE public.tlspreference OWNER TO kis;

--
-- Name: tlsversion; Type: TYPE; Schema: public; Owner: kis
--

CREATE TYPE public.tlsversion AS ENUM (
    'ssl2',
    'ssl3',
    'tls10',
    'tls11',
    'tls12',
    'tls13'
);


ALTER TYPE public.tlsversion OWNER TO kis;

--
-- Name: add_services_to_host_name(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.add_services_to_host_name() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
                        -- RAISE NOTICE 'DELETE host name service';
                        -- Check if a host's service was deleted. If so, then delete the corresponding host name service
                        DELETE FROM service
                        WHERE id IN (SELECT s.id FROM service s
                                     INNER JOIN host_name hn ON s.host_name_id = hn.id
                                     INNER JOIN host_host_name_mapping hhnm ON hhnm.host_name_id = hn.id AND ((hhnm.type & 1) = 1 OR (hhnm.type & 2) = 2)
                                     INNER JOIN host h ON hhnm.host_id = h.id
                                     WHERE s.protocol = OLD.protocol AND s.port = OLD.port AND h.id = OLD.host_id);
                    ELSIF (OLD.host_name_id IS NOT NULL) THEN
                        -- RAISE NOTICE 'DELETE host name service';
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
        $$;


ALTER FUNCTION public.add_services_to_host_name() OWNER TO kis;

--
-- Name: assign_services_to_host_name(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.assign_services_to_host_name() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        DECLARE
        host_service_cursor CURSOR(id_host integer) FOR SELECT * FROM service WHERE service.host_id = id_host;
        host_name_service_cursor CURSOR(id_host_name integer) FOR SELECT * FROM service WHERE service.host_name_id = id_host_name;
        current_row service%ROWTYPE;
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
        $$;


ALTER FUNCTION public.assign_services_to_host_name() OWNER TO kis;

--
-- Name: post_update_host_names_after_domain_name_scope_changes(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.post_update_host_names_after_domain_name_scope_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            IF (TG_OP = 'UPDATE' AND COALESCE(OLD.scope, 'exclude') <> COALESCE(NEW.scope, 'exclude')) THEN
                -- Update scope of all sub-domains if the scope of the second-level domain is updated
                IF (COALESCE(NEW.scope, 'exclude') = 'all') THEN
                    UPDATE host_name
                        SET in_scope = True
                        WHERE domain_name_id = NEW.id;
                ELSIF (COALESCE(NEW.scope, 'exclude') = 'exclude' OR COALESCE(NEW.scope, 'exclude') = 'ignore') THEN
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
        $$;


ALTER FUNCTION public.post_update_host_names_after_domain_name_scope_changes() OWNER TO kis;

--
-- Name: post_update_network_scopes_after_network_changes(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.post_update_network_scopes_after_network_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        DECLARE
            sub_net inet;
        BEGIN
            -- This trigger updates all networks and hosts based on the current network's scope
            -- RAISE NOTICE 'BEGIN POST NETWORK: TG_OP = %, address = %, new scope = % old scope = %', TG_OP, NEW.address, NEW.scope, OLD.scope;
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
            -- RAISE NOTICE 'END POST NETWORK: TG_OP = %, address = %, new scope = % old scope = %', TG_OP, NEW.address, NEW.scope, OLD.scope;
            RETURN NULL;
        END;
        $$;


ALTER FUNCTION public.post_update_network_scopes_after_network_changes() OWNER TO kis;

--
-- Name: post_update_scopes_after_host_host_name_mapping_update(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.post_update_scopes_after_host_host_name_mapping_update() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
            -- RAISE NOTICE 'BEGIN POST HOST_HOST_NAME_MAPPING: TG_OP = %, host_id = %, host_name_id = %', TG_OP, current_host_id, current_host_name_id;
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
                -- RAISE NOTICE '  network_scope = %, host_record_count = %', network_scope, COALESCE(host_record_count, 0);
                
                -- If we have a domain scope of type vhost and an in scope host, then we have to put the host_name in scope
                IF COALESCE(domain_scope, 'exclude') = 'vhost' THEN
                    UPDATE host_name SET in_scope = COALESCE(host_name_record_count, 0) > 0
                        WHERE id = current_host_name_id;
                END IF;
                IF COALESCE(network_scope, 'exclude') = 'vhost' THEN
                    UPDATE host SET in_scope = COALESCE(host_record_count, 0) > 0
                        WHERE id = current_host_id;
                END IF;
                -- RAISE NOTICE 'END POST HOST_HOST_NAME_MAPPING: TG_OP = %, host_id = %, host_name_id = %', TG_OP, current_host_id, current_host_name_id;
            END IF;
            RETURN NULL;
        END;
        $$;


ALTER FUNCTION public.post_update_scopes_after_host_host_name_mapping_update() OWNER TO kis;

--
-- Name: pre_command_changes(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.pre_command_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
        $$;


ALTER FUNCTION public.pre_command_changes() OWNER TO kis;

--
-- Name: pre_update_domain_name_scope_changes(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.pre_update_domain_name_scope_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
        $$;


ALTER FUNCTION public.pre_update_domain_name_scope_changes() OWNER TO kis;

--
-- Name: pre_update_host_name_scope(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.pre_update_host_name_scope() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
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
            ELSIF (COALESCE(domain_scope, 'exclude') = 'exclude' OR COALESCE(domain_scope, 'exclude') = 'ignore') THEN
                NEW.in_scope := False;
            END IF;
            RETURN NEW;
        END;
        $$;


ALTER FUNCTION public.pre_update_host_name_scope() OWNER TO kis;

--
-- Name: pre_update_hosts_after_host_changes(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.pre_update_hosts_after_host_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        DECLARE
            network_scope scopetype;
        BEGIN
            -- RAISE NOTICE 'BEGIN PRE HOST: TG_OP = %, address = %, new scope = %, old scope = %, network_id = %', TG_OP, NEW.address, NEW.in_scope, OLD.in_scope, NEW.network_id;
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
                        EXISTS(SELECT * FROM host_host_name_mapping m
                               INNER JOIN host_name hn ON m.host_name_id = hn.id AND
                                                          COALESCE(hn.in_scope, FALSE) AND
                                                          COALESCE(m.type, 4) < 3 AND
                                                          m.host_id = NEW.id)) THEN
                        NEW.in_scope = True;
                    ELSIF network_scope <> 'strict' THEN
                        NEW.in_scope = False;
                    END IF;
                ELSE
                    NEW.in_scope = False;
                END IF;
            END IF;
            -- RAISE NOTICE 'END PRE HOST: TG_OP = %, address = %, new scope = %, old scope = %, network_id = %', TG_OP, NEW.address, NEW.in_scope, OLD.in_scope, NEW.network_id;
            RETURN NEW;
        END;
        $$;


ALTER FUNCTION public.pre_update_hosts_after_host_changes() OWNER TO kis;

--
-- Name: pre_update_network_scopes_after_network_changes(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.pre_update_network_scopes_after_network_changes() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        DECLARE
            network inet;
            scope scopetype;
            net_id integer;
        BEGIN
            -- RAISE NOTICE 'BEGIN PRE NETWORK: TG_OP = %, address = %, new scope = % old scope = %', TG_OP, NEW.address, NEW.scope, OLD.scope;
            -- This trigger performs consistency checks as well as updates the scope of the current network
            -- accordingly.
            IF (TG_OP = 'INSERT' OR TG_OP = 'UPDATE') THEN
                IF COALESCE(NEW.scope, 'exclude') = 'vhost' AND
                   EXISTS(SELECT * FROM domain_name d
                            WHERE d.workspace_id = NEW.workspace_id AND
                                  COALESCE(d.scope, 'exclude') = 'vhost') THEN
                    RAISE EXCEPTION 'scope vhost cannot be set at domain and network level at the same time';
                ELSIF (TG_OP = 'UPDATE' AND OLD.address <> NEW.address) THEN
                    RAISE EXCEPTION 'changing the networks address (%) is not allowed as it might make scoping
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
                              n.scope <> 'ignore' AND
                              n.scope <> NEW.scope
                        LIMIT 1;
                    IF network IS NOT NULL THEN
                        -- If a scope contradiction exists, then raise an exception
                        RAISE EXCEPTION 'insert failed because there is the following scope contradiction: Current
                                         network (%) with scope % cannot be inserted as it has a different
                                         scope than the parent network % with scope %. update the scope of the
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
                -- RAISE NOTICE 'END PRE NETWORK: TG_OP = %, address = %, new scope = % old scope = %', TG_OP, NEW.address, NEW.scope, OLD.scope;
            ELSIF (TG_OP = 'DELETE') THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$;


ALTER FUNCTION public.pre_update_network_scopes_after_network_changes() OWNER TO kis;

--
-- Name: update_service_check(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE FUNCTION public.update_service_check() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
        BEGIN
            IF (TG_OP = 'UPDATE' AND (OLD.protocol <> NEW.protocol OR OLD.port <> NEW.port)) THEN
                    RAISE EXCEPTION 'the service port or protocol cannot be updated as they are part of the primary key. delete service and create a new one.';
            END IF;
            RETURN NEW;
        END;
        $$;


ALTER FUNCTION public.update_service_check() OWNER TO kis;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: additional_info; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.additional_info (
    id integer NOT NULL,
    name text NOT NULL,
    "values" text[] NOT NULL,
    service_id integer,
    host_name_id integer,
    email_id integer,
    company_id integer,
    host_id integer,
    network_id integer,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone,
    CONSTRAINT _additional_info_mutex_constraint CHECK (((((((
CASE
    WHEN (service_id IS NULL) THEN 0
    ELSE 1
END +
CASE
    WHEN (host_id IS NULL) THEN 0
    ELSE 1
END) +
CASE
    WHEN (network_id IS NULL) THEN 0
    ELSE 1
END) +
CASE
    WHEN (email_id IS NULL) THEN 0
    ELSE 1
END) +
CASE
    WHEN (company_id IS NULL) THEN 0
    ELSE 1
END) +
CASE
    WHEN (host_name_id IS NULL) THEN 0
    ELSE 1
END) = 1))
);


ALTER TABLE public.additional_info OWNER TO kis;

--
-- Name: additional_info_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.additional_info_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.additional_info_id_seq OWNER TO kis;

--
-- Name: additional_info_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.additional_info_id_seq OWNED BY public.additional_info.id;


--
-- Name: cert_info; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.cert_info (
    id integer NOT NULL,
    pem text NOT NULL,
    serial_number text NOT NULL,
    cert_type public.certtype NOT NULL,
    parent_id integer,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone,
    service_id integer,
    company_id integer,
    host_name_id integer,
    CONSTRAINT _cert_info_mutex_constraint CHECK ((((
CASE
    WHEN ((NOT (service_id IS NULL)) AND (company_id IS NULL) AND (host_name_id IS NULL)) THEN 1
    ELSE 0
END +
CASE
    WHEN ((service_id IS NULL) AND (NOT (company_id IS NULL)) AND (host_name_id IS NULL)) THEN 1
    ELSE 0
END) +
CASE
    WHEN ((service_id IS NULL) AND (company_id IS NULL) AND (NOT (host_name_id IS NULL))) THEN 1
    ELSE 0
END) = 1))
);


ALTER TABLE public.cert_info OWNER TO kis;

--
-- Name: cert_info_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.cert_info_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.cert_info_id_seq OWNER TO kis;

--
-- Name: cert_info_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.cert_info_id_seq OWNED BY public.cert_info.id;


--
-- Name: cipher_suite; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.cipher_suite (
    id integer NOT NULL,
    iana_name text NOT NULL,
    gnutls_name text,
    openssl_name text,
    byte_1 integer NOT NULL,
    byte_2 integer NOT NULL,
    security public.ciphersuitesecurity NOT NULL
);


ALTER TABLE public.cipher_suite OWNER TO kis;

--
-- Name: cipher_suite_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.cipher_suite_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.cipher_suite_id_seq OWNER TO kis;

--
-- Name: cipher_suite_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.cipher_suite_id_seq OWNED BY public.cipher_suite.id;


--
-- Name: collector_name; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.collector_name (
    id integer NOT NULL,
    name character varying(50) NOT NULL,
    type public.collectortype NOT NULL,
    priority integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.collector_name OWNER TO kis;

--
-- Name: collector_name_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.collector_name_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.collector_name_id_seq OWNER TO kis;

--
-- Name: collector_name_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.collector_name_id_seq OWNED BY public.collector_name.id;


--
-- Name: command; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.command (
    id integer NOT NULL,
    os_command text[] NOT NULL,
    description text,
    hide boolean NOT NULL,
    status public.commandstatus NOT NULL,
    stdout_output text[],
    stderr_output text[],
    xml_output text,
    json_output json[],
    binary_output bytea,
    execution_info json,
    hint text[],
    return_code integer,
    collector_name_id integer NOT NULL,
    host_id integer,
    service_id integer,
    host_name_id integer,
    network_id integer,
    email_id integer,
    company_id integer,
    workspace_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone,
    start_time timestamp without time zone,
    stop_time timestamp without time zone,
    CONSTRAINT _command_mutex_constraint CHECK ((((((((
CASE
    WHEN ((NOT (service_id IS NULL)) AND (NOT (host_id IS NULL)) AND (host_name_id IS NULL) AND (network_id IS NULL) AND (email_id IS NULL) AND (company_id IS NULL)) THEN 1
    ELSE 0
END +
CASE
    WHEN ((NOT (service_id IS NULL)) AND (host_id IS NULL) AND (NOT (host_name_id IS NULL)) AND (network_id IS NULL) AND (email_id IS NULL) AND (company_id IS NULL)) THEN 1
    ELSE 0
END) +
CASE
    WHEN ((service_id IS NULL) AND (NOT (host_id IS NULL)) AND (host_name_id IS NULL) AND (network_id IS NULL) AND (email_id IS NULL) AND (company_id IS NULL)) THEN 1
    ELSE 0
END) +
CASE
    WHEN ((service_id IS NULL) AND (host_id IS NULL) AND (NOT (host_name_id IS NULL)) AND (network_id IS NULL) AND (email_id IS NULL) AND (company_id IS NULL)) THEN 1
    ELSE 0
END) +
CASE
    WHEN ((service_id IS NULL) AND (host_id IS NULL) AND (host_name_id IS NULL) AND (NOT (network_id IS NULL)) AND (email_id IS NULL) AND (company_id IS NULL)) THEN 1
    ELSE 0
END) +
CASE
    WHEN ((service_id IS NULL) AND (host_id IS NULL) AND (host_name_id IS NULL) AND (network_id IS NULL) AND (NOT (email_id IS NULL)) AND (company_id IS NULL)) THEN 1
    ELSE 0
END) +
CASE
    WHEN ((service_id IS NULL) AND (host_id IS NULL) AND (host_name_id IS NULL) AND (network_id IS NULL) AND (email_id IS NULL) AND (company_id IS NOT NULL)) THEN 1
    ELSE 0
END) = 1))
);


ALTER TABLE public.command OWNER TO kis;

--
-- Name: command_file_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.command_file_mapping (
    id integer NOT NULL,
    file_name text NOT NULL,
    command_id integer NOT NULL,
    file_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.command_file_mapping OWNER TO kis;

--
-- Name: command_file_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.command_file_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.command_file_mapping_id_seq OWNER TO kis;

--
-- Name: command_file_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.command_file_mapping_id_seq OWNED BY public.command_file_mapping.id;


--
-- Name: command_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.command_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.command_id_seq OWNER TO kis;

--
-- Name: command_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.command_id_seq OWNED BY public.command.id;


--
-- Name: company; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.company (
    id integer NOT NULL,
    name text NOT NULL,
    in_scope boolean DEFAULT false NOT NULL,
    workspace_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.company OWNER TO kis;

--
-- Name: company_domain_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.company_domain_name_mapping (
    id integer NOT NULL,
    verified boolean DEFAULT false NOT NULL,
    company_id integer NOT NULL,
    domain_name_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.company_domain_name_mapping OWNER TO kis;

--
-- Name: company_domain_name_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.company_domain_name_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.company_domain_name_mapping_id_seq OWNER TO kis;

--
-- Name: company_domain_name_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.company_domain_name_mapping_id_seq OWNED BY public.company_domain_name_mapping.id;


--
-- Name: company_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.company_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.company_id_seq OWNER TO kis;

--
-- Name: company_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.company_id_seq OWNED BY public.company.id;


--
-- Name: company_network_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.company_network_mapping (
    id integer NOT NULL,
    verified boolean DEFAULT false NOT NULL,
    company_id integer NOT NULL,
    network_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.company_network_mapping OWNER TO kis;

--
-- Name: company_network_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.company_network_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.company_network_mapping_id_seq OWNER TO kis;

--
-- Name: company_network_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.company_network_mapping_id_seq OWNED BY public.company_network_mapping.id;


--
-- Name: credential; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.credential (
    id integer NOT NULL,
    username text,
    domain text,
    password text,
    type public.credentialtype,
    complete boolean NOT NULL,
    service_id integer,
    email_id integer,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone,
    CONSTRAINT _credential_all_constraint CHECK (((service_id IS NULL) OR (email_id IS NULL))),
    CONSTRAINT _credential_constraint CHECK (((NOT (service_id IS NULL)) OR (NOT (email_id IS NULL)))),
    CONSTRAINT _credential_mutex_constraint CHECK (((NOT (service_id IS NULL)) OR (NOT (email_id IS NULL))))
);


ALTER TABLE public.credential OWNER TO kis;

--
-- Name: credential_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.credential_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.credential_id_seq OWNER TO kis;

--
-- Name: credential_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.credential_id_seq OWNED BY public.credential.id;


--
-- Name: domain_name; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.domain_name (
    id integer NOT NULL,
    name text NOT NULL,
    scope public.scopetype DEFAULT 'exclude'::public.scopetype NOT NULL,
    workspace_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.domain_name OWNER TO kis;

--
-- Name: domain_name_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.domain_name_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.domain_name_id_seq OWNER TO kis;

--
-- Name: domain_name_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.domain_name_id_seq OWNED BY public.domain_name.id;


--
-- Name: email; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.email (
    id integer NOT NULL,
    address text NOT NULL,
    host_name_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.email OWNER TO kis;

--
-- Name: email_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.email_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.email_id_seq OWNER TO kis;

--
-- Name: email_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.email_id_seq OWNED BY public.email.id;


--
-- Name: file; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.file (
    id integer NOT NULL,
    content bytea NOT NULL,
    workspace_id integer NOT NULL,
    type public.filetype NOT NULL,
    sha256_value text NOT NULL
);


ALTER TABLE public.file OWNER TO kis;

--
-- Name: file_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.file_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.file_id_seq OWNER TO kis;

--
-- Name: file_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.file_id_seq OWNED BY public.file.id;


--
-- Name: host; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.host (
    id integer NOT NULL,
    mac_address macaddr,
    address inet NOT NULL,
    in_scope boolean DEFAULT false NOT NULL,
    os_family text,
    is_up boolean NOT NULL,
    reason_up text,
    os_details text,
    workgroup text,
    workspace_id integer NOT NULL,
    network_id integer,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.host OWNER TO kis;

--
-- Name: host_host_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.host_host_name_mapping (
    id integer NOT NULL,
    host_id integer NOT NULL,
    host_name_id integer NOT NULL,
    type integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.host_host_name_mapping OWNER TO kis;

--
-- Name: host_host_name_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.host_host_name_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.host_host_name_mapping_id_seq OWNER TO kis;

--
-- Name: host_host_name_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.host_host_name_mapping_id_seq OWNED BY public.host_host_name_mapping.id;


--
-- Name: host_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.host_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.host_id_seq OWNER TO kis;

--
-- Name: host_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.host_id_seq OWNED BY public.host.id;


--
-- Name: host_name; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.host_name (
    id integer NOT NULL,
    name text,
    in_scope boolean DEFAULT false NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone,
    domain_name_id integer NOT NULL
);


ALTER TABLE public.host_name OWNER TO kis;

--
-- Name: host_name_host_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.host_name_host_name_mapping (
    id integer NOT NULL,
    source_host_name_id integer NOT NULL,
    resolved_host_name_id integer NOT NULL,
    type integer,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.host_name_host_name_mapping OWNER TO kis;

--
-- Name: host_name_host_name_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.host_name_host_name_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.host_name_host_name_mapping_id_seq OWNER TO kis;

--
-- Name: host_name_host_name_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.host_name_host_name_mapping_id_seq OWNED BY public.host_name_host_name_mapping.id;


--
-- Name: host_name_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.host_name_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.host_name_id_seq OWNER TO kis;

--
-- Name: host_name_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.host_name_id_seq OWNED BY public.host_name.id;


--
-- Name: host_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.host_name_mapping (
    id integer NOT NULL,
    host_id integer NOT NULL,
    host_name_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.host_name_mapping OWNER TO kis;

--
-- Name: host_name_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.host_name_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.host_name_mapping_id_seq OWNER TO kis;

--
-- Name: host_name_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.host_name_mapping_id_seq OWNED BY public.host_name_mapping.id;


--
-- Name: http_query; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.http_query (
    id integer NOT NULL,
    query text NOT NULL,
    path_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.http_query OWNER TO kis;

--
-- Name: http_query_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.http_query_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.http_query_id_seq OWNER TO kis;

--
-- Name: http_query_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.http_query_id_seq OWNED BY public.http_query.id;


--
-- Name: network; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.network (
    id integer NOT NULL,
    address inet NOT NULL,
    scope public.scopetype,
    workspace_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.network OWNER TO kis;

--
-- Name: network_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.network_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.network_id_seq OWNER TO kis;

--
-- Name: network_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.network_id_seq OWNED BY public.network.id;


--
-- Name: path; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.path (
    id integer NOT NULL,
    name text NOT NULL,
    return_code integer,
    size_bytes integer,
    type public.pathtype NOT NULL,
    service_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.path OWNER TO kis;

--
-- Name: path_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.path_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.path_id_seq OWNER TO kis;

--
-- Name: path_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.path_id_seq OWNED BY public.path.id;


--
-- Name: service; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.service (
    id integer NOT NULL,
    protocol public.protocoltype NOT NULL,
    port integer NOT NULL,
    nmap_service_name text,
    nessus_service_name text,
    nmap_service_confidence integer,
    nessus_service_confidence integer,
    nmap_service_name_original text,
    state public.servicestate NOT NULL,
    nmap_service_state_reason character varying(25),
    nmap_product text,
    nmap_version text,
    nmap_extra_info text,
    nmap_tunnel text,
    nmap_os_type text,
    smb_message_signing boolean,
    rdp_nla boolean,
    host_id integer,
    host_name_id integer,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone,
    CONSTRAINT _service_all_constraint CHECK (((host_id IS NULL) OR (host_name_id IS NULL))),
    CONSTRAINT _service_mutex_constraint CHECK (((NOT (host_id IS NULL)) OR (NOT (host_name_id IS NULL))))
);


ALTER TABLE public.service OWNER TO kis;

--
-- Name: service_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.service_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.service_id_seq OWNER TO kis;

--
-- Name: service_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.service_id_seq OWNED BY public.service.id;


--
-- Name: service_method; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.service_method (
    id integer NOT NULL,
    name text NOT NULL,
    service_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.service_method OWNER TO kis;

--
-- Name: service_method_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.service_method_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.service_method_id_seq OWNER TO kis;

--
-- Name: service_method_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.service_method_id_seq OWNED BY public.service_method.id;


--
-- Name: source; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source (
    id integer NOT NULL,
    name text NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source OWNER TO kis;

--
-- Name: source_additional_info_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_additional_info_mapping (
    id integer NOT NULL,
    additional_info_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_additional_info_mapping OWNER TO kis;

--
-- Name: source_additional_info_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_additional_info_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_additional_info_mapping_id_seq OWNER TO kis;

--
-- Name: source_additional_info_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_additional_info_mapping_id_seq OWNED BY public.source_additional_info_mapping.id;


--
-- Name: source_cert_info_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_cert_info_mapping (
    id integer NOT NULL,
    cert_info_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_cert_info_mapping OWNER TO kis;

--
-- Name: source_cert_info_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_cert_info_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_cert_info_mapping_id_seq OWNER TO kis;

--
-- Name: source_cert_info_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_cert_info_mapping_id_seq OWNED BY public.source_cert_info_mapping.id;


--
-- Name: source_company_domain_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_company_domain_name_mapping (
    id integer NOT NULL,
    company_domain_name_mapping_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_company_domain_name_mapping OWNER TO kis;

--
-- Name: source_company_domain_name_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_company_domain_name_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_company_domain_name_mapping_id_seq OWNER TO kis;

--
-- Name: source_company_domain_name_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_company_domain_name_mapping_id_seq OWNED BY public.source_company_domain_name_mapping.id;


--
-- Name: source_company_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_company_mapping (
    id integer NOT NULL,
    company_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_company_mapping OWNER TO kis;

--
-- Name: source_company_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_company_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_company_mapping_id_seq OWNER TO kis;

--
-- Name: source_company_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_company_mapping_id_seq OWNED BY public.source_company_mapping.id;


--
-- Name: source_company_network_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_company_network_mapping (
    id integer NOT NULL,
    company_network_mapping_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_company_network_mapping OWNER TO kis;

--
-- Name: source_company_network_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_company_network_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_company_network_mapping_id_seq OWNER TO kis;

--
-- Name: source_company_network_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_company_network_mapping_id_seq OWNED BY public.source_company_network_mapping.id;


--
-- Name: source_credential_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_credential_mapping (
    id integer NOT NULL,
    credential_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_credential_mapping OWNER TO kis;

--
-- Name: source_credential_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_credential_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_credential_mapping_id_seq OWNER TO kis;

--
-- Name: source_credential_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_credential_mapping_id_seq OWNED BY public.source_credential_mapping.id;


--
-- Name: source_email_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_email_mapping (
    id integer NOT NULL,
    email_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_email_mapping OWNER TO kis;

--
-- Name: source_email_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_email_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_email_mapping_id_seq OWNER TO kis;

--
-- Name: source_email_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_email_mapping_id_seq OWNED BY public.source_email_mapping.id;


--
-- Name: source_host_host_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_host_host_name_mapping (
    id integer NOT NULL,
    host_host_name_mapping_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_host_host_name_mapping OWNER TO kis;

--
-- Name: source_host_host_name_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_host_host_name_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_host_host_name_mapping_id_seq OWNER TO kis;

--
-- Name: source_host_host_name_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_host_host_name_mapping_id_seq OWNED BY public.source_host_host_name_mapping.id;


--
-- Name: source_host_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_host_mapping (
    id integer NOT NULL,
    host_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_host_mapping OWNER TO kis;

--
-- Name: source_host_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_host_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_host_mapping_id_seq OWNER TO kis;

--
-- Name: source_host_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_host_mapping_id_seq OWNED BY public.source_host_mapping.id;


--
-- Name: source_host_name_host_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_host_name_host_name_mapping (
    id integer NOT NULL,
    host_name_host_name_mapping_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_host_name_host_name_mapping OWNER TO kis;

--
-- Name: source_host_name_host_name_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_host_name_host_name_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_host_name_host_name_mapping_id_seq OWNER TO kis;

--
-- Name: source_host_name_host_name_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_host_name_host_name_mapping_id_seq OWNED BY public.source_host_name_host_name_mapping.id;


--
-- Name: source_host_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_host_name_mapping (
    id integer NOT NULL,
    host_name_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_host_name_mapping OWNER TO kis;

--
-- Name: source_host_name_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_host_name_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_host_name_mapping_id_seq OWNER TO kis;

--
-- Name: source_host_name_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_host_name_mapping_id_seq OWNED BY public.source_host_name_mapping.id;


--
-- Name: source_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_id_seq OWNER TO kis;

--
-- Name: source_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_id_seq OWNED BY public.source.id;


--
-- Name: source_network_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_network_mapping (
    id integer NOT NULL,
    network_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_network_mapping OWNER TO kis;

--
-- Name: source_network_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_network_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_network_mapping_id_seq OWNER TO kis;

--
-- Name: source_network_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_network_mapping_id_seq OWNED BY public.source_network_mapping.id;


--
-- Name: source_path_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_path_mapping (
    id integer NOT NULL,
    path_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_path_mapping OWNER TO kis;

--
-- Name: source_path_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_path_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_path_mapping_id_seq OWNER TO kis;

--
-- Name: source_path_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_path_mapping_id_seq OWNED BY public.source_path_mapping.id;


--
-- Name: source_service_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_service_mapping (
    id integer NOT NULL,
    service_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_service_mapping OWNER TO kis;

--
-- Name: source_service_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_service_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_service_mapping_id_seq OWNER TO kis;

--
-- Name: source_service_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_service_mapping_id_seq OWNED BY public.source_service_mapping.id;


--
-- Name: source_service_method_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_service_method_mapping (
    id integer NOT NULL,
    service_name_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_service_method_mapping OWNER TO kis;

--
-- Name: source_service_method_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_service_method_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_service_method_mapping_id_seq OWNER TO kis;

--
-- Name: source_service_method_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_service_method_mapping_id_seq OWNED BY public.source_service_method_mapping.id;


--
-- Name: source_tls_info_cipher_suite_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_tls_info_cipher_suite_mapping (
    id integer NOT NULL,
    tls_info_cipher_suite_mapping_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_tls_info_cipher_suite_mapping OWNER TO kis;

--
-- Name: source_tls_info_cipher_suite_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_tls_info_cipher_suite_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_tls_info_cipher_suite_mapping_id_seq OWNER TO kis;

--
-- Name: source_tls_info_cipher_suite_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_tls_info_cipher_suite_mapping_id_seq OWNED BY public.source_tls_info_cipher_suite_mapping.id;


--
-- Name: source_vhost_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.source_vhost_name_mapping (
    id integer NOT NULL,
    vhost_name_mapping_id integer NOT NULL,
    source_id integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.source_vhost_name_mapping OWNER TO kis;

--
-- Name: source_vhost_name_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.source_vhost_name_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.source_vhost_name_mapping_id_seq OWNER TO kis;

--
-- Name: source_vhost_name_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.source_vhost_name_mapping_id_seq OWNED BY public.source_vhost_name_mapping.id;


--
-- Name: tls_info; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.tls_info (
    id integer NOT NULL,
    version public.tlsversion NOT NULL,
    service_id integer NOT NULL,
    compressors text[],
    preference public.tlspreference,
    heartbleed boolean
);


ALTER TABLE public.tls_info OWNER TO kis;

--
-- Name: tls_info_cipher_suite_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.tls_info_cipher_suite_mapping (
    id integer NOT NULL,
    cipher_suite_id integer NOT NULL,
    tls_info_id integer NOT NULL,
    kex_algorithm_details public.keyexchangealgorithm,
    kex_bits integer,
    "order" integer,
    prefered boolean,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.tls_info_cipher_suite_mapping OWNER TO kis;

--
-- Name: tls_info_cipher_suite_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.tls_info_cipher_suite_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tls_info_cipher_suite_mapping_id_seq OWNER TO kis;

--
-- Name: tls_info_cipher_suite_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.tls_info_cipher_suite_mapping_id_seq OWNED BY public.tls_info_cipher_suite_mapping.id;


--
-- Name: tls_info_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.tls_info_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.tls_info_id_seq OWNER TO kis;

--
-- Name: tls_info_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.tls_info_id_seq OWNED BY public.tls_info.id;


--
-- Name: version; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.version (
    id integer NOT NULL,
    major_number integer NOT NULL,
    minor_number integer NOT NULL,
    revision_number integer NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.version OWNER TO kis;

--
-- Name: version_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.version_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.version_id_seq OWNER TO kis;

--
-- Name: version_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.version_id_seq OWNED BY public.version.id;


--
-- Name: vhost_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.vhost_name_mapping (
    id integer NOT NULL,
    service_id integer NOT NULL,
    host_name_id integer,
    host_id integer,
    return_code integer,
    size_bytes integer,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone,
    CONSTRAINT _vhost_name_mapping_mutex_constraint CHECK (((
CASE
    WHEN ((NOT (host_name_id IS NULL)) AND (host_id IS NULL)) THEN 1
    ELSE 0
END +
CASE
    WHEN ((host_name_id IS NULL) AND (NOT (host_id IS NULL))) THEN 1
    ELSE 0
END) = 1))
);


ALTER TABLE public.vhost_name_mapping OWNER TO kis;

--
-- Name: vhost_name_mapping_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.vhost_name_mapping_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.vhost_name_mapping_id_seq OWNER TO kis;

--
-- Name: vhost_name_mapping_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.vhost_name_mapping_id_seq OWNED BY public.vhost_name_mapping.id;


--
-- Name: workspace; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE public.workspace (
    id integer NOT NULL,
    name character varying(25) NOT NULL,
    creation_date timestamp without time zone NOT NULL,
    last_modified timestamp without time zone
);


ALTER TABLE public.workspace OWNER TO kis;

--
-- Name: workspace_id_seq; Type: SEQUENCE; Schema: public; Owner: kis
--

CREATE SEQUENCE public.workspace_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.workspace_id_seq OWNER TO kis;

--
-- Name: workspace_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: kis
--

ALTER SEQUENCE public.workspace_id_seq OWNED BY public.workspace.id;


--
-- Name: additional_info id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info ALTER COLUMN id SET DEFAULT nextval('public.additional_info_id_seq'::regclass);


--
-- Name: cert_info id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cert_info ALTER COLUMN id SET DEFAULT nextval('public.cert_info_id_seq'::regclass);


--
-- Name: cipher_suite id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cipher_suite ALTER COLUMN id SET DEFAULT nextval('public.cipher_suite_id_seq'::regclass);


--
-- Name: collector_name id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.collector_name ALTER COLUMN id SET DEFAULT nextval('public.collector_name_id_seq'::regclass);


--
-- Name: command id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command ALTER COLUMN id SET DEFAULT nextval('public.command_id_seq'::regclass);


--
-- Name: command_file_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command_file_mapping ALTER COLUMN id SET DEFAULT nextval('public.command_file_mapping_id_seq'::regclass);


--
-- Name: company id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company ALTER COLUMN id SET DEFAULT nextval('public.company_id_seq'::regclass);


--
-- Name: company_domain_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company_domain_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.company_domain_name_mapping_id_seq'::regclass);


--
-- Name: company_network_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company_network_mapping ALTER COLUMN id SET DEFAULT nextval('public.company_network_mapping_id_seq'::regclass);


--
-- Name: credential id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.credential ALTER COLUMN id SET DEFAULT nextval('public.credential_id_seq'::regclass);


--
-- Name: domain_name id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.domain_name ALTER COLUMN id SET DEFAULT nextval('public.domain_name_id_seq'::regclass);


--
-- Name: email id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.email ALTER COLUMN id SET DEFAULT nextval('public.email_id_seq'::regclass);


--
-- Name: file id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.file ALTER COLUMN id SET DEFAULT nextval('public.file_id_seq'::regclass);


--
-- Name: host id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host ALTER COLUMN id SET DEFAULT nextval('public.host_id_seq'::regclass);


--
-- Name: host_host_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_host_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.host_host_name_mapping_id_seq'::regclass);


--
-- Name: host_name id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name ALTER COLUMN id SET DEFAULT nextval('public.host_name_id_seq'::regclass);


--
-- Name: host_name_host_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name_host_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.host_name_host_name_mapping_id_seq'::regclass);


--
-- Name: host_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.host_name_mapping_id_seq'::regclass);


--
-- Name: http_query id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.http_query ALTER COLUMN id SET DEFAULT nextval('public.http_query_id_seq'::regclass);


--
-- Name: network id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.network ALTER COLUMN id SET DEFAULT nextval('public.network_id_seq'::regclass);


--
-- Name: path id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.path ALTER COLUMN id SET DEFAULT nextval('public.path_id_seq'::regclass);


--
-- Name: service id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.service ALTER COLUMN id SET DEFAULT nextval('public.service_id_seq'::regclass);


--
-- Name: service_method id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.service_method ALTER COLUMN id SET DEFAULT nextval('public.service_method_id_seq'::regclass);


--
-- Name: source id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source ALTER COLUMN id SET DEFAULT nextval('public.source_id_seq'::regclass);


--
-- Name: source_additional_info_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_additional_info_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_additional_info_mapping_id_seq'::regclass);


--
-- Name: source_cert_info_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_cert_info_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_cert_info_mapping_id_seq'::regclass);


--
-- Name: source_company_domain_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_domain_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_company_domain_name_mapping_id_seq'::regclass);


--
-- Name: source_company_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_company_mapping_id_seq'::regclass);


--
-- Name: source_company_network_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_network_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_company_network_mapping_id_seq'::regclass);


--
-- Name: source_credential_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_credential_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_credential_mapping_id_seq'::regclass);


--
-- Name: source_email_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_email_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_email_mapping_id_seq'::regclass);


--
-- Name: source_host_host_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_host_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_host_host_name_mapping_id_seq'::regclass);


--
-- Name: source_host_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_host_mapping_id_seq'::regclass);


--
-- Name: source_host_name_host_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_name_host_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_host_name_host_name_mapping_id_seq'::regclass);


--
-- Name: source_host_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_host_name_mapping_id_seq'::regclass);


--
-- Name: source_network_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_network_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_network_mapping_id_seq'::regclass);


--
-- Name: source_path_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_path_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_path_mapping_id_seq'::regclass);


--
-- Name: source_service_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_service_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_service_mapping_id_seq'::regclass);


--
-- Name: source_service_method_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_service_method_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_service_method_mapping_id_seq'::regclass);


--
-- Name: source_tls_info_cipher_suite_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_tls_info_cipher_suite_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_tls_info_cipher_suite_mapping_id_seq'::regclass);


--
-- Name: source_vhost_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_vhost_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_vhost_name_mapping_id_seq'::regclass);


--
-- Name: tls_info id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.tls_info ALTER COLUMN id SET DEFAULT nextval('public.tls_info_id_seq'::regclass);


--
-- Name: tls_info_cipher_suite_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.tls_info_cipher_suite_mapping ALTER COLUMN id SET DEFAULT nextval('public.tls_info_cipher_suite_mapping_id_seq'::regclass);


--
-- Name: version id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.version ALTER COLUMN id SET DEFAULT nextval('public.version_id_seq'::regclass);


--
-- Name: vhost_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.vhost_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.vhost_name_mapping_id_seq'::regclass);


--
-- Name: workspace id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.workspace ALTER COLUMN id SET DEFAULT nextval('public.workspace_id_seq'::regclass);


--
-- Data for Name: additional_info; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.additional_info (id, name, "values", service_id, host_name_id, email_id, company_id, host_id, network_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: cert_info; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.cert_info (id, pem, serial_number, cert_type, parent_id, creation_date, last_modified, service_id, company_id, host_name_id) FROM stdin;
\.


--
-- Data for Name: cipher_suite; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.cipher_suite (id, iana_name, gnutls_name, openssl_name, byte_1, byte_2, security) FROM stdin;
1	TLS_AES_128_CCM_8_SHA256	\N	\N	19	5	secure
2	TLS_AES_128_CCM_SHA256	\N	TLS_AES_128_CCM_SHA256	19	4	secure
3	TLS_AES_128_GCM_SHA256	\N	TLS_AES_128_GCM_SHA256	19	1	recommended
4	TLS_AES_256_GCM_SHA384	\N	TLS_AES_256_GCM_SHA384	19	2	recommended
5	TLS_CHACHA20_POLY1305_SHA256	\N	\N	19	3	recommended
6	TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA	\N	\N	0	25	insecure
7	TLS_DH_anon_EXPORT_WITH_RC4_40_MD5	\N	\N	0	23	insecure
8	TLS_DH_anon_WITH_3DES_EDE_CBC_SHA	TLS_DH_ANON_3DES_EDE_CBC_SHA1	ADH-DES-CBC3-SHA	0	27	insecure
9	TLS_DH_anon_WITH_AES_128_CBC_SHA	TLS_DH_ANON_AES_128_CBC_SHA1	ADH-AES128-SHA	0	52	insecure
10	TLS_DH_anon_WITH_AES_128_CBC_SHA256	TLS_DH_ANON_AES_128_CBC_SHA256	ADH-AES128-SHA256	0	108	insecure
11	TLS_DH_anon_WITH_AES_128_GCM_SHA256	TLS_DH_ANON_AES_128_GCM_SHA256	ADH-AES128-GCM-SHA256	0	166	insecure
12	TLS_DH_anon_WITH_AES_256_CBC_SHA	TLS_DH_ANON_AES_256_CBC_SHA1	ADH-AES256-SHA	0	58	insecure
13	TLS_DH_anon_WITH_AES_256_CBC_SHA256	TLS_DH_ANON_AES_256_CBC_SHA256	ADH-AES256-SHA256	0	109	insecure
14	TLS_DH_anon_WITH_AES_256_GCM_SHA384	TLS_DH_ANON_AES_256_GCM_SHA384	ADH-AES256-GCM-SHA384	0	167	insecure
15	TLS_DH_anon_WITH_ARIA_128_CBC_SHA256	\N	\N	192	70	insecure
16	TLS_DH_anon_WITH_ARIA_128_GCM_SHA256	\N	\N	192	90	insecure
17	TLS_DH_anon_WITH_ARIA_256_CBC_SHA384	\N	\N	192	71	insecure
18	TLS_DH_anon_WITH_ARIA_256_GCM_SHA384	\N	\N	192	91	insecure
19	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA	TLS_DH_ANON_CAMELLIA_128_CBC_SHA1	ADH-CAMELLIA128-SHA	0	70	insecure
20	TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256	TLS_DH_ANON_CAMELLIA_128_CBC_SHA256	ADH-CAMELLIA128-SHA256	0	191	insecure
21	TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256	TLS_DH_ANON_CAMELLIA_128_GCM_SHA256	\N	192	132	insecure
22	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA	TLS_DH_ANON_CAMELLIA_256_CBC_SHA1	ADH-CAMELLIA256-SHA	0	137	insecure
23	TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256	TLS_DH_ANON_CAMELLIA_256_CBC_SHA256	ADH-CAMELLIA256-SHA256	0	197	insecure
24	TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384	TLS_DH_ANON_CAMELLIA_256_GCM_SHA384	\N	192	133	insecure
25	TLS_DH_anon_WITH_DES_CBC_SHA	\N	\N	0	26	insecure
26	TLS_DH_anon_WITH_RC4_128_MD5	TLS_DH_ANON_ARCFOUR_128_MD5	\N	0	24	insecure
27	TLS_DH_anon_WITH_SEED_CBC_SHA	\N	ADH-SEED-SHA	0	155	insecure
28	TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA	\N	\N	0	11	insecure
29	TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA	\N	\N	0	13	weak
30	TLS_DH_DSS_WITH_AES_128_CBC_SHA	\N	\N	0	48	weak
31	TLS_DH_DSS_WITH_AES_128_CBC_SHA256	\N	\N	0	62	weak
32	TLS_DH_DSS_WITH_AES_128_GCM_SHA256	\N	\N	0	164	weak
33	TLS_DH_DSS_WITH_AES_256_CBC_SHA	\N	\N	0	54	weak
34	TLS_DH_DSS_WITH_AES_256_CBC_SHA256	\N	\N	0	104	weak
35	TLS_DH_DSS_WITH_AES_256_GCM_SHA384	\N	\N	0	165	weak
36	TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256	\N	\N	192	62	weak
37	TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256	\N	\N	192	88	weak
38	TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384	\N	\N	192	63	weak
39	TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384	\N	\N	192	89	weak
40	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA	\N	\N	0	66	weak
41	TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256	\N	\N	0	187	weak
42	TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256	\N	\N	192	130	weak
43	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA	\N	\N	0	133	weak
44	TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256	\N	\N	0	193	weak
45	TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384	\N	\N	192	131	weak
46	TLS_DH_DSS_WITH_DES_CBC_SHA	\N	\N	0	12	insecure
47	TLS_DH_DSS_WITH_SEED_CBC_SHA	\N	\N	0	151	weak
48	TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA	\N	\N	0	17	insecure
49	TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA	TLS_DHE_DSS_3DES_EDE_CBC_SHA1	DHE-DSS-DES-CBC3-SHA	0	19	weak
50	TLS_DHE_DSS_WITH_AES_128_CBC_SHA	TLS_DHE_DSS_AES_128_CBC_SHA1	DHE-DSS-AES128-SHA	0	50	weak
51	TLS_DHE_DSS_WITH_AES_128_CBC_SHA256	TLS_DHE_DSS_AES_128_CBC_SHA256	DHE-DSS-AES128-SHA256	0	64	weak
52	TLS_DHE_DSS_WITH_AES_128_GCM_SHA256	TLS_DHE_DSS_AES_128_GCM_SHA256	DHE-DSS-AES128-GCM-SHA256	0	162	recommended
53	TLS_DHE_DSS_WITH_AES_256_CBC_SHA	TLS_DHE_DSS_AES_256_CBC_SHA1	DHE-DSS-AES256-SHA	0	56	weak
54	TLS_DHE_DSS_WITH_AES_256_CBC_SHA256	TLS_DHE_DSS_AES_256_CBC_SHA256	DHE-DSS-AES256-SHA256	0	106	weak
55	TLS_DHE_DSS_WITH_AES_256_GCM_SHA384	TLS_DHE_DSS_AES_256_GCM_SHA384	DHE-DSS-AES256-GCM-SHA384	0	163	recommended
56	TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256	\N	\N	192	66	weak
57	TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256	\N	\N	192	86	recommended
58	TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384	\N	\N	192	67	weak
59	TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384	\N	\N	192	87	recommended
60	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA	TLS_DHE_DSS_CAMELLIA_128_CBC_SHA1	DHE-DSS-CAMELLIA128-SHA	0	68	weak
61	TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256	TLS_DHE_DSS_CAMELLIA_128_CBC_SHA256	DHE-DSS-CAMELLIA128-SHA256	0	189	weak
62	TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256	TLS_DHE_DSS_CAMELLIA_128_GCM_SHA256	\N	192	128	recommended
63	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA	TLS_DHE_DSS_CAMELLIA_256_CBC_SHA1	DHE-DSS-CAMELLIA256-SHA	0	135	weak
64	TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256	TLS_DHE_DSS_CAMELLIA_256_CBC_SHA256	DHE-DSS-CAMELLIA256-SHA256	0	195	weak
65	TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384	TLS_DHE_DSS_CAMELLIA_256_GCM_SHA384	\N	192	129	recommended
66	TLS_DHE_DSS_WITH_DES_CBC_SHA	\N	\N	0	18	insecure
67	TLS_DHE_DSS_WITH_SEED_CBC_SHA	\N	DHE-DSS-SEED-SHA	0	153	weak
68	TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA	TLS_DHE_PSK_3DES_EDE_CBC_SHA1	DHE-PSK-3DES-EDE-CBC-SHA	0	143	weak
69	TLS_DHE_PSK_WITH_AES_128_CBC_SHA	TLS_DHE_PSK_AES_128_CBC_SHA1	DHE-PSK-AES128-CBC-SHA	0	144	weak
70	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256	TLS_DHE_PSK_AES_128_CBC_SHA256	DHE-PSK-AES128-CBC-SHA256	0	178	weak
71	TLS_DHE_PSK_WITH_AES_128_CCM	TLS_DHE_PSK_AES_128_CCM	DHE-PSK-AES128-CCM	192	166	secure
72	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256	TLS_DHE_PSK_AES_128_GCM_SHA256	DHE-PSK-AES128-GCM-SHA256	0	170	recommended
73	TLS_DHE_PSK_WITH_AES_256_CBC_SHA	TLS_DHE_PSK_AES_256_CBC_SHA1	DHE-PSK-AES256-CBC-SHA	0	145	weak
74	TLS_DHE_PSK_WITH_AES_256_CBC_SHA384	TLS_DHE_PSK_AES_256_CBC_SHA384	DHE-PSK-AES256-CBC-SHA384	0	179	weak
75	TLS_DHE_PSK_WITH_AES_256_CCM	TLS_DHE_PSK_AES_256_CCM	DHE-PSK-AES256-CCM	192	167	secure
76	TLS_DHE_PSK_WITH_AES_256_GCM_SHA384	TLS_DHE_PSK_AES_256_GCM_SHA384	DHE-PSK-AES256-GCM-SHA384	0	171	recommended
77	TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256	\N	\N	192	102	weak
78	TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256	\N	\N	192	108	recommended
79	TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384	\N	\N	192	103	weak
80	TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384	\N	\N	192	109	recommended
81	TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256	TLS_DHE_PSK_CAMELLIA_128_CBC_SHA256	DHE-PSK-CAMELLIA128-SHA256	192	150	weak
82	TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256	TLS_DHE_PSK_CAMELLIA_128_GCM_SHA256	\N	192	144	recommended
83	TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384	TLS_DHE_PSK_CAMELLIA_256_CBC_SHA384	DHE-PSK-CAMELLIA256-SHA384	192	151	weak
84	TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384	TLS_DHE_PSK_CAMELLIA_256_GCM_SHA384	\N	192	145	recommended
85	TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256	TLS_DHE_PSK_CHACHA20_POLY1305	DHE-PSK-CHACHA20-POLY1305	204	173	recommended
86	TLS_DHE_PSK_WITH_NULL_SHA	TLS_DHE_PSK_NULL_SHA1	DHE-PSK-NULL-SHA	0	45	insecure
87	TLS_DHE_PSK_WITH_NULL_SHA256	TLS_DHE_PSK_NULL_SHA256	DHE-PSK-NULL-SHA256	0	180	insecure
88	TLS_DHE_PSK_WITH_NULL_SHA384	TLS_DHE_PSK_NULL_SHA384	DHE-PSK-NULL-SHA384	0	181	insecure
89	TLS_DHE_PSK_WITH_RC4_128_SHA	TLS_DHE_PSK_ARCFOUR_128_SHA1	\N	0	142	insecure
90	TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA	\N	\N	0	20	insecure
91	TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA	TLS_DHE_RSA_3DES_EDE_CBC_SHA1	DHE-RSA-DES-CBC3-SHA	0	22	weak
92	TLS_DHE_RSA_WITH_AES_128_CBC_SHA	TLS_DHE_RSA_AES_128_CBC_SHA1	DHE-RSA-AES128-SHA	0	51	weak
93	TLS_DHE_RSA_WITH_AES_128_CBC_SHA256	TLS_DHE_RSA_AES_128_CBC_SHA256	DHE-RSA-AES128-SHA256	0	103	weak
94	TLS_DHE_RSA_WITH_AES_128_CCM	TLS_DHE_RSA_AES_128_CCM	DHE-RSA-AES128-CCM	192	158	secure
95	TLS_DHE_RSA_WITH_AES_128_CCM_8	TLS_DHE_RSA_AES_128_CCM_8	DHE-RSA-AES128-CCM8	192	162	secure
96	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256	TLS_DHE_RSA_AES_128_GCM_SHA256	DHE-RSA-AES128-GCM-SHA256	0	158	secure
97	TLS_DHE_RSA_WITH_AES_256_CBC_SHA	TLS_DHE_RSA_AES_256_CBC_SHA1	DHE-RSA-AES256-SHA	0	57	weak
98	TLS_DHE_RSA_WITH_AES_256_CBC_SHA256	TLS_DHE_RSA_AES_256_CBC_SHA256	DHE-RSA-AES256-SHA256	0	107	weak
99	TLS_DHE_RSA_WITH_AES_256_CCM	TLS_DHE_RSA_AES_256_CCM	DHE-RSA-AES256-CCM	192	159	secure
100	TLS_DHE_RSA_WITH_AES_256_CCM_8	TLS_DHE_RSA_AES_256_CCM_8	DHE-RSA-AES256-CCM8	192	163	secure
101	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384	TLS_DHE_RSA_AES_256_GCM_SHA384	DHE-RSA-AES256-GCM-SHA384	0	159	secure
102	TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256	\N	\N	192	68	weak
103	TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256	\N	\N	192	82	secure
104	TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384	\N	\N	192	69	weak
105	TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384	\N	\N	192	83	secure
106	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA	TLS_DHE_RSA_CAMELLIA_128_CBC_SHA1	DHE-RSA-CAMELLIA128-SHA	0	69	weak
107	TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256	TLS_DHE_RSA_CAMELLIA_128_CBC_SHA256	DHE-RSA-CAMELLIA128-SHA256	0	190	weak
108	TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256	TLS_DHE_RSA_CAMELLIA_128_GCM_SHA256	\N	192	124	secure
109	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA	TLS_DHE_RSA_CAMELLIA_256_CBC_SHA1	DHE-RSA-CAMELLIA256-SHA	0	136	weak
110	TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256	TLS_DHE_RSA_CAMELLIA_256_CBC_SHA256	DHE-RSA-CAMELLIA256-SHA256	0	196	weak
111	TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384	TLS_DHE_RSA_CAMELLIA_256_GCM_SHA384	\N	192	125	secure
112	TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256	TLS_DHE_RSA_CHACHA20_POLY1305	DHE-RSA-CHACHA20-POLY1305	204	170	secure
113	TLS_DHE_RSA_WITH_DES_CBC_SHA	\N	\N	0	21	insecure
114	TLS_DHE_RSA_WITH_SEED_CBC_SHA	\N	DHE-RSA-SEED-SHA	0	154	weak
115	TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA	\N	\N	0	14	insecure
116	TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA	\N	\N	0	16	weak
117	TLS_DH_RSA_WITH_AES_128_CBC_SHA	\N	\N	0	49	weak
118	TLS_DH_RSA_WITH_AES_128_CBC_SHA256	\N	\N	0	63	weak
119	TLS_DH_RSA_WITH_AES_128_GCM_SHA256	\N	\N	0	160	weak
120	TLS_DH_RSA_WITH_AES_256_CBC_SHA	\N	\N	0	55	weak
121	TLS_DH_RSA_WITH_AES_256_CBC_SHA256	\N	\N	0	105	weak
122	TLS_DH_RSA_WITH_AES_256_GCM_SHA384	\N	\N	0	161	weak
123	TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256	\N	\N	192	64	weak
124	TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256	\N	\N	192	84	weak
125	TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384	\N	\N	192	65	weak
126	TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384	\N	\N	192	85	weak
127	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA	\N	\N	0	67	weak
128	TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256	\N	\N	0	188	weak
129	TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256	\N	\N	192	126	weak
130	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA	\N	\N	0	134	weak
131	TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256	\N	\N	0	194	weak
132	TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384	\N	\N	192	127	weak
133	TLS_DH_RSA_WITH_DES_CBC_SHA	\N	\N	0	15	insecure
134	TLS_DH_RSA_WITH_SEED_CBC_SHA	\N	\N	0	152	weak
135	TLS_ECCPWD_WITH_AES_128_CCM_SHA256	\N	\N	192	178	secure
136	TLS_ECCPWD_WITH_AES_128_GCM_SHA256	\N	\N	192	176	secure
137	TLS_ECCPWD_WITH_AES_256_CCM_SHA384	\N	\N	192	179	secure
138	TLS_ECCPWD_WITH_AES_256_GCM_SHA384	\N	\N	192	177	secure
139	TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA	TLS_ECDH_ANON_3DES_EDE_CBC_SHA1	AECDH-DES-CBC3-SHA	192	23	insecure
140	TLS_ECDH_anon_WITH_AES_128_CBC_SHA	TLS_ECDH_ANON_AES_128_CBC_SHA1	AECDH-AES128-SHA	192	24	insecure
141	TLS_ECDH_anon_WITH_AES_256_CBC_SHA	TLS_ECDH_ANON_AES_256_CBC_SHA1	AECDH-AES256-SHA	192	25	insecure
142	TLS_ECDH_anon_WITH_NULL_SHA	TLS_ECDH_ANON_NULL_SHA1	AECDH-NULL-SHA	192	21	insecure
143	TLS_ECDH_anon_WITH_RC4_128_SHA	TLS_ECDH_ANON_ARCFOUR_128_SHA1	\N	192	22	insecure
144	TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA	\N	\N	192	3	weak
145	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA	\N	\N	192	4	weak
146	TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256	\N	\N	192	37	weak
147	TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256	\N	\N	192	45	weak
148	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA	\N	\N	192	5	weak
149	TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384	\N	\N	192	38	weak
150	TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384	\N	\N	192	46	weak
151	TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256	\N	\N	192	74	weak
152	TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256	\N	\N	192	94	weak
153	TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384	\N	\N	192	75	weak
154	TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384	\N	\N	192	95	weak
155	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256	\N	\N	192	116	weak
156	TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256	\N	\N	192	136	weak
157	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384	\N	\N	192	117	weak
158	TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384	\N	\N	192	137	weak
159	TLS_ECDH_ECDSA_WITH_NULL_SHA	\N	\N	192	1	insecure
160	TLS_ECDH_ECDSA_WITH_RC4_128_SHA	\N	\N	192	2	insecure
161	TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA	TLS_ECDHE_ECDSA_3DES_EDE_CBC_SHA1	ECDHE-ECDSA-DES-CBC3-SHA	192	8	weak
162	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA	TLS_ECDHE_ECDSA_AES_128_CBC_SHA1	ECDHE-ECDSA-AES128-SHA	192	9	weak
163	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256	TLS_ECDHE_ECDSA_AES_128_CBC_SHA256	ECDHE-ECDSA-AES128-SHA256	192	35	weak
164	TLS_ECDHE_ECDSA_WITH_AES_128_CCM	TLS_ECDHE_ECDSA_AES_128_CCM	ECDHE-ECDSA-AES128-CCM	192	172	secure
165	TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8	TLS_ECDHE_ECDSA_AES_128_CCM_8	ECDHE-ECDSA-AES128-CCM8	192	174	secure
166	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256	TLS_ECDHE_ECDSA_AES_128_GCM_SHA256	ECDHE-ECDSA-AES128-GCM-SHA256	192	43	recommended
167	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA	TLS_ECDHE_ECDSA_AES_256_CBC_SHA1	ECDHE-ECDSA-AES256-SHA	192	10	weak
168	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384	TLS_ECDHE_ECDSA_AES_256_CBC_SHA384	ECDHE-ECDSA-AES256-SHA384	192	36	weak
169	TLS_ECDHE_ECDSA_WITH_AES_256_CCM	TLS_ECDHE_ECDSA_AES_256_CCM	ECDHE-ECDSA-AES256-CCM	192	173	secure
170	TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8	TLS_ECDHE_ECDSA_AES_256_CCM_8	ECDHE-ECDSA-AES256-CCM8	192	175	secure
171	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384	TLS_ECDHE_ECDSA_AES_256_GCM_SHA384	ECDHE-ECDSA-AES256-GCM-SHA384	192	44	recommended
172	TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256	\N	\N	192	72	weak
173	TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256	\N	\N	192	92	recommended
174	TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384	\N	\N	192	73	weak
175	TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384	\N	\N	192	93	recommended
176	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256	TLS_ECDHE_ECDSA_CAMELLIA_128_CBC_SHA256	ECDHE-ECDSA-CAMELLIA128-SHA256	192	114	weak
177	TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256	TLS_ECDHE_ECDSA_CAMELLIA_128_GCM_SHA256	\N	192	134	recommended
178	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384	TLS_ECDHE_ECDSA_CAMELLIA_256_CBC_SHA384	ECDHE-ECDSA-CAMELLIA256-SHA384	192	115	weak
179	TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384	TLS_ECDHE_ECDSA_CAMELLIA_256_GCM_SHA384	\N	192	135	recommended
180	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256	TLS_ECDHE_ECDSA_CHACHA20_POLY1305	ECDHE-ECDSA-CHACHA20-POLY1305	204	169	recommended
181	TLS_ECDHE_ECDSA_WITH_NULL_SHA	TLS_ECDHE_ECDSA_NULL_SHA1	ECDHE-ECDSA-NULL-SHA	192	6	insecure
182	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA	TLS_ECDHE_ECDSA_ARCFOUR_128_SHA1	\N	192	7	insecure
183	TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA	TLS_ECDHE_PSK_3DES_EDE_CBC_SHA1	ECDHE-PSK-3DES-EDE-CBC-SHA	192	52	weak
184	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA	TLS_ECDHE_PSK_AES_128_CBC_SHA1	ECDHE-PSK-AES128-CBC-SHA	192	53	weak
185	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256	TLS_ECDHE_PSK_AES_128_CBC_SHA256	ECDHE-PSK-AES128-CBC-SHA256	192	55	weak
186	TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256	\N	\N	208	3	secure
187	TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256	\N	\N	208	5	secure
188	TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256	\N	\N	208	1	recommended
189	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA	TLS_ECDHE_PSK_AES_256_CBC_SHA1	ECDHE-PSK-AES256-CBC-SHA	192	54	weak
190	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384	TLS_ECDHE_PSK_AES_256_CBC_SHA384	ECDHE-PSK-AES256-CBC-SHA384	192	56	weak
191	TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384	\N	\N	208	2	recommended
192	TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256	\N	\N	192	112	weak
193	TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384	\N	\N	192	113	weak
194	TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256	TLS_ECDHE_PSK_CAMELLIA_128_CBC_SHA256	ECDHE-PSK-CAMELLIA128-SHA256	192	154	weak
195	TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384	TLS_ECDHE_PSK_CAMELLIA_256_CBC_SHA384	ECDHE-PSK-CAMELLIA256-SHA384	192	155	weak
196	TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256	TLS_ECDHE_PSK_CHACHA20_POLY1305	ECDHE-PSK-CHACHA20-POLY1305	204	172	recommended
197	TLS_ECDHE_PSK_WITH_NULL_SHA	TLS_ECDHE_PSK_NULL_SHA1	ECDHE-PSK-NULL-SHA	192	57	insecure
198	TLS_ECDHE_PSK_WITH_NULL_SHA256	TLS_ECDHE_PSK_NULL_SHA256	ECDHE-PSK-NULL-SHA256	192	58	insecure
199	TLS_ECDHE_PSK_WITH_NULL_SHA384	TLS_ECDHE_PSK_NULL_SHA384	ECDHE-PSK-NULL-SHA384	192	59	insecure
200	TLS_ECDHE_PSK_WITH_RC4_128_SHA	TLS_ECDHE_PSK_ARCFOUR_128_SHA1	\N	192	51	insecure
201	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA	TLS_ECDHE_RSA_3DES_EDE_CBC_SHA1	ECDHE-RSA-DES-CBC3-SHA	192	18	weak
202	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA	TLS_ECDHE_RSA_AES_128_CBC_SHA1	ECDHE-RSA-AES128-SHA	192	19	weak
203	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256	TLS_ECDHE_RSA_AES_128_CBC_SHA256	ECDHE-RSA-AES128-SHA256	192	39	weak
204	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256	TLS_ECDHE_RSA_AES_128_GCM_SHA256	ECDHE-RSA-AES128-GCM-SHA256	192	47	secure
205	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA	TLS_ECDHE_RSA_AES_256_CBC_SHA1	ECDHE-RSA-AES256-SHA	192	20	weak
206	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384	TLS_ECDHE_RSA_AES_256_CBC_SHA384	ECDHE-RSA-AES256-SHA384	192	40	weak
207	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384	TLS_ECDHE_RSA_AES_256_GCM_SHA384	ECDHE-RSA-AES256-GCM-SHA384	192	48	secure
208	TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256	\N	\N	192	76	weak
209	TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256	\N	\N	192	96	secure
210	TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384	\N	\N	192	77	weak
211	TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384	\N	\N	192	97	secure
212	TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256	TLS_ECDHE_RSA_CAMELLIA_128_CBC_SHA256	ECDHE-RSA-CAMELLIA128-SHA256	192	118	weak
213	TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256	TLS_ECDHE_RSA_CAMELLIA_128_GCM_SHA256	\N	192	138	secure
214	TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384	TLS_ECDHE_RSA_CAMELLIA_256_CBC_SHA384	ECDHE-RSA-CAMELLIA256-SHA384	192	119	weak
215	TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384	TLS_ECDHE_RSA_CAMELLIA_256_GCM_SHA384	\N	192	139	secure
216	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256	TLS_ECDHE_RSA_CHACHA20_POLY1305	ECDHE-RSA-CHACHA20-POLY1305	204	168	secure
217	TLS_ECDHE_RSA_WITH_NULL_SHA	TLS_ECDHE_RSA_NULL_SHA1	ECDHE-RSA-NULL-SHA	192	16	insecure
218	TLS_ECDHE_RSA_WITH_RC4_128_SHA	TLS_ECDHE_RSA_ARCFOUR_128_SHA1	\N	192	17	insecure
219	TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA	\N	\N	192	13	weak
220	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA	\N	\N	192	14	weak
221	TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256	\N	\N	192	41	weak
222	TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256	\N	\N	192	49	weak
223	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA	\N	\N	192	15	weak
224	TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384	\N	\N	192	42	weak
225	TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384	\N	\N	192	50	weak
226	TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256	\N	\N	192	78	weak
227	TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256	\N	\N	192	98	weak
228	TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384	\N	\N	192	79	weak
229	TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384	\N	\N	192	99	weak
230	TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256	\N	\N	192	120	weak
231	TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256	\N	\N	192	140	weak
232	TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384	\N	\N	192	121	weak
233	TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384	\N	\N	192	141	weak
234	TLS_ECDH_RSA_WITH_NULL_SHA	\N	\N	192	11	insecure
235	TLS_ECDH_RSA_WITH_RC4_128_SHA	\N	\N	192	12	insecure
236	TLS_GOSTR341112_256_WITH_28147_CNT_IMIT	\N	\N	193	2	secure
237	TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC	\N	\N	193	0	secure
238	TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC	\N	\N	193	1	secure
239	TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5	\N	\N	0	41	insecure
240	TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA	\N	\N	0	38	insecure
241	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5	\N	\N	0	42	insecure
242	TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA	\N	\N	0	39	insecure
243	TLS_KRB5_EXPORT_WITH_RC4_40_MD5	\N	\N	0	43	insecure
244	TLS_KRB5_EXPORT_WITH_RC4_40_SHA	\N	\N	0	40	insecure
245	TLS_KRB5_WITH_3DES_EDE_CBC_MD5	\N	\N	0	35	insecure
246	TLS_KRB5_WITH_3DES_EDE_CBC_SHA	\N	\N	0	31	weak
247	TLS_KRB5_WITH_DES_CBC_MD5	\N	\N	0	34	insecure
248	TLS_KRB5_WITH_DES_CBC_SHA	\N	\N	0	30	insecure
249	TLS_KRB5_WITH_IDEA_CBC_MD5	\N	\N	0	37	insecure
250	TLS_KRB5_WITH_IDEA_CBC_SHA	\N	\N	0	33	weak
251	TLS_KRB5_WITH_RC4_128_MD5	\N	\N	0	36	insecure
252	TLS_KRB5_WITH_RC4_128_SHA	\N	\N	0	32	insecure
253	TLS_NULL_WITH_NULL_NULL	\N	\N	0	0	insecure
254	TLS_PSK_DHE_WITH_AES_128_CCM_8	TLS_DHE_PSK_AES_128_CCM_8	DHE-PSK-AES128-CCM8	192	170	secure
255	TLS_PSK_DHE_WITH_AES_256_CCM_8	TLS_DHE_PSK_AES_256_CCM_8	DHE-PSK-AES256-CCM8	192	171	secure
256	TLS_PSK_WITH_3DES_EDE_CBC_SHA	TLS_PSK_3DES_EDE_CBC_SHA1	PSK-3DES-EDE-CBC-SHA	0	139	weak
257	TLS_PSK_WITH_AES_128_CBC_SHA	TLS_PSK_AES_128_CBC_SHA1	PSK-AES128-CBC-SHA	0	140	weak
258	TLS_PSK_WITH_AES_128_CBC_SHA256	TLS_PSK_AES_128_CBC_SHA256	PSK-AES128-CBC-SHA256	0	174	weak
259	TLS_PSK_WITH_AES_128_CCM	TLS_PSK_AES_128_CCM	PSK-AES128-CCM	192	164	weak
260	TLS_PSK_WITH_AES_128_CCM_8	TLS_PSK_AES_128_CCM_8	PSK-AES128-CCM8	192	168	weak
261	TLS_PSK_WITH_AES_128_GCM_SHA256	TLS_PSK_AES_128_GCM_SHA256	PSK-AES128-GCM-SHA256	0	168	weak
262	TLS_PSK_WITH_AES_256_CBC_SHA	TLS_PSK_AES_256_CBC_SHA1	PSK-AES256-CBC-SHA	0	141	weak
263	TLS_PSK_WITH_AES_256_CBC_SHA384	TLS_PSK_AES_256_CBC_SHA384	PSK-AES256-CBC-SHA384	0	175	weak
264	TLS_PSK_WITH_AES_256_CCM	TLS_PSK_AES_256_CCM	PSK-AES256-CCM	192	165	weak
265	TLS_PSK_WITH_AES_256_CCM_8	TLS_PSK_AES_256_CCM_8	PSK-AES256-CCM8	192	169	weak
266	TLS_PSK_WITH_AES_256_GCM_SHA384	TLS_PSK_AES_256_GCM_SHA384	PSK-AES256-GCM-SHA384	0	169	weak
267	TLS_PSK_WITH_ARIA_128_CBC_SHA256	\N	\N	192	100	weak
268	TLS_PSK_WITH_ARIA_128_GCM_SHA256	\N	\N	192	106	weak
269	TLS_PSK_WITH_ARIA_256_CBC_SHA384	\N	\N	192	101	weak
270	TLS_PSK_WITH_ARIA_256_GCM_SHA384	\N	\N	192	107	weak
271	TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256	TLS_PSK_CAMELLIA_128_CBC_SHA256	PSK-CAMELLIA128-SHA256	192	148	weak
272	TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256	TLS_PSK_CAMELLIA_128_GCM_SHA256	\N	192	142	weak
273	TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384	TLS_PSK_CAMELLIA_256_CBC_SHA384	PSK-CAMELLIA256-SHA384	192	149	weak
274	TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384	TLS_PSK_CAMELLIA_256_GCM_SHA384	\N	192	143	weak
275	TLS_PSK_WITH_CHACHA20_POLY1305_SHA256	TLS_PSK_CHACHA20_POLY1305	PSK-CHACHA20-POLY1305	204	171	weak
276	TLS_PSK_WITH_NULL_SHA	TLS_PSK_NULL_SHA1	PSK-NULL-SHA	0	44	insecure
277	TLS_PSK_WITH_NULL_SHA256	TLS_PSK_NULL_SHA256	PSK-NULL-SHA256	0	176	insecure
278	TLS_PSK_WITH_NULL_SHA384	TLS_PSK_NULL_SHA384	PSK-NULL-SHA384	0	177	insecure
279	TLS_PSK_WITH_RC4_128_SHA	TLS_PSK_ARCFOUR_128_SHA1	\N	0	138	insecure
280	TLS_RSA_EXPORT_WITH_DES40_CBC_SHA	\N	\N	0	8	insecure
281	TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5	\N	\N	0	6	insecure
282	TLS_RSA_EXPORT_WITH_RC4_40_MD5	\N	\N	0	3	insecure
283	TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA	TLS_RSA_PSK_3DES_EDE_CBC_SHA1	RSA-PSK-3DES-EDE-CBC-SHA	0	147	weak
284	TLS_RSA_PSK_WITH_AES_128_CBC_SHA	TLS_RSA_PSK_AES_128_CBC_SHA1	RSA-PSK-AES128-CBC-SHA	0	148	weak
285	TLS_RSA_PSK_WITH_AES_128_CBC_SHA256	TLS_RSA_PSK_AES_128_CBC_SHA256	RSA-PSK-AES128-CBC-SHA256	0	182	weak
286	TLS_RSA_PSK_WITH_AES_128_GCM_SHA256	TLS_RSA_PSK_AES_128_GCM_SHA256	RSA-PSK-AES128-GCM-SHA256	0	172	weak
287	TLS_RSA_PSK_WITH_AES_256_CBC_SHA	TLS_RSA_PSK_AES_256_CBC_SHA1	RSA-PSK-AES256-CBC-SHA	0	149	weak
288	TLS_RSA_PSK_WITH_AES_256_CBC_SHA384	TLS_RSA_PSK_AES_256_CBC_SHA384	RSA-PSK-AES256-CBC-SHA384	0	183	weak
289	TLS_RSA_PSK_WITH_AES_256_GCM_SHA384	TLS_RSA_PSK_AES_256_GCM_SHA384	RSA-PSK-AES256-GCM-SHA384	0	173	weak
290	TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256	\N	\N	192	104	weak
291	TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256	\N	\N	192	110	weak
292	TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384	\N	\N	192	105	weak
293	TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384	\N	\N	192	111	weak
294	TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256	TLS_RSA_PSK_CAMELLIA_128_CBC_SHA256	RSA-PSK-CAMELLIA128-SHA256	192	152	weak
295	TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256	TLS_RSA_PSK_CAMELLIA_128_GCM_SHA256	\N	192	146	weak
296	TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384	TLS_RSA_PSK_CAMELLIA_256_CBC_SHA384	RSA-PSK-CAMELLIA256-SHA384	192	153	weak
297	TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384	TLS_RSA_PSK_CAMELLIA_256_GCM_SHA384	\N	192	147	weak
298	TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256	TLS_RSA_PSK_CHACHA20_POLY1305	RSA-PSK-CHACHA20-POLY1305	204	174	weak
299	TLS_RSA_PSK_WITH_NULL_SHA	TLS_RSA_PSK_NULL_SHA1	RSA-PSK-NULL-SHA	0	46	insecure
300	TLS_RSA_PSK_WITH_NULL_SHA256	TLS_RSA_PSK_NULL_SHA256	RSA-PSK-NULL-SHA256	0	184	insecure
301	TLS_RSA_PSK_WITH_NULL_SHA384	TLS_RSA_PSK_NULL_SHA384	RSA-PSK-NULL-SHA384	0	185	insecure
302	TLS_RSA_PSK_WITH_RC4_128_SHA	TLS_RSA_PSK_ARCFOUR_128_SHA1	\N	0	146	insecure
303	TLS_RSA_WITH_3DES_EDE_CBC_SHA	TLS_RSA_3DES_EDE_CBC_SHA1	DES-CBC3-SHA	0	10	weak
304	TLS_RSA_WITH_AES_128_CBC_SHA	TLS_RSA_AES_128_CBC_SHA1	AES128-SHA	0	47	weak
305	TLS_RSA_WITH_AES_128_CBC_SHA256	TLS_RSA_AES_128_CBC_SHA256	AES128-SHA256	0	60	weak
306	TLS_RSA_WITH_AES_128_CCM	TLS_RSA_AES_128_CCM	AES128-CCM	192	156	weak
307	TLS_RSA_WITH_AES_128_CCM_8	TLS_RSA_AES_128_CCM_8	AES128-CCM8	192	160	weak
308	TLS_RSA_WITH_AES_128_GCM_SHA256	TLS_RSA_AES_128_GCM_SHA256	AES128-GCM-SHA256	0	156	weak
309	TLS_RSA_WITH_AES_256_CBC_SHA	TLS_RSA_AES_256_CBC_SHA1	AES256-SHA	0	53	weak
310	TLS_RSA_WITH_AES_256_CBC_SHA256	TLS_RSA_AES_256_CBC_SHA256	AES256-SHA256	0	61	weak
311	TLS_RSA_WITH_AES_256_CCM	TLS_RSA_AES_256_CCM	AES256-CCM	192	157	weak
312	TLS_RSA_WITH_AES_256_CCM_8	TLS_RSA_AES_256_CCM_8	AES256-CCM8	192	161	weak
313	TLS_RSA_WITH_AES_256_GCM_SHA384	TLS_RSA_AES_256_GCM_SHA384	AES256-GCM-SHA384	0	157	weak
314	TLS_RSA_WITH_ARIA_128_CBC_SHA256	\N	\N	192	60	weak
315	TLS_RSA_WITH_ARIA_128_GCM_SHA256	\N	\N	192	80	weak
316	TLS_RSA_WITH_ARIA_256_CBC_SHA384	\N	\N	192	61	weak
317	TLS_RSA_WITH_ARIA_256_GCM_SHA384	\N	\N	192	81	weak
318	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA	TLS_RSA_CAMELLIA_128_CBC_SHA1	CAMELLIA128-SHA	0	65	weak
319	TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256	TLS_RSA_CAMELLIA_128_CBC_SHA256	CAMELLIA128-SHA256	0	186	weak
320	TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256	TLS_RSA_CAMELLIA_128_GCM_SHA256	\N	192	122	weak
321	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA	TLS_RSA_CAMELLIA_256_CBC_SHA1	CAMELLIA256-SHA	0	132	weak
322	TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256	TLS_RSA_CAMELLIA_256_CBC_SHA256	CAMELLIA256-SHA256	0	192	weak
323	TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384	TLS_RSA_CAMELLIA_256_GCM_SHA384	\N	192	123	weak
324	TLS_RSA_WITH_DES_CBC_SHA	\N	\N	0	9	insecure
325	TLS_RSA_WITH_IDEA_CBC_SHA	\N	IDEA-CBC-SHA	0	7	weak
326	TLS_RSA_WITH_NULL_MD5	TLS_RSA_NULL_MD5	NULL-MD5	0	1	insecure
327	TLS_RSA_WITH_NULL_SHA	TLS_RSA_NULL_SHA1	NULL-SHA	0	2	insecure
328	TLS_RSA_WITH_NULL_SHA256	TLS_RSA_NULL_SHA256	NULL-SHA256	0	59	insecure
329	TLS_RSA_WITH_RC4_128_MD5	TLS_RSA_ARCFOUR_128_MD5	\N	0	4	insecure
330	TLS_RSA_WITH_RC4_128_SHA	TLS_RSA_ARCFOUR_128_SHA1	\N	0	5	insecure
331	TLS_RSA_WITH_SEED_CBC_SHA	\N	SEED-SHA	0	150	weak
332	TLS_SHA256_SHA256	\N	\N	192	180	recommended
333	TLS_SHA384_SHA384	\N	\N	192	181	recommended
334	TLS_SM4_CCM_SM3	\N	\N	0	199	insecure
335	TLS_SM4_GCM_SM3	\N	\N	0	198	insecure
336	TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA	TLS_SRP_SHA_DSS_3DES_EDE_CBC_SHA1	SRP-DSS-3DES-EDE-CBC-SHA	192	28	weak
337	TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA	TLS_SRP_SHA_DSS_AES_128_CBC_SHA1	SRP-DSS-AES-128-CBC-SHA	192	31	weak
338	TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA	TLS_SRP_SHA_DSS_AES_256_CBC_SHA1	SRP-DSS-AES-256-CBC-SHA	192	34	weak
339	TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA	TLS_SRP_SHA_RSA_3DES_EDE_CBC_SHA1	SRP-RSA-3DES-EDE-CBC-SHA	192	27	weak
340	TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA	TLS_SRP_SHA_RSA_AES_128_CBC_SHA1	SRP-RSA-AES-128-CBC-SHA	192	30	weak
341	TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA	TLS_SRP_SHA_RSA_AES_256_CBC_SHA1	SRP-RSA-AES-256-CBC-SHA	192	33	weak
342	TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA	TLS_SRP_SHA_3DES_EDE_CBC_SHA1	SRP-3DES-EDE-CBC-SHA	192	26	weak
343	TLS_SRP_SHA_WITH_AES_128_CBC_SHA	TLS_SRP_SHA_AES_128_CBC_SHA1	SRP-AES-128-CBC-SHA	192	29	weak
344	TLS_SRP_SHA_WITH_AES_256_CBC_SHA	TLS_SRP_SHA_AES_256_CBC_SHA1	SRP-AES-256-CBC-SHA	192	32	weak
\.


--
-- Data for Name: collector_name; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.collector_name (id, name, type, priority, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: command; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.command (id, os_command, description, hide, status, stdout_output, stderr_output, xml_output, json_output, binary_output, execution_info, hint, return_code, collector_name_id, host_id, service_id, host_name_id, network_id, email_id, company_id, workspace_id, creation_date, last_modified, start_time, stop_time) FROM stdin;
\.


--
-- Data for Name: command_file_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.command_file_mapping (id, file_name, command_id, file_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: company; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.company (id, name, in_scope, workspace_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: company_domain_name_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.company_domain_name_mapping (id, verified, company_id, domain_name_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: company_network_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.company_network_mapping (id, verified, company_id, network_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: credential; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.credential (id, username, domain, password, type, complete, service_id, email_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: domain_name; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.domain_name (id, name, scope, workspace_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: email; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.email (id, address, host_name_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: file; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.file (id, content, workspace_id, type, sha256_value) FROM stdin;
\.


--
-- Data for Name: host; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.host (id, mac_address, address, in_scope, os_family, is_up, reason_up, os_details, workgroup, workspace_id, network_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: host_host_name_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.host_host_name_mapping (id, host_id, host_name_id, type, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: host_name; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.host_name (id, name, in_scope, creation_date, last_modified, domain_name_id) FROM stdin;
\.


--
-- Data for Name: host_name_host_name_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.host_name_host_name_mapping (id, source_host_name_id, resolved_host_name_id, type, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: host_name_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.host_name_mapping (id, host_id, host_name_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: http_query; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.http_query (id, query, path_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: network; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.network (id, address, scope, workspace_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: path; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.path (id, name, return_code, size_bytes, type, service_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: service; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.service (id, protocol, port, nmap_service_name, nessus_service_name, nmap_service_confidence, nessus_service_confidence, nmap_service_name_original, state, nmap_service_state_reason, nmap_product, nmap_version, nmap_extra_info, nmap_tunnel, nmap_os_type, smb_message_signing, rdp_nla, host_id, host_name_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: service_method; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.service_method (id, name, service_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source (id, name, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_additional_info_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_additional_info_mapping (id, additional_info_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_cert_info_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_cert_info_mapping (id, cert_info_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_company_domain_name_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_company_domain_name_mapping (id, company_domain_name_mapping_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_company_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_company_mapping (id, company_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_company_network_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_company_network_mapping (id, company_network_mapping_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_credential_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_credential_mapping (id, credential_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_email_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_email_mapping (id, email_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_host_host_name_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_host_host_name_mapping (id, host_host_name_mapping_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_host_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_host_mapping (id, host_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_host_name_host_name_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_host_name_host_name_mapping (id, host_name_host_name_mapping_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_host_name_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_host_name_mapping (id, host_name_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_network_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_network_mapping (id, network_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_path_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_path_mapping (id, path_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_service_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_service_mapping (id, service_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_service_method_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_service_method_mapping (id, service_name_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_tls_info_cipher_suite_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_tls_info_cipher_suite_mapping (id, tls_info_cipher_suite_mapping_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: source_vhost_name_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.source_vhost_name_mapping (id, vhost_name_mapping_id, source_id, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: tls_info; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.tls_info (id, version, service_id, compressors, preference, heartbleed) FROM stdin;
\.


--
-- Data for Name: tls_info_cipher_suite_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.tls_info_cipher_suite_mapping (id, cipher_suite_id, tls_info_id, kex_algorithm_details, kex_bits, "order", prefered, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: version; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.version (id, major_number, minor_number, revision_number, creation_date, last_modified) FROM stdin;
1	0	4	0	2022-10-03 16:38:01.591627	\N
\.


--
-- Data for Name: vhost_name_mapping; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.vhost_name_mapping (id, service_id, host_name_id, host_id, return_code, size_bytes, creation_date, last_modified) FROM stdin;
\.


--
-- Data for Name: workspace; Type: TABLE DATA; Schema: public; Owner: kis
--

COPY public.workspace (id, name, creation_date, last_modified) FROM stdin;
\.


--
-- Name: additional_info_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.additional_info_id_seq', 1, false);


--
-- Name: cert_info_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.cert_info_id_seq', 1, false);


--
-- Name: cipher_suite_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.cipher_suite_id_seq', 344, true);


--
-- Name: collector_name_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.collector_name_id_seq', 1, false);


--
-- Name: command_file_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.command_file_mapping_id_seq', 1, false);


--
-- Name: command_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.command_id_seq', 1, false);


--
-- Name: company_domain_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.company_domain_name_mapping_id_seq', 1, false);


--
-- Name: company_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.company_id_seq', 1, false);


--
-- Name: company_network_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.company_network_mapping_id_seq', 1, false);


--
-- Name: credential_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.credential_id_seq', 1, false);


--
-- Name: domain_name_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.domain_name_id_seq', 1, false);


--
-- Name: email_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.email_id_seq', 1, false);


--
-- Name: file_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.file_id_seq', 1, false);


--
-- Name: host_host_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.host_host_name_mapping_id_seq', 1, false);


--
-- Name: host_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.host_id_seq', 1, false);


--
-- Name: host_name_host_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.host_name_host_name_mapping_id_seq', 1, false);


--
-- Name: host_name_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.host_name_id_seq', 1, false);


--
-- Name: host_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.host_name_mapping_id_seq', 1, false);


--
-- Name: http_query_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.http_query_id_seq', 1, false);


--
-- Name: network_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.network_id_seq', 1, false);


--
-- Name: path_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.path_id_seq', 1, false);


--
-- Name: service_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.service_id_seq', 1, false);


--
-- Name: service_method_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.service_method_id_seq', 1, false);


--
-- Name: source_additional_info_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_additional_info_mapping_id_seq', 1, false);


--
-- Name: source_cert_info_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_cert_info_mapping_id_seq', 1, false);


--
-- Name: source_company_domain_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_company_domain_name_mapping_id_seq', 1, false);


--
-- Name: source_company_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_company_mapping_id_seq', 1, false);


--
-- Name: source_company_network_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_company_network_mapping_id_seq', 1, false);


--
-- Name: source_credential_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_credential_mapping_id_seq', 1, false);


--
-- Name: source_email_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_email_mapping_id_seq', 1, false);


--
-- Name: source_host_host_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_host_host_name_mapping_id_seq', 1, false);


--
-- Name: source_host_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_host_mapping_id_seq', 1, false);


--
-- Name: source_host_name_host_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_host_name_host_name_mapping_id_seq', 1, false);


--
-- Name: source_host_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_host_name_mapping_id_seq', 1, false);


--
-- Name: source_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_id_seq', 1, false);


--
-- Name: source_network_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_network_mapping_id_seq', 1, false);


--
-- Name: source_path_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_path_mapping_id_seq', 1, false);


--
-- Name: source_service_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_service_mapping_id_seq', 1, false);


--
-- Name: source_service_method_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_service_method_mapping_id_seq', 1, false);


--
-- Name: source_tls_info_cipher_suite_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_tls_info_cipher_suite_mapping_id_seq', 1, false);


--
-- Name: source_vhost_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_vhost_name_mapping_id_seq', 1, false);


--
-- Name: tls_info_cipher_suite_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.tls_info_cipher_suite_mapping_id_seq', 1, false);


--
-- Name: tls_info_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.tls_info_id_seq', 1, false);


--
-- Name: version_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.version_id_seq', 1, true);


--
-- Name: vhost_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.vhost_name_mapping_id_seq', 1, false);


--
-- Name: workspace_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.workspace_id_seq', 1, false);


--
-- Name: additional_info _additional_info_company_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT _additional_info_company_unique UNIQUE (name, company_id);


--
-- Name: additional_info _additional_info_email_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT _additional_info_email_unique UNIQUE (name, email_id);


--
-- Name: additional_info _additional_info_host_name_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT _additional_info_host_name_unique UNIQUE (name, host_name_id);


--
-- Name: additional_info _additional_info_host_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT _additional_info_host_unique UNIQUE (name, host_id);


--
-- Name: additional_info _additional_info_network_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT _additional_info_network_unique UNIQUE (name, network_id);


--
-- Name: additional_info _additional_info_service_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT _additional_info_service_unique UNIQUE (name, service_id);


--
-- Name: cert_info _cert_info_company_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cert_info
    ADD CONSTRAINT _cert_info_company_unique UNIQUE (company_id, serial_number);


--
-- Name: cert_info _cert_info_host_name_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cert_info
    ADD CONSTRAINT _cert_info_host_name_unique UNIQUE (host_name_id, serial_number);


--
-- Name: cert_info _cert_info_service_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cert_info
    ADD CONSTRAINT _cert_info_service_unique UNIQUE (service_id, serial_number);


--
-- Name: collector_name _collector_name_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.collector_name
    ADD CONSTRAINT _collector_name_unique UNIQUE (name, type);


--
-- Name: command _command_company_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT _command_company_unique UNIQUE (os_command, collector_name_id, company_id);


--
-- Name: command _command_email_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT _command_email_unique UNIQUE (os_command, collector_name_id, email_id);


--
-- Name: command_file_mapping _command_file_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command_file_mapping
    ADD CONSTRAINT _command_file_unique UNIQUE (file_id, command_id);


--
-- Name: command _command_network_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT _command_network_unique UNIQUE (os_command, collector_name_id, network_id);


--
-- Name: command _command_service_host_name_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT _command_service_host_name_unique UNIQUE (os_command, collector_name_id, service_id, host_name_id);


--
-- Name: command _command_service_host_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT _command_service_host_unique UNIQUE (os_command, collector_name_id, host_id, service_id);


--
-- Name: company_domain_name_mapping _company_domain_name_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company_domain_name_mapping
    ADD CONSTRAINT _company_domain_name_unique UNIQUE (company_id, domain_name_id);


--
-- Name: company_network_mapping _company_network_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company_network_mapping
    ADD CONSTRAINT _company_network_mapping_unique UNIQUE (company_id, network_id);


--
-- Name: company _company_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company
    ADD CONSTRAINT _company_unique UNIQUE (name, workspace_id);


--
-- Name: credential _credential_email_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT _credential_email_unique UNIQUE (username, password, type, email_id);


--
-- Name: credential _credential_service_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT _credential_service_unique UNIQUE (username, password, type, service_id);


--
-- Name: domain_name _domain_name_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.domain_name
    ADD CONSTRAINT _domain_name_unique UNIQUE (name, workspace_id);


--
-- Name: email _email_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.email
    ADD CONSTRAINT _email_unique UNIQUE (address, host_name_id);


--
-- Name: file _file_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.file
    ADD CONSTRAINT _file_unique UNIQUE (type, sha256_value, workspace_id);


--
-- Name: host_host_name_mapping _host_host_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_host_name_mapping
    ADD CONSTRAINT _host_host_name_mapping_unique UNIQUE (host_id, host_name_id);


--
-- Name: host_name_host_name_mapping _host_name_host_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name_host_name_mapping
    ADD CONSTRAINT _host_name_host_name_mapping_unique UNIQUE (source_host_name_id, resolved_host_name_id);


--
-- Name: host_name_mapping _host_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name_mapping
    ADD CONSTRAINT _host_name_mapping_unique UNIQUE (host_id, host_name_id);


--
-- Name: host_name _host_name_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name
    ADD CONSTRAINT _host_name_unique UNIQUE (name, domain_name_id);


--
-- Name: host _host_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host
    ADD CONSTRAINT _host_unique UNIQUE (workspace_id, address);


--
-- Name: http_query _http_query_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.http_query
    ADD CONSTRAINT _http_query_unique UNIQUE (query, path_id);


--
-- Name: network _network_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.network
    ADD CONSTRAINT _network_unique UNIQUE (address, workspace_id);


--
-- Name: path _path_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.path
    ADD CONSTRAINT _path_unique UNIQUE (name, type, service_id);


--
-- Name: service _service_host_name_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.service
    ADD CONSTRAINT _service_host_name_unique UNIQUE (port, protocol, host_name_id);


--
-- Name: service _service_host_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.service
    ADD CONSTRAINT _service_host_unique UNIQUE (port, protocol, host_id);


--
-- Name: service_method _service_method_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.service_method
    ADD CONSTRAINT _service_method_unique UNIQUE (name, service_id);


--
-- Name: source_additional_info_mapping _source_additional_info_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_additional_info_mapping
    ADD CONSTRAINT _source_additional_info_mapping_unique UNIQUE (additional_info_id, source_id);


--
-- Name: source_cert_info_mapping _source_cert_info_mapping_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_cert_info_mapping
    ADD CONSTRAINT _source_cert_info_mapping_mapping_unique UNIQUE (cert_info_id, source_id);


--
-- Name: source_company_domain_name_mapping _source_company_domain_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_domain_name_mapping
    ADD CONSTRAINT _source_company_domain_name_mapping_unique UNIQUE (company_domain_name_mapping_id, source_id);


--
-- Name: source_company_mapping _source_company_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_mapping
    ADD CONSTRAINT _source_company_mapping_unique UNIQUE (company_id, source_id);


--
-- Name: source_company_network_mapping _source_company_network_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_network_mapping
    ADD CONSTRAINT _source_company_network_mapping_unique UNIQUE (company_network_mapping_id, source_id);


--
-- Name: source_credential_mapping _source_credential_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_credential_mapping
    ADD CONSTRAINT _source_credential_mapping_unique UNIQUE (credential_id, source_id);


--
-- Name: source_email_mapping _source_email_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_email_mapping
    ADD CONSTRAINT _source_email_mapping_unique UNIQUE (email_id, source_id);


--
-- Name: source_host_host_name_mapping _source_host_host_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_host_name_mapping
    ADD CONSTRAINT _source_host_host_name_mapping_unique UNIQUE (host_host_name_mapping_id, source_id);


--
-- Name: source_host_mapping _source_host_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_mapping
    ADD CONSTRAINT _source_host_mapping_unique UNIQUE (host_id, source_id);


--
-- Name: source_host_name_host_name_mapping _source_host_name_host_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_name_host_name_mapping
    ADD CONSTRAINT _source_host_name_host_name_mapping_unique UNIQUE (host_name_host_name_mapping_id, source_id);


--
-- Name: source_host_name_mapping _source_host_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_name_mapping
    ADD CONSTRAINT _source_host_name_mapping_unique UNIQUE (host_name_id, source_id);


--
-- Name: source_network_mapping _source_network_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_network_mapping
    ADD CONSTRAINT _source_network_mapping_unique UNIQUE (network_id, source_id);


--
-- Name: source_service_mapping _source_service_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_service_mapping
    ADD CONSTRAINT _source_service_mapping_unique UNIQUE (service_id, source_id);


--
-- Name: source_vhost_name_mapping _source_vhost_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_vhost_name_mapping
    ADD CONSTRAINT _source_vhost_name_mapping_unique UNIQUE (vhost_name_mapping_id, source_id);


--
-- Name: tls_info_cipher_suite_mapping _tls_info_cipher_suite_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.tls_info_cipher_suite_mapping
    ADD CONSTRAINT _tls_info_cipher_suite_mapping_unique UNIQUE (tls_info_id, cipher_suite_id, kex_algorithm_details);


--
-- Name: tls_info _tls_info_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.tls_info
    ADD CONSTRAINT _tls_info_unique UNIQUE (service_id, version);


--
-- Name: source_tls_info_cipher_suite_mapping _tls_source_info_cipher_suite_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_tls_info_cipher_suite_mapping
    ADD CONSTRAINT _tls_source_info_cipher_suite_mapping_unique UNIQUE (tls_info_cipher_suite_mapping_id, source_id);


--
-- Name: version _version_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.version
    ADD CONSTRAINT _version_unique UNIQUE (major_number, minor_number, revision_number);


--
-- Name: vhost_name_mapping _vhost_host_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.vhost_name_mapping
    ADD CONSTRAINT _vhost_host_mapping_unique UNIQUE (service_id, host_id);


--
-- Name: vhost_name_mapping _vhost_host_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.vhost_name_mapping
    ADD CONSTRAINT _vhost_host_name_mapping_unique UNIQUE (service_id, host_name_id);


--
-- Name: additional_info additional_info_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT additional_info_pkey PRIMARY KEY (id);


--
-- Name: cert_info cert_info_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cert_info
    ADD CONSTRAINT cert_info_pkey PRIMARY KEY (id);


--
-- Name: cipher_suite cipher_suite_gnutls_name_key; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cipher_suite
    ADD CONSTRAINT cipher_suite_gnutls_name_key UNIQUE (gnutls_name);


--
-- Name: cipher_suite cipher_suite_iana_name_key; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cipher_suite
    ADD CONSTRAINT cipher_suite_iana_name_key UNIQUE (iana_name);


--
-- Name: cipher_suite cipher_suite_openssl_name_key; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cipher_suite
    ADD CONSTRAINT cipher_suite_openssl_name_key UNIQUE (openssl_name);


--
-- Name: cipher_suite cipher_suite_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cipher_suite
    ADD CONSTRAINT cipher_suite_pkey PRIMARY KEY (id);


--
-- Name: collector_name collector_name_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.collector_name
    ADD CONSTRAINT collector_name_pkey PRIMARY KEY (id);


--
-- Name: command_file_mapping command_file_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command_file_mapping
    ADD CONSTRAINT command_file_mapping_pkey PRIMARY KEY (id);


--
-- Name: command command_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT command_pkey PRIMARY KEY (id);


--
-- Name: company_domain_name_mapping company_domain_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company_domain_name_mapping
    ADD CONSTRAINT company_domain_name_mapping_pkey PRIMARY KEY (id);


--
-- Name: company_network_mapping company_network_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company_network_mapping
    ADD CONSTRAINT company_network_mapping_pkey PRIMARY KEY (id);


--
-- Name: company company_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company
    ADD CONSTRAINT company_pkey PRIMARY KEY (id);


--
-- Name: credential credential_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT credential_pkey PRIMARY KEY (id);


--
-- Name: domain_name domain_name_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.domain_name
    ADD CONSTRAINT domain_name_pkey PRIMARY KEY (id);


--
-- Name: email email_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.email
    ADD CONSTRAINT email_pkey PRIMARY KEY (id);


--
-- Name: file file_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.file
    ADD CONSTRAINT file_pkey PRIMARY KEY (id);


--
-- Name: host_host_name_mapping host_host_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_host_name_mapping
    ADD CONSTRAINT host_host_name_mapping_pkey PRIMARY KEY (id);


--
-- Name: host_name_host_name_mapping host_name_host_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name_host_name_mapping
    ADD CONSTRAINT host_name_host_name_mapping_pkey PRIMARY KEY (id);


--
-- Name: host_name_mapping host_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name_mapping
    ADD CONSTRAINT host_name_mapping_pkey PRIMARY KEY (id);


--
-- Name: host_name host_name_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name
    ADD CONSTRAINT host_name_pkey PRIMARY KEY (id);


--
-- Name: host host_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host
    ADD CONSTRAINT host_pkey PRIMARY KEY (id);


--
-- Name: http_query http_query_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.http_query
    ADD CONSTRAINT http_query_pkey PRIMARY KEY (id);


--
-- Name: network network_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.network
    ADD CONSTRAINT network_pkey PRIMARY KEY (id);


--
-- Name: path path_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.path
    ADD CONSTRAINT path_pkey PRIMARY KEY (id);


--
-- Name: service_method service_method_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.service_method
    ADD CONSTRAINT service_method_pkey PRIMARY KEY (id);


--
-- Name: service service_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.service
    ADD CONSTRAINT service_pkey PRIMARY KEY (id);


--
-- Name: source_additional_info_mapping source_additional_info_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_additional_info_mapping
    ADD CONSTRAINT source_additional_info_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_cert_info_mapping source_cert_info_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_cert_info_mapping
    ADD CONSTRAINT source_cert_info_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_company_domain_name_mapping source_company_domain_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_domain_name_mapping
    ADD CONSTRAINT source_company_domain_name_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_company_mapping source_company_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_mapping
    ADD CONSTRAINT source_company_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_company_network_mapping source_company_network_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_network_mapping
    ADD CONSTRAINT source_company_network_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_credential_mapping source_credential_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_credential_mapping
    ADD CONSTRAINT source_credential_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_email_mapping source_email_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_email_mapping
    ADD CONSTRAINT source_email_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_host_host_name_mapping source_host_host_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_host_name_mapping
    ADD CONSTRAINT source_host_host_name_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_host_mapping source_host_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_mapping
    ADD CONSTRAINT source_host_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_host_name_host_name_mapping source_host_name_host_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_name_host_name_mapping
    ADD CONSTRAINT source_host_name_host_name_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_host_name_mapping source_host_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_name_mapping
    ADD CONSTRAINT source_host_name_mapping_pkey PRIMARY KEY (id);


--
-- Name: source source_name_key; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source
    ADD CONSTRAINT source_name_key UNIQUE (name);


--
-- Name: source_network_mapping source_network_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_network_mapping
    ADD CONSTRAINT source_network_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_path_mapping source_path_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_path_mapping
    ADD CONSTRAINT source_path_mapping_pkey PRIMARY KEY (id);


--
-- Name: source source_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source
    ADD CONSTRAINT source_pkey PRIMARY KEY (id);


--
-- Name: source_service_mapping source_service_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_service_mapping
    ADD CONSTRAINT source_service_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_service_method_mapping source_service_method_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_service_method_mapping
    ADD CONSTRAINT source_service_method_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_tls_info_cipher_suite_mapping source_tls_info_cipher_suite_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_tls_info_cipher_suite_mapping
    ADD CONSTRAINT source_tls_info_cipher_suite_mapping_pkey PRIMARY KEY (id);


--
-- Name: source_vhost_name_mapping source_vhost_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_vhost_name_mapping
    ADD CONSTRAINT source_vhost_name_mapping_pkey PRIMARY KEY (id);


--
-- Name: tls_info_cipher_suite_mapping tls_info_cipher_suite_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.tls_info_cipher_suite_mapping
    ADD CONSTRAINT tls_info_cipher_suite_mapping_pkey PRIMARY KEY (id);


--
-- Name: tls_info tls_info_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.tls_info
    ADD CONSTRAINT tls_info_pkey PRIMARY KEY (id);


--
-- Name: version version_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.version
    ADD CONSTRAINT version_pkey PRIMARY KEY (id);


--
-- Name: vhost_name_mapping vhost_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.vhost_name_mapping
    ADD CONSTRAINT vhost_name_mapping_pkey PRIMARY KEY (id);


--
-- Name: workspace workspace_name_key; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.workspace
    ADD CONSTRAINT workspace_name_key UNIQUE (name);


--
-- Name: workspace workspace_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.workspace
    ADD CONSTRAINT workspace_pkey PRIMARY KEY (id);


--
-- Name: service check_service_update; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER check_service_update BEFORE UPDATE ON public.service FOR EACH ROW EXECUTE FUNCTION public.update_service_check();


--
-- Name: host_host_name_mapping host_host_name_mapping_insert; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER host_host_name_mapping_insert AFTER INSERT OR UPDATE ON public.host_host_name_mapping FOR EACH ROW EXECUTE FUNCTION public.assign_services_to_host_name();


--
-- Name: domain_name post_update_domain_name_scope_trigger; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER post_update_domain_name_scope_trigger AFTER INSERT OR UPDATE ON public.domain_name FOR EACH ROW EXECUTE FUNCTION public.post_update_host_names_after_domain_name_scope_changes();


--
-- Name: host_host_name_mapping post_update_host_host_name_mapping_trigger; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER post_update_host_host_name_mapping_trigger AFTER INSERT OR DELETE OR UPDATE ON public.host_host_name_mapping FOR EACH ROW EXECUTE FUNCTION public.post_update_scopes_after_host_host_name_mapping_update();


--
-- Name: network post_update_network_scope_trigger; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER post_update_network_scope_trigger AFTER INSERT OR DELETE OR UPDATE ON public.network FOR EACH ROW EXECUTE FUNCTION public.post_update_network_scopes_after_network_changes();


--
-- Name: command pre_command_changes; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER pre_command_changes BEFORE INSERT ON public.command FOR EACH ROW EXECUTE FUNCTION public.pre_command_changes();


--
-- Name: domain_name pre_update_domain_name_scope_trigger; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER pre_update_domain_name_scope_trigger BEFORE INSERT OR UPDATE ON public.domain_name FOR EACH ROW EXECUTE FUNCTION public.pre_update_domain_name_scope_changes();


--
-- Name: host_name pre_update_host_name_scope_trigger; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER pre_update_host_name_scope_trigger BEFORE INSERT OR UPDATE ON public.host_name FOR EACH ROW EXECUTE FUNCTION public.pre_update_host_name_scope();


--
-- Name: host pre_update_host_scope_trigger; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER pre_update_host_scope_trigger BEFORE INSERT OR UPDATE ON public.host FOR EACH ROW EXECUTE FUNCTION public.pre_update_hosts_after_host_changes();


--
-- Name: network pre_update_network_scope_trigger; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER pre_update_network_scope_trigger BEFORE INSERT OR DELETE OR UPDATE ON public.network FOR EACH ROW EXECUTE FUNCTION public.pre_update_network_scopes_after_network_changes();


--
-- Name: service service_insert; Type: TRIGGER; Schema: public; Owner: kis
--

CREATE TRIGGER service_insert AFTER INSERT OR DELETE OR UPDATE ON public.service FOR EACH ROW EXECUTE FUNCTION public.add_services_to_host_name();


--
-- Name: additional_info additional_info_company_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT additional_info_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.company(id) ON DELETE CASCADE;


--
-- Name: additional_info additional_info_email_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT additional_info_email_id_fkey FOREIGN KEY (email_id) REFERENCES public.email(id) ON DELETE CASCADE;


--
-- Name: additional_info additional_info_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT additional_info_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.host(id) ON DELETE CASCADE;


--
-- Name: additional_info additional_info_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT additional_info_host_name_id_fkey FOREIGN KEY (host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: additional_info additional_info_network_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT additional_info_network_id_fkey FOREIGN KEY (network_id) REFERENCES public.network(id) ON DELETE CASCADE;


--
-- Name: additional_info additional_info_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.additional_info
    ADD CONSTRAINT additional_info_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: cert_info cert_info_company_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cert_info
    ADD CONSTRAINT cert_info_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.company(id) ON DELETE CASCADE;


--
-- Name: cert_info cert_info_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cert_info
    ADD CONSTRAINT cert_info_host_name_id_fkey FOREIGN KEY (host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: cert_info cert_info_parent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cert_info
    ADD CONSTRAINT cert_info_parent_id_fkey FOREIGN KEY (parent_id) REFERENCES public.cert_info(id) ON DELETE CASCADE;


--
-- Name: cert_info cert_info_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.cert_info
    ADD CONSTRAINT cert_info_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: command command_collector_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT command_collector_name_id_fkey FOREIGN KEY (collector_name_id) REFERENCES public.collector_name(id) ON DELETE CASCADE;


--
-- Name: command command_company_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT command_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.company(id) ON DELETE CASCADE;


--
-- Name: command command_email_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT command_email_id_fkey FOREIGN KEY (email_id) REFERENCES public.email(id) ON DELETE CASCADE;


--
-- Name: command_file_mapping command_file_mapping_command_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command_file_mapping
    ADD CONSTRAINT command_file_mapping_command_id_fkey FOREIGN KEY (command_id) REFERENCES public.command(id) ON DELETE CASCADE;


--
-- Name: command_file_mapping command_file_mapping_file_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command_file_mapping
    ADD CONSTRAINT command_file_mapping_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.file(id) ON DELETE CASCADE;


--
-- Name: command command_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT command_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.host(id) ON DELETE CASCADE;


--
-- Name: command command_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT command_host_name_id_fkey FOREIGN KEY (host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: command command_network_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT command_network_id_fkey FOREIGN KEY (network_id) REFERENCES public.network(id) ON DELETE CASCADE;


--
-- Name: command command_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT command_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: command command_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.command
    ADD CONSTRAINT command_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;


--
-- Name: company_domain_name_mapping company_domain_name_mapping_company_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company_domain_name_mapping
    ADD CONSTRAINT company_domain_name_mapping_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.company(id) ON DELETE CASCADE;


--
-- Name: company_domain_name_mapping company_domain_name_mapping_domain_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company_domain_name_mapping
    ADD CONSTRAINT company_domain_name_mapping_domain_name_id_fkey FOREIGN KEY (domain_name_id) REFERENCES public.domain_name(id) ON DELETE CASCADE;


--
-- Name: company_network_mapping company_network_mapping_company_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company_network_mapping
    ADD CONSTRAINT company_network_mapping_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.company(id) ON DELETE CASCADE;


--
-- Name: company_network_mapping company_network_mapping_network_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company_network_mapping
    ADD CONSTRAINT company_network_mapping_network_id_fkey FOREIGN KEY (network_id) REFERENCES public.network(id) ON DELETE CASCADE;


--
-- Name: company company_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.company
    ADD CONSTRAINT company_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;


--
-- Name: credential credential_email_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT credential_email_id_fkey FOREIGN KEY (email_id) REFERENCES public.email(id) ON DELETE CASCADE;


--
-- Name: credential credential_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT credential_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: domain_name domain_name_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.domain_name
    ADD CONSTRAINT domain_name_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;


--
-- Name: email email_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.email
    ADD CONSTRAINT email_host_name_id_fkey FOREIGN KEY (host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: file file_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.file
    ADD CONSTRAINT file_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;


--
-- Name: host_host_name_mapping host_host_name_mapping_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_host_name_mapping
    ADD CONSTRAINT host_host_name_mapping_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.host(id) ON DELETE CASCADE;


--
-- Name: host_host_name_mapping host_host_name_mapping_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_host_name_mapping
    ADD CONSTRAINT host_host_name_mapping_host_name_id_fkey FOREIGN KEY (host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: host_name host_name_domain_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name
    ADD CONSTRAINT host_name_domain_name_id_fkey FOREIGN KEY (domain_name_id) REFERENCES public.domain_name(id) ON DELETE CASCADE;


--
-- Name: host_name_host_name_mapping host_name_host_name_mapping_resolved_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name_host_name_mapping
    ADD CONSTRAINT host_name_host_name_mapping_resolved_host_name_id_fkey FOREIGN KEY (resolved_host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: host_name_host_name_mapping host_name_host_name_mapping_source_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name_host_name_mapping
    ADD CONSTRAINT host_name_host_name_mapping_source_host_name_id_fkey FOREIGN KEY (source_host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: host_name_mapping host_name_mapping_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name_mapping
    ADD CONSTRAINT host_name_mapping_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.host(id) ON DELETE CASCADE;


--
-- Name: host_name_mapping host_name_mapping_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host_name_mapping
    ADD CONSTRAINT host_name_mapping_host_name_id_fkey FOREIGN KEY (host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: host host_network_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host
    ADD CONSTRAINT host_network_id_fkey FOREIGN KEY (network_id) REFERENCES public.network(id) ON DELETE SET NULL;


--
-- Name: host host_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.host
    ADD CONSTRAINT host_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;


--
-- Name: http_query http_query_path_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.http_query
    ADD CONSTRAINT http_query_path_id_fkey FOREIGN KEY (path_id) REFERENCES public.path(id) ON DELETE CASCADE;


--
-- Name: network network_workspace_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.network
    ADD CONSTRAINT network_workspace_id_fkey FOREIGN KEY (workspace_id) REFERENCES public.workspace(id) ON DELETE CASCADE;


--
-- Name: path path_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.path
    ADD CONSTRAINT path_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: service service_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.service
    ADD CONSTRAINT service_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.host(id) ON DELETE CASCADE;


--
-- Name: service service_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.service
    ADD CONSTRAINT service_host_name_id_fkey FOREIGN KEY (host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: service_method service_method_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.service_method
    ADD CONSTRAINT service_method_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: source_additional_info_mapping source_additional_info_mapping_additional_info_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_additional_info_mapping
    ADD CONSTRAINT source_additional_info_mapping_additional_info_id_fkey FOREIGN KEY (additional_info_id) REFERENCES public.additional_info(id) ON DELETE CASCADE;


--
-- Name: source_additional_info_mapping source_additional_info_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_additional_info_mapping
    ADD CONSTRAINT source_additional_info_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_cert_info_mapping source_cert_info_mapping_cert_info_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_cert_info_mapping
    ADD CONSTRAINT source_cert_info_mapping_cert_info_id_fkey FOREIGN KEY (cert_info_id) REFERENCES public.cert_info(id) ON DELETE CASCADE;


--
-- Name: source_cert_info_mapping source_cert_info_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_cert_info_mapping
    ADD CONSTRAINT source_cert_info_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_company_domain_name_mapping source_company_domain_name_ma_company_domain_name_mapping__fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_domain_name_mapping
    ADD CONSTRAINT source_company_domain_name_ma_company_domain_name_mapping__fkey FOREIGN KEY (company_domain_name_mapping_id) REFERENCES public.company_domain_name_mapping(id) ON DELETE CASCADE;


--
-- Name: source_company_domain_name_mapping source_company_domain_name_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_domain_name_mapping
    ADD CONSTRAINT source_company_domain_name_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_company_mapping source_company_mapping_company_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_mapping
    ADD CONSTRAINT source_company_mapping_company_id_fkey FOREIGN KEY (company_id) REFERENCES public.company(id) ON DELETE CASCADE;


--
-- Name: source_company_mapping source_company_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_mapping
    ADD CONSTRAINT source_company_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_company_network_mapping source_company_network_mapping_company_network_mapping_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_network_mapping
    ADD CONSTRAINT source_company_network_mapping_company_network_mapping_id_fkey FOREIGN KEY (company_network_mapping_id) REFERENCES public.company_network_mapping(id) ON DELETE CASCADE;


--
-- Name: source_company_network_mapping source_company_network_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_network_mapping
    ADD CONSTRAINT source_company_network_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_credential_mapping source_credential_mapping_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_credential_mapping
    ADD CONSTRAINT source_credential_mapping_credential_id_fkey FOREIGN KEY (credential_id) REFERENCES public.credential(id) ON DELETE CASCADE;


--
-- Name: source_credential_mapping source_credential_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_credential_mapping
    ADD CONSTRAINT source_credential_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_email_mapping source_email_mapping_email_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_email_mapping
    ADD CONSTRAINT source_email_mapping_email_id_fkey FOREIGN KEY (email_id) REFERENCES public.email(id) ON DELETE CASCADE;


--
-- Name: source_email_mapping source_email_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_email_mapping
    ADD CONSTRAINT source_email_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_host_host_name_mapping source_host_host_name_mapping_host_host_name_mapping_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_host_name_mapping
    ADD CONSTRAINT source_host_host_name_mapping_host_host_name_mapping_id_fkey FOREIGN KEY (host_host_name_mapping_id) REFERENCES public.host_host_name_mapping(id) ON DELETE CASCADE;


--
-- Name: source_host_host_name_mapping source_host_host_name_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_host_name_mapping
    ADD CONSTRAINT source_host_host_name_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_host_mapping source_host_mapping_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_mapping
    ADD CONSTRAINT source_host_mapping_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.host(id) ON DELETE CASCADE;


--
-- Name: source_host_mapping source_host_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_mapping
    ADD CONSTRAINT source_host_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_host_name_host_name_mapping source_host_name_host_name_ma_host_name_host_name_mapping__fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_name_host_name_mapping
    ADD CONSTRAINT source_host_name_host_name_ma_host_name_host_name_mapping__fkey FOREIGN KEY (host_name_host_name_mapping_id) REFERENCES public.host_name_host_name_mapping(id) ON DELETE CASCADE;


--
-- Name: source_host_name_host_name_mapping source_host_name_host_name_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_name_host_name_mapping
    ADD CONSTRAINT source_host_name_host_name_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_host_name_mapping source_host_name_mapping_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_name_mapping
    ADD CONSTRAINT source_host_name_mapping_host_name_id_fkey FOREIGN KEY (host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: source_host_name_mapping source_host_name_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_host_name_mapping
    ADD CONSTRAINT source_host_name_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_network_mapping source_network_mapping_network_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_network_mapping
    ADD CONSTRAINT source_network_mapping_network_id_fkey FOREIGN KEY (network_id) REFERENCES public.network(id) ON DELETE CASCADE;


--
-- Name: source_network_mapping source_network_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_network_mapping
    ADD CONSTRAINT source_network_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_path_mapping source_path_mapping_path_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_path_mapping
    ADD CONSTRAINT source_path_mapping_path_id_fkey FOREIGN KEY (path_id) REFERENCES public.path(id) ON DELETE CASCADE;


--
-- Name: source_path_mapping source_path_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_path_mapping
    ADD CONSTRAINT source_path_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_service_mapping source_service_mapping_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_service_mapping
    ADD CONSTRAINT source_service_mapping_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: source_service_mapping source_service_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_service_mapping
    ADD CONSTRAINT source_service_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_service_method_mapping source_service_method_mapping_service_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_service_method_mapping
    ADD CONSTRAINT source_service_method_mapping_service_name_id_fkey FOREIGN KEY (service_name_id) REFERENCES public.service_method(id) ON DELETE CASCADE;


--
-- Name: source_service_method_mapping source_service_method_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_service_method_mapping
    ADD CONSTRAINT source_service_method_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_tls_info_cipher_suite_mapping source_tls_info_cipher_suite__tls_info_cipher_suite_mappin_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_tls_info_cipher_suite_mapping
    ADD CONSTRAINT source_tls_info_cipher_suite__tls_info_cipher_suite_mappin_fkey FOREIGN KEY (tls_info_cipher_suite_mapping_id) REFERENCES public.tls_info_cipher_suite_mapping(id) ON DELETE CASCADE;


--
-- Name: source_tls_info_cipher_suite_mapping source_tls_info_cipher_suite_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_tls_info_cipher_suite_mapping
    ADD CONSTRAINT source_tls_info_cipher_suite_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_vhost_name_mapping source_vhost_name_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_vhost_name_mapping
    ADD CONSTRAINT source_vhost_name_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_vhost_name_mapping source_vhost_name_mapping_vhost_name_mapping_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_vhost_name_mapping
    ADD CONSTRAINT source_vhost_name_mapping_vhost_name_mapping_id_fkey FOREIGN KEY (vhost_name_mapping_id) REFERENCES public.vhost_name_mapping(id) ON DELETE CASCADE;


--
-- Name: tls_info_cipher_suite_mapping tls_info_cipher_suite_mapping_cipher_suite_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.tls_info_cipher_suite_mapping
    ADD CONSTRAINT tls_info_cipher_suite_mapping_cipher_suite_id_fkey FOREIGN KEY (cipher_suite_id) REFERENCES public.cipher_suite(id) ON DELETE CASCADE;


--
-- Name: tls_info_cipher_suite_mapping tls_info_cipher_suite_mapping_tls_info_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.tls_info_cipher_suite_mapping
    ADD CONSTRAINT tls_info_cipher_suite_mapping_tls_info_id_fkey FOREIGN KEY (tls_info_id) REFERENCES public.tls_info(id) ON DELETE CASCADE;


--
-- Name: tls_info tls_info_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.tls_info
    ADD CONSTRAINT tls_info_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- Name: vhost_name_mapping vhost_name_mapping_host_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.vhost_name_mapping
    ADD CONSTRAINT vhost_name_mapping_host_id_fkey FOREIGN KEY (host_id) REFERENCES public.host(id) ON DELETE CASCADE;


--
-- Name: vhost_name_mapping vhost_name_mapping_host_name_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.vhost_name_mapping
    ADD CONSTRAINT vhost_name_mapping_host_name_id_fkey FOREIGN KEY (host_name_id) REFERENCES public.host_name(id) ON DELETE CASCADE;


--
-- Name: vhost_name_mapping vhost_name_mapping_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.vhost_name_mapping
    ADD CONSTRAINT vhost_name_mapping_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.service(id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

