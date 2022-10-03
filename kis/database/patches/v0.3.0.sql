--
-- Name: version; Type: TABLE; Schema: public; Owner: kis
--

DROP TABLE IF EXISTS public.version CASCADE;
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
-- Name: version id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.version ALTER COLUMN id SET DEFAULT nextval('public.version_id_seq'::regclass);

INSERT INTO public.version(major_number, minor_number, revision_number, creation_date) VALUES (0, 3, 0, NOW());

--
-- Name: version_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.version_id_seq', 1, true);


--
-- Name: version _version_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.version
    ADD CONSTRAINT _version_unique UNIQUE (major_number, minor_number, revision_number);

--
-- Name: version version_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.version
    ADD CONSTRAINT version_pkey PRIMARY KEY (id);



--
-- Name: update_service_check(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE OR REPLACE FUNCTION public.update_service_check() RETURNS trigger
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

--
-- Name: service check_service_update; Type: TRIGGER; Schema: public; Owner: kis
--
DROP TRIGGER IF EXISTS check_service_update ON public.service;
CREATE TRIGGER check_service_update BEFORE UPDATE ON public.service FOR EACH ROW EXECUTE FUNCTION public.update_service_check();



--
-- Name: assign_services_to_host_name(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE OR REPLACE FUNCTION public.assign_services_to_host_name() RETURNS trigger
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
-- Name: host_host_name_mapping host_host_name_mapping_insert; Type: TRIGGER; Schema: public; Owner: kis
--
DROP TRIGGER IF EXISTS host_host_name_mapping_insert ON public.host_host_name_mapping;
CREATE TRIGGER host_host_name_mapping_insert AFTER INSERT OR UPDATE ON public.host_host_name_mapping FOR EACH ROW EXECUTE FUNCTION public.assign_services_to_host_name();



--
-- Name: add_services_to_host_name(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE OR REPLACE FUNCTION public.add_services_to_host_name() RETURNS trigger
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
-- Name: pre_update_hosts_after_host_changes(); Type: FUNCTION; Schema: public; Owner: kis
--

CREATE OR REPLACE FUNCTION public.pre_update_hosts_after_host_changes() RETURNS trigger
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
-- Name: service service_insert; Type: TRIGGER; Schema: public; Owner: kis
--
DROP TRIGGER IF EXISTS service_insert ON public.service;
CREATE TRIGGER service_insert AFTER INSERT OR DELETE OR UPDATE ON public.service FOR EACH ROW EXECUTE FUNCTION public.add_services_to_host_name();





--
-- CREATE/UPDATE TABLES
--
DROP TABLE IF EXISTS vhost_mapping CASCADE;

--
-- Name: source_vhost_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE IF NOT EXISTS public.source_vhost_name_mapping (
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

CREATE SEQUENCE IF NOT EXISTS public.source_vhost_name_mapping_id_seq
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
-- Name: source_vhost_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_vhost_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_vhost_name_mapping_id_seq'::regclass);

--
-- Name: vhost_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.vhost_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.vhost_name_mapping_id_seq'::regclass);

--
-- Name: source_vhost_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_vhost_name_mapping_id_seq', 1, false);

--
-- Name: vhost_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.vhost_name_mapping_id_seq', 1, false);

--
-- Name: source_vhost_name_mapping _source_vhost_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_vhost_name_mapping
    ADD CONSTRAINT _source_vhost_name_mapping_unique UNIQUE (vhost_name_mapping_id, source_id);

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
-- Name: source_vhost_name_mapping source_vhost_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_vhost_name_mapping
    ADD CONSTRAINT source_vhost_name_mapping_pkey PRIMARY KEY (id);

--
-- Name: vhost_name_mapping vhost_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.vhost_name_mapping
    ADD CONSTRAINT vhost_name_mapping_pkey PRIMARY KEY (id);

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



