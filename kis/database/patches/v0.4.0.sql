ALTER type public.scopetype ADD VALUE IF NOT EXISTS 'ignore';
ALTER type public.commandstatus ADD VALUE IF NOT EXISTS 'skipped';

ALTER TABLE company_domain_name_mapping ADD COLUMN IF NOT EXISTS verified BOOLEAN;
ALTER TABLE company_network_mapping ADD COLUMN IF NOT EXISTS verified BOOLEAN;
ALTER TABLE company_domain_name_mapping ALTER COLUMN verified SET DEFAULT FALSE;
ALTER TABLE company_network_mapping ALTER COLUMN verified SET DEFAULT FALSE;
UPDATE company_network_mapping SET verified=FALSE;
UPDATE company_domain_name_mapping SET verified=FALSE;
ALTER TABLE company_domain_name_mapping ALTER COLUMN verified SET NOT NULL;
ALTER TABLE company_network_mapping ALTER COLUMN verified SET NOT NULL;


CREATE OR REPLACE FUNCTION post_update_host_names_after_domain_name_scope_changes()
        RETURNS TRIGGER AS $$
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
        $$ LANGUAGE PLPGSQL;


CREATE OR REPLACE FUNCTION pre_update_host_name_scope()
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
            ELSIF (COALESCE(domain_scope, 'exclude') = 'exclude' OR COALESCE(domain_scope, 'exclude') = 'ignore') THEN
                NEW.in_scope := False;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE PLPGSQL;


CREATE OR REPLACE FUNCTION pre_update_network_scopes_after_network_changes()
        RETURNS TRIGGER AS $$
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
        $$ LANGUAGE PLPGSQL;

UPDATE public.version SET major_number = 0, minor_number = 4, revision_number = 0;


--
-- Name: source_company_domain_name_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE IF NOT EXISTS public.source_company_domain_name_mapping (
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

CREATE SEQUENCE IF NOT EXISTS public.source_company_domain_name_mapping_id_seq
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
-- Name: source_company_domain_name_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_domain_name_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_company_domain_name_mapping_id_seq'::regclass);

--
-- Name: source_company_domain_name_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_company_domain_name_mapping_id_seq', 1, false);

--
-- Name: source_company_domain_name_mapping _source_company_domain_name_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_domain_name_mapping
    DROP CONSTRAINT IF EXISTS _source_company_domain_name_mapping_unique;

ALTER TABLE ONLY public.source_company_domain_name_mapping
    ADD CONSTRAINT _source_company_domain_name_mapping_unique UNIQUE (company_domain_name_mapping_id, source_id);

--
-- Name: source_company_domain_name_mapping source_company_domain_name_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_domain_name_mapping
    DROP CONSTRAINT IF EXISTS source_company_domain_name_mapping_pkey;

ALTER TABLE ONLY public.source_company_domain_name_mapping
    ADD CONSTRAINT source_company_domain_name_mapping_pkey PRIMARY KEY (id);

--
-- Name: source_company_domain_name_mapping source_company_domain_name_ma_company_domain_name_mapping__fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_domain_name_mapping
    DROP CONSTRAINT IF EXISTS source_company_domain_name_ma_company_domain_name_mapping__fkey;

ALTER TABLE ONLY public.source_company_domain_name_mapping
    ADD CONSTRAINT source_company_domain_name_ma_company_domain_name_mapping__fkey FOREIGN KEY (company_domain_name_mapping_id) REFERENCES public.company_domain_name_mapping(id) ON DELETE CASCADE;


--
-- Name: source_company_domain_name_mapping source_company_domain_name_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_domain_name_mapping
    DROP CONSTRAINT IF EXISTS source_company_domain_name_mapping_source_id_fkey;

ALTER TABLE ONLY public.source_company_domain_name_mapping
    ADD CONSTRAINT source_company_domain_name_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;


--
-- Name: source_company_network_mapping; Type: TABLE; Schema: public; Owner: kis
--

CREATE TABLE IF NOT EXISTS public.source_company_network_mapping (
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

CREATE SEQUENCE IF NOT EXISTS public.source_company_network_mapping_id_seq
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
-- Name: source_company_network_mapping id; Type: DEFAULT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_network_mapping ALTER COLUMN id SET DEFAULT nextval('public.source_company_network_mapping_id_seq'::regclass);


--
-- Name: source_company_network_mapping_id_seq; Type: SEQUENCE SET; Schema: public; Owner: kis
--

SELECT pg_catalog.setval('public.source_company_network_mapping_id_seq', 1, false);

--
-- Name: source_company_network_mapping _source_company_network_mapping_unique; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_network_mapping
    DROP CONSTRAINT IF EXISTS _source_company_network_mapping_unique;

ALTER TABLE ONLY public.source_company_network_mapping
    ADD CONSTRAINT _source_company_network_mapping_unique UNIQUE (company_network_mapping_id, source_id);

--
-- Name: source_company_network_mapping source_company_network_mapping_pkey; Type: CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_network_mapping
    DROP CONSTRAINT IF EXISTS source_company_network_mapping_pkey;

ALTER TABLE ONLY public.source_company_network_mapping
    ADD CONSTRAINT source_company_network_mapping_pkey PRIMARY KEY (id);

--
-- Name: source_company_network_mapping source_company_network_mapping_company_network_mapping_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_network_mapping
    DROP CONSTRAINT IF EXISTS source_company_network_mapping_company_network_mapping_id_fkey;

ALTER TABLE ONLY public.source_company_network_mapping
    ADD CONSTRAINT source_company_network_mapping_company_network_mapping_id_fkey FOREIGN KEY (company_network_mapping_id) REFERENCES public.company_network_mapping(id) ON DELETE CASCADE;


--
-- Name: source_company_network_mapping source_company_network_mapping_source_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: kis
--

ALTER TABLE ONLY public.source_company_network_mapping
    DROP CONSTRAINT IF EXISTS source_company_network_mapping_source_id_fkey;

ALTER TABLE ONLY public.source_company_network_mapping
    ADD CONSTRAINT source_company_network_mapping_source_id_fkey FOREIGN KEY (source_id) REFERENCES public.source(id) ON DELETE CASCADE;