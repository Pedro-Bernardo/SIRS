--
-- PostgreSQL database dump
--

-- Dumped from database version 12.0
-- Dumped by pg_dump version 12.0

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
-- Name: remove_points(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.remove_points() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
	UPDATE accounts AC
	SET points = AC.points - 1
	WHERE OLD.user_id = AC.id;
	RETURN NEW;
END
$$;


ALTER FUNCTION public.remove_points() OWNER TO sirs;

--
-- Name: remove_user(); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.remove_user() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN	
	DELETE FROM sessions USING accounts  WHERE user_id = (SELECT user_id FROM accounts WHERE username = OLD.username);	
	DELETE FROM submissions WHERE user_id = (SELECT user_id FROM accounts WHERE username = OLD.username);
	
	DROP TRIGGER IF EXISTS remove_user ON accounts;
	DELETE FROM accounts WHERE username = OLD.username;
	
	CREATE TRIGGER remove_user BEFORE DELETE ON accounts
    FOR EACH ROW EXECUTE PROCEDURE remove_user();
	
	RETURN NEW;
END
$$;


ALTER FUNCTION public.remove_user() OWNER TO sirs;

--
-- Name: update_points(); Type: FUNCTION; Schema: public; Owner: sirs
--

CREATE FUNCTION public.update_points() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
	UPDATE accounts AC
	SET points = AC.points +1
	WHERE NEW.user_id = AC.id;
	RETURN NEW;
END
$$;


ALTER FUNCTION public.update_points() OWNER TO sirs;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: accounts; Type: TABLE; Schema: public; Owner: sirs
--

CREATE TABLE public.accounts (
    id integer NOT NULL,
    username text NOT NULL,
    public_key text NOT NULL,
    pass text NOT NULL,
    points integer NOT NULL
);


ALTER TABLE public.accounts OWNER TO sirs;

--
-- Name: accounts_id_seq; Type: SEQUENCE; Schema: public; Owner: sirs
--

CREATE SEQUENCE public.accounts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.accounts_id_seq OWNER TO sirs;

--
-- Name: accounts_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sirs
--

ALTER SEQUENCE public.accounts_id_seq OWNED BY public.accounts.id;


--
-- Name: binaries; Type: TABLE; Schema: public; Owner: sirs
--

CREATE TABLE public.binaries (
    id integer NOT NULL,
    bin_fp text NOT NULL
);


ALTER TABLE public.binaries OWNER TO sirs;

--
-- Name: binaries_id_seq; Type: SEQUENCE; Schema: public; Owner: sirs
--

CREATE SEQUENCE public.binaries_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.binaries_id_seq OWNER TO sirs;

--
-- Name: binaries_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sirs
--

ALTER SEQUENCE public.binaries_id_seq OWNED BY public.binaries.id;


--
-- Name: sessions; Type: TABLE; Schema: public; Owner: sirs
--

CREATE TABLE public.sessions (
    user_id integer NOT NULL,
    secret text
);


ALTER TABLE public.sessions OWNER TO sirs;

--
-- Name: submissions; Type: TABLE; Schema: public; Owner: sirs
--

CREATE TABLE public.submissions (
    id integer NOT NULL,
    user_id integer NOT NULL,
    vuln text NOT NULL,
    bin_id integer NOT NULL
);


ALTER TABLE public.submissions OWNER TO sirs;

--
-- Name: submissions_id_seq; Type: SEQUENCE; Schema: public; Owner: sirs
--

CREATE SEQUENCE public.submissions_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.submissions_id_seq OWNER TO sirs;

--
-- Name: submissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: sirs
--

ALTER SEQUENCE public.submissions_id_seq OWNED BY public.submissions.id;


--
-- Name: accounts id; Type: DEFAULT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.accounts ALTER COLUMN id SET DEFAULT nextval('public.accounts_id_seq'::regclass);


--
-- Name: binaries id; Type: DEFAULT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.binaries ALTER COLUMN id SET DEFAULT nextval('public.binaries_id_seq'::regclass);


--
-- Name: submissions id; Type: DEFAULT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.submissions ALTER COLUMN id SET DEFAULT nextval('public.submissions_id_seq'::regclass);


--
-- Name: accounts accounts_pkey; Type: CONSTRAINT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);


--
-- Name: accounts accounts_username_key; Type: CONSTRAINT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_username_key UNIQUE (username);


--
-- Name: binaries binaries_bin_fp_unique; Type: CONSTRAINT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.binaries
    ADD CONSTRAINT binaries_bin_fp_unique UNIQUE (bin_fp);


--
-- Name: binaries binaries_pkey; Type: CONSTRAINT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.binaries
    ADD CONSTRAINT binaries_pkey PRIMARY KEY (id);


--
-- Name: sessions sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (user_id);


--
-- Name: submissions submissions_pkey; Type: CONSTRAINT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.submissions
    ADD CONSTRAINT submissions_pkey PRIMARY KEY (id);


--
-- Name: submissions submissions_vuln_bin_id_unique; Type: CONSTRAINT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.submissions
    ADD CONSTRAINT submissions_vuln_bin_id_unique UNIQUE (vuln, bin_id);


--
-- Name: submissions remove_points; Type: TRIGGER; Schema: public; Owner: sirs
--

CREATE TRIGGER remove_points AFTER DELETE ON public.submissions FOR EACH ROW EXECUTE FUNCTION public.remove_points();


--
-- Name: accounts remove_user; Type: TRIGGER; Schema: public; Owner: sirs
--

CREATE TRIGGER remove_user BEFORE DELETE ON public.accounts FOR EACH ROW EXECUTE FUNCTION public.remove_user();


--
-- Name: submissions update_points; Type: TRIGGER; Schema: public; Owner: sirs
--

CREATE TRIGGER update_points AFTER INSERT ON public.submissions FOR EACH ROW EXECUTE FUNCTION public.update_points();


--
-- Name: sessions session_user_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT session_user_id_fk FOREIGN KEY (user_id) REFERENCES public.accounts(id);


--
-- Name: submissions submission_userid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.submissions
    ADD CONSTRAINT submission_userid_fkey FOREIGN KEY (user_id) REFERENCES public.accounts(id);


--
-- Name: submissions submissions_bin_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: sirs
--

ALTER TABLE ONLY public.submissions
    ADD CONSTRAINT submissions_bin_id_fkey FOREIGN KEY (bin_id) REFERENCES public.binaries(id);


--
-- PostgreSQL database dump complete
--

