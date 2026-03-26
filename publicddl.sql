-- public.systemsnapshots definition

-- Drop table

-- DROP TABLE public.systemsnapshots;

CREATE TABLE public.systemsnapshots (
	snapshotid serial4 NOT NULL,
	systemuuid varchar(255) NULL,
	snapshottime timestamp NULL,
	CONSTRAINT systemsnapshots_pkey PRIMARY KEY (snapshotid)
);


-- public.unique_autorunsc_signer_path_cmdline definition

-- Drop table

-- DROP TABLE public.unique_autorunsc_signer_path_cmdline;

CREATE TABLE public.unique_autorunsc_signer_path_cmdline (
	id serial4 NOT NULL,
	signer varchar(255) NULL,
	imagepath varchar(255) NULL,
	launchstring varchar(2048) NULL,
	short_launchstring varchar(255) NULL,
	CONSTRAINT unique_autorunsc_signer_path_cmdline_pkey PRIMARY KEY (id)
);


-- public.arpcache definition

-- Drop table

-- DROP TABLE public.arpcache;

CREATE TABLE public.arpcache (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	interfaceindex int4 NULL,
	ipaddress varchar(255) NULL,
	linklayeraddress varchar(255) NULL,
	state varchar(255) NULL,
	CONSTRAINT arpcache_pkey PRIMARY KEY (id),
	CONSTRAINT arpcache_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.autorunsc definition

-- Drop table

-- DROP TABLE public.autorunsc;

CREATE TABLE public.autorunsc (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	entrylocation varchar(255) NULL,
	entry varchar(255) NULL,
	enabled varchar(255) NULL,
	category varchar(255) NULL,
	profile varchar(255) NULL,
	signer varchar(255) NULL,
	company varchar(255) NULL,
	imagepath varchar(255) NULL,
	"version" varchar(255) NULL,
	launchstring varchar(2047) NULL,
	md5 varchar(255) NULL,
	sha1 varchar(255) NULL,
	pesha1 varchar(255) NULL,
	pesha256 varchar(255) NULL,
	sha256 varchar(255) NULL,
	imp varchar(255) NULL,
	unique_autorunsc_id int4 NULL,
	CONSTRAINT autorunsc_pkey PRIMARY KEY (id),
	CONSTRAINT autorunsc_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);
CREATE INDEX idx_snap ON public.autorunsc USING btree (snapshotid);


-- public.computerinfo definition

-- Drop table

-- DROP TABLE public.computerinfo;

CREATE TABLE public.computerinfo (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	csname varchar(255) NULL,
	csdnshostname varchar(255) NULL,
	csdomain varchar(255) NULL,
	csmanufacturer varchar(255) NULL,
	csmodel varchar(255) NULL,
	cspartofdomain bool NULL,
	cspcsystemtype varchar(255) NULL,
	osname varchar(255) NULL,
	ostype varchar(255) NULL,
	osversion varchar(255) NULL,
	ossystemdrive varchar(255) NULL,
	oslastbootuptime timestamp NULL,
	CONSTRAINT computerinfo_pkey PRIMARY KEY (id),
	CONSTRAINT computerinfo_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.diskvolumes definition

-- Drop table

-- DROP TABLE public.diskvolumes;

CREATE TABLE public.diskvolumes (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	uniqueid varchar(255) NULL,
	driveletter varchar(255) NULL,
	drivetype varchar(255) NULL,
	"size" int8 NULL,
	filesystemlabel varchar(255) NULL,
	filesystem varchar(255) NULL,
	CONSTRAINT diskvolumes_pkey PRIMARY KEY (id),
	CONSTRAINT diskvolumes_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.dnssearchsuffixes definition

-- Drop table

-- DROP TABLE public.dnssearchsuffixes;

CREATE TABLE public.dnssearchsuffixes (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	interfaceindex int4 NULL,
	suffixsearch varchar(255) NULL,
	CONSTRAINT dnssearchsuffixes_pkey PRIMARY KEY (id),
	CONSTRAINT dnssearchsuffixes_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.dnsservers definition

-- Drop table

-- DROP TABLE public.dnsservers;

CREATE TABLE public.dnsservers (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	interfaceindex int4 NULL,
	serveraddress varchar(255) NULL,
	CONSTRAINT dnsservers_pkey PRIMARY KEY (id),
	CONSTRAINT dnsservers_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public."groups" definition

-- Drop table

-- DROP TABLE public."groups";

CREATE TABLE public."groups" (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	"name" varchar(255) NULL,
	sid varchar(255) NULL,
	CONSTRAINT groups_pkey PRIMARY KEY (id),
	CONSTRAINT groups_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.ipaddresses definition

-- Drop table

-- DROP TABLE public.ipaddresses;

CREATE TABLE public.ipaddresses (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	interfaceindex int4 NULL,
	ipaddress varchar(255) NULL,
	prefixlength int4 NULL,
	addressfamily varchar(255) NULL,
	"type" varchar(255) NULL,
	skipassource bool NULL,
	validlifetimeticks int8 NULL,
	CONSTRAINT ipaddresses_pkey PRIMARY KEY (id),
	CONSTRAINT ipaddresses_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.members definition

-- Drop table

-- DROP TABLE public.members;

CREATE TABLE public.members (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	usersid varchar(255) NULL,
	groupsid varchar(255) NULL,
	CONSTRAINT members_pkey PRIMARY KEY (id),
	CONSTRAINT members_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.netadapters definition

-- Drop table

-- DROP TABLE public.netadapters;

CREATE TABLE public.netadapters (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	macaddress varchar(255) NULL,
	status varchar(255) NULL,
	physicalmediatype varchar(255) NULL,
	interfaceindex int4 NULL,
	"name" varchar(255) NULL,
	interfacedescription varchar(255) NULL,
	connectionspecificsuffix varchar(255) NULL,
	registerthisconnectionsaddress bool NULL,
	CONSTRAINT netadapters_pkey PRIMARY KEY (id),
	CONSTRAINT netadapters_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.processes definition

-- Drop table

-- DROP TABLE public.processes;

CREATE TABLE public.processes (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	processname varchar(255) NULL,
	username varchar(255) NULL,
	creationdate timestamp NULL,
	parentprocessid int4 NULL,
	processid int4 NULL,
	commandline varchar(2048) NULL,
	executablepath varchar(255) NULL,
	CONSTRAINT processes_pkey PRIMARY KEY (id),
	CONSTRAINT processes_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);
CREATE INDEX idx_snapshotid_process ON public.processes USING btree (snapshotid, processname);


-- public.routes definition

-- Drop table

-- DROP TABLE public.routes;

CREATE TABLE public.routes (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	interfaceindex int4 NULL,
	destinationprefix varchar(255) NULL,
	nexthop varchar(255) NULL,
	routemetric int4 NULL,
	CONSTRAINT routes_pkey PRIMARY KEY (id),
	CONSTRAINT routes_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.shares definition

-- Drop table

-- DROP TABLE public.shares;

CREATE TABLE public.shares (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	"name" varchar(255) NULL,
	"path" varchar(255) NULL,
	scopename varchar(255) NULL,
	CONSTRAINT shares_pkey PRIMARY KEY (id),
	CONSTRAINT shares_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.tcpconnections definition

-- Drop table

-- DROP TABLE public.tcpconnections;

CREATE TABLE public.tcpconnections (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	localaddress varchar(255) NULL,
	localport int4 NULL,
	remoteaddress varchar(255) NULL,
	remoteport int4 NULL,
	owningprocess int4 NULL,
	creationtime timestamp NULL,
	state varchar(255) NULL,
	CONSTRAINT tcpconnections_pkey PRIMARY KEY (id),
	CONSTRAINT tcpconnections_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.udpconnections definition

-- Drop table

-- DROP TABLE public.udpconnections;

CREATE TABLE public.udpconnections (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	localaddress varchar(255) NULL,
	localport int4 NULL,
	remoteaddress varchar(255) NULL,
	remoteport int4 NULL,
	owningprocess int4 NULL,
	creationtime timestamp NULL,
	CONSTRAINT udpconnections_pkey PRIMARY KEY (id),
	CONSTRAINT udpconnections_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.userexecutables definition

-- Drop table

-- DROP TABLE public.userexecutables;

CREATE TABLE public.userexecutables (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	fullname varchar(2048) NULL,
	length int4 NULL,
	CONSTRAINT userexecutables_pkey PRIMARY KEY (id),
	CONSTRAINT userexecutables_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);


-- public.users definition

-- Drop table

-- DROP TABLE public.users;

CREATE TABLE public.users (
	id serial4 NOT NULL,
	snapshotid int4 NULL,
	"name" varchar(255) NULL,
	enabled bool NULL,
	lastlogon timestamp NULL,
	passwordlastset timestamp NULL,
	principalsource varchar(255) NULL,
	sid varchar(255) NULL,
	CONSTRAINT users_pkey PRIMARY KEY (id),
	CONSTRAINT users_snapshotid_fkey FOREIGN KEY (snapshotid) REFERENCES public.systemsnapshots(snapshotid)
);