-- Schema Migration / Maintenance Scripts
-- Originally embedded in collect-snapshots.ps1 (formerly autoruns-psql-1.ps1).
-- These were used during a one-time schema migration and for periodic maintenance.
-- Run manually in psql as needed.

-- ============================================================
-- 1. Create deduplicated autoruns lookup table
-- ============================================================

CREATE TABLE unique_autorunsc_signer_path_cmdline (
    id SERIAL PRIMARY KEY,
    signer VARCHAR(255),
    imagepath VARCHAR(255),
    launchstring VARCHAR(2048),
    short_launchstring VARCHAR(255)
);

INSERT INTO unique_autorunsc_signer_path_cmdline (signer, imagepath, launchstring, short_launchstring)
SELECT
    signer,
    imagepath,
    launchstring,
    SUBSTRING(launchstring FROM 1 FOR 255)::character varying(255) AS short_launchstring
FROM autorunsc
GROUP BY 
    autorunsc.signer, 
    autorunsc.imagepath, 
    autorunsc.launchstring;

-- ============================================================
-- 2. Add unique_autorunsc_id FK column to autorunsc
-- ============================================================

ALTER TABLE autorunsc ADD COLUMN unique_autorunsc_id INT;

UPDATE autorunsc 
SET unique_autorunsc_id = unique_autorunsc_signer_path_cmdline.id
FROM unique_autorunsc_signer_path_cmdline
WHERE 
    unique_autorunsc_signer_path_cmdline.signer = autorunsc.signer
    AND unique_autorunsc_signer_path_cmdline.imagepath = autorunsc.imagepath
    AND unique_autorunsc_signer_path_cmdline.launchstring = autorunsc.launchstring;

-- ============================================================
-- 3. Verify: count autoruns per unique entry
-- ============================================================

SELECT public_autorunsc.unique_autorunsc_id, Count(public_autorunsc.id) AS CountOfid
FROM public_autorunsc
GROUP BY public_autorunsc.unique_autorunsc_id;

-- ============================================================
-- 4. Purge old snapshots and rebuild unique autoruns table
--    Run inside a transaction for safety.
-- ============================================================

BEGIN;

DO $$ 
BEGIN
    CREATE TEMP TABLE old_snapshots AS
    SELECT snapshotid FROM public.systemsnapshots WHERE snapshottime < CURRENT_DATE + INTERVAL '12 hours';

    DELETE FROM public.arpcache WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.autorunsc WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.computerinfo WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.diskvolumes WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.dnssearchsuffixes WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.dnsservers WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.groups WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.ipaddresses WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.members WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.netadapters WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.processes WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.routes WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.shares WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.tcpconnections WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.udpconnections WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.userexecutables WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM public.users WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);

    DELETE FROM public.systemsnapshots WHERE snapshotid IN (SELECT snapshotid FROM old_snapshots);
    DELETE FROM unique_autorunsc_signer_path_cmdline;
        
    INSERT INTO unique_autorunsc_signer_path_cmdline (signer, imagepath, launchstring, short_launchstring)
    SELECT
        signer,
        imagepath,
        launchstring,
        SUBSTRING(launchstring FROM 1 FOR 255)::character varying(255) AS short_launchstring
    FROM autorunsc
    GROUP BY 
        autorunsc.signer, 
        autorunsc.imagepath, 
        autorunsc.launchstring;

    UPDATE autorunsc 
    SET unique_autorunsc_id = unique_autorunsc_signer_path_cmdline.id
    FROM unique_autorunsc_signer_path_cmdline
    WHERE 
        unique_autorunsc_signer_path_cmdline.signer = autorunsc.signer
        AND unique_autorunsc_signer_path_cmdline.imagepath = autorunsc.imagepath
        AND unique_autorunsc_signer_path_cmdline.launchstring = autorunsc.launchstring;

EXCEPTION WHEN OTHERS THEN
    -- In case of error, rollback the transaction
    ROLLBACK;
    RAISE;
END $$;

COMMIT;
