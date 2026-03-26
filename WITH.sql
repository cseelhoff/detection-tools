-- Diff autoruns between the latest and oldest snapshots per system.
-- Surfaces new entries (in latest but not oldest) and removed entries (in oldest but not latest).

WITH 
latest_snapshots AS (
    SELECT systemuuid, MAX(snapshotid) AS snapshotid
    FROM systemsnapshots
    GROUP BY systemuuid
),
oldest_snapshots AS (
    SELECT s.systemuuid, MIN(s.snapshotid) AS snapshotid
    FROM systemsnapshots s
    WHERE s.snapshotid NOT IN (SELECT snapshotid FROM latest_snapshots)
    GROUP BY s.systemuuid
),
latest_entries AS (
    SELECT a.*, ss.systemuuid
    FROM autorunsc a
    INNER JOIN latest_snapshots ss ON a.snapshotid = ss.snapshotid
),
oldest_entries AS (
    SELECT a.*, ss.systemuuid
    FROM autorunsc a
    INNER JOIN oldest_snapshots ss ON a.snapshotid = ss.snapshotid
)
-- New entries: in latest but not in oldest
SELECT latest_entries.*
FROM latest_entries
LEFT JOIN oldest_entries
    ON latest_entries.launchstring = oldest_entries.launchstring
    AND latest_entries.md5 = oldest_entries.md5
    AND latest_entries.systemuuid = oldest_entries.systemuuid
WHERE oldest_entries.systemuuid IS NULL
UNION
-- Removed entries: in oldest but not in latest
SELECT oldest_entries.*
FROM oldest_entries
LEFT JOIN latest_entries
    ON latest_entries.launchstring = oldest_entries.launchstring
    AND latest_entries.md5 = oldest_entries.md5
    AND latest_entries.systemuuid = oldest_entries.systemuuid
WHERE latest_entries.systemuuid IS NULL;
