CREATE VIEW system_snapshots_view AS
SELECT 
    systemsnapshots.systemuuid, 
    MAX(systemsnapshots.snapshottime) AS maxsnapshottime, 
    MAX(systemsnapshots.snapshotid) AS maxsnapshotid
FROM 
    systemsnapshots
GROUP BY 
    systemsnapshots.systemuuid;