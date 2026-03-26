
SELECT 
    unique_autorun_counts.CountOfid, 
    autorunsc.entry, 
    autorunsc.signer, 
    autorunsc.imagepath, 
    autorunsc.launchstring, 
    autorunsc.md5, 
    computerinfo.csname
FROM 
    (
        SELECT 
            autorunsc.unique_autorunsc_id, 
            COUNT(autorunsc.id) AS CountOfid
        FROM 
            autorunsc
        GROUP BY 
            autorunsc.unique_autorunsc_id
    ) AS unique_autorun_counts
INNER JOIN 
    autorunsc 
ON 
    unique_autorun_counts.unique_autorunsc_id = autorunsc.unique_autorunsc_id
INNER JOIN 
    computerinfo 
ON 
    autorunsc.snapshotid = computerinfo.snapshotid
ORDER BY 
    unique_autorun_counts.CountOfid;