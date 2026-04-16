#!/usr/bin/env python3
"""Analyze MFT file inventory in PostgreSQL to find directories to exclude."""
import psycopg2

conn = psycopg2.connect('host=localhost user=postgres password=postgres dbname=postgres')
cur = conn.cursor()
SID = 1

def run(title, sql):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")
    cur.execute(sql)
    rows = cur.fetchall()
    cols = [d[0] for d in cur.description]
    # Print header
    header = "  "
    for i, col in enumerate(cols):
        if i == 0:
            header += f"{col:55s}"
        else:
            header += f"{col:>12s}"
    print(header)
    print("  " + "-" * len(header))
    for row in rows:
        line = "  "
        for i, val in enumerate(row):
            if i == 0:
                line += f"{str(val):55s}"
            elif isinstance(val, float):
                line += f"{val:>11.1f}%"
            else:
                line += f"{val:>12,}"
        print(line)
    return rows

# 1. Top-level directory breakdown
run("TOP-LEVEL DIRECTORY BREAKDOWN", f"""
SELECT split_part(fullpath, chr(92), 2) as directory, 
       count(*) as files,
       round(count(*)*100.0/(SELECT count(*) FROM fileinventory WHERE snapshotid={SID}),1) as pct
FROM fileinventory WHERE snapshotid={SID}
GROUP BY 1 ORDER BY files DESC LIMIT 25
""")

# 2. Second-level breakdown for top dirs
for top_dir in ['Windows', 'Users', 'Program Files', 'Program Files (x86)', 'ProgramData']:
    run(f"SECOND-LEVEL: C:\\{top_dir}", f"""
    SELECT split_part(fullpath, chr(92), 3) as subdirectory,
           count(*) as files,
           round(count(*)*100.0/(SELECT count(*) FROM fileinventory WHERE snapshotid={SID}),1) as pct
    FROM fileinventory 
    WHERE snapshotid={SID} AND split_part(fullpath, chr(92), 2) = '{top_dir}'
    GROUP BY 1 ORDER BY files DESC LIMIT 15
    """)

# 3. WinSxS and assembly breakdown
run("WINDOWS SUB-DIRECTORIES (biggest)", f"""
SELECT split_part(fullpath, chr(92), 3) as win_subdir,
       count(*) as files,
       round(count(*)*100.0/(SELECT count(*) FROM fileinventory WHERE snapshotid={SID}),1) as pct
FROM fileinventory 
WHERE snapshotid={SID} AND split_part(fullpath, chr(92), 2) = 'Windows'
GROUP BY 1 ORDER BY files DESC LIMIT 20
""")

# 4. File extension distribution
run("FILE EXTENSION DISTRIBUTION", f"""
SELECT CASE 
         WHEN position('.' in reverse(filename)) > 0 
         THEN lower(right(filename, position('.' in reverse(filename))))
         ELSE '(no ext)' 
       END as extension,
       count(*) as files,
       round(count(*)*100.0/(SELECT count(*) FROM fileinventory WHERE snapshotid={SID}),1) as pct
FROM fileinventory WHERE snapshotid={SID}
GROUP BY 1 ORDER BY files DESC LIMIT 25
""")

# 5. Candidate exclusion directories — known static/uninteresting
run("CANDIDATE EXCLUSION PATTERNS (cumulative reduction)", f"""
WITH exclusions AS (
    SELECT fullpath,
        CASE 
            WHEN fullpath LIKE 'C:\\Windows\\WinSxS\\%' THEN 'WinSxS'
            WHEN fullpath LIKE 'C:\\Windows\\assembly\\%' THEN 'assembly (GAC)'
            WHEN fullpath LIKE 'C:\\Windows\\servicing\\%' THEN 'servicing'
            WHEN fullpath LIKE 'C:\\Windows\\Installer\\%' THEN 'Installer (MSI cache)'
            WHEN fullpath LIKE 'C:\\Windows\\SoftwareDistribution\\%' THEN 'SoftwareDistribution'
            WHEN fullpath LIKE 'C:\\Windows\\System32\\DriverStore\\%' THEN 'DriverStore'
            WHEN fullpath LIKE 'C:\\Windows\\System32\\catroot%' THEN 'catroot (cert catalogs)'
            WHEN fullpath LIKE 'C:\\Windows\\Logs\\%' THEN 'Windows Logs'
            WHEN fullpath LIKE 'C:\\Windows\\Temp\\%' THEN 'Windows Temp'
            WHEN fullpath LIKE 'C:\\Windows\\Prefetch\\%' THEN 'Prefetch'
            WHEN fullpath LIKE 'C:\\Windows\\Fonts\\%' THEN 'Fonts'
            WHEN fullpath LIKE 'C:\\Windows\\Globalization\\%' THEN 'Globalization'
            WHEN fullpath LIKE 'C:\\Windows\\IME\\%' THEN 'IME'
            WHEN fullpath LIKE 'C:\\Windows\\Speech%' THEN 'Speech'
            WHEN fullpath LIKE 'C:\\Windows\\rescache\\%' THEN 'rescache'
            WHEN fullpath LIKE 'C:\\Windows\\DiagTrack\\%' THEN 'DiagTrack'
            WHEN fullpath LIKE 'C:\\Windows\\Microsoft.NET\\%' THEN '.NET Framework'
            WHEN fullpath LIKE 'C:\\ProgramData\\Package Cache\\%' THEN 'Package Cache'
            WHEN fullpath LIKE 'C:\\ProgramData\\Microsoft\\Windows Defender\\%' THEN 'Defender data'
            WHEN fullpath LIKE '%\\node_modules\\%' THEN 'node_modules'
            WHEN fullpath LIKE '%\\.git\\%' THEN '.git'
            WHEN fullpath LIKE '%\\__pycache__\\%' THEN '__pycache__'
            WHEN fullpath LIKE '%\\.nuget\\%' THEN '.nuget'
            WHEN fullpath LIKE '%\\.cache\\%' THEN '.cache'
            WHEN filename LIKE '%.manifest' THEN '*.manifest files'
            WHEN filename LIKE '%.cat' THEN '*.cat (catalog files)'
            WHEN filename LIKE '%.mum' THEN '*.mum (update manifests)'
            WHEN filename LIKE '%.mui' THEN '*.mui (language resources)'
            ELSE NULL
        END as exclusion_category
    FROM fileinventory WHERE snapshotid={SID}
)
SELECT coalesce(exclusion_category, '** KEPT (interesting) **') as category,
       count(*) as files,
       round(count(*)*100.0/(SELECT count(*) FROM fileinventory WHERE snapshotid={SID}),1) as pct
FROM exclusions
GROUP BY 1
ORDER BY files DESC
""")

# 6. What remains after all exclusions
cur.execute(f"""
SELECT count(*) as total FROM fileinventory WHERE snapshotid={SID}
""")
total = cur.fetchone()[0]

cur.execute(f"""
SELECT count(*) FROM fileinventory WHERE snapshotid={SID}
AND fullpath NOT LIKE 'C:\\Windows\\WinSxS\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\assembly\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\servicing\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\Installer\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\SoftwareDistribution\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\System32\\DriverStore\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\System32\\catroot%%'
AND fullpath NOT LIKE 'C:\\Windows\\Logs\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\Temp\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\Prefetch\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\Fonts\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\Globalization\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\IME\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\Speech%%'
AND fullpath NOT LIKE 'C:\\Windows\\rescache\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\DiagTrack\\%%'
AND fullpath NOT LIKE 'C:\\Windows\\Microsoft.NET\\%%'
AND fullpath NOT LIKE 'C:\\ProgramData\\Package Cache\\%%'
AND fullpath NOT LIKE 'C:\\ProgramData\\Microsoft\\Windows Defender\\%%'
AND fullpath NOT LIKE '%%\\node_modules\\%%'
AND fullpath NOT LIKE '%%\\.git\\%%'
AND fullpath NOT LIKE '%%\\__pycache__\\%%'
AND fullpath NOT LIKE '%%\\.nuget\\%%'
AND fullpath NOT LIKE '%%\\.cache\\%%'
AND filename NOT LIKE '%%.manifest'
AND filename NOT LIKE '%%.cat'
AND filename NOT LIKE '%%.mum'
AND filename NOT LIKE '%%.mui'
""")
remaining = cur.fetchone()[0]
removed = total - remaining
print(f"\n{'='*70}")
print(f"  SUMMARY")
print(f"{'='*70}")
print(f"  Total files:                {total:>12,}")
print(f"  Excluded (static/noise):    {removed:>12,} ({removed*100.0/total:.1f}%)")
print(f"  Remaining (interesting):    {remaining:>12,} ({remaining*100.0/total:.1f}%)")
print(f"  Reduction ratio:            {total/remaining:.1f}x smaller")
print(f"{'='*70}")

conn.close()
