#!/usr/bin/env python3
"""Analyze schema compatibility between Windows and Linux snapshot data."""
import json

w = json.load(open('system-info_CPT-HOFF.json', encoding='utf-8-sig'))
l = json.load(open('system-info_10.10.11.32.json'))
tables = json.load(open('table_definitions.json'))

print('TABLE COMPATIBILITY ANALYSIS')
print('=' * 80)
for tbl in tables:
    name = tbl['name']
    cols = tbl['columns']
    wdata = w.get(name, [])
    ldata = l.get(name, [])
    if not isinstance(wdata, list): wdata = [wdata] if wdata else []
    if not isinstance(ldata, list): ldata = [ldata] if ldata else []

    wkeys = set()
    lkeys = set()
    if wdata and isinstance(wdata[0], dict): wkeys = set(wdata[0].keys())
    if ldata and isinstance(ldata[0], dict): lkeys = set(ldata[0].keys())

    col_names = set(c['name'] for c in cols)

    if not ldata:
        continue

    has_issues = False
    issues = []

    # Check type mismatches
    if ldata and isinstance(ldata[0], dict):
        for col in cols:
            cname = col['name']
            ctype = col['type']
            if cname in ldata[0]:
                val = ldata[0][cname]
                if 'INTEGER' in ctype.upper() and not isinstance(val, (int, float, type(None))):
                    issues.append(f'  ** {cname}: schema={ctype} but linux val={type(val).__name__}({repr(val)[:60]})')
                elif 'BIGINT' in ctype.upper() and not isinstance(val, (int, float, type(None))):
                    issues.append(f'  ** {cname}: schema={ctype} but linux val={type(val).__name__}({repr(val)[:60]})')
                elif 'BOOLEAN' in ctype.upper() and not isinstance(val, (bool, type(None))):
                    issues.append(f'  ** {cname}: schema={ctype} but linux val={type(val).__name__}({repr(val)[:60]})')
                elif 'TIMESTAMP' in ctype.upper() and isinstance(val, str):
                    # Check if it looks like a parseable timestamp
                    if val and not any(c.isdigit() for c in val[:4]):
                        issues.append(f'  ** {cname}: schema={ctype} but linux val="{val[:50]}"')
                elif isinstance(val, (list, dict)):
                    issues.append(f'  ** {cname}: schema={ctype} but linux val={type(val).__name__}')

    missing_in_schema = lkeys - col_names
    missing_in_linux = col_names - lkeys

    if issues or missing_in_schema or missing_in_linux:
        print(f'\n--- {name} ---')
        print(f'  Schema cols: {sorted(col_names)}')
        if wkeys: print(f'  Win keys:    {sorted(wkeys)}')
        print(f'  Lin keys:    {sorted(lkeys)}')
        if missing_in_schema:
            print(f'  Linux keys NOT in schema: {sorted(missing_in_schema)}')
        if missing_in_linux:
            print(f'  Schema cols NOT in linux: {sorted(missing_in_linux)}')
        for iss in issues:
            print(iss)
    else:
        print(f'  {name}: OK (compatible)')
