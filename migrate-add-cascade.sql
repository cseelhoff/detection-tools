-- Migration: add ON DELETE CASCADE to every snapshotid foreign key.
-- Auto-discovers all FKs pointing at public.systemsnapshots and rebuilds them
-- with ON DELETE CASCADE. Idempotent — safe to re-run.

DO $$
DECLARE
    r RECORD;
    col_list TEXT;
    ref_col_list TEXT;
BEGIN
    FOR r IN
        SELECT
            n.nspname   AS schema_name,
            cl.relname  AS table_name,
            c.conname   AS constraint_name,
            c.conrelid,
            c.confrelid,
            c.conkey,
            c.confkey
        FROM pg_constraint c
        JOIN pg_class cl      ON cl.oid = c.conrelid
        JOIN pg_namespace n   ON n.oid = cl.relnamespace
        JOIN pg_class refcl   ON refcl.oid = c.confrelid
        JOIN pg_namespace refn ON refn.oid = refcl.relnamespace
        WHERE c.contype = 'f'
          AND refn.nspname = 'public'
          AND refcl.relname = 'systemsnapshots'
          AND c.confdeltype <> 'c'  -- 'c' = CASCADE; skip if already cascading
    LOOP
        SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY k.ord)
          INTO col_list
          FROM unnest(r.conkey) WITH ORDINALITY AS k(attnum, ord)
          JOIN pg_attribute a ON a.attrelid = r.conrelid AND a.attnum = k.attnum;

        SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY k.ord)
          INTO ref_col_list
          FROM unnest(r.confkey) WITH ORDINALITY AS k(attnum, ord)
          JOIN pg_attribute a ON a.attrelid = r.confrelid AND a.attnum = k.attnum;

        EXECUTE format(
            'ALTER TABLE %I.%I DROP CONSTRAINT %I',
            r.schema_name, r.table_name, r.constraint_name
        );
        EXECUTE format(
            'ALTER TABLE %I.%I ADD CONSTRAINT %I FOREIGN KEY (%s) REFERENCES public.systemsnapshots(%s) ON DELETE CASCADE',
            r.schema_name, r.table_name, r.constraint_name, col_list, ref_col_list
        );
        RAISE NOTICE 'Updated % on %.%', r.constraint_name, r.schema_name, r.table_name;
    END LOOP;
END $$;
