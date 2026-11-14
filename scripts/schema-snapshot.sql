-- Prints the public schema as sorted, one-per-line facts read from the catalogs, so the output is the same
-- on every supported PostgreSQL version (unlike pg_dump text). Used by scripts/check-migrations.sh.
\pset format unaligned
\pset tuples_only on
\pset fieldsep ' | '

SELECT 'column', table_name, column_name, data_type, is_nullable, coalesce(column_default, '-')
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name <> '_sqlx_migrations'
ORDER BY table_name, column_name;

-- contype 'n' (NOT NULL as a constraint) exists only from PostgreSQL 18; is_nullable above already covers it.
SELECT 'constraint', conrelid::regclass, conname, pg_get_constraintdef(oid)
FROM pg_constraint
WHERE connamespace = 'public'::regnamespace AND contype <> 'n' AND conrelid <> 0
  AND conrelid::regclass::text <> '_sqlx_migrations'
ORDER BY conrelid::regclass::text, conname;

SELECT 'index', tablename, indexname, indexdef
FROM pg_indexes
WHERE schemaname = 'public' AND tablename <> '_sqlx_migrations'
ORDER BY tablename, indexname;

SELECT 'trigger', tgrelid::regclass, tgname, pg_get_triggerdef(oid)
FROM pg_trigger
WHERE NOT tgisinternal AND tgrelid IN (SELECT oid FROM pg_class WHERE relnamespace = 'public'::regnamespace)
ORDER BY tgrelid::regclass::text, tgname;

SELECT 'function', proname, pg_get_function_identity_arguments(oid), md5(prosrc)
FROM pg_proc
WHERE pronamespace = 'public'::regnamespace
ORDER BY proname, 3;

SELECT 'view', viewname, md5(definition) FROM pg_views WHERE schemaname = 'public' ORDER BY viewname;

SELECT 'sequence', sequencename FROM pg_sequences WHERE schemaname = 'public' ORDER BY sequencename;

SELECT 'type', typname FROM pg_type
WHERE typnamespace = 'public'::regnamespace AND typtype IN ('e', 'd')
ORDER BY typname;
