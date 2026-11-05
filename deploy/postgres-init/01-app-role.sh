#!/bin/sh
# Runs once, on first init of an empty data directory, as the bootstrap superuser.
# Creates the non-superuser application role that owns the cvenom database.
set -eu

: "${APP_DB_PASSWORD:?APP_DB_PASSWORD must be set}"

# The password travels as a psql variable and is quoted by psql itself (:'pw'),
# never interpolated into the SQL text by the shell. The heredoc is quoted so
# the shell expands nothing inside it.
psql -v ON_ERROR_STOP=1 -v pw="$APP_DB_PASSWORD" -v dbname="${POSTGRES_DB:-cvenom}" \
     --username "$POSTGRES_USER" --dbname "${POSTGRES_DB:-cvenom}" <<'SQL'
CREATE ROLE cvenom_app LOGIN PASSWORD :'pw'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER DATABASE :"dbname" OWNER TO cvenom_app;
REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"dbname" TO cvenom_app;
-- Migrations run as cvenom_app: it owns the schema and may create objects in it.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO cvenom_app;
GRANT ALL ON SCHEMA public TO cvenom_app;
SQL
