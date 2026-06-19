#!/bin/sh
# postgres docker-entrypoint runs this on first container init only
# (when /var/lib/postgresql/data is empty).
#
# POSTGRES_USER/POSTGRES_DB are already set up by the entrypoint — we just
# add the migrator role and grant the same DDL/DML split that bin/install.sh
# applies on a native install.
set -e

: "${DB_MIGRATOR_USER:?required}"
: "${DB_MIGRATOR_PASSWORD:?required}"
: "${DB_USER:?required}"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname   "$POSTGRES_DB" <<-EOSQL
    CREATE ROLE ${DB_MIGRATOR_USER} LOGIN PASSWORD '${DB_MIGRATOR_PASSWORD}';

    -- migrator owns DDL
    GRANT ALL ON SCHEMA public TO ${DB_MIGRATOR_USER};

    -- app role: schema-usage only, plus default DML on future tables/sequences
    GRANT USAGE ON SCHEMA public TO ${DB_USER};
    ALTER DEFAULT PRIVILEGES FOR ROLE ${DB_MIGRATOR_USER} IN SCHEMA public
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ${DB_USER};
    ALTER DEFAULT PRIVILEGES FOR ROLE ${DB_MIGRATOR_USER} IN SCHEMA public
        GRANT USAGE, SELECT ON SEQUENCES TO ${DB_USER};
EOSQL
