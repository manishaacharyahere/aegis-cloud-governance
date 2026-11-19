#!/bin/sh
# Creates the database the local Dex identity provider (auth profile) stores
# its keys, sessions and refresh tokens in. Runs on a fresh volume; for an
# existing one: docker compose exec postgres sh /docker-entrypoint-initdb.d/20-dex-db.sh
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
SELECT 'CREATE DATABASE dex' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'dex') \gexec
EOSQL
