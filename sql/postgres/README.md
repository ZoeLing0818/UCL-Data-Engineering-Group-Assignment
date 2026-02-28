# PostgreSQL Schema

Execution order:

1. `sql/postgres/01_create_schemas.sql`
2. `sql/postgres/02_create_tables.sql`
3. `sql/postgres/03_create_indexes.sql`

Purpose:

- the `staging` schema stores structured intermediate tables
- the `mart` schema stores the final analytics master table

If your teammates need to create the database directly, this folder is ready to use as a handoff package.
