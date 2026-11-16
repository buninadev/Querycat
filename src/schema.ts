import { AGENT_MAX_ROW_LIMIT, MAX_TIMEOUT_SECONDS } from "./limits.js";
import { runReadOnlyQuery, type QueryOutcome, type Session } from "./postgres.js";

const SCHEMA_QUERY_OPTIONS = { limit: AGENT_MAX_ROW_LIMIT, timeoutMs: MAX_TIMEOUT_SECONDS * 1000 };

const LIST_TABLES_SQL = `
  SELECT n.nspname AS schema, c.relname AS name,
    CASE c.relkind WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned' WHEN 'v' THEN 'view'
      WHEN 'm' THEN 'matview' WHEN 'f' THEN 'foreign' END AS kind,
    GREATEST(c.reltuples::bigint, 0) AS approx_rows,
    obj_description(c.oid, 'pg_class') AS comment
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f')
    AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
    AND NOT c.relispartition
    AND has_table_privilege(c.oid, 'SELECT')
  ORDER BY 1, 2`;

/** Accepts "table" or "schema.table"; a bare name is resolved through the search_path. */
function describeTableSql(table: string): string {
  const literal = `'${table.replace(/'/g, "''")}'`;
  return `
  WITH target AS (SELECT to_regclass(${literal}) AS oid),
  pk AS (
    SELECT unnest(i.indkey) AS attnum FROM pg_index i, target t WHERE i.indrelid = t.oid AND i.indisprimary
  ),
  fk AS (
    SELECT unnest(con.conkey) AS attnum,
      confrelid::regclass::text || '(' || (
        SELECT string_agg(a.attname, ', ') FROM pg_attribute a
        WHERE a.attrelid = con.confrelid AND a.attnum = ANY(con.confkey)
      ) || ')' AS ref
    FROM pg_constraint con, target t WHERE con.conrelid = t.oid AND con.contype = 'f'
  )
  SELECT a.attname AS "column", format_type(a.atttypid, a.atttypmod) AS type,
    NOT a.attnotnull AS nullable,
    pg_get_expr(d.adbin, d.adrelid) AS "default",
    EXISTS (SELECT 1 FROM pk WHERE pk.attnum = a.attnum) AS pk,
    (SELECT string_agg(ref, ', ') FROM fk WHERE fk.attnum = a.attnum) AS "references",
    col_description(a.attrelid, a.attnum) AS comment
  FROM pg_attribute a
  JOIN target t ON a.attrelid = t.oid
  LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
  WHERE a.attnum > 0 AND NOT a.attisdropped
  ORDER BY a.attnum`;
}

export function listTables(session: Session): Promise<QueryOutcome> {
  return runReadOnlyQuery(session, LIST_TABLES_SQL, SCHEMA_QUERY_OPTIONS);
}

export function describeTable(session: Session, table: string): Promise<QueryOutcome> {
  return runReadOnlyQuery(session, describeTableSql(table), SCHEMA_QUERY_OPTIONS);
}
