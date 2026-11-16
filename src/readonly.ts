import type pg from "pg";

export interface ReadOnlyCheckResult {
  /** The rule, phrased so that it reads as satisfied, e.g. "No CREATE on the database". */
  label: string;
  /** What breaks the rule, one line per grant. Empty when the rule holds. */
  findings: string[];
  /** SQL or steps that would make the rule hold. */
  fix: string[];
}

export interface ReadOnlyReport {
  passed: boolean;
  /** Why it passed, e.g. the server is a replica. */
  reason?: string;
  checks: ReadOnlyCheckResult[];
  /** Every finding from every check, as stored with the connection. */
  findings: string[];
  /** How to create a role that would pass, shown when the check fails. */
  recipe?: string[];
}

interface CheckContext {
  user: string;
  database: string;
  schemas: string[];
}

type Row = Record<string, unknown>;

interface Check {
  label: string;
  sql: string;
  values?: unknown[];
  describe(row: Row, context: CheckContext): string;
  fix(rows: Row[], context: CheckContext): string[];
}

/** Max rows fetched per check, so a role with thousands of grants still prints a readable report. */
const MAX_FINDINGS_PER_CHECK = 25;

const USER_SCHEMAS = `
  n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg_toast%'
  AND n.nspname NOT LIKE 'pg_temp_%'
`;

/** current_user plus every role it can SET ROLE to; any of them having write access counts. */
const MY_ROLES = `
  WITH my_roles AS (
    SELECT oid, rolname FROM pg_roles WHERE pg_has_role(current_user, oid, 'MEMBER')
  )
`;

/**
 * Who explicitly holds `privilege` in `acl`: the user, a role it belongs to, or PUBLIC.
 * Empty when the access is implicit (ownership or superuser), which other checks report.
 */
function grantHolders(acl: string, privilege: string): string {
  return `ARRAY(
    SELECT DISTINCT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END
    FROM aclexplode(${acl}) a
    WHERE a.privilege_type = ${privilege}
      AND (a.grantee = 0 OR a.grantee IN (SELECT oid FROM my_roles))
  ) AS granted_to`;
}

/** Built-in roles that can write data, touch the server filesystem, or kill other sessions. */
const DANGEROUS_BUILTIN_ROLES = [
  "pg_write_all_data",
  "pg_write_server_files",
  "pg_execute_server_program",
  "pg_signal_backend",
  "pg_checkpoint",
];

const SIMPLE_IDENTIFIER = /^[a-z_][a-z0-9_$]*$/;

export function quoteIdent(name: string): string {
  return SIMPLE_IDENTIFIER.test(name) ? name : `"${name.replace(/"/g, '""')}"`;
}

const qualified = (schema: unknown, name: unknown) => `${quoteIdent(String(schema))}.${quoteIdent(String(name))}`;

const unique = (values: string[]) => [...new Set(values)];

const schemasOf = (rows: Row[]) => unique(rows.map((row) => quoteIdent(String(row.nspname))));

const tablesOf = (rows: Row[]) => unique(rows.map((row) => qualified(row.nspname, row.relname)));

function holdersOf(row: Row): string[] {
  return (row.granted_to as string[] | undefined) ?? [];
}

function isPublicGrant(row: Row): boolean {
  const holders = holdersOf(row);
  return holders.length === 1 && holders[0] === "PUBLIC";
}

/** " (granted to writers)" when the grant comes from somewhere other than the user itself. */
function grantSource(row: Row, context: CheckContext): string {
  const others = holdersOf(row).filter((holder) => holder !== context.user);
  return others.length ? ` (granted to ${others.join(", ")})` : "";
}

const IMPLICIT_ACCESS_FIX =
  "No explicit grant found: access comes from ownership or superuser. " +
  "Use a dedicated read-only role (recipe below).";

/** The grants one REVOKE statement has to cover. */
interface RevokeTarget {
  privileges: string[];
  grants: Row[];
  /** Ready to splice into SQL: PUBLIC or a quoted role name. */
  grantee: string;
}

/**
 * Turns grant holders into REVOKE statements. A grant on the user itself is
 * revoked directly; one on a group role is fixed by leaving the group, since
 * revoking from the group would change access for everyone in it.
 */
function revokeStatements(rows: Row[], context: CheckContext, revoke: (target: RevokeTarget) => string): string[] {
  const statements = new Set<string>();
  const grantsByHolder = new Map<string, Row[]>();
  for (const row of rows) {
    const holders = holdersOf(row);
    if (holders.length === 0) statements.add(IMPLICIT_ACCESS_FIX);
    for (const holder of holders) grantsByHolder.set(holder, [...(grantsByHolder.get(holder) ?? []), row]);
  }
  for (const [holder, grants] of grantsByHolder) {
    const privileges = unique(grants.map((row) => String(row.priv))).sort();
    if (holder === "PUBLIC") {
      statements.add(`${revoke({ privileges, grants, grantee: "PUBLIC" })}  -- affects every role`);
    } else if (holder === context.user) {
      statements.add(revoke({ privileges, grants, grantee: quoteIdent(holder) }));
    } else {
      const leaveGroup = `REVOKE ${quoteIdent(holder)} FROM ${quoteIdent(context.user)};`;
      statements.add(`${leaveGroup}  -- leaves the group that grants this`);
    }
  }
  return [...statements];
}

const checks: Check[] = [
  {
    label: "No admin attributes (SUPERUSER, CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS)",
    sql: `${MY_ROLES}
      SELECT r.rolname, attr FROM pg_roles r JOIN my_roles m ON m.oid = r.oid
      CROSS JOIN LATERAL (VALUES
        ('SUPERUSER', r.rolsuper), ('CREATEROLE', r.rolcreaterole), ('CREATEDB', r.rolcreatedb),
        ('REPLICATION', r.rolreplication), ('BYPASSRLS', r.rolbypassrls)
      ) AS a(attr, enabled)
      WHERE enabled`,
    describe: (row) => `role ${row.rolname} has ${row.attr}`,
    fix: (rows, context) => {
      const rolesWithAttrs = new Map<string, string[]>();
      for (const row of rows) {
        const role = String(row.rolname);
        rolesWithAttrs.set(role, [...(rolesWithAttrs.get(role) ?? []), `NO${row.attr}`]);
      }
      return [...rolesWithAttrs].map(([role, attrs]) =>
        role === context.user
          ? `ALTER ROLE ${quoteIdent(role)} ${attrs.join(" ")};`
          : `REVOKE ${quoteIdent(role)} FROM ${quoteIdent(context.user)};  -- ${role} has ${attrs.join(", ")}`,
      );
    },
  },
  {
    label: "Not a member of write-capable built-in roles",
    sql: `${MY_ROLES}
      SELECT m.rolname, EXISTS (
        SELECT 1 FROM pg_auth_members am
        WHERE am.roleid = m.oid AND am.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)
      ) AS direct
      FROM my_roles m WHERE m.rolname = ANY($1)`,
    values: [DANGEROUS_BUILTIN_ROLES],
    describe: (row) => `member of ${row.rolname}${row.direct ? "" : " (through another role)"}`,
    fix: (rows, context) =>
      rows.map((row) =>
        row.direct
          ? `REVOKE ${row.rolname} FROM ${quoteIdent(context.user)};`
          : `${row.rolname} comes through another role: find it with \\du ${context.user} and revoke that membership.`,
      ),
  },
  {
    label: "No CREATE on the database",
    sql: `${MY_ROLES}
      SELECT d.datname, 'CREATE' AS priv, ${grantHolders("d.datacl", "'CREATE'")}
      FROM pg_database d
      WHERE d.datname = current_database()
        AND EXISTS (SELECT 1 FROM my_roles m WHERE has_database_privilege(m.oid, d.oid, 'CREATE'))`,
    describe: (row, context) => `CREATE on database ${row.datname} (can create schemas)${grantSource(row, context)}`,
    fix: (rows, context) =>
      revokeStatements(
        rows,
        context,
        ({ grantee }) => `REVOKE CREATE ON DATABASE ${quoteIdent(context.database)} FROM ${grantee};`,
      ),
  },
  {
    label: "No CREATE on any schema",
    sql: `${MY_ROLES}
      SELECT n.nspname, 'CREATE' AS priv, ${grantHolders("n.nspacl", "'CREATE'")}
      FROM pg_namespace n
      WHERE ${USER_SCHEMAS}
        AND EXISTS (SELECT 1 FROM my_roles m WHERE has_schema_privilege(m.oid, n.oid, 'CREATE'))`,
    describe: (row, context) => `CREATE on schema ${row.nspname} (can create tables)${grantSource(row, context)}`,
    fix: (rows, context) =>
      revokeStatements(
        rows,
        context,
        ({ grants, grantee }) => `REVOKE CREATE ON SCHEMA ${schemasOf(grants).join(", ")} FROM ${grantee};`,
      ),
  },
  {
    label: "Owns no tables, views or sequences",
    sql: `SELECT n.nspname, c.relname, pg_get_userbyid(c.relowner) AS owner
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE ${USER_SCHEMAS} AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
        AND pg_has_role(current_user, c.relowner, 'MEMBER')`,
    describe: (row, context) =>
      `owns ${qualified(row.nspname, row.relname)}${row.owner === context.user ? "" : ` (through role ${row.owner})`}`,
    fix: () => [
      "An owner can always write and ownership can't be revoked. Connect with a role that owns nothing (recipe below).",
    ],
  },
  {
    label: "No INSERT, UPDATE, DELETE, TRUNCATE or TRIGGER on tables and views",
    // Table-level grants first, then column-level ones (e.g. GRANT UPDATE (note) ON orders),
    // which live in each column's ACL and need their own REVOKE syntax.
    sql: `${MY_ROLES}
      SELECT * FROM (
        SELECT n.nspname, c.relname, p.priv, ${grantHolders("c.relacl", "p.priv")}, NULL::text[] AS columns
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN (VALUES ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('TRIGGER')) AS p(priv)
        WHERE ${USER_SCHEMAS} AND c.relkind IN ('r', 'p', 'v', 'f')
          AND EXISTS (SELECT 1 FROM my_roles m WHERE has_table_privilege(m.oid, c.oid, p.priv))
        UNION ALL
        SELECT n.nspname, c.relname, x.privilege_type,
          ARRAY[CASE WHEN x.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee)::text END],
          array_agg(a.attname::text ORDER BY a.attnum)
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(a.attacl) x
        WHERE ${USER_SCHEMAS} AND c.relkind IN ('r', 'p', 'v', 'f') AND a.attnum > 0 AND NOT a.attisdropped
          AND x.privilege_type IN ('INSERT', 'UPDATE')
          AND (x.grantee = 0 OR x.grantee IN (SELECT oid FROM my_roles))
        GROUP BY n.nspname, c.relname, x.privilege_type, x.grantee
      ) grants
      ORDER BY nspname, relname, priv`,
    describe: (row, context) => {
      const columns = row.columns ? ` (columns: ${(row.columns as string[]).join(", ")})` : "";
      return `${row.priv} on ${qualified(row.nspname, row.relname)}${columns}${grantSource(row, context)}`;
    },
    fix: (rows, context) => {
      const tableLevel = rows.filter((row) => !row.columns);
      const columnLevel = rows.filter((row) => row.columns);
      const tableFixes = revokeStatements(tableLevel, context, ({ privileges, grants, grantee }) => {
        // Revoking from PUBLIC affects every role, so it names only the flagged tables.
        if (grantee === "PUBLIC") {
          return `REVOKE ${privileges.join(", ")} ON ${tablesOf(grants).join(", ")} FROM PUBLIC;`;
        }
        return `REVOKE ${privileges.join(", ")} ON ALL TABLES IN SCHEMA ${schemasOf(grants).join(", ")} FROM ${grantee};`;
      });
      const columnFixes = columnLevel.flatMap((row) =>
        revokeStatements([row], context, ({ privileges, grantee }) => {
          const columns = (row.columns as string[]).map(quoteIdent).join(", ");
          return `REVOKE ${privileges.join(", ")} (${columns}) ON ${qualified(row.nspname, row.relname)} FROM ${grantee};`;
        }),
      );
      return unique([...tableFixes, ...columnFixes]);
    },
  },
  {
    label: "No UPDATE on sequences",
    sql: `${MY_ROLES}
      SELECT n.nspname, c.relname, 'UPDATE' AS priv, ${grantHolders("c.relacl", "'UPDATE'")}
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE ${USER_SCHEMAS} AND c.relkind = 'S'
        AND EXISTS (SELECT 1 FROM my_roles m WHERE has_sequence_privilege(m.oid, c.oid, 'UPDATE'))`,
    describe: (row, context) => `UPDATE on sequence ${qualified(row.nspname, row.relname)}${grantSource(row, context)}`,
    fix: (rows, context) =>
      revokeStatements(
        rows,
        context,
        ({ grants, grantee }) =>
          `REVOKE UPDATE ON ALL SEQUENCES IN SCHEMA ${schemasOf(grants).join(", ")} FROM ${grantee};`,
      ),
  },
];

/** SQL for a role that passes every check, to run as an admin. */
function readOnlyRoleRecipe(context: CheckContext): string[] {
  const schemas = (context.schemas.length ? context.schemas : ["public"]).map(quoteIdent).join(", ");
  return [
    "CREATE ROLE querycat_ro LOGIN PASSWORD '<choose a password>';",
    `GRANT CONNECT ON DATABASE ${quoteIdent(context.database)} TO querycat_ro;`,
    `GRANT USAGE ON SCHEMA ${schemas} TO querycat_ro;`,
    `GRANT SELECT ON ALL TABLES IN SCHEMA ${schemas} TO querycat_ro;`,
    `ALTER DEFAULT PRIVILEGES IN SCHEMA ${schemas} GRANT SELECT ON TABLES TO querycat_ro;  -- run as the role that creates tables`,
  ];
}

async function loadContext(client: pg.Client): Promise<CheckContext & { inRecovery: boolean }> {
  const { rows } = await client.query<{ user: string; database: string; schemas: string[]; in_recovery: boolean }>(`
    SELECT current_user AS user, current_database() AS database, pg_is_in_recovery() AS in_recovery,
      ARRAY(SELECT n.nspname::text FROM pg_namespace n WHERE ${USER_SCHEMAS} ORDER BY 1) AS schemas`);
  const row = rows[0]!;
  return { user: row.user, database: row.database, schemas: row.schemas, inRecovery: row.in_recovery };
}

/**
 * Decides whether the connected role can change anything, by reading the
 * privilege catalog. It never attempts a write.
 */
export async function checkReadOnly(client: pg.Client): Promise<ReadOnlyReport> {
  const context = await loadContext(client);
  if (context.inRecovery) {
    const replica = { label: "Server is a hot-standby replica, so it cannot accept writes", findings: [], fix: [] };
    return { passed: true, reason: "server is a hot-standby replica", checks: [replica], findings: [] };
  }

  const results: ReadOnlyCheckResult[] = [];
  let fixableByRevokingPublic = true;
  for (const check of checks) {
    const { rows } = await client.query<Row>(`${check.sql} LIMIT ${MAX_FINDINGS_PER_CHECK}`, check.values);
    fixableByRevokingPublic &&= rows.every(isPublicGrant);
    results.push({
      label: check.label,
      findings: rows.map((row) => check.describe(row, context)),
      fix: rows.length ? check.fix(rows, context) : [],
    });
  }

  const findings = results.flatMap((result) => result.findings);
  const passed = findings.length === 0;
  return {
    passed,
    reason: passed ? "no write privileges found" : undefined,
    checks: results,
    findings,
    // A new role would inherit PUBLIC grants too, so the recipe only helps with the other problems.
    recipe: passed || fixableByRevokingPublic ? undefined : readOnlyRoleRecipe(context),
  };
}
