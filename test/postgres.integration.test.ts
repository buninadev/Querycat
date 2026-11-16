import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { openSession, runReadOnlyQuery, withSession, type Session } from "../src/postgres.js";
import { ConnectionError } from "../src/diagnose.js";
import { checkReadOnly } from "../src/readonly.js";
import type { Connection } from "../src/store.js";

/**
 * Needs a disposable Postgres where the URL's user can create roles, e.g.:
 *   docker run -d --rm --name qcat-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:55432:5432 postgres:17-alpine
 *   QUERYCAT_TEST_ADMIN_URL=postgres://postgres:pw@127.0.0.1:55432/postgres npm test
 */
const adminUrl = process.env.QUERYCAT_TEST_ADMIN_URL;
const suffix = Math.random().toString(36).slice(2, 8);
const roles = {
  reader: `qc_reader_${suffix}`,
  writer: `qc_writer_${suffix}`,
  sneaky: `qc_sneaky_${suffix}`,
  column: `qc_column_${suffix}`,
};
const schema = `qc_test_${suffix}`;
const PASSWORD = "test-pw";

function connectionAs(role: string): Connection {
  const url = new URL(adminUrl!);
  return {
    id: role.replace(/_/g, "-"),
    host: url.hostname,
    port: Number(url.port || 5432),
    database: url.pathname.slice(1),
    user: role,
    ssl: { mode: "disable" },
  } as Connection;
}

function sessionAs(role: string): Promise<Session> {
  return openSession(connectionAs(role), { password: PASSWORD });
}

function reportFor(role: string) {
  return withSession(connectionAs(role), { password: PASSWORD }, (session) => checkReadOnly(session.client));
}

describe.skipIf(!adminUrl)("postgres integration", () => {
  const admin = new pg.Client({ connectionString: adminUrl });

  beforeAll(async () => {
    await admin.connect();
    await admin.query(`
      CREATE SCHEMA ${schema};
      CREATE TABLE ${schema}.items (id int PRIMARY KEY, name text);
      INSERT INTO ${schema}.items SELECT g, 'item ' || g FROM generate_series(1, 50) g;
      CREATE ROLE ${roles.reader} LOGIN PASSWORD '${PASSWORD}';
      CREATE ROLE ${roles.writer} LOGIN PASSWORD '${PASSWORD}';
      CREATE ROLE ${roles.sneaky} LOGIN NOINHERIT PASSWORD '${PASSWORD}';
      CREATE ROLE ${roles.column} LOGIN PASSWORD '${PASSWORD}';
      GRANT UPDATE (name) ON ${schema}.items TO ${roles.column};
      GRANT USAGE ON SCHEMA ${schema} TO ${roles.reader}, ${roles.writer}, ${roles.sneaky};
      GRANT SELECT ON ALL TABLES IN SCHEMA ${schema} TO ${roles.reader}, ${roles.writer}, ${roles.sneaky};
      GRANT UPDATE ON ${schema}.items TO ${roles.writer};
      GRANT ${roles.writer} TO ${roles.sneaky};
    `);
  });

  afterAll(async () => {
    await admin.query(`
      DROP SCHEMA ${schema} CASCADE;
      DROP ROLE ${roles.column}; DROP ROLE ${roles.sneaky}; DROP ROLE ${roles.writer}; DROP ROLE ${roles.reader};
    `);
    await admin.end();
  });

  it("passes a SELECT-only role", async () => {
    expect(await reportFor(roles.reader)).toMatchObject({ passed: true, findings: [] });
  });

  const fixesOf = (report: Awaited<ReturnType<typeof reportFor>>) => report.checks.flatMap((check) => check.fix);

  it("flags a role with UPDATE and suggests revoking it", async () => {
    const report = await reportFor(roles.writer);
    expect(report.passed).toBe(false);
    expect(report.findings).toContain(`UPDATE on ${schema}.items`);
    expect(fixesOf(report)).toContain(`REVOKE UPDATE ON ALL TABLES IN SCHEMA ${schema} FROM ${roles.writer};`);
  });

  it("flags a role that can SET ROLE to a writer and suggests leaving that role", async () => {
    const report = await reportFor(roles.sneaky);
    expect(report.passed).toBe(false);
    expect(report.findings).toContain(`UPDATE on ${schema}.items (granted to ${roles.writer})`);
    expect(fixesOf(report).some((fix) => fix.startsWith(`REVOKE ${roles.writer} FROM ${roles.sneaky};`))).toBe(true);
  });

  it("flags column-level grants, and its suggested fix makes the check pass", async () => {
    const report = await reportFor(roles.column);
    expect(report.findings).toContain(`UPDATE on ${schema}.items (columns: name)`);
    const fixes = fixesOf(report);
    expect(fixes).toEqual([`REVOKE UPDATE (name) ON ${schema}.items FROM ${roles.column};`]);

    for (const fix of fixes) await admin.query(fix);
    expect(await reportFor(roles.column)).toMatchObject({ passed: true, findings: [] });
  });

  it("flags the admin role", async () => {
    const report = await checkReadOnly(admin);
    expect(report.findings.some((f) => f.includes("SUPERUSER"))).toBe(true);
  });

  describe("connection failures", () => {
    const attempt = async (overrides: Partial<Connection>, password = PASSWORD) => {
      const connection = { ...connectionAs(roles.reader), ...overrides };
      return openSession(connection, { password }).then(
        (session) => session.close().then(() => undefined),
        (error: unknown) => error,
      );
    };

    it("pins a wrong password to the login step", async () => {
      const error = await attempt({}, "wrong-password");
      expect(error).toBeInstanceOf(ConnectionError);
      expect((error as ConnectionError).diagnosis.step).toBe("login");
    });

    it("pins a missing database to the database step", async () => {
      const error = (await attempt({ database: `missing_${suffix}` })) as ConnectionError;
      expect(error.diagnosis).toMatchObject({ step: "database", reason: `database "missing_${suffix}" does not exist` });
    });

    it("pins a closed port to the reach step", async () => {
      const error = (await attempt({ port: 1 })) as ConnectionError;
      expect(error.diagnosis.step).toBe("reach");
    });
  });

  describe("queries", () => {
    let session: Session;
    beforeAll(async () => {
      session = await sessionAs(roles.writer);
    });
    afterAll(() => session.close());

    const run = (sql: string, limit = 500) => runReadOnlyQuery(session, sql, { limit, timeoutMs: 2000 });

    it("returns rows and marks truncation", async () => {
      const result = await run(`SELECT id, name FROM ${schema}.items ORDER BY id`, 10);
      expect(result.columns).toEqual(["id", "name"]);
      expect(result.rows).toHaveLength(10);
      expect(result.truncated).toBe(true);
    });

    it("blocks writes even for a write-capable role", async () => {
      await expect(run(`UPDATE ${schema}.items SET name = 'x'`)).rejects.toThrow(/read-only transaction/);
      await expect(run(`WITH u AS (UPDATE ${schema}.items SET name = 'x' RETURNING 1) SELECT * FROM u`)).rejects.toThrow(
        /read-only transaction/,
      );
      await expect(run(`SELECT set_config('transaction_read_only', 'off', true)`)).rejects.toThrow();
    });

    it("rejects multiple statements", async () => {
      await expect(run(`SELECT 1; UPDATE ${schema}.items SET name = 'x'`)).rejects.toThrow(/multiple commands/);
    });

    it("enforces the statement timeout", async () => {
      await expect(runReadOnlyQuery(session, "SELECT pg_sleep(2)", { limit: 1, timeoutMs: 200 })).rejects.toThrow(
        /statement timeout/,
      );
    });

    it("left the data untouched", async () => {
      const { rows } = await admin.query(`SELECT count(*)::int AS n FROM ${schema}.items WHERE name = 'x'`);
      expect(rows[0].n).toBe(0);
    });
  });
});
