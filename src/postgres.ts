import { readFileSync } from "node:fs";
import type { ConnectionOptions } from "node:tls";
import pg from "pg";
import Cursor from "pg-cursor";
import { ExitCode, QuerycatError, scrubSecrets } from "./errors.js";
import type { Connection, Secrets, SslConfig } from "./store.js";
import { ConnectionError, diagnosePostgresError, diagnoseSshError } from "./diagnose.js";
import { CONNECT_TIMEOUT_MS } from "./limits.js";
import { openTunnel, type Tunnel } from "./tunnel.js";

/** Date and time values are returned as Postgres prints them, so no timezone conversion sneaks in. */
const RAW_TEXT_TYPE_OIDS = new Set([
  1082, // date
  1083, // time
  1114, // timestamp
  1184, // timestamptz
  1266, // timetz
]);

function getTypeParser(oid: number, format?: "text" | "binary") {
  return RAW_TEXT_TYPE_OIDS.has(oid) ? (value: string) => value : pg.types.getTypeParser(oid, format);
}

const typeParsers: pg.CustomTypesConfig = {
  getTypeParser: getTypeParser as pg.CustomTypesConfig["getTypeParser"],
};

export interface Session {
  client: pg.Client;
  secrets: Secrets;
  close(): Promise<void>;
}

export interface QueryOutcome {
  columns: string[];
  rows: unknown[][];
  truncated: boolean;
  command: string;
  durationMs: number;
}

function readOptionalFile(path: string | undefined): Buffer | undefined {
  return path ? readFileSync(path) : undefined;
}

function sslOptions(ssl: SslConfig, servername: string): false | ConnectionOptions {
  if (ssl.mode === "disable") return false;
  const files = {
    ca: readOptionalFile(ssl.caPath),
    cert: readOptionalFile(ssl.certPath),
    key: readOptionalFile(ssl.keyPath),
  };
  switch (ssl.mode) {
    case "require":
      return { ...files, rejectUnauthorized: false };
    case "verify-ca":
      return { ...files, rejectUnauthorized: true, checkServerIdentity: () => undefined };
    case "verify-full":
      return { ...files, rejectUnauthorized: true, servername };
  }
}

function secretScrubber(secrets: Secrets): (text: string) => string {
  return (text) => scrubSecrets(text, Object.values(secrets));
}

async function connectTunnel(connection: Connection, secrets: Secrets): Promise<Tunnel | undefined> {
  const { ssh } = connection;
  if (!ssh) return undefined;
  try {
    return await openTunnel(ssh, secrets, { host: connection.host, port: connection.port });
  } catch (error) {
    throw new ConnectionError(connection, diagnoseSshError(connection, ssh, error, secretScrubber(secrets)));
  }
}

/** Opens a connection, or throws a ConnectionError saying which step failed and how to fix it. */
export async function openSession(connection: Connection, secrets: Secrets): Promise<Session> {
  const tunnel = await connectTunnel(connection, secrets);
  let client: pg.Client | undefined;
  try {
    client = new pg.Client({
      host: tunnel ? "127.0.0.1" : connection.host,
      port: tunnel ? tunnel.localPort : connection.port,
      database: connection.database,
      user: connection.user,
      password: secrets.password,
      ssl: sslOptions(connection.ssl, connection.host),
      application_name: "querycat",
      connectionTimeoutMillis: CONNECT_TIMEOUT_MS,
      types: typeParsers,
    });
    // An idle client can emit errors (e.g. server restart); the next query reports them instead.
    client.on("error", () => {});
    await client.connect();
  } catch (error) {
    await client?.end().catch(() => {});
    tunnel?.close();
    const diagnosis = diagnosePostgresError(connection, error, secretScrubber(secrets), tunnel?.forwardError());
    throw new ConnectionError(connection, diagnosis);
  }

  return {
    client,
    secrets,
    async close() {
      await client.end().catch(() => {});
      tunnel?.close();
    },
  };
}

export async function withSession<T>(
  connection: Connection,
  secrets: Secrets,
  work: (session: Session) => Promise<T>,
): Promise<T> {
  const session = await openSession(connection, secrets);
  try {
    return await work(session);
  } finally {
    await session.close();
  }
}

function readFromCursor(
  cursor: Cursor<unknown[]>,
  maxRows: number,
): Promise<{ rows: unknown[][]; result: pg.QueryResult }> {
  return new Promise((resolve, reject) => {
    cursor.read(maxRows, (error, rows, result) => (error ? reject(error) : resolve({ rows, result })));
  });
}

/**
 * Runs one statement inside a READ ONLY transaction that is always rolled back.
 * A cursor uses the extended protocol, which rejects multiple statements
 * ("SELECT 1; DELETE ...") and lets us stop reading after `limit` rows.
 */
export async function runReadOnlyQuery(
  session: Session,
  sql: string,
  options: { limit: number; timeoutMs: number },
): Promise<QueryOutcome> {
  const { client } = session;
  const started = performance.now();
  await client.query("BEGIN READ ONLY");
  try {
    await client.query(`SET LOCAL statement_timeout = ${Math.floor(options.timeoutMs)}`);
    const cursor = client.query(new Cursor<unknown[]>(sql, undefined, { rowMode: "array", types: typeParsers }));
    try {
      const { rows, result } = await readFromCursor(cursor, options.limit + 1);
      return {
        columns: (result.fields ?? []).map((field) => field.name),
        rows: rows.slice(0, options.limit),
        truncated: rows.length > options.limit,
        command: result.command ?? "",
        durationMs: Math.round(performance.now() - started),
      };
    } finally {
      await cursor.close().catch(() => {});
    }
  } catch (error) {
    throw new QuerycatError(describePgError(error as pg.DatabaseError, session.secrets), ExitCode.QueryFailed);
  } finally {
    await client.query("ROLLBACK").catch(() => {});
  }
}

function describePgError(error: pg.DatabaseError, secrets: Secrets): string {
  const lines = [error.message];
  if (error.detail) lines.push(`detail: ${error.detail}`);
  if (error.hint) lines.push(`hint: ${error.hint}`);
  if (error.position) lines.push(`at character ${error.position}`);
  return scrubSecrets(lines.join("\n"), Object.values(secrets));
}
