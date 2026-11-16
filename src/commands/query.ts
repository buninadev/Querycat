import { readFileSync } from "node:fs";
import { confirm } from "@inquirer/prompts";
import { appendAudit, readAudit, type AuditEntry } from "../audit.js";
import { ExitCode, QuerycatError } from "../errors.js";
import { isInteractive, requireHuman, warn } from "../human.js";
import { AGENT_MAX_ROW_LIMIT, DEFAULT_ROW_LIMIT, MAX_TIMEOUT_SECONDS } from "../limits.js";
import { OUTPUT_FORMATS, renderOutcome, summaryLine, type OutputFormat } from "../output.js";
import { runReadOnlyQuery, withSession, type QueryOutcome } from "../postgres.js";
import { describeTable, listTables } from "../schema.js";
import { decryptSecrets, loadConnection, type Connection } from "../store.js";

export const DEFAULT_LOG_ENTRIES = 20;

export interface QueryOptions {
  file?: string;
  limit?: string;
  timeout?: string;
  format?: string;
  json?: boolean;
}

function parsePositiveInt(value: string, flag: string): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < 1) {
    throw new QuerycatError(`${flag} must be a positive whole number, got "${value}".`);
  }
  return parsed;
}

async function resolveLimit(raw: string | undefined): Promise<number> {
  if (raw === undefined) return DEFAULT_ROW_LIMIT;
  const limit = parsePositiveInt(raw, "--limit");
  if (limit <= AGENT_MAX_ROW_LIMIT) return limit;

  requireHuman(`fetch more than ${AGENT_MAX_ROW_LIMIT} rows`);
  const approved = await confirm({
    message: `Fetch up to ${limit} rows? This is above the ${AGENT_MAX_ROW_LIMIT}-row safety limit.`,
    default: false,
  });
  if (!approved) throw new QuerycatError("Cancelled.", ExitCode.Refused);
  return limit;
}

function resolveTimeoutMs(raw: string | undefined): number {
  if (raw === undefined) return MAX_TIMEOUT_SECONDS * 1000;
  const seconds = parsePositiveInt(raw, "--timeout");
  if (seconds > MAX_TIMEOUT_SECONDS) {
    throw new QuerycatError(`--timeout is capped at ${MAX_TIMEOUT_SECONDS} seconds.`);
  }
  return seconds * 1000;
}

function resolveFormat(options: Pick<QueryOptions, "format" | "json">): OutputFormat {
  if (options.json) return "json";
  const format = options.format ?? "table";
  if (!OUTPUT_FORMATS.includes(format as OutputFormat)) {
    throw new QuerycatError(`--format must be one of: ${OUTPUT_FORMATS.join(", ")}.`);
  }
  return format as OutputFormat;
}

function readRawSql(sqlArg: string | undefined, file: string | undefined): string | undefined {
  if (file) return readFileSync(file, "utf8");
  if (sqlArg) return sqlArg;
  if (!process.stdin.isTTY) return readFileSync(0, "utf8");
  return undefined;
}

function readSql(sqlArg: string | undefined, file: string | undefined): string {
  const sql = readRawSql(sqlArg, file);
  if (!sql?.trim()) {
    throw new QuerycatError('No SQL given. Usage: qcat query <id> "SELECT ..." (or -f file.sql, or pipe it in).');
  }
  return sql.trim();
}

/** Loads a connection and refuses it if its last read-only check failed. */
function loadQueryableConnection(id: string): Connection {
  const connection = loadConnection(id);
  if (connection.readonly.status === "unverified") {
    throw new QuerycatError(
      `"${id}" failed its last read-only check, so queries are blocked. Run \`qcat test ${id}\` in a terminal.`,
      ExitCode.Refused,
    );
  }
  if (connection.readonly.status === "override") {
    warn(`"${id}" is write-capable (read-only check overridden). Query runs in a READ ONLY transaction.`);
  }
  return connection;
}

export async function queryCommand(id: string, sqlArg: string | undefined, options: QueryOptions): Promise<void> {
  const format = resolveFormat(options);
  const timeoutMs = resolveTimeoutMs(options.timeout);
  const sql = readSql(sqlArg, options.file);
  const connection = loadQueryableConnection(id);
  const limit = await resolveLimit(options.limit);
  const audit = (result: Partial<AuditEntry>) =>
    appendAudit({ at: new Date().toISOString(), id, sql, limit, ...result });

  let outcome: QueryOutcome;
  try {
    outcome = await withSession(connection, decryptSecrets(connection), (session) =>
      runReadOnlyQuery(session, sql, { limit, timeoutMs }),
    );
  } catch (error) {
    audit({ error: (error as Error).message });
    throw error;
  }

  audit({ rows: outcome.rows.length, truncated: outcome.truncated, durationMs: outcome.durationMs });
  console.log(renderOutcome(outcome, format, limit));
  console.error(summaryLine(outcome, limit));
}

export async function schemaCommand(
  id: string,
  table: string | undefined,
  options: Pick<QueryOptions, "format" | "json">,
): Promise<void> {
  const format = resolveFormat(options);
  const connection = loadQueryableConnection(id);
  const outcome = await withSession(connection, decryptSecrets(connection), (session) =>
    table ? describeTable(session, table) : listTables(session),
  );
  if (table && outcome.rows.length === 0) {
    throw new QuerycatError(`Table "${table}" not found or not visible to this role.`, ExitCode.QueryFailed);
  }
  console.log(renderOutcome(outcome, format, outcome.rows.length));
}

export function logCommand(id: string | undefined, options: { tail?: string; json?: boolean }): void {
  const count = options.tail ? parsePositiveInt(options.tail, "--tail") : DEFAULT_LOG_ENTRIES;
  const entries = readAudit(id).slice(-count);
  if (options.json) {
    console.log(JSON.stringify(entries));
    return;
  }
  for (const entry of entries) {
    const result = entry.error ? `ERROR ${entry.error.split("\n")[0]}` : `${entry.rows} rows, ${entry.durationMs} ms`;
    console.log(`${entry.at}  ${entry.id}  ${result}\n    ${entry.sql.replace(/\s+/g, " ")}`);
  }
  if (entries.length === 0 && isInteractive()) console.error("No queries logged yet.");
}
