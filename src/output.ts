import type { QueryOutcome } from "./postgres.js";

export const OUTPUT_FORMATS = ["table", "json", "csv", "ndjson"] as const;
export type OutputFormat = (typeof OUTPUT_FORMATS)[number];

const MAX_TABLE_CELL_WIDTH = 120;

/** Converts driver values (Buffers, objects, bigints) into JSON-safe values. */
function toPlainValue(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (Buffer.isBuffer(value)) return `\\x${value.toString("hex")}`;
  if (typeof value === "bigint") return value.toString();
  if (value instanceof Date) return value.toISOString();
  return value;
}

function toText(value: unknown): string {
  const plain = toPlainValue(value);
  if (plain === null) return "";
  if (typeof plain === "object") return JSON.stringify(plain);
  return String(plain);
}

/** Duplicate column names (SELECT a.id, b.id) become id, id_2 so object keys don't collide. */
function uniqueColumnNames(columns: string[]): string[] {
  const seen = new Map<string, number>();
  return columns.map((name) => {
    const count = (seen.get(name) ?? 0) + 1;
    seen.set(name, count);
    return count === 1 ? name : `${name}_${count}`;
  });
}

function rowsAsObjects(outcome: QueryOutcome): Record<string, unknown>[] {
  const keys = uniqueColumnNames(outcome.columns);
  return outcome.rows.map((row) => Object.fromEntries(keys.map((key, i) => [key, toPlainValue(row[i])])));
}

function csvCell(value: unknown): string {
  const text = toText(value);
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function truncateCell(text: string): string {
  const singleLine = text.replace(/\s*\n\s*/g, " ");
  return singleLine.length > MAX_TABLE_CELL_WIDTH ? `${singleLine.slice(0, MAX_TABLE_CELL_WIDTH - 1)}…` : singleLine;
}

function renderTable(outcome: QueryOutcome): string {
  if (outcome.columns.length === 0) return outcome.command || "OK";
  const header = outcome.columns;
  const body = outcome.rows.map((row) => row.map((value) => (value === null ? "NULL" : truncateCell(toText(value)))));
  const widths = header.map((name, i) => Math.max(name.length, ...body.map((row) => row[i]?.length ?? 0)));
  const line = (cells: string[]) => cells.map((cell, i) => cell.padEnd(widths[i] ?? 0)).join(" | ").trimEnd();
  return [line(header), widths.map((width) => "-".repeat(width)).join("-+-"), ...body.map(line)].join("\n");
}

export function renderOutcome(outcome: QueryOutcome, format: OutputFormat, limit: number): string {
  switch (format) {
    case "json":
      return JSON.stringify({
        columns: outcome.columns,
        rows: rowsAsObjects(outcome),
        rowCount: outcome.rows.length,
        truncated: outcome.truncated,
        limit,
        durationMs: outcome.durationMs,
      });
    case "ndjson":
      return rowsAsObjects(outcome).map((row) => JSON.stringify(row)).join("\n");
    case "csv":
      return [outcome.columns, ...outcome.rows].map((row) => row.map(csvCell).join(",")).join("\n");
    case "table":
      return renderTable(outcome);
  }
}

/** Status line for stderr, so stdout stays clean for piping. */
export function summaryLine(outcome: QueryOutcome, limit: number): string {
  const rows = `${outcome.rows.length} row${outcome.rows.length === 1 ? "" : "s"}`;
  const truncated = outcome.truncated ? ` (truncated at --limit ${limit}; more rows exist)` : "";
  return `${rows}${truncated} in ${outcome.durationMs} ms`;
}
