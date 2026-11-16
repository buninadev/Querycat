import { describe, expect, it } from "vitest";
import { renderOutcome, summaryLine } from "../src/output.js";
import type { QueryOutcome } from "../src/postgres.js";

const outcome = (columns: string[], rows: unknown[][], truncated = false): QueryOutcome => ({
  columns,
  rows,
  truncated,
  command: "SELECT",
  durationMs: 3,
});

describe("output rendering", () => {
  it("quotes CSV cells containing commas, quotes or newlines", () => {
    const csv = renderOutcome(outcome(["id", "note"], [[1, 'a, "b"'], [2, "line\nbreak"], [3, null]]), "csv", 10);
    expect(csv).toBe('id,note\n1,"a, ""b"""\n2,"line\nbreak"\n3,');
  });

  it("keeps duplicate column names apart in JSON", () => {
    const json = JSON.parse(renderOutcome(outcome(["id", "id"], [[1, 2]]), "json", 10));
    expect(json.rows).toEqual([{ id: 1, id_2: 2 }]);
    expect(json.columns).toEqual(["id", "id"]);
  });

  it("encodes binary data as Postgres hex", () => {
    const line = renderOutcome(outcome(["data"], [[Buffer.from([0xde, 0xad])]]), "ndjson", 10);
    expect(JSON.parse(line)).toEqual({ data: "\\xdead" });
  });

  it("aligns table columns and shows NULL", () => {
    const table = renderOutcome(outcome(["id", "name"], [[1, "alice"], [22, null]]), "table", 10);
    expect(table.split("\n")).toEqual(["id | name", "---+------", "1  | alice", "22 | NULL"]);
  });

  it("reports truncation in the summary", () => {
    expect(summaryLine(outcome(["x"], [[1]], true), 1)).toMatch(/1 row \(truncated at --limit 1/);
  });
});
