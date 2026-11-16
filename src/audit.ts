import { appendFileSync, existsSync, readFileSync } from "node:fs";
import { auditLogPath, ensurePrivateDir, PRIVATE_FILE_MODE, querycatHome } from "./paths.js";

export interface AuditEntry {
  at: string;
  id: string;
  sql: string;
  rows?: number;
  truncated?: boolean;
  limit: number;
  durationMs?: number;
  error?: string;
}

export function appendAudit(entry: AuditEntry): void {
  ensurePrivateDir(querycatHome());
  appendFileSync(auditLogPath(), JSON.stringify(entry) + "\n", { mode: PRIVATE_FILE_MODE });
}

export function readAudit(filterId?: string): AuditEntry[] {
  const path = auditLogPath();
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as AuditEntry)
    .filter((entry) => !filterId || entry.id === filterId);
}
