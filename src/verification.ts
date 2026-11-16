import { confirm } from "@inquirer/prompts";
import { printChecklist, type ChecklistItem, type ChecklistSection } from "./checklist.js";
import { toConnection } from "./connection-input.js";
import { connectionChecklist, ConnectionError, type Diagnosis } from "./diagnose.js";
import { promptConnection, type ConnectionInput } from "./form.js";
import { confirmByTyping, isInteractive, warn } from "./human.js";
import { withSession } from "./postgres.js";
import { checkReadOnly, type ReadOnlyCheckResult, type ReadOnlyReport } from "./readonly.js";
import {
  decryptSecrets,
  type Connection,
  type ReadOnlyRecord,
  type ReadOnlyStatus,
  type Secrets,
} from "./store.js";

const READ_ONLY_TITLE = "Read-only";

function connectionSection(connection: Connection, diagnosis?: Diagnosis): ChecklistSection {
  return { title: `Connection "${connection.id}"`, items: connectionChecklist(connection, diagnosis) };
}

function readOnlyItem(check: ReadOnlyCheckResult): ChecklistItem {
  const passed = check.findings.length === 0;
  return passed
    ? { label: check.label, state: "pass" }
    : { label: check.label, state: "fail", details: check.findings.map((finding) => `- ${finding}`), fix: check.fix };
}

function printReport(connection: Connection, report: ReadOnlyReport): void {
  printChecklist([connectionSection(connection), { title: READ_ONLY_TITLE, items: report.checks.map(readOnlyItem) }]);
  if (report.passed) {
    console.error(`✅ "${connection.id}" is read-only: ${report.reason}.`);
    return;
  }
  if (report.recipe) {
    console.error("\nRecommended: a dedicated read-only role (run as an admin, then `qcat edit` with it):");
    for (const line of report.recipe) console.error(`  ${line}`);
  }
  const problemCount = report.findings.length;
  warn(`"${connection.id}" can WRITE (${problemCount} problem${problemCount === 1 ? "" : "s"} above).`);
}

function printConnectionFailure(error: ConnectionError): void {
  printChecklist([
    connectionSection(error.connection, error.diagnosis),
    { title: READ_ONLY_TITLE, items: [{ label: "Read-only checks (not run: no connection)", state: "skip" }] },
  ]);
}

/**
 * Connects and runs the read-only check, printing the checklist either way.
 * Returns undefined when the connection itself failed.
 */
async function runChecks(connection: Connection, secrets: Secrets): Promise<ReadOnlyReport | undefined> {
  console.error("Connecting and checking privileges...");
  try {
    const report = await withSession(connection, secrets, (session) => checkReadOnly(session.client));
    printReport(connection, report);
    return report;
  } catch (error) {
    if (!(error instanceof ConnectionError)) throw error;
    printConnectionFailure(error);
    return undefined;
  }
}

/** Asks the human whether to keep a connection that failed the check. */
async function confirmWriteOverride(id: string): Promise<boolean> {
  warn("Queries still run inside READ ONLY transactions, but the role itself can change data.");
  warn("Best fix: apply the fixes above or use a dedicated read-only role.");
  const keep = await confirm({ message: "Keep this connection anyway?", default: false });
  return keep && (await confirmByTyping(id, "This connection will be marked as write-capable."));
}

function recordFor(report: ReadOnlyReport, status: ReadOnlyStatus): ReadOnlyRecord {
  return {
    status,
    checkedAt: new Date().toISOString(),
    reason: report.reason,
    findings: report.findings.length ? report.findings : undefined,
  };
}

async function acceptOrOverride(draft: Connection, report: ReadOnlyReport): Promise<Connection | undefined> {
  if (report.passed) return { ...draft, readonly: recordFor(report, "verified") };
  if (await confirmWriteOverride(draft.id)) return { ...draft, readonly: recordFor(report, "override") };
  return undefined;
}

/**
 * Prompts for the details, connects and runs the read-only check. On a connection
 * error the user can fix the details and retry without retyping everything.
 * Returns undefined when the user gives up or declines a failed check.
 */
export async function collectVerifiedConnection(
  id: string,
  defaults: Partial<ConnectionInput>,
  createdAt?: string,
): Promise<Connection | undefined> {
  let input = await promptConnection(defaults);
  for (;;) {
    const draft = toConnection(id, input, { status: "unverified", checkedAt: new Date().toISOString() }, createdAt);
    const report = await runChecks(draft, input.secrets);
    if (report) return acceptOrOverride(draft, report);
    if (!(await confirm({ message: "Edit the details and try again?", default: true }))) return undefined;
    input = await promptConnection(input);
  }
}

async function statusAfterRecheck(connection: Connection, report: ReadOnlyReport): Promise<ReadOnlyStatus> {
  if (report.passed) return "verified";
  if (connection.readonly.status === "override") return "override";
  if (isInteractive() && (await confirmWriteOverride(connection.id))) return "override";
  warn(`Queries on "${connection.id}" are blocked until this is fixed or overridden.`);
  return "unverified";
}

/**
 * Re-checks a saved connection. A failure keeps an earlier override; otherwise a
 * human at a terminal may override now, and without one queries become blocked.
 * Returns undefined when it could not connect; the saved status is then left alone.
 */
export async function recheckConnection(connection: Connection): Promise<ReadOnlyRecord | undefined> {
  const report = await runChecks(connection, decryptSecrets(connection));
  if (!report) return undefined;
  return recordFor(report, await statusAfterRecheck(connection, report));
}
