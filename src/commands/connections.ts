import { confirm } from "@inquirer/prompts";
import { toConnectionInput } from "../connection-input.js";
import { ExitCode, QuerycatError } from "../errors.js";
import { parseConnectionUrl } from "../form.js";
import { requireHuman } from "../human.js";
import {
  assertValidId,
  connectionExists,
  decryptSecrets,
  listConnections,
  loadConnection,
  removeConnection,
  saveConnection,
  type Connection,
  type ReadOnlyStatus,
} from "../store.js";
import { collectVerifiedConnection, recheckConnection } from "../verification.js";

const NO_CONNECTIONS_HINT = "No connections saved yet. Add one with `qcat add <id>`.";

export async function addCommand(id: string, options: { url?: string }): Promise<void> {
  requireHuman("add a connection");
  assertValidId(id);
  if (connectionExists(id)) {
    throw new QuerycatError(`"${id}" already exists. Use \`qcat edit ${id}\` to change it.`);
  }
  const defaults = options.url ? parseConnectionUrl(options.url) : {};
  const connection = await collectVerifiedConnection(id, defaults);
  if (!connection) {
    console.error("Nothing saved.");
    return;
  }
  saveConnection(connection);
  console.error(`Saved "${id}".`);
}

export async function editCommand(id: string): Promise<void> {
  requireHuman("edit a connection");
  const existing = loadConnection(id);
  const defaults = toConnectionInput(existing, decryptSecrets(existing));
  const connection = await collectVerifiedConnection(id, defaults, existing.createdAt);
  if (!connection) {
    console.error(`Nothing changed; "${id}" keeps its previous settings.`);
    return;
  }
  saveConnection(connection);
  console.error(`Updated "${id}".`);
}

export async function removeCommand(id: string): Promise<void> {
  requireHuman("remove a connection");
  loadConnection(id);
  if (await confirm({ message: `Delete connection "${id}"?`, default: false })) {
    removeConnection(id);
    console.error(`Removed "${id}".`);
  }
}

async function testOne(connection: Connection): Promise<boolean> {
  const readonly = await recheckConnection(connection);
  if (!readonly) return false;
  saveConnection({ ...connection, readonly, updatedAt: new Date().toISOString() });
  return readonly.status === "verified";
}

export async function testCommand(id: string | undefined): Promise<void> {
  const connections = id ? [loadConnection(id)] : listConnections();
  if (connections.length === 0) console.error(NO_CONNECTIONS_HINT);
  let allPassed = true;
  for (const [index, connection] of connections.entries()) {
    if (index > 0) console.error("");
    try {
      allPassed = (await testOne(connection)) && allPassed;
    } catch (error) {
      allPassed = false;
      console.error(`❌ ${(error as Error).message}`);
    }
  }
  if (!allPassed) process.exitCode = ExitCode.Refused;
}

const STATUS_LABEL: Record<ReadOnlyStatus, string> = {
  verified: "read-only",
  override: "WRITE (override)",
  unverified: "BLOCKED (check failed)",
};

const STATUS_WIDTH = Math.max(...Object.values(STATUS_LABEL).map((label) => label.length));

function describeTarget(connection: Connection): string {
  return `${connection.user}@${connection.host}:${connection.port}/${connection.database}`;
}

function printConnectionsJson(connections: Connection[]): void {
  const summary = connections.map((connection) => ({
    id: connection.id,
    target: describeTarget(connection),
    ssh: connection.ssh ? `${connection.ssh.username}@${connection.ssh.host}` : null,
    readonly: connection.readonly.status,
  }));
  console.log(JSON.stringify(summary));
}

export function listCommand(options: { json?: boolean }): void {
  const connections = listConnections();
  if (options.json) {
    printConnectionsJson(connections);
    return;
  }
  if (connections.length === 0) {
    console.error(NO_CONNECTIONS_HINT);
    return;
  }
  const idWidth = Math.max(2, ...connections.map((connection) => connection.id.length));
  for (const connection of connections) {
    const id = connection.id.padEnd(idWidth);
    const status = STATUS_LABEL[connection.readonly.status].padEnd(STATUS_WIDTH);
    const via = connection.ssh ? `  via ssh ${connection.ssh.host}` : "";
    console.log(`${id}  ${status}  ${describeTarget(connection)}${via}`);
  }
}

const SHOW_LABEL_WIDTH = 10;

export function showCommand(id: string): void {
  const connection = loadConnection(id);
  const { ssl, ssh, readonly } = connection;
  const fields: Array<[string, string | undefined]> = [
    ["id", connection.id],
    ["engine", connection.engine],
    ["host", `${connection.host}:${connection.port}`],
    ["database", connection.database],
    ["user", connection.user],
    ["password", "******** (encrypted)"],
    ["ssl", ssl.mode],
    ["ssl ca", ssl.caPath],
    ["ssl cert", ssl.certPath],
    ["ssl key", ssl.keyPath],
    ["ssh", ssh && `${ssh.username}@${ssh.host}:${ssh.port} (${ssh.auth.method})`],
    ["ssh key", ssh?.auth.method === "key" ? ssh.auth.privateKeyPath : undefined],
    ["status", `${STATUS_LABEL[readonly.status]}, checked ${readonly.checkedAt}`],
    ["created", connection.createdAt],
    ["updated", connection.updatedAt],
  ];
  for (const [label, value] of fields) {
    if (value) console.log(`${label.padEnd(SHOW_LABEL_WIDTH)} ${value}`);
  }
  const indent = " ".repeat(SHOW_LABEL_WIDTH);
  for (const finding of readonly.findings ?? []) console.log(`${indent} - ${finding}`);
}
