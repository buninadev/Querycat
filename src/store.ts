import { existsSync, readdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { decryptSecret, encryptSecret, type EncryptedSecret } from "./crypto.js";
import { QuerycatError } from "./errors.js";
import { connectionsDir, ensurePrivateDir, PRIVATE_FILE_MODE } from "./paths.js";

export type SslMode = "disable" | "require" | "verify-ca" | "verify-full";

export interface SslConfig {
  mode: SslMode;
  caPath?: string;
  certPath?: string;
  keyPath?: string;
}

export type SshAuth =
  | { method: "agent" }
  | { method: "key"; privateKeyPath: string; passphrase?: EncryptedSecret }
  | { method: "password"; password: EncryptedSecret };

export interface SshConfig {
  host: string;
  port: number;
  username: string;
  auth: SshAuth;
}

/**
 * verified   – the read-only check passed.
 * override   – the check failed and a human chose to keep the connection anyway.
 * unverified – a later check failed; queries are refused until it is fixed or overridden.
 */
export type ReadOnlyStatus = "verified" | "override" | "unverified";

export interface ReadOnlyRecord {
  status: ReadOnlyStatus;
  checkedAt: string;
  reason?: string;
  findings?: string[];
}

export interface Connection {
  id: string;
  engine: "postgres";
  host: string;
  port: number;
  database: string;
  user: string;
  password: EncryptedSecret;
  ssl: SslConfig;
  ssh?: SshConfig;
  readonly: ReadOnlyRecord;
  createdAt: string;
  updatedAt: string;
}

/** Plaintext secrets, only ever held in memory. */
export interface Secrets {
  password: string;
  sshPassword?: string;
  sshPassphrase?: string;
}

const ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,62}$/;

export function assertValidId(id: string): void {
  if (!ID_PATTERN.test(id)) {
    throw new QuerycatError(
      `Invalid id "${id}". Use lowercase letters, digits, "-" or "_" (max 63 chars, starting with a letter or digit).`,
    );
  }
}

function connectionPath(id: string): string {
  assertValidId(id);
  return join(connectionsDir(), `${id}.json`);
}

export function connectionExists(id: string): boolean {
  return existsSync(connectionPath(id));
}

export function loadConnection(id: string): Connection {
  const path = connectionPath(id);
  if (!existsSync(path)) {
    throw new QuerycatError(`No connection named "${id}". Run \`qcat list\` to see the saved ones.`);
  }
  return JSON.parse(readFileSync(path, "utf8")) as Connection;
}

export function saveConnection(connection: Connection): void {
  ensurePrivateDir(connectionsDir());
  const path = connectionPath(connection.id);
  const tempPath = `${path}.tmp`;
  writeFileSync(tempPath, JSON.stringify(connection, null, 2) + "\n", { mode: PRIVATE_FILE_MODE });
  renameSync(tempPath, path);
}

export function removeConnection(id: string): void {
  rmSync(connectionPath(id));
}

export function listConnections(): Connection[] {
  const dir = connectionsDir();
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => loadConnection(file.slice(0, -".json".length)))
    .sort((a, b) => a.id.localeCompare(b.id));
}

const secretContext = {
  password: (id: string) => `${id}:password`,
  sshPassword: (id: string) => `${id}:ssh.password`,
  sshPassphrase: (id: string) => `${id}:ssh.passphrase`,
};

export function encryptPassword(id: string, password: string): EncryptedSecret {
  return encryptSecret(password, secretContext.password(id));
}

export function encryptSshPassword(id: string, password: string): EncryptedSecret {
  return encryptSecret(password, secretContext.sshPassword(id));
}

export function encryptSshPassphrase(id: string, passphrase: string): EncryptedSecret {
  return encryptSecret(passphrase, secretContext.sshPassphrase(id));
}

export function decryptSecrets(connection: Connection): Secrets {
  const { id, ssh } = connection;
  const secrets: Secrets = { password: decryptSecret(connection.password, secretContext.password(id)) };
  if (ssh?.auth.method === "password") {
    secrets.sshPassword = decryptSecret(ssh.auth.password, secretContext.sshPassword(id));
  }
  if (ssh?.auth.method === "key" && ssh.auth.passphrase) {
    secrets.sshPassphrase = decryptSecret(ssh.auth.passphrase, secretContext.sshPassphrase(id));
  }
  return secrets;
}
