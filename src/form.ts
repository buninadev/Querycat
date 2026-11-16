import { existsSync } from "node:fs";
import { confirm, input, number, password, select } from "@inquirer/prompts";
import { QuerycatError } from "./errors.js";
import { toAbsolutePath } from "./paths.js";
import type { Secrets, SslConfig, SslMode } from "./store.js";

export type SshMethod = "agent" | "key" | "password";

/** Everything the form collects, with secrets still in plaintext. */
export interface ConnectionInput {
  host: string;
  port: number;
  database: string;
  user: string;
  ssl: SslConfig;
  ssh?: {
    host: string;
    port: number;
    username: string;
    method: SshMethod;
    privateKeyPath?: string;
  };
  secrets: Secrets;
}

const DEFAULT_POSTGRES_PORT = 5432;
const DEFAULT_SSH_PORT = 22;
const MAX_PORT = 65535;

const SSL_MODES: Array<{ value: SslMode; name: string }> = [
  { value: "disable", name: "disable      (no TLS, local/tunneled only)" },
  { value: "require", name: "require      (TLS, server certificate not checked)" },
  { value: "verify-ca", name: "verify-ca    (TLS, certificate checked against CA)" },
  { value: "verify-full", name: "verify-full  (TLS, certificate + hostname checked)" },
];

const required = (value: string) => value.trim().length > 0 || "Required";

const optionalExistingFile = (value: string) =>
  !value.trim() || existsSync(toAbsolutePath(value.trim())) || "File not found";

const requiredExistingFile = (value: string) => (value.trim() ? optionalExistingFile(value) : "Required");

const optionalPath = (value: string) => (value.trim() ? toAbsolutePath(value.trim()) : undefined);

/** Parses postgres://user:pass@host:port/db?sslmode=... into form defaults. */
export function parseConnectionUrl(url: string): Partial<ConnectionInput> {
  if (!URL.canParse(url)) throw new QuerycatError("--url is not a valid URL.");
  const parsed = new URL(url);
  if (!["postgres:", "postgresql:"].includes(parsed.protocol)) {
    throw new QuerycatError(`Expected a postgres:// URL, got ${parsed.protocol}`);
  }
  const sslMode = SSL_MODES.find((m) => m.value === parsed.searchParams.get("sslmode"))?.value;
  return {
    host: parsed.hostname,
    port: parsed.port ? Number(parsed.port) : DEFAULT_POSTGRES_PORT,
    database: decodeURIComponent(parsed.pathname.slice(1)),
    user: decodeURIComponent(parsed.username),
    ssl: sslMode ? { mode: sslMode } : undefined,
    secrets: { password: decodeURIComponent(parsed.password) },
  };
}

function isLocalHost(host: string): boolean {
  return ["localhost", "127.0.0.1", "::1"].includes(host);
}

async function promptPort(message: string, defaultPort: number): Promise<number> {
  return (await number({ message, default: defaultPort, min: 1, max: MAX_PORT, required: true })) as number;
}

/** Keeps the current secret when the user leaves the field empty. */
async function secretField(message: string, current: string | undefined): Promise<string> {
  const hint = current ? " (leave empty to keep current)" : "";
  const value = await password({ message: `${message}${hint}:`, mask: "*" });
  return value || current || "";
}

async function promptCertificates(defaults: SslConfig | undefined, mode: SslMode): Promise<SslConfig> {
  if (mode === "disable") return { mode };
  const hasCerts = Boolean(defaults?.caPath || defaults?.certPath || defaults?.keyPath);
  const useCerts = await confirm({ message: "Use certificate files (CA / client cert)?", default: hasCerts });
  if (!useCerts) return { mode };
  const file = (message: string, current?: string) =>
    input({ message: `${message} (optional):`, default: current, validate: optionalExistingFile });
  return {
    mode,
    caPath: optionalPath(await file("CA certificate path", defaults?.caPath)),
    certPath: optionalPath(await file("Client certificate path", defaults?.certPath)),
    keyPath: optionalPath(await file("Client key path", defaults?.keyPath)),
  };
}

async function promptSsh(
  defaults: ConnectionInput["ssh"],
  currentSecrets: Partial<Secrets>,
): Promise<{ ssh?: ConnectionInput["ssh"]; sshPassword?: string; sshPassphrase?: string }> {
  const useSsh = await confirm({ message: "Connect through an SSH tunnel?", default: Boolean(defaults) });
  if (!useSsh) return {};

  const host = await input({ message: "SSH host:", default: defaults?.host, validate: required });
  const port = await promptPort("SSH port:", defaults?.port ?? DEFAULT_SSH_PORT);
  const username = await input({ message: "SSH user:", default: defaults?.username, validate: required });
  const method = await select<SshMethod>({
    message: "SSH authentication:",
    default: defaults?.method ?? "key",
    choices: [
      { value: "key", name: "private key file" },
      { value: "agent", name: "ssh-agent (SSH_AUTH_SOCK)" },
      { value: "password", name: "password" },
    ],
  });

  const ssh = { host, port, username, method };
  if (method === "agent") return { ssh };
  if (method === "password") {
    return { ssh, sshPassword: await secretField("SSH password", currentSecrets.sshPassword) };
  }
  const keyPath = await input({
    message: "Private key path:",
    default: defaults?.privateKeyPath ?? "~/.ssh/id_ed25519",
    validate: requiredExistingFile,
  });
  const passphrase = await secretField("Key passphrase (empty if none)", currentSecrets.sshPassphrase);
  return { ssh: { ...ssh, privateKeyPath: toAbsolutePath(keyPath.trim()) }, sshPassphrase: passphrase || undefined };
}

export async function promptConnection(defaults: Partial<ConnectionInput> = {}): Promise<ConnectionInput> {
  const host = await input({ message: "Host:", default: defaults.host, validate: required });
  const port = await promptPort("Port:", defaults.port ?? DEFAULT_POSTGRES_PORT);
  const database = await input({ message: "Database:", default: defaults.database, validate: required });
  const user = await input({ message: "User:", default: defaults.user, validate: required });
  const dbPassword = await secretField("Password", defaults.secrets?.password);

  const sslMode = await select<SslMode>({
    message: "SSL mode:",
    default: defaults.ssl?.mode ?? (isLocalHost(host) ? "disable" : "require"),
    choices: SSL_MODES,
  });
  const ssl = await promptCertificates(defaults.ssl, sslMode);
  const { ssh, sshPassword, sshPassphrase } = await promptSsh(defaults.ssh, defaults.secrets ?? {});

  return {
    host: host.trim(),
    port,
    database: database.trim(),
    user: user.trim(),
    ssl,
    ssh,
    secrets: { password: dbPassword, sshPassword, sshPassphrase },
  };
}
