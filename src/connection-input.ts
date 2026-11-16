import type { ConnectionInput } from "./form.js";
import {
  encryptPassword,
  encryptSshPassphrase,
  encryptSshPassword,
  type Connection,
  type ReadOnlyRecord,
  type Secrets,
  type SshConfig,
} from "./store.js";

function toSshConfig(id: string, input: ConnectionInput): SshConfig | undefined {
  const { ssh, secrets } = input;
  if (!ssh) return undefined;
  const base = { host: ssh.host, port: ssh.port, username: ssh.username };
  switch (ssh.method) {
    case "agent":
      return { ...base, auth: { method: "agent" } };
    case "password":
      return { ...base, auth: { method: "password", password: encryptSshPassword(id, secrets.sshPassword ?? "") } };
    case "key":
      return {
        ...base,
        auth: {
          method: "key",
          privateKeyPath: ssh.privateKeyPath ?? "",
          passphrase: secrets.sshPassphrase ? encryptSshPassphrase(id, secrets.sshPassphrase) : undefined,
        },
      };
  }
}

/** Turns what the form collected into a storable connection, encrypting its secrets. */
export function toConnection(
  id: string,
  input: ConnectionInput,
  readonly: ReadOnlyRecord,
  createdAt?: string,
): Connection {
  const now = new Date().toISOString();
  return {
    id,
    engine: "postgres",
    host: input.host,
    port: input.port,
    database: input.database,
    user: input.user,
    password: encryptPassword(id, input.secrets.password),
    ssl: input.ssl,
    ssh: toSshConfig(id, input),
    readonly,
    createdAt: createdAt ?? now,
    updatedAt: now,
  };
}

/** Turns a saved connection back into form defaults, for editing. */
export function toConnectionInput(connection: Connection, secrets: Secrets): ConnectionInput {
  const { ssh } = connection;
  return {
    host: connection.host,
    port: connection.port,
    database: connection.database,
    user: connection.user,
    ssl: connection.ssl,
    ssh: ssh && {
      host: ssh.host,
      port: ssh.port,
      username: ssh.username,
      method: ssh.auth.method,
      privateKeyPath: ssh.auth.method === "key" ? ssh.auth.privateKeyPath : undefined,
    },
    secrets,
  };
}
