import { skipAfterFailure, type ChecklistItem } from "./checklist.js";
import { ExitCode, QuerycatError } from "./errors.js";
import { CONNECT_TIMEOUT_MS, SSH_READY_TIMEOUT_MS } from "./limits.js";
import type { Connection, SshConfig } from "./store.js";

/** The order in which a connection attempt can fail. */
export type ConnectionStep = "ssh" | "reach" | "tls" | "login" | "database";

export interface Diagnosis {
  step: ConnectionStep;
  reason: string;
  fix: string[];
  /** The underlying error message, secrets already removed. */
  rawMessage: string;
}

type Classification = Omit<Diagnosis, "rawMessage">;

interface ErrorFacts {
  message: string;
  code?: string;
  path?: string;
}

const UNTRUSTED_CERT_CODES = new Set([
  "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
]);

const DNS_FAILURE_CODES = new Set(["ENOTFOUND", "EAI_AGAIN"]);
const UNREACHABLE_CODES = new Set(["ETIMEDOUT", "EHOSTUNREACH", "ENETUNREACH"]);

const SSH_AUTH_FIX: Record<SshConfig["auth"]["method"], string> = {
  key: "Make sure the key's public half is in ~/.ssh/authorized_keys for that user on the SSH host.",
  password: "Re-enter the SSH password.",
  agent: "Make sure ssh-agent holds a key the SSH host accepts (`ssh-add -l`).",
};

function factsOf(error: unknown, scrub: (text: string) => string): ErrorFacts {
  const { message, code, path } = error as { message?: string; code?: string; path?: string };
  return { message: scrub(message ?? String(error)), code, path };
}

function hasCode(error: ErrorFacts, codes: Set<string>): boolean {
  return error.code !== undefined && codes.has(error.code);
}

const seconds = (ms: number) => ms / 1000;

// In both classifiers the first match wins, so order matters: specific cases
// come before the generic ones that would also match them.

function classifySshError(id: string, ssh: SshConfig, error: ErrorFacts): Classification {
  const where = `${ssh.host}:${ssh.port}`;
  const edit = `Run \`qcat edit ${id}\` and correct the SSH settings.`;
  const step = "ssh";

  if (error.code === "ENOENT") {
    return { step, reason: `SSH key file not found: ${error.path}`, fix: [edit] };
  }
  if (/SSH_AUTH_SOCK/.test(error.message)) {
    return {
      step,
      reason: "ssh-agent is not running in this shell",
      fix: ["Start ssh-agent and `ssh-add` your key, or switch to a key file."],
    };
  }
  if (/passphrase/i.test(error.message)) {
    return { step, reason: "the SSH key passphrase is missing or wrong", fix: [edit] };
  }
  if (/Cannot parse privateKey/i.test(error.message)) {
    return {
      step,
      reason: "the SSH key file is not a valid private key",
      fix: ["Point to the private key (e.g. ~/.ssh/id_ed25519), not the .pub file.", edit],
    };
  }
  if (hasCode(error, DNS_FAILURE_CODES)) {
    return { step, reason: `SSH host "${ssh.host}" could not be found (DNS)`, fix: ["Check the SSH host name.", edit] };
  }
  if (error.code === "ECONNREFUSED") {
    return { step, reason: `nothing accepts SSH connections on ${where}`, fix: ["Check the SSH host and port.", edit] };
  }
  if (/timed out|ETIMEDOUT/i.test(error.message)) {
    return {
      step,
      reason: `${where} did not answer within ${seconds(SSH_READY_TIMEOUT_MS)} seconds`,
      fix: ["Check the host, and whether you need a VPN or a firewall allowlist for your IP."],
    };
  }
  if (/authentication methods failed/i.test(error.message)) {
    return {
      step,
      reason: `the SSH host rejected user "${ssh.username}" (${ssh.auth.method} auth)`,
      fix: [SSH_AUTH_FIX[ssh.auth.method], edit],
    };
  }
  return { step, reason: "the SSH connection failed", fix: [edit] };
}

function classifyPostgresError(connection: Connection, error: ErrorFacts, forwardError?: string): Classification {
  const { host, port, user, database, id } = connection;
  const where = `${host}:${port}`;
  const edit = `Run \`qcat edit ${id}\` to change the connection details.`;

  if (forwardError) {
    return {
      step: "reach",
      reason: `the SSH host could not reach ${where}: ${forwardError}`,
      fix: [
        "Through a tunnel, host and port must be as seen from the SSH host (often a private IP or internal name).",
        edit,
      ],
    };
  }
  if (error.code === "ENOENT") {
    return { step: "tls", reason: `certificate file not found: ${error.path}`, fix: [edit] };
  }
  if (hasCode(error, DNS_FAILURE_CODES)) {
    return {
      step: "reach",
      reason: `host "${host}" could not be found (DNS)`,
      fix: ["Check the host name. If it only resolves inside a private network, connect through an SSH tunnel.", edit],
    };
  }
  if (error.code === "ECONNREFUSED") {
    return {
      step: "reach",
      reason: `nothing is listening on ${where}`,
      fix: ["Check the port, and that Postgres listens on that address (listen_addresses).", edit],
    };
  }
  if (hasCode(error, UNREACHABLE_CODES) || /timeout/i.test(error.message)) {
    return {
      step: "reach",
      reason: `no answer from ${where} within ${seconds(CONNECT_TIMEOUT_MS)} seconds`,
      fix: [
        "A firewall or security group is probably dropping the connection: allowlist your IP, use your VPN, or connect through an SSH tunnel.",
      ],
    };
  }
  if (/does not support SSL/i.test(error.message)) {
    return {
      step: "tls",
      reason: "the server has SSL turned off",
      fix: ['Set SSL mode to "disable" if the network is private (e.g. tunneled), or enable SSL on the server.', edit],
    };
  }
  if (hasCode(error, UNTRUSTED_CERT_CODES) || /verify the first certificate/i.test(error.message)) {
    return {
      step: "tls",
      reason: "the server's certificate is not signed by a CA this machine trusts",
      fix: [
        "Add the CA certificate file in the form (cloud providers publish one, e.g. the AWS RDS bundle).",
        'Or use SSL mode "require" (encrypted, certificate not checked).',
        edit,
      ],
    };
  }
  if (error.code === "ERR_TLS_CERT_ALTNAME_INVALID") {
    return {
      step: "tls",
      reason: `the certificate is issued for a different host name than "${host}"`,
      fix: ['Connect using the host name on the certificate, or use SSL mode "verify-ca".', edit],
    };
  }
  if (error.code === "CERT_HAS_EXPIRED") {
    return {
      step: "tls",
      reason: "the server's certificate has expired",
      fix: ['Ask the database owner to renew it, or use SSL mode "require" meanwhile.'],
    };
  }
  if (error.code === "28P01") {
    return {
      step: "login",
      reason: `the password for user "${user}" was rejected`,
      fix: ["Re-enter the password and check the user name.", edit],
    };
  }
  if (error.code === "28000" && /pg_hba/.test(error.message)) {
    const requiresEncryption = /no encryption|SSL off/i.test(error.message);
    if (requiresEncryption) {
      return {
        step: "login",
        reason: "the server only accepts encrypted connections",
        fix: ['Set SSL mode to "require" or stricter.', edit],
      };
    }
    return {
      step: "login",
      reason: "the server does not allow this user from your address",
      fix: ["Ask the database owner to allow your IP in pg_hba.conf, or connect through an SSH tunnel."],
    };
  }
  if (error.code === "28000") {
    return {
      step: "login",
      reason: `user "${user}" does not exist or may not log in`,
      fix: ["Check the user name.", edit],
    };
  }
  if (error.code === "3D000") {
    return {
      step: "database",
      reason: `database "${database}" does not exist`,
      fix: ["Check the database name (it is case-sensitive).", edit],
    };
  }
  if (error.code === "42501") {
    return {
      step: "database",
      reason: `user "${user}" may not connect to database "${database}"`,
      fix: [`GRANT CONNECT ON DATABASE "${database}" TO "${user}";`],
    };
  }
  if (error.code === "53300") {
    return {
      step: "login",
      reason: "the server has no free connection slots",
      fix: ["Try again later, or ask the database owner to raise max_connections."],
    };
  }
  if (/terminated unexpectedly/i.test(error.message)) {
    return {
      step: "reach",
      reason: "the server closed the connection immediately",
      fix: ["Often an SSL mismatch or a proxy in between: try another SSL mode.", edit],
    };
  }
  return { step: "login", reason: "the connection failed", fix: [edit] };
}

/** Explains a failure to open the SSH tunnel. */
export function diagnoseSshError(
  connection: Connection,
  ssh: SshConfig,
  error: unknown,
  scrub: (text: string) => string,
): Diagnosis {
  const facts = factsOf(error, scrub);
  return { ...classifySshError(connection.id, ssh, facts), rawMessage: facts.message };
}

/**
 * Explains a failure to connect to Postgres. `forwardError` is the tunnel's
 * reason for refusing to reach the database, which outranks the Postgres error.
 */
export function diagnosePostgresError(
  connection: Connection,
  error: unknown,
  scrub: (text: string) => string,
  forwardError?: string,
): Diagnosis {
  const facts = factsOf(error, scrub);
  return { ...classifyPostgresError(connection, facts, forwardError), rawMessage: facts.message };
}

export class ConnectionError extends QuerycatError {
  constructor(
    readonly connection: Connection,
    readonly diagnosis: Diagnosis,
  ) {
    const lines = [
      `Could not connect to "${connection.id}": ${diagnosis.reason}.`,
      `  details: ${diagnosis.rawMessage}`,
      ...diagnosis.fix.map((step) => `  fix: ${step}`),
    ];
    super(lines.join("\n"), ExitCode.ConnectionFailed);
  }
}

function stepLabels(connection: Connection): Array<[ConnectionStep, string]> {
  const { ssh, ssl, host, port, user, database } = connection;
  const steps: Array<[ConnectionStep, string]> = [];
  if (ssh) steps.push(["ssh", `SSH tunnel via ${ssh.username}@${ssh.host}:${ssh.port}`]);
  steps.push(["reach", `Reach ${host}:${port}${ssh ? " from the SSH host" : ""}`]);
  steps.push(["tls", ssl.mode === "disable" ? "TLS off" : `TLS (${ssl.mode})`]);
  steps.push(["login", `Log in as ${user}`]);
  steps.push(["database", `Open database ${database}`]);
  return steps;
}

/** One line per connection step; with a diagnosis, the failing step carries its reason and fix. */
export function connectionChecklist(connection: Connection, diagnosis?: Diagnosis): ChecklistItem[] {
  const items = stepLabels(connection).map(([step, label]): ChecklistItem => {
    if (step !== diagnosis?.step) return { label, state: "pass" };
    const details = [diagnosis.reason, `error: ${diagnosis.rawMessage}`];
    return { label, state: "fail", details, fix: diagnosis.fix };
  });
  return skipAfterFailure(items);
}
