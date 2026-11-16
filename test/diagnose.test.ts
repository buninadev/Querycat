import { describe, expect, it } from "vitest";
import { connectionChecklist, ConnectionError, diagnosePostgresError, diagnoseSshError } from "../src/diagnose.js";
import type { Connection, SshConfig } from "../src/store.js";

const connection = {
  id: "prod",
  host: "db.example.com",
  port: 5432,
  database: "app",
  user: "reader",
  ssl: { mode: "verify-full" },
} as Connection;

const ssh: SshConfig = { host: "bastion", port: 22, username: "me", auth: { method: "key", privateKeyPath: "/k" } };
const tunneled = { ...connection, ssh } as Connection;

const noScrub = (text: string) => text;
const errorWith = (message: string, code?: string) => Object.assign(new Error(message), { code });

describe("diagnosePostgresError", () => {
  it.each([
    ["password rejected", "login", errorWith('password authentication failed for user "reader"', "28P01")],
    ["missing database", "database", errorWith('database "app" does not exist', "3D000")],
    ["no CONNECT grant", "database", errorWith('permission denied for database "app"', "42501")],
    ["port closed", "reach", errorWith("connect ECONNREFUSED 1.2.3.4:5432", "ECONNREFUSED")],
    ["unknown host", "reach", errorWith("getaddrinfo ENOTFOUND db.example.com", "ENOTFOUND")],
    ["firewall drop", "reach", errorWith("timeout expired")],
    ["SSL off on server", "tls", errorWith("The server does not support SSL connections")],
    ["untrusted certificate", "tls", errorWith("self-signed certificate in certificate chain", "SELF_SIGNED_CERT_IN_CHAIN")],
    ["host name mismatch", "tls", errorWith("Hostname/IP does not match", "ERR_TLS_CERT_ALTNAME_INVALID")],
    ["pg_hba requires SSL", "login", errorWith('no pg_hba.conf entry for host "1.2.3.4", user "reader", no encryption', "28000")],
  ])("pins %s to the %s step", (_, step, error) => {
    expect(diagnosePostgresError(connection, error, noScrub).step).toBe(step);
  });

  it("suggests SSL when pg_hba refuses an unencrypted connection", () => {
    const error = errorWith('no pg_hba.conf entry for host "1.2.3.4", user "reader", no encryption', "28000");
    const diagnosis = diagnosePostgresError(connection, error, noScrub);
    expect(diagnosis.reason).toBe("the server only accepts encrypted connections");
    expect(diagnosis.fix[0]).toMatch(/require/);
  });

  it("blames the tunnel target when the SSH host could not open a channel", () => {
    const error = errorWith("Connection terminated unexpectedly");
    const diagnosis = diagnosePostgresError(tunneled, error, noScrub, "Channel open failure: Connection refused");
    expect(diagnosis.step).toBe("reach");
    expect(diagnosis.reason).toContain("SSH host could not reach db.example.com:5432");
  });

  it("explains SSH authentication failures per method", () => {
    const error = errorWith("All configured authentication methods failed");
    const diagnosis = diagnoseSshError(tunneled, ssh, error, noScrub);
    expect(diagnosis.step).toBe("ssh");
    expect(diagnosis.fix[0]).toMatch(/authorized_keys/);
  });

  it("puts reason, details and fix in the error message for non-interactive callers", () => {
    const diagnosis = diagnosePostgresError(connection, errorWith("boom", "28P01"), noScrub);
    const message = new ConnectionError(connection, diagnosis).message;
    expect(message).toContain('Could not connect to "prod": the password for user "reader" was rejected.');
    expect(message).toContain("details: boom");
    expect(message).toContain("fix: Run `qcat edit prod`");
  });
});

describe("connectionChecklist", () => {
  it("passes every step when connected", () => {
    const items = connectionChecklist(tunneled);
    expect(items.map((item) => item.label)).toEqual([
      "SSH tunnel via me@bastion:22",
      "Reach db.example.com:5432 from the SSH host",
      "TLS (verify-full)",
      "Log in as reader",
      "Open database app",
    ]);
    expect(items.every((item) => item.state === "pass")).toBe(true);
  });

  it("passes steps before the failure and skips the ones after", () => {
    const diagnosis = diagnosePostgresError(connection, errorWith("x", "28P01"), noScrub);
    const states = connectionChecklist(connection, diagnosis).map((item) => item.state);
    expect(states).toEqual(["pass", "pass", "fail", "skip"]);
  });
});
