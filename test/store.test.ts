import { statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  assertValidId,
  connectionExists,
  decryptSecrets,
  encryptPassword,
  encryptSshPassphrase,
  listConnections,
  loadConnection,
  removeConnection,
  saveConnection,
  type Connection,
} from "../src/store.js";
import { useTempHome } from "./helpers.js";

function makeConnection(id: string, overrides: Partial<Connection> = {}): Connection {
  const now = new Date().toISOString();
  return {
    id,
    engine: "postgres",
    host: "db.example.com",
    port: 5432,
    database: "app",
    user: "reader",
    password: encryptPassword(id, "secret"),
    ssl: { mode: "require" },
    readonly: { status: "verified", checkedAt: now },
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

describe("connection store", () => {
  const home = useTempHome();

  it("accepts simple ids and rejects path-like ones", () => {
    expect(() => assertValidId("prod-main_2")).not.toThrow();
    for (const bad of ["", "../etc", "Prod", "a/b", "-start", "x".repeat(64)]) {
      expect(() => assertValidId(bad)).toThrow(/Invalid id/);
    }
  });

  it("saves, lists, loads and removes connections", () => {
    saveConnection(makeConnection("staging"));
    saveConnection(makeConnection("prod"));
    expect(listConnections().map((c) => c.id)).toEqual(["prod", "staging"]);
    expect(loadConnection("prod").host).toBe("db.example.com");

    removeConnection("prod");
    expect(connectionExists("prod")).toBe(false);
    expect(() => loadConnection("prod")).toThrow(/No connection named/);
  });

  it("writes files only the owner can read", () => {
    saveConnection(makeConnection("prod"));
    expect(statSync(join(home.path(), "connections")).mode & 0o777).toBe(0o700);
    expect(statSync(join(home.path(), "connections", "prod.json")).mode & 0o777).toBe(0o600);
  });

  it("never stores the password in plaintext", () => {
    saveConnection(makeConnection("prod"));
    expect(JSON.stringify(loadConnection("prod"))).not.toContain("secret");
  });

  it("decrypts the database and SSH secrets", () => {
    const connection = makeConnection("prod", {
      ssh: {
        host: "bastion",
        port: 22,
        username: "me",
        auth: { method: "key", privateKeyPath: "/k", passphrase: encryptSshPassphrase("prod", "phrase") },
      },
    });
    expect(decryptSecrets(connection)).toEqual({ password: "secret", sshPassphrase: "phrase" });
  });
});
