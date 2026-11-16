import { statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { decryptSecret, encryptSecret } from "../src/crypto.js";
import { useTempHome } from "./helpers.js";

describe("secret encryption", () => {
  const home = useTempHome();

  it("round-trips a secret", () => {
    const secret = encryptSecret("p@ss w0rd", "prod:password");
    expect(secret.ct).not.toContain("p@ss");
    expect(decryptSecret(secret, "prod:password")).toBe("p@ss w0rd");
  });

  it("creates the key file readable only by the owner", () => {
    encryptSecret("x", "a:password");
    expect(statSync(join(home.path(), "key")).mode & 0o777).toBe(0o600);
  });

  it("refuses a secret moved to another connection", () => {
    const secret = encryptSecret("x", "prod:password");
    expect(() => decryptSecret(secret, "staging:password")).toThrow(/Cannot decrypt/);
  });

  it("refuses a tampered ciphertext", () => {
    const secret = encryptSecret("hello", "prod:password");
    const tampered = { ...secret, ct: Buffer.from("jello").toString("base64") };
    expect(() => decryptSecret(tampered, "prod:password")).toThrow(/Cannot decrypt/);
  });

  it("refuses to decrypt after the key changes", () => {
    const secret = encryptSecret("x", "prod:password");
    writeFileSync(join(home.path(), "key"), Buffer.alloc(32, 1).toString("base64"));
    expect(() => decryptSecret(secret, "prod:password")).toThrow(/Cannot decrypt/);
  });
});
