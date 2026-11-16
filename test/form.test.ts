import { describe, expect, it } from "vitest";
import { parseConnectionUrl } from "../src/form.js";

describe("parseConnectionUrl", () => {
  it("decodes every part of a postgres URL", () => {
    expect(parseConnectionUrl("postgresql://ro%20user:p%40ss@db.example.com:6543/my%20db?sslmode=verify-full")).toEqual({
      host: "db.example.com",
      port: 6543,
      database: "my db",
      user: "ro user",
      ssl: { mode: "verify-full" },
      secrets: { password: "p@ss" },
    });
  });

  it("leaves SSL unset when the URL has no sslmode, so the form picks a default", () => {
    const parsed = parseConnectionUrl("postgres://u:p@localhost/app");
    expect(parsed.ssl).toBeUndefined();
    expect(parsed.port).toBe(5432);
  });

  it("rejects non-postgres URLs", () => {
    expect(() => parseConnectionUrl("mysql://u:p@h/db")).toThrow(/postgres:\/\//);
  });
});
