import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach } from "vitest";

/** Points QUERYCAT_HOME at a fresh temp directory for each test. */
export function useTempHome(): { path: () => string } {
  let home = "";
  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), "querycat-test-"));
    process.env.QUERYCAT_HOME = home;
  });
  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
    delete process.env.QUERYCAT_HOME;
  });
  return { path: () => home };
}
