import { mkdirSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

const PRIVATE_DIR_MODE = 0o700;
export const PRIVATE_FILE_MODE = 0o600;

export function querycatHome(): string {
  return process.env.QUERYCAT_HOME ?? join(homedir(), ".config", "querycat");
}

export function connectionsDir(): string {
  return join(querycatHome(), "connections");
}

export function keyFilePath(): string {
  return join(querycatHome(), "key");
}

export function auditLogPath(): string {
  return join(querycatHome(), "audit.log");
}

/** Turns "~/x" or a relative path into an absolute one, so stored paths work from any directory. */
export function toAbsolutePath(path: string): string {
  if (path === "~" || path.startsWith("~/")) return join(homedir(), path.slice(1));
  return resolve(path);
}

export function ensurePrivateDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: PRIVATE_DIR_MODE });
  chmodSync(dir, PRIVATE_DIR_MODE);
}
