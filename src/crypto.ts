import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { ensurePrivateDir, keyFilePath, PRIVATE_FILE_MODE, querycatHome } from "./paths.js";
import { QuerycatError } from "./errors.js";

const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32;
const IV_BYTES = 12;

export interface EncryptedSecret {
  v: 1;
  alg: typeof ALGORITHM;
  iv: string;
  tag: string;
  ct: string;
}

/**
 * The key file lives next to the connections. Anyone who can read both can
 * decrypt the secrets: this keeps passwords out of plain sight, nothing more.
 */
function loadOrCreateKey(): Buffer {
  const path = keyFilePath();
  if (existsSync(path)) {
    const key = Buffer.from(readFileSync(path, "utf8").trim(), "base64");
    if (key.length !== KEY_BYTES) {
      throw new QuerycatError(`Key file ${path} is corrupted.`);
    }
    return key;
  }
  ensurePrivateDir(querycatHome());
  const key = randomBytes(KEY_BYTES);
  writeFileSync(path, key.toString("base64") + "\n", { mode: PRIVATE_FILE_MODE });
  return key;
}

/** `context` binds the ciphertext to one connection field, so secrets can't be swapped between files. */
export function encryptSecret(plaintext: string, context: string): EncryptedSecret {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, loadOrCreateKey(), iv);
  cipher.setAAD(Buffer.from(context));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return {
    v: 1,
    alg: ALGORITHM,
    iv: iv.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ct: ct.toString("base64"),
  };
}

export function decryptSecret(secret: EncryptedSecret, context: string): string {
  try {
    const decipher = createDecipheriv(ALGORITHM, loadOrCreateKey(), Buffer.from(secret.iv, "base64"));
    decipher.setAAD(Buffer.from(context));
    decipher.setAuthTag(Buffer.from(secret.tag, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(secret.ct, "base64")), decipher.final()]).toString("utf8");
  } catch {
    throw new QuerycatError(
      `Cannot decrypt the stored secret (${context}). The key file may have changed; re-enter it with \`qcat edit\`.`,
    );
  }
}
