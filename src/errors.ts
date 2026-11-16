export const ExitCode = {
  Ok: 0,
  QueryFailed: 1,
  ConnectionFailed: 2,
  Usage: 3,
  Refused: 4,
} as const;

export type ExitCodeValue = (typeof ExitCode)[keyof typeof ExitCode];

export class QuerycatError extends Error {
  constructor(
    message: string,
    readonly exitCode: ExitCodeValue = ExitCode.Usage,
  ) {
    super(message);
  }
}

/**
 * Shorter secrets are left alone: replacing every "x" in a message would garble it
 * ("timeout e***pired") while protecting almost nothing.
 */
const MIN_SCRUBBED_SECRET_LENGTH = 4;

/** Removes every known secret from a message before it reaches the terminal. */
export function scrubSecrets(message: string, secrets: Array<string | undefined>): string {
  let scrubbed = message;
  for (const secret of secrets) {
    if (secret && secret.length >= MIN_SCRUBBED_SECRET_LENGTH) scrubbed = scrubbed.split(secret).join("***");
  }
  return scrubbed;
}
