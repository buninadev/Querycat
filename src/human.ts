import { input } from "@inquirer/prompts";
import { ExitCode, QuerycatError } from "./errors.js";

/**
 * Agents run commands without a terminal attached. Anything that changes
 * stored connections or loosens a safety limit requires one.
 */
export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

export function requireHuman(action: string): void {
  if (!isInteractive()) {
    throw new QuerycatError(
      `Refusing to ${action}: this needs a human at an interactive terminal.`,
      ExitCode.Refused,
    );
  }
}

/** Goes to stderr, so warnings never end up in piped query output. */
export function warn(message: string): void {
  console.error(`⚠️  ${message}`);
}

/** A deliberate confirmation: the user has to type the exact word back. */
export async function confirmByTyping(word: string, message: string): Promise<boolean> {
  const answer = await input({ message: `${message} Type "${word}" to confirm:` });
  return answer.trim() === word;
}
