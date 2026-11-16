#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { Command } from "commander";
import {
  addCommand,
  editCommand,
  listCommand,
  removeCommand,
  showCommand,
  testCommand,
} from "./commands/connections.js";
import { DEFAULT_LOG_ENTRIES, logCommand, queryCommand, schemaCommand } from "./commands/query.js";
import { QuerycatError } from "./errors.js";
import { AGENT_MAX_ROW_LIMIT, DEFAULT_ROW_LIMIT, MAX_TIMEOUT_SECONDS } from "./limits.js";
import { OUTPUT_FORMATS } from "./output.js";

const packageJsonUrl = new URL("../package.json", import.meta.url);
const { version } = JSON.parse(readFileSync(packageJsonUrl, "utf8")) as { version: string };
const FORMAT_CHOICES = OUTPUT_FORMATS.join(" | ");

const program = new Command()
  .name("qcat")
  .description("Read-only Postgres queries against saved connections. Credentials never leave the tool.")
  .version(version);

program
  .command("add <id>")
  .description("add a connection (interactive). It is saved only if it passes the read-only check")
  .option("--url <url>", "prefill the form from a postgres:// URL")
  .action(addCommand);

program
  .command("edit <id>")
  .description("change a saved connection (interactive), then re-check it")
  .action(editCommand);

program.command("remove <id>").description("delete a saved connection (interactive)").action(removeCommand);

program
  .command("list")
  .description("list saved connections (no secrets)")
  .option("--json", "output JSON")
  .action(listCommand);

program.command("show <id>").description("show a connection's details, password masked").action(showCommand);

program
  .command("test [id]")
  .description("re-run the connection and read-only check (all connections when no id is given)")
  .action(testCommand);

program
  .command("query <id> [sql]")
  .description("run one read-only SQL statement")
  .option("-f, --file <path>", "read SQL from a file (stdin is also accepted)")
  .option(
    "-l, --limit <rows>",
    `max rows returned (default ${DEFAULT_ROW_LIMIT}, above ${AGENT_MAX_ROW_LIMIT} needs a human)`,
  )
  .option("-t, --timeout <seconds>", `statement timeout (default and max ${MAX_TIMEOUT_SECONDS})`)
  .option("--format <format>", FORMAT_CHOICES, "table")
  .option("--json", "shorthand for --format json")
  .action(queryCommand);

program
  .command("schema <id> [table]")
  .description("list tables, or describe one table's columns, keys and references")
  .option("--format <format>", FORMAT_CHOICES, "table")
  .option("--json", "shorthand for --format json")
  .action(schemaCommand);

program
  .command("log [id]")
  .description("show recent queries from the local audit log")
  .option("-n, --tail <count>", "number of entries", String(DEFAULT_LOG_ENTRIES))
  .option("--json", "output JSON")
  .action(logCommand);

function isPromptCancelled(error: unknown): boolean {
  return error instanceof Error && error.name === "ExitPromptError";
}

try {
  await program.parseAsync();
} catch (error) {
  if (isPromptCancelled(error)) {
    process.exitCode = 130;
  } else if (error instanceof QuerycatError) {
    console.error(`error: ${error.message}`);
    process.exitCode = error.exitCode;
  } else {
    console.error(`unexpected error: ${(error as Error).stack ?? error}`);
    process.exitCode = 1;
  }
}
