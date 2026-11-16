# Using querycat from a coding agent

## Snippet for a project's CLAUDE.md / AGENTS.md

```markdown
## Database access

Query non-local databases only through `qcat`. Never ask for credentials or
connection strings.

- `qcat list --json`: available connection ids
- `qcat schema <id>`: tables; `qcat schema <id> <table>`: columns and references
- `qcat query <id> "<one SQL statement>" --format csv`: results (csv is compact; use --json for nested data)

Rules:
- One statement per call. Everything runs in a read-only transaction; writes fail.
- Default limit is 500 rows. Raise it with `--limit N` up to 2000. Prefer aggregates
  (count, group by) and filters over pulling many rows.
- Timeout is 60 s. Add WHERE clauses and LIMIT on large tables.
- Exit code 4 means a safety rule refused the command. Tell the user; don't work around it.
```

## Claude Code permissions

Add this to `~/.claude/settings.json` or the project's `.claude/settings.json`:

```json
{
  "permissions": {
    "allow": [
      "Bash(qcat list:*)",
      "Bash(qcat schema:*)",
      "Bash(qcat query:*)"
    ],
    "deny": [
      "Read(~/.config/querycat/**)",
      "Edit(~/.config/querycat/**)",
      "Bash(cat ~/.config/querycat:*)",
      "Bash(qcat add:*)",
      "Bash(qcat edit:*)",
      "Bash(qcat remove:*)"
    ]
  }
}
```

Be honest about the limit here. The deny rules block the obvious ways to read the secrets folder. A shell command can still reach it by other means (another tool, a script, a different path spelling). The real protections are:

1. **Use a read-only database role.** That's what `qcat add` checks for.
2. **Read-only transactions on every query**, which Postgres enforces itself.
3. Management commands refuse to run without an interactive terminal.
