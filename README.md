# querycat (`qcat`)

A small CLI for running **read-only** queries against saved Postgres connections.
You add a connection once. After that, you or a coding agent can query it by name,
and the password is never printed.

```sh
qcat add prod-main                 # interactive; saved only if the role is read-only
qcat query prod-main "SELECT id, email FROM users ORDER BY id DESC" --limit 20
qcat schema prod-main orders       # columns, primary key, references
```

## Install

Needs Node 20 or newer.

```sh
git clone <this repo> querycat && cd querycat
npm install          # also builds dist/
npm link             # puts `querycat` and `qcat` on your PATH
```

To uninstall: `npm unlink -g querycat`.

## Commands

| Command | What it does |
|---|---|
| `qcat add <id> [--url postgres://...]` | Interactive form: host, port, database, user, password, SSL mode, optional certificate files, optional SSH tunnel. Connects and runs the read-only check before saving. |
| `qcat edit <id>` | Same form, prefilled. Leave a secret empty to keep it. Re-runs the check. |
| `qcat remove <id>` | Deletes a connection after confirmation. |
| `qcat list [--json]` | Lists connections and their read-only status. No secrets. |
| `qcat show <id>` | Shows a connection's details, password masked, plus any check findings. |
| `qcat test [id]` | Re-runs the connection and read-only check (all connections if no id). |
| `qcat query <id> [sql]` | Runs one statement. SQL can also come from `-f file.sql` or stdin. |
| `qcat schema <id> [table]` | Lists tables, or describes one table (`table` or `schema.table`). |
| `qcat log [id] [-n 20]` | Recent queries from the local audit log. |

Query options:

| Option | Default | Notes |
|---|---|---|
| `-l, --limit <rows>` | 500 | Up to 2000 is allowed anywhere. Above 2000 asks for confirmation and only works in an interactive terminal. |
| `-t, --timeout <seconds>` | 60 | Statement timeout. 60 is also the maximum. |
| `--format` | `table` | `table`, `json`, `csv`, `ndjson`. `--json` is shorthand. |

Rows go to stdout. Status lines and warnings go to stderr, so output can be piped.

Exit codes: `0` ok, `1` query failed, `2` connection failed, `3` bad usage or unknown id, `4` refused by a safety rule.

## Safety model

### When adding a connection
The read-only check reads Postgres's privilege catalog. It never attempts a write. It fails if the role, or any role it can `SET ROLE` to, has:

- `SUPERUSER`, `CREATEROLE`, `CREATEDB`, `REPLICATION` or `BYPASSRLS`
- membership in `pg_write_all_data`, `pg_write_server_files`, `pg_execute_server_program`, `pg_signal_backend` or `pg_checkpoint`
- `CREATE` on the database or on any schema
- ownership of any table, view or sequence
- `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE` or `TRIGGER` on any table or view, or `UPDATE` on a sequence

A hot-standby replica passes automatically.

`add`, `edit` and `test` print a checklist. When a connection is rejected, it shows which step failed, why, and how to fix it:

```
Connection "prod-main"
  ✔ SSH tunnel via deploy@bastion.example.com:22
  ✔ Reach 10.0.4.12:5432 from the SSH host
  ✔ TLS (verify-full)
  ✔ Log in as app_reader
  ✔ Open database app
Read-only
  ✔ No admin attributes (SUPERUSER, CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS)
  ✔ Not a member of write-capable built-in roles
  ✔ No CREATE on the database
  ✘ No CREATE on any schema
      - CREATE on schema sales (can create tables)
      fix:
        REVOKE CREATE ON SCHEMA sales FROM app_reader;
  ✔ Owns no tables, views or sequences
  ✘ No INSERT, UPDATE, DELETE, TRUNCATE or TRIGGER on tables and views
      - DELETE on public.orders (granted to writers)
      - UPDATE on public.users (columns: email)
      fix:
        REVOKE writers FROM app_reader;  -- leaves the group that grants this
        REVOKE UPDATE (email) ON public.users FROM app_reader;
  ✔ No UPDATE on sequences
```

- **Connection steps.** A failed step shows the server's error, a plain reason (wrong password, firewall drop, untrusted certificate, the SSH host can't reach the database, and so on) and what to change.
- **Read-only rules.** A failed rule lists the offending grants and the SQL that removes them. The SQL targets whoever holds the grant:
  - granted to the user: revoked from the user
  - granted to a group role: you leave that group, since revoking from the group would change access for everyone else in it
  - granted to `PUBLIC`: revoked from `PUBLIC`, marked as affecting every role
- **Recipe.** When ownership or admin attributes are involved, it also prints a recipe for a dedicated read-only role.

If the check fails, you can still keep the connection by typing its id to confirm. It is then marked `WRITE (override)`, and every query against it prints a warning.

If a later `qcat test` fails on a connection that had passed, it becomes `BLOCKED` and queries are refused until you fix the role or override in a terminal.

### On every query
- The statement runs inside `BEGIN READ ONLY` and is always rolled back. Postgres itself rejects writes, even for a write-capable role.
- Only one statement per call. Querycat sends it through the extended protocol, so `SELECT 1; DELETE ...` is rejected.
- Statement timeout of 60 s and row cap of 500 by default.
- Every query is appended to `~/.config/querycat/audit.log`.

### What only a human can do
`add`, `edit`, `remove`, overriding a failed check and `--limit` above 2000 all require an interactive terminal. Agents run commands without one, so they get exit code `4`.

## Storage and encryption

Everything lives in `~/.config/querycat/`. Set `QUERYCAT_HOME` to use another folder.

```
~/.config/querycat/
  key                  random 256-bit key, created on first use (chmod 600)
  connections/<id>.json
  audit.log
```

Passwords and SSH secrets are encrypted with AES-256-GCM using the key file. Each ciphertext is bound to its connection id and field. **This only keeps secrets out of plain sight.** Anyone who can read both the key file and a connection file can decrypt it. Keep the folder private. It is chmod 700 and lives outside this repo so it is never committed.

If the key file is lost, run `qcat edit <id>` and re-enter the passwords.

SSL certificate and SSH key files are stored as absolute paths, not copied.

## Using it from an agent

See [docs/AGENTS.md](docs/AGENTS.md) for a CLAUDE.md snippet and Claude Code permission rules.

## Development

```sh
npm run build        # tsc -> dist/
npm run dev          # tsc --watch
npm test             # unit tests

# integration tests need a disposable Postgres where the user can create roles:
docker run -d --rm --name qcat-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:55432:5432 postgres:17-alpine
QUERYCAT_TEST_ADMIN_URL=postgres://postgres:pw@127.0.0.1:55432/postgres npm test
```

| File | Role |
|---|---|
| `src/cli.ts` | Command definitions |
| `src/commands/connections.ts` | add, edit, remove, list, show, test |
| `src/commands/query.ts` | query, schema, log, and the limit rules |
| `src/limits.ts` | Row limits and the statement timeout cap |
| `src/verification.ts` | Read-only check flow for add, edit and test, including the override prompt |
| `src/form.ts` | Interactive connection form |
| `src/connection-input.ts` | Converts between form input and stored connections (encrypts secrets) |
| `src/postgres.ts` | Connecting (SSL, tunnel) and the read-only query runner |
| `src/readonly.ts` | Privilege check: one rule per check, with findings and fix SQL |
| `src/diagnose.ts` | Turns connection errors into the failing step, a reason and a fix |
| `src/checklist.ts` | Renders the ✔ / ✘ / · checklist |
| `src/schema.ts` | Table listing and description queries |
| `src/tunnel.ts` | SSH local port forward |
| `src/store.ts` | Connection files and their secrets |
| `src/crypto.ts` | Key file and AES-GCM |
| `src/output.ts` | table, json, csv, ndjson rendering |
| `src/audit.ts` | Query log |
