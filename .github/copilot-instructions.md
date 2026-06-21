# Bouncer: destructive-command guardrails

Bouncer enforces these rules at the door via a fail-closed `preToolUse` hook. This
list is the **advisory, defense-in-depth layer**: do not propose or run any of the
following destructive shell commands. The hook will deny them anyway, so don't waste a turn.

Never run a command that:

- Deletes broadly or irrecoverably: `rm -rf /`, `rm -rf ~`, `rm -rf .`, `rm -rf *`, `rm -rf --no-preserve-root /`, `sudo rm -rf`, deleting `node_modules ../../*` or parent/glob targets.
- Writes to or formats a raw disk device: `dd of=/dev/sd*`, `mkfs.*`, `wipefs -a /dev/*`, `echo ... > /dev/sda`.
- Overwrites protected system files: `chmod 777 /etc/passwd`, `chmod -R 777 /`, `chown -R ... /`, `echo ... > /etc/passwd`.
- Spawns a fork bomb (`:(){ :|:& };:`) or kills init (`kill -9 1`).
- Rewrites or destroys git history/remote: `git push --force origin main`, `git reset --hard`, `git clean -fdx`.
- Pipes a URL straight to a shell (RCE): `curl ... | sh`, `wget -qO- ... | bash`.
- Exfiltrates secrets: `curl -d @.env ...`, `curl -T id_rsa ...`, posting to paste/exfil hosts.
- Exposes secrets: `cat .env`, `cat ~/.ssh/id_rsa`, `printenv`, `echo $AWS_SECRET_ACCESS_KEY`.
- Destroys a database/store: `DROP TABLE/DATABASE/SCHEMA`, `TRUNCATE`, un-`WHERE`'d `DELETE`/`UPDATE`, `redis-cli flushall`, `dropdb`.
- Performs an irreversible release/data loss: `npm publish`, `docker volume rm`.

If a task seems to require one of these, stop and ask the user first. Prefer scoped,
reversible alternatives (a `WHERE` clause, `--force-with-lease`, a dry run).
