# Bouncer is active

A door-guard sits in front of your shell. Every `run_shell_command` call passes
the door before it runs; destructive commands are **blocked** by an enforced
`BeforeTool` hook — not by you, and not negotiable.

Don't try to run the footguns below. They will be bounced with the exact rule
that fired, and the turn is wasted. Reach for the safe alternative instead.

**Bounced at the door (non-exhaustive):**

- `rm -rf ~`, `rm -rf /`, `rm` on system dirs or with parent-traversal / glob targets
- `dd`/`mkfs`/`wipefs` to a disk device; writing to `/dev/sd*`, `/dev/nvme*`
- overwriting `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`
- `DROP TABLE`/`DROP DATABASE`/`TRUNCATE`; `DELETE`/`UPDATE` with no `WHERE`
- `redis-cli flushall`/`flushdb`, `dropdb`
- `curl … | sh` (piping a URL straight to the shell); `curl`/`wget` to paste / exfil hosts
- uploading or `cat`-ing secrets: `.env`, `id_rsa`, `*.pem`, `*.key`, credentials
- `git push --force` to main/master, `git reset --hard`, `git clean -f`, `git checkout .`
- `chmod 777`, `chown /`, `kill -9 1`, fork bombs, `npm publish`, `crontab -r`

**Walk right in:** read-only inspection, scoped edits, `git status`/`diff`/`add`/`commit`,
tests, builds, a `WHERE`'d `UPDATE`, normal `npm`/`docker`/`psql` work.

This advisory is belt-and-suspenders. The real enforcement is the hook — but
not provoking it keeps your turns productive. Tune with
`BOUNCER_LEVEL=critical|high|strict`; disable with `BOUNCER_OFF=1`.
