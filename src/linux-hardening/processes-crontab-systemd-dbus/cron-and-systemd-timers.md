# Cron Jobs and Systemd Timers

{{#include ../../banners/hacktricks-training.md}}

Scheduled tasks can run with a different identity and environment from the current shell. Enumerate cron, `at`, anacron, and systemd timers, then trace each scheduled command through its scripts, imports, working directory, and writable inputs.

## Enumerate schedules

```bash
crontab -l 2>/dev/null
ls -la /etc/crontab /etc/cron.* /var/spool/cron* 2>/dev/null
atq 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

System crontabs usually include a user field; a user's crontab does not. Inspect the effective PATH and environment of the actual scheduler. `run-parts --test /etc/cron.daily` shows which file names would be selected on that host. Control characters can hide an entry in casual output, so use `cat -A` or `sed -n l` when a schedule looks suspicious.

## Trace privileged file and command resolution

```bash
systemctl cat <name>.timer <name>.service
systemctl show <name>.service -p User -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/to/scheduled/script
```

Review writable script chains, `EnvironmentFile=` paths, drop-ins, symlinks, relative commands, wildcard expansion, and binaries copied or executed by a privileged task. A timer may activate a service with a different name through its `Unit=` setting. The [PATH](../linux-basics/linux-environment-variables.md#path), [wildcard](../interesting-files-permissions/wildcards-spare-tricks.md), and [file-link](../main-system-information/filesystem-links-and-file-descriptors.md) pages explain the main primitives.

A privileged backup job can also **disclose** data without executing attacker-supplied commands. Trace whether a lower-privileged user can create a control file that the job reads, whether the job then opens a protected source such as `/etc/shadow`, and whether an attacker-selected URL or readable output receives the result. Verify all three parts before calling it a disclosure path. A fixed shell command in the same script does not by itself make that control file a shell-injection input. Inspect the script and file permissions without running the job or planting a control file during enumeration.

A root-run parser that feeds untrusted text into Bash arithmetic can execute substitutions in that text. The [privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md#bash-arithmetic-expansion-injection-in-cron-log-parsers) gives a worked example. Confirm the input source and parsing command before treating every arithmetic expression as exploitable.

Also inspect privileged jobs that materialize files from another user's Git repository. A script may use `git ls-tree` and `git cat-file` rather than `git checkout`, yet still trust attacker-controlled tree paths when it joins them to a staging directory. Absolute paths and `..` components can escape that directory unless the destination is normalized and checked for containment before writing. `git -c safe.directory=*` permits access to repositories with different ownership; it does not by itself create the arbitrary-write condition.

A root-run database backup can create another ownership boundary. PostgreSQL [`pg_basebackup`](https://www.postgresql.org/docs/14/app-pgbasebackup.html) copies additional regular files placed in the source data directory, and its default plain format writes files into `-D` as a directory tree. If a lower-privileged account can create or modify those source files, inspect the resulting destination ownership and mode, whether its path is traversable and executable, and whether the mount has `nosuid`. A root-owned copy with preserved set-ID permissions can be dangerous; a tar-only backup, stripped permissions, or an inaccessible destination does not establish the same path. Trace the scheduled wrapper and effective user before treating the backup command as a finding.

## Observe short-lived work

A single process snapshot may miss a job that runs for milliseconds. Compare timer/cron declarations with logs and, when authorized, process-event monitoring such as `pspy` or audit. Correlate the scheduled owner, exact command line, and files that the task reads or writes. A loopback scheduler web UI is a separate interface; see the [Crontab UI example](../linux-basics/linux-privilege-escalation/README.md#crontab-ui-alseambusher-running-as-root--web-based-scheduler-privesc).
{{#include ../../banners/hacktricks-training.md}}
