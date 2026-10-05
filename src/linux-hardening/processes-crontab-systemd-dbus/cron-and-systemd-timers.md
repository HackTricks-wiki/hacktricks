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

A root-run parser that feeds untrusted text into Bash arithmetic can execute substitutions in that text. The [privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md#bash-arithmetic-expansion-injection-in-cron-log-parsers) gives a worked example. Confirm the input source and parsing command before treating every arithmetic expression as exploitable.

## Observe short-lived work

A single process snapshot may miss a job that runs for milliseconds. Compare timer/cron declarations with logs and, when authorized, process-event monitoring such as `pspy` or audit. Correlate the scheduled owner, exact command line, and files that the task reads or writes. A loopback scheduler web UI is a separate interface; see the [Crontab UI example](../linux-basics/linux-privilege-escalation/README.md#crontab-ui-alseambusher-running-as-root--web-based-scheduler-privesc).
