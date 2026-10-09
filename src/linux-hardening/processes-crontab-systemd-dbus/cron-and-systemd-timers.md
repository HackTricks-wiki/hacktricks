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

Trace data files as well as scripts. A scheduled simulation or orchestration tool may read a YAML file that defines processes to start; if a lower-privileged user can edit that file and the job runs it under another account, the data can become commands under the job's identity. Verify the exact scheduled command, effective user, file path, parser semantics, and write access (including parent directories) before treating a writable YAML file as an execution path. Reading the schedule and file metadata is enough for passive triage; do not run the job or modify its input during enumeration.

A read-only cron script is still replaceable if the scheduled account runs it by pathname and the lower-privileged user can write and traverse its non-sticky parent directory. Check the schedule's run-as identity, every path component, directory sticky bit, ACLs and mount policy; review metadata without moving the file or running the job.

A scheduled job may also discover input scripts with `find` and pass each one to an interpreter. For example, [gnuplot's `system()` function invokes a shell](https://gnuplot.sourceforge.net/docs_6.0/gnuplot.pdf), so a privileged job that runs `gnuplot` on every `*.plt` file in a lower-privileged user's writable directory can execute commands with the job's identity. [Directory read permission controls listing, while write and search (`x`) control creating and accessing known names](https://www.gnu.org/software/coreutils/manual/html_node/Mode-Structure.html); check write and search access even when `ls` cannot list the directory. Correlate the exact scheduler identity and command, the interpreter's behavior, the selected file pattern, and directory permissions; a writable directory or an installed interpreter alone does not establish escalation. Private schedules and short-lived jobs may require authorized event observation because one process snapshot can miss them.

For a privileged PHP job, inspect literal `include`/`require` statements as part of the executable script chain. [PHP evaluates included files](https://www.php.net/manual/en/function.include.php), so a group-writable included `.php` file can run code with the job's identity even when the main script is read-only. Verify the scheduled identity, effective include-path resolution, file and directory permissions, and whether the job actually runs; a sample cron line in a comment is only a clue. The same review applies to a root-owned [PHP built-in server](https://www.php.net/commandline.webserver) started with `-S` and `-t <document-root>`: a loopback listener may still execute application PHP for local requests. Inspect the process and source without invoking either trigger during enumeration.

For a privileged PHP server that calls functions from a custom native extension, trace the service's PHP SAPI and its effective `php.ini` plus scanned `.ini` files before reviewing the extension. [PHP loads configured `extension` libraries at startup](https://www.php.net/manual/en/ini.core.php), and [CLI and web SAPIs can use different configuration files](https://www.php.net/manual/en/configuration.file.php). A reachable login form or local listener can therefore pass user-controlled strings into compiled code running with the service identity. Record the unit's `User=`, `ExecStart=`, working directory, actual extension path, and caller-controlled arguments; the mere presence of a `.so` or a loopback socket does not establish a memory-corruption flaw. Analyze any custom parser separately rather than sending probes during passive enumeration.

When a privileged wrapper hashes a script by pathname and later opens that pathname again to execute it, the digest authenticates only the object read during the first open. If a lower-privileged user can replace the script's directory entry between those opens, the later execution may resolve a different object even when the original script file is root-owned. A FIFO can lengthen the check phase, but the path depends on replaceable parent-directory rights, actual separate opens, scheduler identity, sticky-bit and mount rules, and timing. Inspect the wrapper and `namei -l` output as a passive lead; a successful checksum alone is not proof that the later pathname is protected.

A privileged backup job can also **disclose** data without executing attacker-supplied commands. Trace whether a lower-privileged user can create a control file that the job reads, whether the job then opens a protected source such as `/etc/shadow`, and whether an attacker-selected URL or readable output receives the result. Verify all three parts before calling it a disclosure path. A fixed shell command in the same script does not by itself make that control file a shell-injection input. Inspect the script and file permissions without running the job or planting a control file during enumeration.

If a cron entry invokes a helper script, inspect the helper's working directory and archive command too. An unquoted wildcard over a directory writable by another user can turn filenames into archiver options; GNU tar's checkpoint actions are one example. Confirm the scheduled run-as identity, writable input directory, exact archiver and options, and whether `--` terminates option parsing before claiming a cross-user command path. See [wildcard and tar behavior](../interesting-files-permissions/wildcards-spare-tricks.md).

Process command-line text is another untrusted input to a privileged helper. A lower-privileged user can choose a process title or `argv[0]` that matches `pgrep -f`; a matching name does not authenticate the executable or its owner. If a root-run script captures that text, rewrites part of it into `apache2ctl`/`httpd`, and executes the result without a fixed argument array, attacker-chosen options can select a different configuration directory or error log. Apache configuration parsing can load modules or reach configured helpers, so do not validate an untrusted configuration as root during enumeration. Inspect the scheduler owner, exact helper, process identity, and data-to-argument flow; this is option/configuration injection unless shell metacharacter execution is separately demonstrated.

A root-run parser that feeds untrusted text into Bash arithmetic can execute substitutions in that text. The [privilege escalation guide](../linux-basics/linux-privilege-escalation/README.md#bash-arithmetic-expansion-injection-in-cron-log-parsers) gives a worked example. Confirm the input source and parsing command before treating every arithmetic expression as exploitable.

Also inspect privileged jobs that materialize files from another user's Git repository. A script may use `git ls-tree` and `git cat-file` rather than `git checkout`, yet still trust attacker-controlled tree paths when it joins them to a staging directory. Absolute paths and `..` components can escape that directory unless the destination is normalized and checked for containment before writing. `git -c safe.directory=*` permits access to repositories with different ownership; it does not by itself create the arbitrary-write condition.

A root-run database backup can create another ownership boundary. PostgreSQL [`pg_basebackup`](https://www.postgresql.org/docs/14/app-pgbasebackup.html) copies additional regular files placed in the source data directory, and its default plain format writes files into `-D` as a directory tree. If a lower-privileged account can create or modify those source files, inspect the resulting destination ownership and mode, whether its path is traversable and executable, and whether the mount has `nosuid`. A root-owned copy with preserved set-ID permissions can be dangerous; a tar-only backup, stripped permissions, or an inaccessible destination does not establish the same path. Trace the scheduled wrapper and effective user before treating the backup command as a finding.

## Observe short-lived work

A single process snapshot may miss a job that runs for milliseconds. Compare timer/cron declarations with logs and, when authorized, process-event monitoring such as `pspy` or audit. Correlate the scheduled owner, exact command line, and files that the task reads or writes. A loopback scheduler web UI is a separate interface; see the [Crontab UI example](../linux-basics/linux-privilege-escalation/README.md#crontab-ui-alseambusher-running-as-root--web-based-scheduler-privesc).
{{#include ../../banners/hacktricks-training.md}}
