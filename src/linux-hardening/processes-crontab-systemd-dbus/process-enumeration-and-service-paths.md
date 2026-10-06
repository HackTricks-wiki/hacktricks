# Process Enumeration and Service Paths

{{#include ../../banners/hacktricks-training.md}}

The useful question is which privileged process consumes data or code that a lower-privileged user can influence. Inspect the process tree, live environment, open files, and the unit or script that launched each candidate.

## Map processes and ownership

```bash
ps -eo user,pid,ppid,tty,comm,args --sort=ppid
pstree -alp 2>/dev/null
systemctl list-units --type=service --state=running 2>/dev/null
ss -lntup
```

A cross-user parent-child relationship can be normal, but an unexpected transition warrants review of the parent command, arguments, executable, working directory, and referenced files. Use [users and sessions](../user-information/user-and-session-triage.md) to interpret the owner and login context.

## Inspect runtime artifacts

```bash
readlink /proc/<PID>/exe
tr '\0' ' ' </proc/<PID>/cmdline; echo
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

Deleted executables and deleted-but-open files remain referenced until their last descriptor closes. They can preserve evidence or accessible secrets. Process environments and memory may contain credentials, but reading another process is constrained by ownership, `/proc` mount options, Yama ptrace policy, and other security controls. See [file descriptors](../main-system-information/filesystem-links-and-file-descriptors.md) and [post-exploitation credential hunting](../post-exploitation/README.md) for related techniques.

## Follow the service execution chain

```bash
systemctl cat <unit>.service
systemctl show <unit>.service -p User -p Group -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/from/ExecStart
```

Check the unit, drop-ins, `EnvironmentFile=`, helper scripts, relative commands, writable directories, and socket activation. A root-owned unit can still be unsafe if it reads a user-writable config or script. The [arbitrary file write](../interesting-files-permissions/write-to-root.md) page covers common service and unit abuse paths. Monitor short-lived jobs with [pspy](https://github.com/DominicBreuker/pspy) or audit/process telemetry when a one-time `ps` listing misses them.
{{#include ../../banners/hacktricks-training.md}}
