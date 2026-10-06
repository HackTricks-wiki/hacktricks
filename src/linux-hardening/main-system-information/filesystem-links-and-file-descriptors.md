# Symlinks, Hardlinks, and File Descriptors

{{#include ../../banners/hacktricks-training.md}}

A path names an object at the time it is resolved; an open file descriptor keeps a reference to the object after the pathname changes. This difference explains symlink races, hidden hardlinks, deleted-file recovery, and inherited descriptor leaks. See [filesystem, inodes and recovery](filesystem-inodes-and-recovery.md) for inode and mount background.

## Inspect links and path ownership

```bash
namei -l /path/to/privileged/input
stat -c '%D %i %h %U:%G %a %n' /path/to/file
readlink -f /path/to/link
find /path/to/tree -type l -ls 2>/dev/null
find /path/to/tree -type f -links +1 -ls 2>/dev/null
```

A symlink redirects pathname resolution; a hardlink is another name for the same inode on the same filesystem. If a privileged task reads or writes a predictable path inside a user-writable directory, a user may be able to redirect that path to a sensitive target. Check ownership and permissions on every parent directory, not just the final file. `fs.protected_symlinks` and `fs.protected_hardlinks` reduce common cross-user attacks but do not make arbitrary writable paths safe.

## Look for path races

The dangerous pattern is a privileged program checking one pathname and later opening the same pathname without keeping a safe reference to the checked object. An attacker who controls a parent directory can replace a file or symlink between the two operations. The same issue appears in temporary files, timer-driven scripts, archive extraction, and backup workflows. Confirm the actual read/write operation and the target's permissions before claiming impact.

## Inspect open descriptors

```bash
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

A process can retain access to a file after it is deleted or renamed. A privileged process may also pass a descriptor through a Unix socket, or unintentionally leave it open across `execve()` if close-on-exec is missing. Inspect `/proc/<PID>/fd` targets for sensitive files, deleted files, host paths visible inside a container, and unexpected sockets. Dereferencing another process's descriptors is subject to kernel access checks; a visible symlink does not guarantee that its contents can be read.

When a service uses an inherited descriptor, review its launch chain and descriptor numbers before trying shell redirection or `/proc/self/fd/<N>`. If a file is deleted but still open, [deleted-file recovery](filesystem-inodes-and-recovery.md#deleted-file-recovery-through-open-fds) may preserve evidence or recover content. For process-level triage, continue with [process enumeration and service paths](../processes-crontab-systemd-dbus/process-enumeration-and-service-paths.md).
{{#include ../../banners/hacktricks-training.md}}
