# Filesystem, Inodes and Recovery

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse is often about confusing the relationship between a visible path and the object behind it. Disk images may hide another filesystem, writable mounts may be consumed by privileged jobs, hardlinks may expose the same inode through a different name, and deleted files may still be readable through an open file descriptor.

This page focuses on the technique, not on one specific lab or target.

## Disk Images and Loop Mounts

A regular file can contain a complete filesystem. Backup images, copied block devices, VM artifacts, or renamed blobs can therefore contain credentials, scripts, SSH keys, configuration files, or flags even when they do not look useful from the outside.

Identify likely images:

```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```

If mounting is allowed, mount unknown images read-only first:

```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```

If mounting is not available, inspect the filesystem metadata directly:

```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```

The technique is useful because it turns a normal-looking file into a second filesystem tree. Treat it as a way to recover hidden data, not as a privilege escalation by itself.

## Writable Mount Abuse

A writable mount becomes dangerous when a more privileged context later trusts something inside it. The important question is not only "can I write here?", but "who later reads, executes, imports, or loads from here?".

Find writable mounts and suspicious consumers:

```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```

Common abuse patterns:

- A privileged cron or systemd unit runs a writable script from the mount.
- A privileged service loads plugins, config, templates, or helper binaries from the mount.
- A mount contains SUID files and allows modification, replacement, or path manipulation.
- A container or chroot exposes a host-backed path that is writable from the restricted environment.

Generic validation pattern:

```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```

When proving impact in an authorized lab, keep the payload observable and minimal, for example writing `id` output to a temporary file. The core technique is delayed execution through a trusted writable location.

## Inodes and Path Confusion

An inode is the filesystem object; a path is only a name pointing to it. This matters because two different paths can point to the same inode, and a deleted pathname does not always mean the data is gone.

Compare files by inode and device:

```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```

Find every visible pathname for the same inode:

```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```

Search directly by inode number when you only have metadata:

```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```

This technique is useful when a file appears under an unexpected name, when an application validates one path but uses another, or when a privileged wrapper interacts with an inode that is also reachable somewhere else.

## Hardlink Abuse

Hardlinks create multiple names for the same inode. They do not point to a target path like symlinks do; they are equal names for the same file object.

Find SUID files with multiple hardlinks:

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Inspect one suspicious file:

```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```

Why it matters:

- A sensitive file may be reachable through a less obvious path.
- A SUID wrapper may be hidden behind a name that does not look privileged.
- Cleanup that removes one pathname may leave another hardlink alive.

Modern kernels and mount options can restrict hardlink creation to reduce this class of abuse, but existing hardlinks are still worth reviewing.

## Deleted File Recovery Through Open FDs

When a process keeps a file open, the file data can remain available even after the pathname is deleted. Linux exposes those open descriptors under `/proc/<pid>/fd/`.

Find deleted open files:

```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```

Recover the data when permissions allow it:

```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```

This is a practical technique for recovering deleted logs, temporary secrets, dropped binaries, rotated files, or scripts removed after execution.

## ext Recovery With debugfs

On ext filesystems, `debugfs` can inspect inode metadata and sometimes dump file contents from a filesystem image. Work on a copy or a read-only image whenever possible.

List entries and inspect inodes:

```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```

Dump a known inode:

```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```

This is not guaranteed recovery. It depends on filesystem state, whether blocks were reused, and whether the metadata still exists. The technique is still valuable because it lets you inspect inode-level state without relying on normal path traversal.

## Inode Exhaustion and Ordering

Inode exhaustion happens when a filesystem runs out of file objects even if free disk space remains. It usually causes reliability failures, but it can also explain strange behavior during incident response or lab triage.

Check inode pressure:

```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```

Inode numbers and timestamps can also help reconstruct activity in simple lab environments:

```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```

Treat ordering as a clue, not proof. Copy operations, archive extraction, filesystem type, restores, and concurrent writes can all change allocation patterns.

## Defensive Notes

- Mount unknown images read-only during analysis.
- Keep privileged scripts, service units, plugins, and helper paths outside user-writable mounts.
- Use `nosuid`, `nodev`, and `noexec` where operationally appropriate, but do not treat them as a complete boundary.
- Restrict access to `/proc/<pid>/fd`, process metadata, and cross-user process inspection where possible.
- Monitor writable mount points, unexpected hardlinks to privileged files, and deleted-but-open sensitive files.
{{#include ../../banners/hacktricks-training.md}}
