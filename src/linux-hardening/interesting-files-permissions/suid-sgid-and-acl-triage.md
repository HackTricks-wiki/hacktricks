# SUID, SGID, ACLs, and Sensitive Files

{{#include ../../banners/hacktricks-training.md}}

SUID and SGID change the effective identity of an executed file; ACLs can grant access that ordinary `ls -l` mode bits do not show. Review both when a user can read, write, or execute more than the apparent owner and group permissions suggest.

## Enumerate privileged executables

```bash
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
findmnt -no TARGET,OPTIONS
getcap -r / 2>/dev/null
```

Focus on custom or recently changed executables, unusual owners, and files on writable mounts. A `nosuid` mount can suppress set-ID behavior; file capabilities are a separate privilege mechanism described in [Linux capabilities](linux-capabilities.md). Compare a suspicious binary with its package and check what it executes, opens, or loads with elevated identity.

A SUID program that invokes a shell, relative command, or library from a writable path may cross a trust boundary. See [SUID shared-library and linker abuse](suid-shared-library-and-linker-abuse.md), the [PATH guidance](../linux-basics/linux-environment-variables.md#path), and the [user-ID explanation](../user-information/euid-ruid-suid.md). For known command-specific escapes, check [GTFOBins](https://gtfobins.github.io/) against the exact binary and invocation allowed on the host.

## Inspect ACLs and sensitive paths

```bash
getfacl -p /path/to/file /path/to/parent 2>/dev/null
namei -l /path/to/file
find /etc /opt /var -type f -writable -ls 2>/dev/null | head -80
ls -la /etc/sudoers.d /etc/ld.so.preload /etc/ld.so.conf.d 2>/dev/null
```

A writable parent directory may permit replacement even when the file itself is root-owned. An ACL may quietly grant access to a sudoers drop-in, service unit, cron script, library path, or credential file. Check both the ACL and the full path. If arbitrary privileged file writes are possible, follow [Arbitrary File Write to Root](write-to-root.md); for linker configuration and preload cases, see the [`ld.so` example](ld.so.conf-example.md). Treat exposed backups, `.env` files, database configs, SSH material, and history as possible credential sources, with access governed by the actual permissions of each file.
