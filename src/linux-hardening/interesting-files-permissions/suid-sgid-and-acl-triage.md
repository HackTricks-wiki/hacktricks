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

### Privileged wrappers that pass SQL to the SQLite CLI

If a custom SUID program passes user-controlled SQL to the **`sqlite3` command-line program**, inspect the exact command and effective identity before treating its query as read-only. The CLI's `edit()` SQL function invokes an editor (from its second argument or `VISUAL`), and its SQL `load_extension()` function can load a shared library when extension loading is enabled. These are potential code-execution paths at the CLI process's identity even if the wrapper fixes `PATH` or uses an absolute `sqlite3` path. The SQL must actually reach those functions, and the CLI must retain the relevant feature; merely finding `sqlite3` in a binary or on the host is not evidence of an escalation. The SQLite **library** disables extension loading by default, so distinguish it from the CLI. Where a privileged application must process untrusted SQL, SQLite's CLI `--safe` mode disables `edit()`, `load_extension()`, and other side-effectful functions. See the [SQLite CLI documentation](https://www.sqlite.org/cli.html#the_edit_sql_function), [safe-mode documentation](https://www.sqlite.org/cli.html#the_safe_command_line_option), and [extension-loading documentation](https://www.sqlite.org/loadext.html#loading_an_extension).

### Privileged file readers that feed a verbose client

A custom SUID/SGID wrapper may check access to a caller-selected pathname and then pass that file to another command. Review the effective identity at both the access check and the later open, resolve any `../` components against the real base directory, and inspect how the child handles invalid input. If a database client reads a private file as SQL with verbose output, it may echo the file's contents in errors even though the SQL is invalid. This is a cross-user disclosure only when the child can read a file that the caller cannot, the caller can select that file through the wrapper, and the output is visible; the presence of `mysql` or another client string alone proves none of these conditions.

### Netdata `ndsudo` search path

[CVE-2024-32019](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93) affected some Netdata `ndsudo` builds. The root-owned SUID helper searched for its permitted external commands using a caller-supplied `PATH`. Review an installed helper, including one outside the caller's usual `PATH`, only when the current account can execute it. Confirm its owner, SUID bit, executable access (including group/ACL grants), installed build and vendor patch status, and whether `NoNewPrivs` or a `nosuid` mount blocks the identity change. Netdata lists patched builds `v1.45.3` and `v1.45.0-169`; distribution backports need separate confirmation. A dashboard version or the mere presence of `ndsudo` is insufficient evidence of a reachable escalation. The path issue also requires the helper to resolve an external command through a location the caller controls.

### snap-confine and tmpfiles cleanup

CVE-2026-3888 is a race involving privileged `snap-confine` and systemd-tmpfiles cleanup of `/tmp`. A passive review can check whether `snap-confine` is setuid or has file capabilities, compare the installed `snapd` package with the fixed version for that **Ubuntu release**, and inspect the effective `/tmp` age rule and cleanup timer. A matching package and rule are prerequisites, not proof that the race is reachable: runtime timer state, snap layout, package backports, and rule overrides also matter. Older releases may require non-default configuration. Do not run a race probe during routine enumeration. See the [Ubuntu CVE record](https://ubuntu.com/security/CVE-2026-3888) for release-specific package status and the [Qualys advisory](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root) for the component interaction.

## Inspect ACLs and sensitive paths

```bash
getfacl -p /path/to/file /path/to/parent 2>/dev/null
namei -l /path/to/file
find /etc /opt /var -type f -writable -ls 2>/dev/null | head -80
ls -la /etc/sudoers.d /etc/ld.so.preload /etc/ld.so.conf.d 2>/dev/null
```

A writable parent directory may permit replacement even when the file itself is root-owned. An ACL may quietly grant access to a sudoers drop-in, service unit, cron script, library path, or credential file. Check both the ACL and the full path. If arbitrary privileged file writes are possible, follow [Arbitrary File Write to Root](write-to-root.md); for linker configuration and preload cases, see the [`ld.so` example](ld.so.conf-example.md). Treat exposed backups, `.env` files, database configs, SSH material, and history as possible credential sources, with access governed by the actual permissions of each file.
{{#include ../../banners/hacktricks-training.md}}
