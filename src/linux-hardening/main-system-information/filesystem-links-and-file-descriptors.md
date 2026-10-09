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

A scheduled privileged writer can make its output path predictable even when the filename contains a random-looking hash: [C `rand()` repeats its sequence for the same `srand()` seed](https://man7.org/linux/man-pages/man3/rand.3.html), including a seed derived from a known execution time. If the job also reads caller-writable database rows when constructing that name, verify the exact row-to-name algorithm, seed and libc behavior, schedule, the caller's row-write and directory-create rights, and whether a pre-existing symlink can be placed before the privileged open. [`fopen(..., "w")` creates or truncates the resolved file](https://man7.org/linux/man-pages/man3/fopen.3.html); check the actual implementation for link-safe open flags or atomic replacement, effective write identity, target permissions, and sticky-directory symlink policy. A predictable name or writable row alone is only a review lead. Inspect code, schedule, and metadata without inserting rows or running the job during passive enumeration.

For a file-conversion service running as another user, review whether a caller can choose an output path or extension and whether the converter follows a pre-existing output symlink. Some converters select the output format from the pathname extension; a link named with an accepted extension can still point to a sensitive extensionless target. A successful cross-user write requires a reachable service, caller control of the path and link, the converter opening the link for output, and write permission at the service identity. Linux `fs.protected_symlinks=1` restricts following another user's link in a **sticky world-writable directory**; it does not provide the same protection for a link in an ordinary user-owned directory. Inspect the resolved path and parent ownership before drawing a conclusion. See [calibre's output-file behavior](https://manual.calibre-ebook.com/generated/en/ebook-convert.html) and the [Linux symlink policy](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html#protected-symlinks).

A sudo-allowed download wrapper needs the same output-path review if it fetches caller-selected data while retaining a caller-controlled working directory. Inspect the actual downloader and whether its selected basename, collision handling, or pre-existing symlink can redirect a privileged write; a URL choice or symlink alone is insufficient. [Axel documents a per-user `~/.axelrc`](https://github.com/axel-download-accelerator/axel/blob/master/doc/axel.txt), and its [example configuration includes `default_filename` and `no_clobber`](https://github.com/axel-download-accelerator/axel/blob/master/doc/axelrc.example), so a wrapper using Axel may also inherit an output-name choice from that file. Confirm the effective `HOME`: [sudo can reset or preserve it according to policy](https://man7.org/linux/man-pages/man8/sudo.8.html), and a user's `.axelrc` is relevant only if the privileged downloader actually reads it. Check the rule, wrapper, config path and permissions, final output name, and target-file state without starting a download during passive enumeration.

For a sudo-allowed ACL wrapper, inspect how it validates a caller-selected file before calling `setfacl`. A lexical prefix check and rejection of `..` do not prevent a symlink inside the allowed directory from resolving outside it; `test -f` follows the link too. Confirm that the wrapper reaches the ACL operation with sufficient privilege, the caller controls the link, and the resulting ACL grants the access needed on the target **and its parent directories**. Some consumers reject files with writable ACLs or loose modes, so an ACL change alone does not establish a working escalation path.

## Review privileged writes into user-mounted FUSE filesystems

An active standalone `user_allow_other` line in `/etc/fuse.conf` permits a non-root user to request `allow_other` or `allow_root` on a FUSE mount. Those mount options can let a root process reach a filesystem implemented by the mounting user. If a sudo-allowed helper writes a secret-bearing log or other output relative to a caller-controlled working directory, review whether that directory can be a user-mounted FUSE filesystem. The FUSE implementation can observe writes even when the resulting file appears root-owned or mode `0600` on an ordinary filesystem.

```bash
grep -n '^[[:space:]]*user_allow_other[[:space:]]*$' /etc/fuse.conf 2>/dev/null
sudo -l
```

This is a **candidate**, not proof of disclosure. Confirm the actual sudo/run-as identity and arguments, the helper's output path and sensitive content, access to `/dev/fuse`, successful mounting with `allow_other` or `allow_root`, and whether the privileged process can enter the mount. Do not run the privileged helper or mount a filesystem during routine enumeration. See the [libfuse policy description](https://github.com/libfuse/libfuse/blob/master/util/fuse.conf) and [libfuse access FAQ](https://github.com/libfuse/libfuse/wiki/FAQ#why-dont-other-users-have-access-to-the-mounted-filesystem).

## Look for path races

The dangerous pattern is a privileged program checking one pathname and later opening the same pathname without keeping a safe reference to the checked object. An attacker who controls a parent directory can replace a file or symlink between the two operations. The same issue appears in temporary files, timer-driven scripts, archive extraction, and backup workflows. Confirm the actual read/write operation and the target's permissions before claiming impact.

Archive **creation** can also disclose files across identities. Info-ZIP `zip -r` normally follows a symlink placed inside the source tree and stores the target's contents; `-y`/`--symlinks` instead stores the link itself. If a lower-privileged user can add a link in a backed-up directory, check the exact archiver/options, the backup job's read identity, and whether the resulting archive is readable by that user. A writable source directory or a symlink alone does not establish disclosure. Review link and archive metadata without triggering the backup or extracting secret content during enumeration. See the [Info-ZIP option documentation](https://sources.debian.org/src/zip/3.0-3/man/zip.1/#L1638).

GNU `tar` has a different default: it normally stores a symlink as a link, while [`-h` / `--dereference` follows it during archive creation](https://www.gnu.org/software/tar/manual/html_node/dereference.html). For a privileged scheduled backup, inspect the exact `tar` invocation, whether a lower-privileged user can replace an input pathname before `tar` reads it, and whether the resulting archive is accessible to that user. A temporary checksum or other sidecar in a writable staging directory can become such an input when explicitly named in a later `tar -h` command. The race window, job identity, symlink policy, target readability under that identity, and archive ACL all need verification. Do not replace files, run the job, or unpack sensitive archives during passive checks.

A repeated host-side transfer can turn an untrusted archive member into a later output path. If a higher-privileged job copies an archive from a lower-trust container, extracts a symlink whose name equals the next transfer's destination basename, and later writes to that same pathname, the later write may reach the link target. Check the archive member name and target, extraction flags and directory, whether the extractor actually leaves that link in place, the transfer implementation's treatment of an existing destination link, and the host job's effective write identity. [GNU tar documents how extraction handles existing files and symlinks](https://www.gnu.org/software/tar/manual/html_section/extract-options.html); [OpenSSH scp uses SFTP by default in modern releases](https://man.openbsd.org/scp.1), so verify the installed transfer behavior rather than assuming all `scp` versions write through a link. A container-visible `scp` process or writable archive alone cannot establish the host extraction and later write. Inspect the job and path metadata without transferring or extracting a crafted archive during enumeration.

Ansible's [`synchronize` module](https://docs.ansible.com/projects/ansible/latest/collections/ansible/posix/synchronize_module.html) wraps rsync; `copy_links: true` copies a symlink's referent instead of the link. For a scheduled backup, check whether a lower-privileged user can create a link inside the exact source tree, whether the synchronization identity can read its target, and whether the resulting copy or archive is readable by that user. The playbook, link placement, run-as identity, and output permissions must all line up; a writable upload directory or `copy_links` setting alone is only a review lead. Inspect metadata and the playbook without creating links or triggering the job.

## Inspect open descriptors

```bash
ls -l /proc/<PID>/fd 2>/dev/null
lsof -p <PID> 2>/dev/null
lsof +L1 2>/dev/null
```

A process can retain access to a file after it is deleted or renamed. A privileged process may also pass a descriptor through a Unix socket, or unintentionally leave it open across `execve()` if close-on-exec is missing. Inspect `/proc/<PID>/fd` targets for sensitive files, deleted files, host paths visible inside a container, and unexpected sockets. Dereferencing another process's descriptors is subject to kernel access checks; a visible symlink does not guarantee that its contents can be read.

A custom SUID helper may open a protected pathname, drop its effective UID, and leave the descriptor open. If it then makes itself dumpable, `/proc/<PID>/fd` ownership and access can change; review the exact credential transition, [`PR_SET_DUMPABLE`](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html), procfs/ptrace policy, and the target file mode. Reopening a descriptor path may bypass an inaccessible **parent directory** while still failing on a file that the caller cannot read. A visible descriptor target or SUID bit alone does not prove disclosure.

Crash artifacts are a separate lead: a core dump can contain process memory, including data previously read under a higher identity. On Ubuntu, [Apport normally places reports in `/var/crash`](https://documentation.ubuntu.com/project/contributors/debugging/apport/); other systems may use a different `core_pattern` handler or systemd storage. Check only report paths, owner, mode, and readability during routine enumeration. A readable report matters only if the relevant process was dumpable, the crash handler retained the sensitive bytes, and the current user can access that report. Do not crash a helper or unpack a dump as part of passive enumeration. See [`core(5)`](https://man7.org/linux/man-pages/man5/core.5.html) for SUID and dump-generation conditions.

When a service uses an inherited descriptor, review its launch chain and descriptor numbers before trying shell redirection or `/proc/self/fd/<N>`. If a file is deleted but still open, [deleted-file recovery](filesystem-inodes-and-recovery.md#deleted-file-recovery-through-open-fds) may preserve evidence or recover content. For process-level triage, continue with [process enumeration and service paths](../processes-crontab-systemd-dbus/process-enumeration-and-service-paths.md).
{{#include ../../banners/hacktricks-training.md}}
