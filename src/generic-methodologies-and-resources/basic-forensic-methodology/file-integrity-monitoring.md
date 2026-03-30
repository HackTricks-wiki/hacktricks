# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

A baseline consists of taking a snapshot of certain parts of a system to **compare it with a future status to highlight changes**.

For example, you can calculate and store the hash of each file of the filesystem to be able to find out which files were modified.\
This can also be done with the user accounts created, processes running, services running and any other thing that shouldn't change much, or at all.

A **useful baseline** usually stores more than just a digest: permissions, owner, group, timestamps, inode, symlink target, ACLs, and selected extended attributes are also worth tracking. From an attacker-hunting perspective, this helps detect **permission-only tampering**, **atomic file replacement**, and **persistence via modified service/unit files** even when the content hash is not the first thing that changes.

### File Integrity Monitoring

File Integrity Monitoring (FIM) is a critical security technique that protects IT environments and data by tracking changes in files. It usually combines:

1. **Baseline comparison:** Store metadata and cryptographic checksums (prefer `SHA-256` or better) for future comparisons.
2. **Real-time notifications:** Subscribe to OS-native file events to know **which file changed, when, and ideally which process/user touched it**.
3. **Periodic re-scan:** Rebuild confidence after reboots, dropped events, agent outages, or deliberate anti-forensic activity.

For threat hunting, FIM is usually more useful when focused on **high-value paths** such as:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

The collection backend matters:

- **`inotify` / `fsnotify`**: easy and common, but watch limits can be exhausted and some edge cases are missed.
- **`auditd` / audit framework**: better when you need **who changed the file** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: newer options used by modern FIM stacks to enrich events and reduce some of the operational pain of plain `inotify` deployments.

Some practical gotchas:

- If a program **replaces** a file with `write temp -> rename`, watching the file itself may stop being useful. **Watch the parent directory**, not only the file.
- `inotify`-based collectors can miss or degrade on **huge directory trees**, **hard-link activity**, or after a **watched file is deleted**.
- Very large recursive watch sets can silently fail if `fs.inotify.max_user_watches`, `max_user_instances`, or `max_queued_events` are too low.
- Network filesystems are usually bad FIM targets for low-noise monitoring.

Example baseline + verification with AIDE:

```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```

Example `osquery` FIM configuration focused on attacker persistence paths:

```json
{
  "schedule": {
    "fim": {
      "query": "SELECT * FROM file_events;",
      "interval": 300,
      "removed": false
    }
  },
  "file_paths": {
    "etc": ["/etc/%%"],
    "systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
    "ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
  }
}
```

If you need **process attribution** instead of only path-level changes, prefer audit-backed telemetry such as `osquery` `process_file_events` or Wazuh `whodata` mode.

### Windows

On Windows, FIM is stronger when you combine **change journals** with **high-signal process/file telemetry**:

- **NTFS USN Journal** gives a persistent per-volume log of file changes.
- **Sysmon Event ID 11** is useful for file creation/overwrite.
- **Sysmon Event ID 2** helps detect **timestomping**.
- **Sysmon Event ID 15** is useful for **named alternate data streams (ADS)** such as `Zone.Identifier` or hidden payload streams.

Quick USN triage examples:

```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```

For deeper anti-forensic ideas around **timestamp manipulation**, **ADS abuse**, and **USN tampering**, check [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Containers

Container FIM frequently misses the real write path. With Docker `overlay2`, changes are committed into the container's **writable upper layer** (`upperdir`/`diff`), not the read-only image layers. Therefore:

- Monitoring only paths from **inside** a short-lived container may miss changes after the container is recreated.
- Monitoring the **host path** that backs the writable layer or the relevant bind-mounted volume is often more useful.
- FIM on image layers is different from FIM on the running container filesystem.

## Attacker-Oriented Hunting Notes

- Track **service definitions** and **task schedulers** as carefully as binaries. Attackers often get persistence by modifying a unit file, cron entry, or task XML rather than patching `/bin/sshd`.
- A content hash alone is insufficient. Many compromises first show up as **owner/mode/xattr/ACL drift**.
- If you suspect a mature intrusion, do both: **real-time FIM** for fresh activity and a **cold baseline comparison** from trusted media.
- If the attacker has root or kernel execution, assume the FIM agent, its database, and even the event source can be tampered with. Store logs and baselines remotely or on read-only media whenever possible.

## Tools

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}
