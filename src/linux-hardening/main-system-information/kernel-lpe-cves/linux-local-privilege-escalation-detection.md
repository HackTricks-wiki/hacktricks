# Linux Local Privilege Escalation Detection

{{#include ../../../banners/hacktricks-training.md}}

Linux LPE detections are more durable when they combine an **outcome rule** (an unprivileged lineage becomes root) with **precursor rules** for SUID/SGID helpers, namespace creation, kernel interfaces, and trusted helpers. A signature for one PoC can miss the same primitive after it moves to another subsystem, while the privilege transition normally remains observable.<sup>[[1]](#references)</sup>

Related exploitation material is covered in [Linux Privilege Escalation](../../linux-basics/linux-privilege-escalation/README.md), [Arbitrary File Write to Root](../../interesting-files-permissions/write-to-root.md), [Linux Capabilities](../../interesting-files-permissions/linux-capabilities.md), and [User Namespaces](../../containers-namespaces/container-security/protections/namespaces/user-namespace.md).

## Required telemetry

Collect process start and credential-change events with stable process/parent identifiers, executable path, working directory, arguments, real and effective UID/GID, and interactive status. For kernel-primitive enrichment, Auditd coverage should include at least `execve`, `socket`, `splice`, and `bind`; namespace-oriented telemetry should retain `unshare` syscall arguments or the command-line flags.<sup>[[1]](#references)</sup>

Do not treat the endpoint and SIEM versions of a rule as equivalent. Endpoint behavior rules can use tighter exclusions to reduce false positives, while broader SIEM rules are useful for hunting and may require environment-specific tuning.<sup>[[1]](#references)</sup>

## Correlate writable execution with a root transition

A common LPE sequence is a non-root execution from `/tmp`, `/var/tmp`, `/dev/shm`, `/home`, or `/run/user`, followed within seconds by a UID change to zero in the same lineage. Correlation on a process or parent entity is more resilient than matching an exploit filename.<sup>[[1]](#references)[[2]](#references)</sup>

```eql
sequence by process.parent.entity_id with maxspan=15s
  [process where event.type == "start" and event.action == "exec" and
    user.id != 0 and process.executable like
      (".*", "/tmp/*", "/var/tmp/*", "/dev/shm/*", "/home/*/*",
       "/run/user/*", "/var/run/user/*")]
  [process where event.type == "change" and event.action == "uid_change" and
    user.id == 0 and process.parent.user.id != 0]
```

For public PoCs, adding a root execution of `id`, `whoami`, or `logname` within roughly ten seconds provides a high-confidence confirmation stage. Do not require this stage for general coverage: custom payloads have no reason to verify their privileges this way.<sup>[[1]](#references)[[3]](#references)</sup>

Use descendant correlation when interpreters, web workers, or service accounts create several intermediate processes before an interactive root shell appears. Useful pivots are a root interactive process whose ancestor was non-root and executable staging in a user-writable directory.<sup>[[1]](#references)</sup>

## Detect SUID/SGID privilege shape, not only names

The generic SUID/SGID signal is an effective root identity with a different non-root real identity. Add context such as a low argument count, an interpreter parent, a shell one-liner, or a parent executable in a writable directory to distinguish exploitation from normal administrative use.<sup>[[1]](#references)[[4]](#references)</sup>

```eql
process where event.type == "start" and event.action == "exec" and
  ((process.user.id == 0 and process.real_user.id != 0) or
   (process.group.id == 0 and process.real_group.id != 0)) and
  (process.parent.executable like ("/tmp/*", "/var/tmp/*", "/dev/shm/*",
                                   "/run/user/*", "/home/*/*") or
   process.parent.name like ("python*", "perl*", "ruby*", "php*"))
```

Maintain three complementary variants:<sup>[[1]](#references)[[4]](#references)</sup>

- **Known helpers:** `su`, `sudo`, `pkexec`, or `passwd` with unusually few arguments.
- **Unknown SUID binaries:** compare `process.executable` or `process.name` with `process.command_line` using `stringcontains()` so coverage is not limited to a name list.
- **Proxy execution:** inspect `process.args` for privileged helper paths such as `pkexec`, `ssh-keysign`, `newuidmap`, or `dbus-daemon-launch-helper`; the process name may identify only the proxy.

Capability-based elevation needs separate coverage because `cap_setuid` can produce a root UID without a set-user-ID bit. Likewise, a copied SUID shell executed with `-p` should be correlated with its non-standard path rather than relying on the original shell pathname.<sup>[[1]](#references)</sup>

## Correlate user namespaces with the privileged outcome

`unshare(CLONE_NEWUSER)` gives the caller capabilities inside the new user namespace, which can expose mount, filesystem, traffic-control, and Netlink attack surfaces. Detect command-line forms such as `-U`, `-Urn`, `--user`, and `--map-root-user`; combined short flags require substring matching rather than exact-token matching.<sup>[[1]](#references)[[5]](#references)</sup>

```eql
sequence by process.parent.entity_id with maxspan=60s
  [process where event.type == "start" and process.name == "unshare" and
    user.id != 0 and
    (process.args in ("--user", "--map-root-user", "--map-current-user") or
     process.args like ("-*U*", "-*r*"))]
  [process where event.type == "change" and event.action == "uid_change" and
    user.id == 0 and process.parent.user.id != 0]
```

Standalone `unshare` execution is a noisier hunting signal but can expose container-escape preparation even when no host process reaches UID 0. Always inspect `/proc/<pid>/uid_map` and `/proc/<pid>/gid_map`: UID 0 inside a user namespace may map to an unprivileged host UID and is not proof of host-root compromise.<sup>[[1]](#references)[[6]](#references)</sup>

## Enrich with kernel-primitive and impact signals

The precursor varies by bug class, so keep it separate from the root-transition rule:<sup>[[1]](#references)</sup>

- A non-root burst of `AF_ALG` sockets plus `splice()` can identify one page-cache corruption path, but ESP, RxRPC, skb cloning, or traffic-control variants may not produce that signature.
- Local compilation, execution from a writable directory, unusual loopback/network activity, and a later SUID helper execution can still describe a kernel exploit when its primitive has no stable userland signature.
- Repeated privileged-helper launches combined with `pidfd_getfd()` can indicate exit-time descriptor theft. The impact may be a stolen `/etc/shadow` or SSH host-key descriptor rather than a root process, so an outcome rule based only on UID transitions is insufficient.

For the underlying primitives, see [AF_ALG plus splice page-cache overwrite](copy-fail-af_alg-splice-page-cache-overwrite-cve-2026-31431.md) and [ptrace exit-race FD theft](linux-ptrace-exit-race-pidfd_getfd-fd-theft.md). Page-cache corruption may leave the disk image unchanged, so disk hashes alone cannot disprove exploitation.<sup>[[1]](#references)</sup>

## Triage order

Prioritize the following evidence during investigation.<sup>[[1]](#references)</sup>

1. Confirm whether UID 0 is host root or namespace-mapped root.
2. Reconstruct the full ancestor/descendant chain, not only the immediate parent.
3. Check whether the initial executable, its parent, or both came from a user-writable path.
4. Compare effective and real IDs and identify any SUID/SGID or file-capability transition.
5. Review precursor syscalls and namespace, mount, Netlink, local-network, or helper activity.
6. Look for impact without a shell: sudoers/account changes, authenticated IPC reuse, or reads of privileged file descriptors.

## References

- [1] [Elastic Security Labs - Linux LPE Detection Engineering: General Privilege Flows and 2026 Kernel Exploit Patterns](https://elastic.co/security-labs/threat-command/linux-privilege-escalation-detection-framework)
- [2] [Elastic rule - Potential Privilege Escalation via a Parent Process Sequence](https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_potential_privesc_via_general_sequence_parent.toml)
- [3] [Elastic rule - General Privilege Escalation Sequence Detected](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/linux/privilege_escalation_general_privilege_escalation_sequence_detected.toml)
- [4] [Elastic rule - Suspicious SUID/SGID Utility Execution](https://github.com/elastic/protections-artifacts/blob/main/behavior/rules/linux/privilege_escalation_suspicious_suid_sgid_utility_execution.toml)
- [5] [Elastic rule - Potential Privilege Escalation via unshare Followed by Root Process](https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_unshare_to_root_process_auditd_sequence.toml)
- [6] [Elastic rule - Namespace Manipulation Using Unshare](https://github.com/elastic/detection-rules/blob/main/rules/linux/privilege_escalation_unshare_namespace_manipulation.toml)

{{#include ../../../banners/hacktricks-training.md}}
