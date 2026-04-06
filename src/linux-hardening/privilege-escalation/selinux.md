# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux is a **label-based Mandatory Access Control (MAC)** system. In practice, this means that even if DAC permissions, groups, or Linux capabilities look enough for an action, the kernel can still deny it because the **source context** is not allowed to access the **target context** with the requested class/permission.

A context usually looks like:

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

From a privesc perspective, the `type` (domain for processes, type for objects) is usually the most important field:

- A process runs in a **domain** such as `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Files and sockets have a **type** such as `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- Policy decides whether one domain can read/write/execute/transition to the other

## Fast Enumeration

If SELinux is enabled, enumerate it early because it can explain why common Linux privesc paths fail or why a privileged wrapper around a "harmless" SELinux tool is actually critical:

```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```

Useful follow-up checks:

```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```

Interesting findings:

- `Disabled` or `Permissive` mode removes most of the value of SELinux as a boundary.
- `unconfined_t` usually means SELinux is present but not meaningfully constraining that process.
- `default_t`, `file_t`, or obviously wrong labels on custom paths often indicate mislabeling or incomplete deployment.
- Local overrides in `file_contexts.local` take precedence over policy defaults, so review them carefully.

## Policy Analysis

SELinux is much easier to attack or bypass when you can answer two questions:

1. **What can my current domain access?**
2. **What domains can I transition into?**

The most useful tools for this are `sepolicy` and **SETools** (`seinfo`, `sesearch`, `sedta`):

```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```

This is especially useful when a host uses **confined users** rather than mapping everyone to `unconfined_u`. In that case, look for:

- user mappings via `semanage login -l`
- allowed roles via `semanage user -l`
- reachable admin domains such as `sysadm_t`, `secadm_t`, `webadm_t`
- `sudoers` entries using `ROLE=` or `TYPE=`

If `sudo -l` contains entries like this, SELinux is part of the privilege boundary:

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Also check whether `newrole` is available:

```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```

`runcon` and `newrole` are not automatically exploitable, but if a privileged wrapper or a `sudoers` rule lets you select a better role/type, they become high-value escalation primitives.

## Files, Relabeling, and High-Value Misconfigurations

The most important operational difference between common SELinux tools is:

- `chcon`: temporary label change on a specific path
- `semanage fcontext`: persistent path-to-label rule
- `restorecon` / `setfiles`: apply the policy/default label again

This matters a lot during privesc because **relabeling is not just cosmetic**. It can turn a file from "blocked by policy" into "readable/executable by a privileged confined service".

Check for local relabel rules and relabel drift:

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

High-value commands to hunt in `sudo -l`, root wrappers, automation scripts, or file capabilities:

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Especially interesting:

- `semanage fcontext`: persistently changes what label a path should receive
- `restorecon` / `setfiles`: reapplies those changes at scale
- `semodule -i`: loads a custom policy module
- `semanage permissive -a <domain_t>`: makes one domain permissive without flipping the whole host
- `setsebool -P`: permanently changes policy booleans
- `load_policy`: reloads the active policy

These are often **helper primitives**, not standalone root exploits. Their value is that they let you:

- make a target domain permissive
- broaden access between your domain and a protected type
- relabel attacker-controlled files so a privileged service can read or execute them
- weaken a confined service enough that an existing local bug becomes exploitable

Example checks:

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

If you can load a policy module as root, you usually control the SELinux boundary:

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

That is why `audit2allow`, `semodule`, and `semanage permissive` should be treated as sensitive admin surfaces during post-exploitation. They can silently convert a blocked chain into a working one without changing classic UNIX permissions.

## Audit Clues

AVC denials are often offensive signal, not just defensive noise. They tell you:

- which target object/type you hit
- which permission was denied
- which domain you currently control
- whether a small policy change would make the chain work

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

If a local exploit or persistence attempt keeps failing with `EACCES` or strange "permission denied" errors despite root-looking DAC permissions, SELinux is usually worth checking before discarding the vector.

## SELinux Users

There are SELinux users in addition to regular Linux users. Each Linux user is mapped to an SELinux user as part of the policy, which lets the system impose different allowed roles and domains on different accounts.

Quick checks:

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```

On many mainstream systems, users are mapped to `unconfined_u`, which reduces the practical impact of user confinement. On hardened deployments, however, confined users can make `sudo`, `su`, `newrole`, and `runcon` much more interesting because **the escalation path may depend on entering a better SELinux role/type, not only on becoming UID 0**.

## SELinux in Containers

Container runtimes commonly launch workloads in a confined domain such as `container_t` and label container content as `container_file_t`. If a container process escapes but still runs with the container label, host writes may still fail because the label boundary stayed intact.

Quick example:

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

Modern container operations worth noting:

- `--security-opt label=disable` can effectively move the workload to an unconfined container-related type such as `spc_t`
- bind mounts with `:z` / `:Z` trigger relabeling of the host path for shared/private container use
- broad relabeling of host content can become a security issue on its own

This page keeps the container content short to avoid duplication. For the container-specific abuse cases and runtime examples, check:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
