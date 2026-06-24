# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

A good container assessment should answer two parallel questions. First, what can an attacker do from the current workload? Second, which operator choices made that possible? Enumeration tools help with the first question, and hardening guidance helps with the second. Keeping both on one page makes the section more useful as a field reference rather than just a catalog of escape tricks.

One practical update for modern environments is that many older container writeups quietly assume a **rootful runtime**, **no user namespace isolation**, and often **cgroup v1**. Those assumptions are not safe anymore. Before spending time on old escape primitives, first confirm whether the workload is rootless or userns-remapped, whether the host is using cgroup v2, and whether Kubernetes or the runtime is now applying default seccomp and AppArmor profiles. These details often decide whether a famous breakout still applies.

## Enumeration Tools

A number of tools remain useful for quickly characterizing a container environment:

- `linpeas` can identify many container indicators, mounted sockets, capability sets, dangerous filesystems, and breakout hints.
- `CDK` focuses specifically on container environments and includes enumeration plus some automated escape checks.
- `amicontained` is lightweight and useful for identifying container restrictions, capabilities, namespace exposure, and likely breakout classes.
- `deepce` is another container-focused enumerator with breakout-oriented checks.
- `grype` is useful when the assessment includes image-package vulnerability review instead of only runtime escape analysis.
- `Tracee` is useful when you need **runtime evidence** rather than static posture alone, especially for suspicious process execution, file access, and container-aware event collection.
- `Inspektor Gadget` is useful in Kubernetes and Linux-host investigations when you need eBPF-backed visibility tied back to pods, containers, namespaces, and other higher-level concepts.

The value of these tools is speed and coverage, not certainty. They help reveal the rough posture quickly, but the interesting findings still need manual interpretation against the actual runtime, namespace, capability, and mount model.

## Hardening Priorities

The most important hardening principles are conceptually simple even though their implementation varies by platform. Avoid privileged containers. Avoid mounted runtime sockets. Do not give containers writable host paths unless there is a very specific reason. Use user namespaces or rootless execution where feasible. Drop all capabilities and add back only the ones the workload truly needs. Keep seccomp, AppArmor, and SELinux enabled rather than disabling them to fix application compatibility problems. Limit resources so that a compromised container cannot trivially deny service to the host.

Image and build hygiene matter as much as runtime posture. Use minimal images, rebuild frequently, scan them, require provenance where practical, and keep secrets out of layers. A container running as non-root with a small image and a narrow syscall and capability surface is much easier to defend than a large convenience image running as host-equivalent root with debugging tools preinstalled.

For Kubernetes, current hardening baselines are more opinionated than many operators still assume. The built-in **Pod Security Standards** treat `restricted` as the "current best practice" profile: `allowPrivilegeEscalation` should be `false`, workloads should run as non-root, seccomp should be explicitly set to `RuntimeDefault` or `Localhost`, and capability sets should be dropped aggressively. During assessment, this matters because a cluster that is only using `warn` or `audit` labels may look hardened on paper while still admitting risky pods in practice.

## Modern Triage Questions

Before diving into escape-specific pages, answer these quick questions:

1. Is the workload **rootful**, **rootless**, or **userns-remapped**?
2. Is the node using **cgroup v1** or **cgroup v2**?
3. Are **seccomp** and **AppArmor/SELinux** explicitly configured, or merely inherited when available?
4. In Kubernetes, is the namespace actually **enforcing** `baseline` or `restricted`, or only warning/auditing?

Useful checks:

```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```

What is interesting here:

- If `/proc/self/uid_map` shows container root mapped to a **high host UID range**, many older host-root writeups become less relevant because root in the container is no longer host-root equivalent.
- If `/sys/fs/cgroup` is `cgroup2fs`, old **cgroup v1**-specific writeups such as `release_agent` abuse should no longer be your first guess.
- If seccomp and AppArmor are only inherited implicitly, portability can be weaker than defenders expect. In Kubernetes, explicitly setting `RuntimeDefault` is often stronger than silently relying on node defaults.
- If `supplementalGroupsPolicy` is set to `Strict`, the pod should avoid silently inheriting extra group memberships from `/etc/group` inside the image, which makes group-based volume and file access behavior more predictable.
- Namespace labels such as `pod-security.kubernetes.io/enforce=restricted` are worth checking directly. `warn` and `audit` are useful, but they do not stop a risky pod from being created.

## Resource-Exhaustion Examples

Resource controls are not glamorous, but they are part of container security because they limit the blast radius of compromise. Without memory, CPU, or PID limits, a simple shell may be enough to degrade the host or neighboring workloads.

Example host-impacting tests:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

These examples are useful because they show that not every dangerous container outcome is a clean "escape". Weak cgroup limits can still turn code execution into real operational impact.

In Kubernetes-backed environments, also check whether resource controls exist at all before treating DoS as theoretical:

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Hardening Tooling

For Docker-centric environments, `docker-bench-security` remains a useful host-side audit baseline because it checks common configuration issues against widely recognized benchmark guidance:

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

The tool is not a substitute for threat modeling, but it is still valuable for finding careless daemon, mount, network, and runtime defaults that accumulate over time.

For Kubernetes and runtime-heavy environments, pair static checks with runtime visibility:

- `Tracee` is useful for container-aware runtime detection and quick forensics when you need to confirm what a compromised workload actually touched.
- `Inspektor Gadget` is useful when the assessment needs kernel-level telemetry mapped back to pods, containers, DNS activity, file execution, or network behavior.

## Checks

Use these as quick first-pass commands during assessment:

```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

What is interesting here:

- A root process with broad capabilities and `Seccomp: 0` deserves immediate attention.
- A root process that also has a **1:1 UID map** is far more interesting than "root" inside a properly isolated user namespace.
- `cgroup2fs` usually means many older **cgroup v1** escape chains are not your best starting point, while missing `memory.max` or `pids.max` still points to weak blast-radius controls.
- Suspicious mounts and runtime sockets often provide a faster path to impact than any kernel exploit.
- The combination of weak runtime posture and weak resource limits usually indicates a generally permissive container environment rather than a single isolated mistake.

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
