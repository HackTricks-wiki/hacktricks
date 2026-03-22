# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

A good container assessment should answer two parallel questions. First, what can an attacker do from the current workload? Second, which operator choices made that possible? Enumeration tools help with the first question, and hardening guidance helps with the second. Keeping both on one page makes the section more useful as a field reference rather than just a catalog of escape tricks.

## Enumeration Tools

A number of tools remain useful for quickly characterizing a container environment:

- `linpeas` can identify many container indicators, mounted sockets, capability sets, dangerous filesystems, and breakout hints.
- `CDK` focuses specifically on container environments and includes enumeration plus some automated escape checks.
- `amicontained` is lightweight and useful for identifying container restrictions, capabilities, namespace exposure, and likely breakout classes.
- `deepce` is another container-focused enumerator with breakout-oriented checks.
- `grype` is useful when the assessment includes image-package vulnerability review instead of only runtime escape analysis.

The value of these tools is speed and coverage, not certainty. They help reveal the rough posture quickly, but the interesting findings still need manual interpretation against the actual runtime, namespace, capability, and mount model.

## Hardening Priorities

The most important hardening principles are conceptually simple even though their implementation varies by platform. Avoid privileged containers. Avoid mounted runtime sockets. Do not give containers writable host paths unless there is a very specific reason. Use user namespaces or rootless execution where feasible. Drop all capabilities and add back only the ones the workload truly needs. Keep seccomp, AppArmor, and SELinux enabled rather than disabling them to fix application compatibility problems. Limit resources so that a compromised container cannot trivially deny service to the host.

Image and build hygiene matter as much as runtime posture. Use minimal images, rebuild frequently, scan them, require provenance where practical, and keep secrets out of layers. A container running as non-root with a small image and a narrow syscall and capability surface is much easier to defend than a large convenience image running as host-equivalent root with debugging tools preinstalled.

## Resource-Exhaustion Examples

Resource controls are not glamorous, but they are part of container security because they limit the blast radius of compromise. Without memory, CPU, or PID limits, a simple shell may be enough to degrade the host or neighboring workloads.

Example host-impacting tests:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

These examples are useful because they show that not every dangerous container outcome is a clean "escape". Weak cgroup limits can still turn code execution into real operational impact.

## Hardening Tooling

For Docker-centric environments, `docker-bench-security` remains a useful host-side audit baseline because it checks common configuration issues against widely recognized benchmark guidance:

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

The tool is not a substitute for threat modeling, but it is still valuable for finding careless daemon, mount, network, and runtime defaults that accumulate over time.

## Checks

Use these as quick first-pass commands during assessment:

```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

What is interesting here:

- A root process with broad capabilities and `Seccomp: 0` deserves immediate attention.
- Suspicious mounts and runtime sockets often provide a faster path to impact than any kernel exploit.
- The combination of weak runtime posture and weak resource limits usually indicates a generally permissive container environment rather than a single isolated mistake.
{{#include ../../../banners/hacktricks-training.md}}
