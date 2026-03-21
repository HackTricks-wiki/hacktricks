# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

One of the biggest sources of confusion in container security is that several completely different components are often collapsed into the same word. "Docker" might refer to an image format, a CLI, a daemon, a build system, a runtime stack, or simply the idea of containers in general. For security work, that ambiguity is a problem, because different layers are responsible for different protections. A breakout caused by a bad bind mount is not the same thing as a breakout caused by a low-level runtime bug, and neither is the same thing as a cluster policy mistake in Kubernetes.

This page separates the ecosystem by role so that the rest of the section can talk precisely about where a protection or weakness actually lives.

## OCI As The Common Language

Modern Linux container stacks often interoperate because they speak a set of OCI specifications. The **OCI Image Specification** describes how images and layers are represented. The **OCI Runtime Specification** describes how the runtime should launch the process, including namespaces, mounts, cgroups, and security settings. The **OCI Distribution Specification** standardizes how registries expose content.

This matters because it explains why a container image built with one tool can often be run with another, and why several engines can share the same low-level runtime. It also explains why security behavior can look similar across different products: many of them are constructing the same OCI runtime configuration and handing it to the same small set of runtimes.

## Low-Level OCI Runtimes

The low-level runtime is the component that is closest to the kernel boundary. It is the part that actually creates namespaces, writes cgroup settings, applies capabilities and seccomp filters, and finally `execve()`s the container process. When people discuss "container isolation" at the mechanical level, this is the layer they are usually talking about, even if they do not say so explicitly.

### `runc`

`runc` is the reference OCI runtime and remains the best-known implementation. It is heavily used under Docker, containerd, and many Kubernetes deployments. A lot of public research and exploitation material targets `runc`-style environments simply because they are common and because `runc` defines the baseline that many people think of when they picture a Linux container. Understanding `runc` therefore gives a reader a strong mental model for classic container isolation.

### `crun`

`crun` is another OCI runtime, written in C and widely used in modern Podman environments. It is often praised for good cgroup v2 support, strong rootless ergonomics, and lower overhead. From a security perspective, the important thing is not that it is written in a different language, but that it still plays the same role: it is the component that turns the OCI configuration into a running process tree under the kernel. A rootless Podman workflow frequently ends up feeling safer not because `crun` magically fixes everything, but because the overall stack around it tends to lean harder into user namespaces and least privilege.

### `runsc` From gVisor

`runsc` is the runtime used by gVisor. Here the boundary changes meaningfully. Instead of passing most syscalls directly to the host kernel in the usual way, gVisor inserts a userspace kernel layer that emulates or mediates large parts of the Linux interface. The result is not a normal `runc` container with a few extra flags; it is a different sandbox design whose purpose is to reduce host-kernel attack surface. Compatibility and performance tradeoffs are part of that design, so environments using `runsc` should be documented differently from normal OCI runtime environments.

### `kata-runtime`

Kata Containers push the boundary further by launching the workload inside a lightweight virtual machine. Administratively, this may still look like a container deployment, and orchestration layers may still treat it as such, but the underlying isolation boundary is closer to virtualization than to a classic host-kernel-shared container. This makes Kata useful when stronger tenant isolation is desired without abandoning container-centric workflows.

## Engines And Container Managers

If the low-level runtime is the component that talks directly to the kernel, the engine or manager is the component that users and operators usually interact with. It handles image pulls, metadata, logs, networks, volumes, lifecycle operations, and API exposure. This layer matters enormously because many real-world compromises happen here: access to a runtime socket or daemon API can be equivalent to host compromise even if the low-level runtime itself is perfectly healthy.

### Docker Engine

Docker Engine is the most recognizable container platform for developers and one of the reasons container vocabulary became so Docker-shaped. The typical path is `docker` CLI to `dockerd`, which in turn coordinates lower-level components such as `containerd` and an OCI runtime. Historically, Docker deployments have often been **rootful**, and access to the Docker socket has therefore been a very powerful primitive. This is why so much practical privilege-escalation material focuses on `docker.sock`: if a process can ask `dockerd` to create a privileged container, mount host paths, or join host namespaces, it may not need a kernel exploit at all.

### Podman

Podman was designed around a more daemonless model. Operationally, this helps reinforce the idea that containers are just processes managed through standard Linux mechanisms rather than through one long-lived privileged daemon. Podman also has a much stronger **rootless** story than the classic Docker deployments many people first learned. That does not make Podman automatically safe, but it changes the default risk profile significantly, especially when combined with user namespaces, SELinux, and `crun`.

### containerd

containerd is a core runtime management component in many modern stacks. It is used under Docker and is also one of the dominant Kubernetes runtime backends. It exposes powerful APIs, manages images and snapshots, and delegates the final process creation to a low-level runtime. Security discussions around containerd should emphasize that access to the containerd socket or `ctr`/`nerdctl` functionality can be just as dangerous as access to Docker's API, even if the interface and workflow feel less "developer friendly".

### CRI-O

CRI-O is more focused than Docker Engine. Instead of being a general-purpose developer platform, it is built around implementing the Kubernetes Container Runtime Interface cleanly. This makes it especially common in Kubernetes distributions and SELinux-heavy ecosystems such as OpenShift. From a security perspective, that narrower scope is useful because it reduces conceptual clutter: CRI-O is very much part of the "run containers for Kubernetes" layer rather than an everything-platform.

### Incus, LXD, And LXC

Incus/LXD/LXC systems are worth separating from Docker-style application containers because they are often used as **system containers**. A system container is usually expected to look more like a lightweight machine with a fuller userspace, long-running services, richer device exposure, and more extensive host integration. The isolation mechanisms are still kernel primitives, but the operational expectations are different. As a result, misconfigurations here often look less like "bad app-container defaults" and more like mistakes in lightweight virtualization or host delegation.

### systemd-nspawn

systemd-nspawn occupies an interesting place because it is systemd-native and very useful for testing, debugging, and running OS-like environments. It is not the dominant cloud-native production runtime, but it appears often enough in labs and distro-oriented environments that it deserves mention. For security analysis, it is another reminder that the concept "container" spans multiple ecosystems and operational styles.

### Apptainer / Singularity

Apptainer (formerly Singularity) is common in research and HPC environments. Its trust assumptions, user workflow, and execution model differ in important ways from Docker/Kubernetes-centric stacks. In particular, these environments often care deeply about letting users run packaged workloads without handing them broad privileged container-management powers. If a reviewer assumes every container environment is basically "Docker on a server", they will misunderstand these deployments badly.

## Build-Time Tooling

A lot of security discussions only talk about run time, but build-time tooling also matters because it determines image contents, build secrets exposure, and how much trusted context gets embedded into the final artifact.

**BuildKit** and `docker buildx` are modern build backends that support features such as caching, secret mounting, SSH forwarding, and multi-platform builds. Those are useful features, but from a security perspective they also create places where secrets can leak into image layers or where an overly broad build context can expose files that should never have been included. **Buildah** plays a similar role in OCI-native ecosystems, especially around Podman, while **Kaniko** is often used in CI environments that do not want to grant a privileged Docker daemon to the build pipeline.

The key lesson is that image creation and image execution are different phases, but a weak build pipeline can create a weak runtime posture long before the container is launched.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes should not be mentally equated with the runtime itself. Kubernetes is the orchestrator. It schedules Pods, stores desired state, and expresses security policy through workload configuration. The kubelet then talks to a CRI implementation such as containerd or CRI-O, which in turn invokes a low-level runtime such as `runc`, `crun`, `runsc`, or `kata-runtime`.

This separation matters because many people wrongly attribute a protection to "Kubernetes" when it is really enforced by the node runtime, or they blame "containerd defaults" for behavior that came from a Pod spec. In practice, the final security posture is a composition: the orchestrator asks for something, the runtime stack translates it, and the kernel finally enforces it.

## Why Runtime Identification Matters During Assessment

If you identify the engine and runtime early, many later observations become easier to interpret. A rootless Podman container suggests user namespaces are likely part of the story. A Docker socket mounted into a workload suggests API-driven privilege escalation is a realistic path. A CRI-O/OpenShift node should immediately make you think about SELinux labels and restricted workload policy. A gVisor or Kata environment should make you more cautious about assuming that a classic `runc` breakout PoC will behave the same way.

That is why one of the first steps in container assessment should always be to answer two simple questions: **which component is managing the container** and **which runtime actually launched the process**. Once those answers are clear, the rest of the environment usually becomes much easier to reason about.

## Runtime Vulnerabilities

Not every container escape comes from operator misconfiguration. Sometimes the runtime itself is the vulnerable component. This matters because a workload may be running with what looks like a careful configuration and still be exposed through a low-level runtime flaw.

The classic example is **CVE-2019-5736** in `runc`, where a malicious container could overwrite the host `runc` binary and then wait for a later `docker exec` or similar runtime invocation to trigger attacker-controlled code. The exploit path is very different from a simple bind-mount or capability mistake because it abuses how the runtime re-enters the container process space during exec handling.

A minimal reproduction workflow from a red-team perspective is:

```bash
go build main.go
./main
```

Then, from the host:

```bash
docker exec -it <container-name> /bin/sh
```

The key lesson is not the exact historical exploit implementation, but the assessment implication: if the runtime version is vulnerable, ordinary in-container code execution may be enough to compromise the host even when the visible container configuration does not look blatantly weak.

Recent runtime CVEs such as `CVE-2024-21626` in `runc`, BuildKit mount races, and containerd parsing bugs reinforce the same point. Runtime version and patch level are part of the security boundary, not merely maintenance trivia.
