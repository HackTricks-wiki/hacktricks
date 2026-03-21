# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

A practical way to define a container is this: a container is a **regular Linux process tree** that has been started under a specific OCI-style configuration so that it sees a controlled filesystem, a controlled set of kernel resources, and a restricted privilege model. The process may believe it is PID 1, may believe it has its own network stack, may believe it owns its own hostname and IPC resources, and may even run as root inside its own user namespace. But under the hood it is still a host process that the kernel schedules like any other.

This is why container security is really the study of how that illusion is constructed and how it fails. If the mount namespace is weak, the process may see the host filesystem. If the user namespace is absent or disabled, root inside the container may map too closely to root on the host. If seccomp is unconfined and the capability set is too broad, the process may reach syscalls and privileged kernel features that should have stayed out of reach. If the runtime socket is mounted inside the container, the container may not need a kernel breakout at all because it can simply ask the runtime to launch a more powerful sibling container or mount the host root filesystem directly.

## How Containers Differ From Virtual Machines

A VM normally carries its own kernel and hardware abstraction boundary. That means the guest kernel can crash, panic, or be exploited without automatically implying direct control of the host kernel. In containers, the workload does not get a separate kernel. Instead, it gets a carefully filtered and namespaced view of the same kernel that the host uses. As a result, containers are usually lighter, faster to start, easier to pack densely on a machine, and better suited to short-lived application deployment. The price is that the isolation boundary depends much more directly on correct host and runtime configuration.

This does not mean containers are "insecure" and VMs are "secure". It means the security model is different. A well-configured container stack with rootless execution, user namespaces, default seccomp, a strict capability set, no host namespace sharing, and strong SELinux or AppArmor enforcement can be very robust. Conversely, a container started with `--privileged`, host PID/network sharing, the Docker socket mounted inside it, and a writable bind mount of `/` is functionally much closer to host root access than to a safely isolated application sandbox. The difference comes from the layers that were enabled or disabled.

There is also a middle ground that readers should understand because it appears more and more often in real environments. **Sandboxed container runtimes** such as **gVisor** and **Kata Containers** intentionally harden the boundary beyond a classic `runc` container. gVisor places a userspace kernel layer between the workload and many host kernel interfaces, while Kata launches the workload inside a lightweight virtual machine. These are still used through container ecosystems and orchestration workflows, but their security properties differ from plain OCI runtimes and should not be mentally grouped with "normal Docker containers" as if everything behaved the same way.

## The Container Stack: Several Layers, Not One

When someone says "this container is insecure", the useful follow-up question is: **which layer made it insecure?** A containerized workload is usually the result of several components working together.

At the top, there is often an **image build layer** such as BuildKit, Buildah, or Kaniko, which creates the OCI image and metadata. Above the low-level runtime, there may be an **engine or manager** such as Docker Engine, Podman, containerd, CRI-O, Incus, or systemd-nspawn. In cluster environments, there may also be an **orchestrator** such as Kubernetes deciding the requested security posture through workload configuration. Finally, the **kernel** is what actually enforces namespaces, cgroups, seccomp, and MAC policy.

This layered model is important for understanding defaults. A restriction may be requested by Kubernetes, translated through CRI by containerd or CRI-O, converted into an OCI spec by the runtime wrapper, and only then enforced by `runc`, `crun`, `runsc`, or another runtime against the kernel. When defaults differ between environments, it is often because one of these layers changed the final configuration. The same mechanism may therefore appear in Docker or Podman as a CLI flag, in Kubernetes as a Pod or `securityContext` field, and in lower-level runtime stacks as OCI configuration generated for the workload. For that reason, CLI examples in this section should be read as **runtime-specific syntax for a general container concept**, not as universal flags supported by every tool.

## The Real Container Security Boundary

In practice, container security comes from **overlapping controls**, not from a single perfect control. Namespaces isolate visibility. cgroups govern and limit resource usage. Capabilities reduce what a privileged-looking process may actually do. seccomp blocks dangerous syscalls before they reach the kernel. AppArmor and SELinux add Mandatory Access Control on top of normal DAC checks. `no_new_privs`, masked procfs paths, and read-only system paths make common privilege and proc/sys abuse chains harder. The runtime itself also matters because it decides how mounts, sockets, labels, and namespace joins are created.

That is why a lot of container security documentation seems repetitive. The same escape chain often depends on multiple mechanisms at once. For example, a writable host bind mount is bad, but it becomes far worse if the container also runs as real root on the host, has `CAP_SYS_ADMIN`, is unconfined by seccomp, and is not restricted by SELinux or AppArmor. Likewise, host PID sharing is a serious exposure, but it becomes dramatically more useful to an attacker when it is combined with `CAP_SYS_PTRACE`, weak procfs protections, or namespace-entry tools such as `nsenter`. The right way to document the topic is therefore not by repeating the same attack on every page, but by explaining what each layer contributes to the final boundary.

## How To Read This Section

The section is organized from the most general concepts to the most specific ones.

Start with the runtime and ecosystem overview:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Then review the control planes and supply-chain surfaces that frequently decide whether an attacker even needs a kernel escape:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Then move into the protection model:

{{#ref}}
protections/
{{#endref}}

The namespace pages explain the kernel isolation primitives individually:

{{#ref}}
protections/namespaces/
{{#endref}}

The pages on cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, and read-only system paths explain the mechanisms that are usually layered on top of namespaces:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## A Good First Enumeration Mindset

When assessing a containerized target, it is much more useful to ask a small set of precise technical questions than to immediately jump to famous escape PoCs. First, identify the **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer, or something more specialized. Then identify the **runtime**: `runc`, `crun`, `runsc`, `kata-runtime`, or another OCI-compatible implementation. After that, check whether the environment is **rootful or rootless**, whether **user namespaces** are active, whether any **host namespaces** are shared, what **capabilities** remain, whether **seccomp** is enabled, whether a **MAC policy** is actually enforcing, whether **dangerous mounts or sockets** are present, and whether the process can interact with the container runtime API.

Those answers tell you far more about the real security posture than the base image name ever will. In many assessments, you can predict the likely breakout family before reading a single application file just by understanding the final container configuration.

## Coverage

This section covers the old Docker-focused material under container-oriented organization: runtime and daemon exposure, authorization plugins, image trust and build secrets, sensitive host mounts, distroless workloads, privileged containers, and the kernel protections normally layered around container execution.
