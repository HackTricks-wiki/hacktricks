# Containers and Namespaces

{{#include ../../banners/hacktricks-training.md}}

A container is a Linux process running with an isolation and privilege configuration. Assess the runtime, mounted host resources, granted capabilities, and namespace settings together. The [container security overview](container-security/README.md) explains these layers and links to each control.

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md) focuses on access to containerd's management interface.
- [RunC privilege escalation](runc-privilege-escalation.md) covers runtime-specific escalation material.
- [Container security](container-security/README.md) explains runtimes, exposed APIs, image risks, sensitive mounts, privileged containers, assessment, and protections such as namespaces, seccomp, and mandatory access control.
