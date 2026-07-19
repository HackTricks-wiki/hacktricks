# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The UTS namespace isolates the **hostname** and **NIS domain name** seen by the process. At first glance this may look trivial compared with mount, PID, or user namespaces, but it is part of what makes a container appear to be its own host. Inside the namespace, the workload can see and sometimes change a hostname that is local to that namespace rather than global to the machine.

On its own, this is usually not the centerpiece of a breakout story. However, once the host UTS namespace is shared, a sufficiently privileged process may influence host identity-related settings, which can matter operationally and occasionally security-wise.

## Lab

You can create a UTS namespace with:

```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```

The hostname change remains local to that namespace and does not alter the host's global hostname. This is a simple but effective demonstration of the isolation property.

## Runtime Usage

Normal containers get an isolated UTS namespace. Docker and Podman can join the host UTS namespace through `--uts=host`, and similar host-sharing patterns can appear in other runtimes and orchestration systems. Most of the time, however, private UTS isolation is simply part of the normal container setup and requires little operator attention.

## Security Impact

Even though the UTS namespace is not usually the most dangerous one to share, it still contributes to the integrity of the container boundary. If the host UTS namespace is exposed and the process has the necessary privileges, it may be able to alter host hostname-related information. That may affect monitoring, logging, operational assumptions, or scripts that make trust decisions based on host identity data.

## Abuse

If the host UTS namespace is shared, the practical question is whether the process can modify host identity settings rather than just read them:

```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```

If the container also has the necessary privilege, test whether the hostname can be changed:

```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```

This is primarily an integrity and operational-impact issue rather than a full escape, but it still shows that the container can directly influence a host-global property.

Impact:

- host identity tampering
- confusing logs, monitoring, or automation that trust the hostname
- usually not a full escape on its own unless combined with other weaknesses

On Docker-style environments, a useful host-side detection pattern is:

```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```

Containers showing `UTSMode=host` are sharing the host UTS namespace and should be reviewed more carefully if they also carry capabilities that let them call `sethostname()` or `setdomainname()`.

## Checks

These commands are enough to see whether the workload has its own hostname view or is sharing the host UTS namespace.

```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```

What is interesting here:

- Matching namespace identifiers with a host process may indicate host UTS sharing.
- If changing the hostname affects more than the container itself, the workload has more influence over host identity than it should.
- This is usually a lower-priority finding than PID, mount, or user namespace issues, but it still confirms how isolated the process really is.

In most environments, the UTS namespace is best thought of as a supporting isolation layer. It is rarely the first thing you chase in a breakout, but it is still part of the overall consistency and safety of the container view.
{{#include ../../../../../banners/hacktricks-training.md}}
