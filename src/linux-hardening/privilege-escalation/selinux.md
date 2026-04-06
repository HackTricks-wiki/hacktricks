# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux 是一个 **基于标签的强制访问控制 (MAC)** 系统。实际上，这意味着即使 DAC 权限、组或 Linux 能力 对某个操作看起来足够，内核仍可能拒绝该操作，因为 **源上下文** 未被允许以请求的类/权限访问 **目标上下文**。

上下文通常看起来像：
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
From a privesc perspective, the `type` (进程的 domain、对象的 type) 通常是最重要的字段：

- 进程以 **domain** 运行，例如 `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- 文件和套接字具有 **type**，例如 `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- 策略决定一个 domain 是否可以 读取/写入/执行/切换 到另一个

## 快速枚举

如果 SELinux 已启用，请尽早枚举它，因为它能解释为什么常见的 Linux privesc 路径会失败，或为什么一个拥有特权的包装器围绕一个“harmless”的 SELinux 工具实际上非常关键：
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
有用的后续检查：
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
有趣的发现：

- `Disabled` or `Permissive` mode removes most of the value of SELinux as a boundary.
- `unconfined_t` usually means SELinux is present but not meaningfully constraining that process.
- `default_t`, `file_t`, or obviously wrong labels on custom paths often indicate mislabeling or incomplete deployment.
- Local overrides in `file_contexts.local` take precedence over policy defaults, so review them carefully.

## 策略分析

SELinux 在能回答以下两个问题时，更容易被攻击或绕过：

1. **我的当前域可以访问什么？**
2. **我可以转入哪些域？**

最有用的工具是 `sepolicy` 和 **SETools**（`seinfo`, `sesearch`, `sedta`）：
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
当主机使用 **受限用户** 而不是将所有人映射到 `unconfined_u` 时，这尤其有用。在这种情况下，请查看：

- 用户映射（通过 `semanage login -l`）
- 允许的角色（通过 `semanage user -l`）
- 可访问的管理员域，例如 `sysadm_t`、`secadm_t`、`webadm_t`
- 使用 `ROLE=` 或 `TYPE=` 的 `sudoers` 条目

如果 `sudo -l` 包含类似这样的条目，SELinux 是权限边界的一部分：
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
还要检查 `newrole` 是否可用：
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` 和 `newrole` 并非自动可利用，但如果一个有特权的包装器或 `sudoers` 规则允许你选择更合适的角色/类型，它们就会成为高价值的提权原语。

## 文件、重新标记与高价值误配置

常见 SELinux 工具之间最重要的操作差异是：

- `chcon`: 对特定路径的临时标签更改
- `semanage fcontext`: 持久的路径到标签规则
- `restorecon` / `setfiles`: 再次应用策略/默认标签

在 privesc 期间这非常重要，因为 **重新标记不仅仅是表面作用**。它可以把一个文件从 "blocked by policy" 变成 "readable/executable by a privileged confined service"。

检查本地重新标记规则和重新标记漂移：
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
在 `sudo -l`、root wrappers、automation scripts 或 file capabilities 中要搜寻的高价值命令：
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
尤其值得注意：

- `semanage fcontext`: 持久地更改路径应接收的标签
- `restorecon` / `setfiles`: 在大规模上重新应用这些更改
- `semodule -i`: 加载自定义策略模块
- `semanage permissive -a <domain_t>`: 将单个域设置为 permissive，而无需切换整个主机
- `setsebool -P`: 永久更改策略布尔值
- `load_policy`: 重新加载活动策略

这些通常是**辅助原语**，而不是独立的 root exploits。它们的价值在于它们允许你：

- 使目标域变为 permissive
- 扩大你的域与受保护类型之间的访问
- 重新标记攻击者控制的文件，使特权服务能够读取或执行它们
- 削弱受限服务到足以让现有的本地漏洞变得可利用

示例检查：
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
如果你可以以 root 身份加载一个策略模块，通常就能控制 SELinux 边界：
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
这就是为什么 `audit2allow`、`semodule` 和 `semanage permissive` 在 post-exploitation 期间应被视为敏感的管理员界面。它们可以在不更改经典 UNIX 权限的情况下，默默地将被阻断的链转换为可用的链。

## 审计线索

AVC 拒绝通常是进攻性的信号，而不仅仅是防御性的噪音。它们会告诉你：

- 你命中的目标对象/类型
- 哪个权限被拒绝
- 你当前控制的是哪个域
- 一个小的策略改动是否能让该链生效
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
如果 local exploit 或 persistence attempt 在尽管看起来像 root 的 DAC 权限下仍不断以 `EACCES` 或奇怪的 "permission denied" 错误失败，通常在放弃该向量之前值得检查 SELinux。

## SELinux 用户

除了常规 Linux 用户外，还有 SELinux 用户。每个 Linux 用户在策略中被映射到一个 SELinux 用户，这使系统能够对不同账户施加不同的允许角色和域。

快速检查：
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
在许多主流系统上，用户被映射到 `unconfined_u`，这减少了用户隔离的实际影响。 在加固部署中，受限用户会让 `sudo`、`su`、`newrole` 和 `runcon` 更有意思，因为 **提升路径可能取决于进入更合适的 SELinux 角色/类型，而不仅仅是成为 UID 0**。

## SELinux 在容器中

容器运行时通常在受限域（例如 `container_t`）中启动工作负载，并将容器内容标记为 `container_file_t`。如果容器进程逃逸但仍以容器标签运行，主机写入可能仍然失败，因为标签边界保持完整。

快速示例：
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
值得注意的现代容器操作：

- `--security-opt label=disable` 可以将工作负载有效地移动到未受约束的与容器相关的类型，例如 `spc_t`
- 带有 `:z` / `:Z` 的 bind mounts 会触发对主机路径的重新标记，以用于容器的共享/私有使用
- 对主机内容的广泛重新标记本身就可能成为一个安全问题

本页将容器相关内容保持简短以避免重复。有关容器特定的滥用案例和运行时示例，请查看：

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## 参考资料

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
