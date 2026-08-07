# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux 是一种基于 **label** 的 Mandatory Access Control (MAC) 系统。实际上，这意味着即使 DAC permissions、groups 或 Linux capabilities 看起来足以执行某个操作，kernel 仍然可能拒绝该操作，因为不允许 **source context** 使用所请求的 class/permission 访问 **target context**。

context 通常如下所示：
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
从 privesc 的角度来看，`type`（进程对应 domain，对象对应 type）通常是最重要的字段：

- 进程运行在某个 **domain** 中，例如 `unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t`
- 文件和 socket 具有某个 **type**，例如 `admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t`
- Policy 决定某个 domain 是否可以对另一个 domain 执行读取、写入、执行或转换操作

## 快速枚举

如果启用了 SELinux，应尽早对其进行枚举，因为它可以解释常见的 Linux privesc 路径为何失败，或者为什么一个围绕“无害” SELinux 工具的特权 wrapper 实际上非常关键：
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

- `Disabled` 或 `Permissive` 模式会使 SELinux 作为边界的大部分价值失效。
- `unconfined_t` 通常意味着 SELinux 已存在，但并未对该进程施加实质性限制。
- 自定义路径上的 `default_t`、`file_t` 或明显错误的标签，通常表示标签配置错误或部署不完整。
- `file_contexts.local` 中的本地覆盖项优先于策略默认值，因此应仔细检查。

## Policy Analysis

当你能够回答以下两个问题时，攻击或绕过 SELinux 会容易得多：

1. **我当前的 domain 可以访问什么？**
2. **我可以 transition 到哪些 domain？**

最实用的工具是 `sepolicy` 和 **SETools**（`seinfo`、`sesearch`、`sedta`）：<sup>[[2]](#references)</sup>
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
当主机使用 **confined users**，而不是将所有用户映射到 `unconfined_u` 时，这尤其有用。在这种情况下，请查找：<sup>[[3]](#references)</sup>

- 通过 `semanage login -l` 查看 user mappings
- 通过 `semanage user -l` 查看 allowed roles
- 可访问的 admin domains，例如 `sysadm_t`、`secadm_t`、`webadm_t`
- 使用 `ROLE=` 或 `TYPE=` 的 `sudoers` 条目

如果 `sudo -l` 包含如下条目，则 SELinux 是 privilege boundary 的一部分：
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
另外检查 `newrole` 是否可用：
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` 和 `newrole` 不会自动构成可利用点，但如果某个 privileged wrapper 或 `sudoers` 规则允许你选择更有利的 role/type，它们就会成为高价值的权限提升原语。

## 文件、重新标记和高价值错误配置

常见 SELinux 工具之间最重要的实际操作差异是：<sup>[[1]](#references)</sup>

- `chcon`：临时更改特定路径的标签
- `semanage fcontext`：持久化的路径到标签规则
- `restorecon` / `setfiles`：再次应用策略/默认标签

这在 privesc 过程中非常重要，因为**重新标记不只是表面上的变化**。它可以将一个原本“被策略阻止”的文件变成“可由 privileged confined service 读取/执行”的文件。

检查本地重新标记规则和标签漂移：
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
一个微妙但实用的细节是：普通的 `restorecon` **并不总能完全还原可疑标签**。如果目标类型位于 `customizable_types` 中，可能需要使用 `-F` 来强制完全重置。从攻击视角来看，这解释了为什么异常的 `chcon` 有时能够在“我们已经运行过 restorecon”这种随意清理后继续存在。
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
在 `sudo -l`、root 封装脚本、自动化脚本或文件 capabilities 中重点查找的高价值命令：
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
如果出现任一 MAC capability，也应交叉检查 [Linux capabilities page](linux-capabilities.md)；`cap_mac_admin` 和 `cap_mac_override` 不常见，但当 SELinux 属于边界的一部分时，它们与此直接相关。

尤其值得关注：

- `semanage fcontext`：持久化修改路径应接收的 label
- `restorecon` / `setfiles`：大规模重新应用这些更改
- `semodule -i`：加载自定义 policy module
- `semanage permissive -a <domain_t>`：仅使一个 domain 进入 permissive 状态，而不切换整个主机
- `setsebool -P`：永久修改 policy booleans
- `load_policy`：重新加载 active policy

这些通常是**辅助原语**，而不是独立的 root exploit。它们的价值在于可以让你：

- 使目标 domain 进入 permissive 状态
- 扩大你的 domain 与受保护 type 之间的访问权限
- 重新标记攻击者控制的文件，使 privileged service 能够读取或执行它们
- 削弱受限 service，使现有的 local bug 变得可利用

示例检查：
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
如果你可以以 root 身份加载策略模块，通常就能控制 SELinux 边界：
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
这就是为什么在 post-exploitation 期间，应将 `audit2allow`、`semodule` 和 `semanage permissive` 视为敏感的 admin surfaces。它们可以在不改变经典 UNIX permissions 的情况下，静默地将一条被阻断的 chain 转换为可正常工作的 chain。

## 隐藏的 Denials 和 Module 提取

一个非常常见的 offensive frustration 是：某条 chain 以普通的 `EACCES` 失败，但预期的 AVC denial 却从未出现。`dontaudit` rules 可能隐藏了你所需的确切 permission。如果你可以通过 `sudo` 或其他 privileged wrapper 运行 `semodule`，暂时禁用 `dontaudit` 可能会将一次 silent failure 转化为精确的 policy clue：<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
这对于审查本地管理员已经做过的更改也很有用。一个小型 custom module 或针对单个 domain 的 permissive rule，通常就是目标服务的行为比基础 policy 所暗示的宽松得多的原因。

## 审计线索

AVC 拒绝通常是 offensive signal，而不只是 defensive noise。它们会告诉你：

- 你命中的 target object/type
- 被拒绝的 permission
- 你当前控制的 domain
- 一个小型 policy 更改是否会让整个链条生效
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
如果本地 exploit 或 persistence 尝试持续因 `EACCES` 或奇怪的“permission denied”错误而失败，即使看起来拥有 root 级别的 DAC 权限，也通常值得先检查 SELinux，再放弃该攻击向量。

## SELinux Users

除了常规 Linux 用户外，还存在 SELinux 用户。作为 policy 的一部分，每个 Linux 用户都会映射到一个 SELinux 用户，使系统能够针对不同账户施加不同的允许角色和 domain。<sup>[[3]](#references)</sup>

快速检查：
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
在许多主流系统中，用户会被映射到 `unconfined_u`，这会降低用户 confinement 在实践中的影响。不过在 hardened 部署中，confined 用户可以让 `sudo`、`su`、`newrole` 和 `runcon` 变得更值得关注，因为 **escalation path 可能取决于进入更合适的 SELinux role/type，而不只是成为 UID 0**。还要记住，某些 confined 用户根本无法调用 `sudo`/`su`，除非 policy 明确允许底层的 setuid transition，因此使用 `staff_u` + `sysadm_r` 的主机可能会将一个看似次要的 `sudo ROLE=` / `TYPE=` 规则变成真正的 privilege boundary。<sup>[[3]](#references)</sup>

## 容器中的 SELinux

容器运行时通常会在类似 `container_t` 的 confined domain 中启动 workload，并将容器内容标记为 `container_file_t`。即使容器进程发生 escape，但仍以容器 label 运行，主机写入操作仍可能失败，因为 label boundary 仍然保持完整。

快速示例：
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` 部分并不是装饰。在许多容器部署中，runtime 会动态分配 MCS categories，以便即使两个进程都以 `container_t` 运行，它们仍会彼此隔离。如果 escape 进入了 host namespace，但保留了原始的 category set，那么 category 不匹配仍可能解释为什么某些 host paths 依然无法读取或写入。

值得注意的现代容器操作：

- `--security-opt label=disable` 可以有效地将 workload 转移到不受限制的容器相关 type，例如 `spc_t`
- 使用 `:z` / `:Z` 的 bind mounts 会触发对 host path 的 relabeling，以供容器共享或私有使用
- 对 host content 进行广泛 relabeling 本身就可能成为安全问题

为避免重复，本页面对容器内容保持简短。有关容器特定的 abuse cases 和 runtime 示例，请查看：

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## 参考资料

- [1] [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [3] [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
