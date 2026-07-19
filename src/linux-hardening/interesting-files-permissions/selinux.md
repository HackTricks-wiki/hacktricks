# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux 是一种**基于标签的强制访问控制（MAC）**系统。实际上，这意味着即使 DAC 权限、组或 Linux capabilities 看起来足以执行某项操作，内核仍可能拒绝该操作，因为**源上下文**不允许使用请求的 class/permission 访问**目标上下文**。

上下文通常如下所示：
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
从 privesc 的角度来看，`type`（进程对应 domain，对象对应 type）通常是最重要的字段：

- 进程运行在诸如 `unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t` 等 **domain** 中
- 文件和 socket 具有诸如 `admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t` 等 **type**
- Policy 决定一个 domain 是否可以对另一个 domain 进行读取、写入、执行或 transition

## 快速枚举

如果启用了 SELinux，应尽早对其进行枚举，因为它可以解释常见的 Linux privesc 路径为何失败，也可以解释为什么一个围绕“无害” SELinux tool 的 privileged wrapper 实际上非常关键：
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

- `Disabled` 或 `Permissive` 模式会使 SELinux 作为边界的绝大部分价值失效。
- `unconfined_t` 通常表示 SELinux 虽然存在，但并未对该进程施加实质性限制。
- 自定义路径上的 `default_t`、`file_t` 或明显错误的标签，通常表明存在标签错误或部署不完整。
- `file_contexts.local` 中的本地覆盖项优先于策略默认值，因此应仔细检查。

## 策略分析

当你能够回答以下两个问题时，攻击或绕过 SELinux 会容易得多：

1. **我当前的域可以访问什么？**
2. **我可以转换到哪些域？**

最有用的工具是 `sepolicy` 和 **SETools**（`seinfo`、`sesearch`、`sedta`）：
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
这在主机使用 **confined users**，而不是将所有用户映射到 `unconfined_u` 时尤其有用。在这种情况下，请查找：

- 通过 `semanage login -l` 查看用户映射
- 通过 `semanage user -l` 查看允许的 roles
- 可访问的管理 domains，例如 `sysadm_t`、`secadm_t`、`webadm_t`
- 使用 `ROLE=` 或 `TYPE=` 的 `sudoers` 条目

如果 `sudo -l` 包含类似以下条目，则 SELinux 是权限边界的一部分：
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
另外检查是否可用 `newrole`：
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` 和 `newrole` 不会自动构成可利用点，但如果某个 privileged wrapper 或 `sudoers` 规则允许你选择更高权限的 role/type，它们就会成为高价值的 escalation 原语。

## 文件、Relabeling 和高价值 Misconfiguration

常见 SELinux 工具之间最重要的实际操作差异是：

- `chcon`：临时更改特定路径上的 label
- `semanage fcontext`：持久化的路径到 label 规则
- `restorecon` / `setfiles`：再次应用 policy/default label

这在 privesc 期间非常重要，因为 **relabeling 不只是表面变化**。它可以将一个原本“被 policy 阻止”的文件，变成“可被具有 privileged 权限的 confined service 读取/执行”的文件。

检查本地 relabel 规则和 relabel 漂移：
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
一个微妙但有用的细节是：普通的 `restorecon` **并不总能完全还原可疑标签**。如果目标类型位于 `customizable_types` 中，可能需要使用 `-F` 来强制完全重置。从攻击角度来看，这解释了为什么异常的 `chcon` 有时能够在“我们已经运行过 restorecon”这种草率清理后继续存在。
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
在 `sudo -l`、root wrappers、automation scripts 或文件 capabilities 中重点查找的高价值命令：
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
如果出现任一 MAC capability，也应交叉检查 [Linux capabilities page](linux-capabilities.md)；`cap_mac_admin` 和 `cap_mac_override` 很少见，但当 SELinux 属于边界的一部分时，它们具有直接相关性。

尤其值得关注：

- `semanage fcontext`：持久化更改路径应接收的 label
- `restorecon` / `setfiles`：大规模重新应用这些更改
- `semodule -i`：加载自定义 policy module
- `semanage permissive -a <domain_t>`：使单个 domain 进入 permissive 状态，而不切换整个主机
- `setsebool -P`：永久更改 policy booleans
- `load_policy`：重新加载 active policy

这些通常是 **helper primitives**，而不是独立的 root exploits。它们的价值在于可以让你：

- 使目标 domain 进入 permissive 状态
- 扩大你的 domain 与受保护 type 之间的访问权限
- 重新标记 attacker-controlled files，使 privileged service 可以读取或执行它们
- 弱化受限 service，使现有的 local bug 变得可利用

示例检查：
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
如果你可以以 root 身份加载 policy module，通常就能控制 SELinux 边界：
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
这就是为什么在 post-exploitation 期间，应将 `audit2allow`、`semodule` 和 `semanage permissive` 视为敏感的管理员操作面。它们可以在不改变经典 UNIX 权限的情况下，静默地将一条被阻断的链路转换为可用链路。

## 隐藏的 Denial 与 Module 提取

一个非常常见的 offensive 困境是：某条链路以含糊的 `EACCES` 失败，而预期的 AVC denial 却从未出现。`dontaudit` 规则可能隐藏了你所需的确切 permission。如果你可以通过 `sudo` 或其他 privileged wrapper 运行 `semodule`，临时禁用 `dontaudit` 可以将一次 silent failure 转化为精确的 policy clue：
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
这对于审查本地管理员已经进行的更改也很有用。一个小型 custom module 或单 domain permissive rule，通常就是导致目标服务表现得比 base policy 所暗示的宽松得多的原因。

## Audit Clues

AVC denials 通常是 offensive signal，而不只是 defensive noise。它们会告诉你：

- 你命中的 target object/type
- 被拒绝的 permission
- 你当前控制的 domain
- 小幅 policy 更改是否能让整个 chain 生效
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
如果本地 exploit 或 persistence 尝试持续因 `EACCES` 或奇怪的“permission denied”错误而失败，即使 root 看起来拥有 DAC permissions，也通常值得先检查 SELinux，再放弃该 vector。

## SELinux 用户

除了常规 Linux 用户之外，还存在 SELinux 用户。每个 Linux 用户都会根据 policy 映射到一个 SELinux 用户，使系统能够对不同账户施加不同的 allowed roles 和 domains。

快速检查：
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
在许多主流系统中，用户会被映射到 `unconfined_u`，这会降低用户 confinement 的实际影响。不过，在 hardened deployment 中，confined users 可以让 `sudo`、`su`、`newrole` 和 `runcon` 变得更值得关注，因为 **escalation path 可能取决于进入更合适的 SELinux role/type，而不只是成为 UID 0**。还要记住，某些 confined users 完全无法调用 `sudo`/`su`，除非 policy 明确允许底层的 setuid transition。因此，使用 `staff_u` + `sysadm_r` 的主机，可能会将一个看似影响较小的 `sudo ROLE=` / `TYPE=` 规则变成真正的 privilege boundary。

## 容器中的 SELinux

Container runtimes 通常会在诸如 `container_t` 的 confined domain 中启动 workloads，并将 container content 标记为 `container_file_t`。即使 container process 发生 escape，但仍以 container label 运行，host writes 仍可能失败，因为 label boundary 仍然完整。

快速示例：
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` 部分并非装饰。在许多容器部署中，runtime 会动态分配 MCS categories，使两个以 `container_t` 运行的进程仍然彼此隔离。如果 escape 进入 host namespace，但保留了原始的 category set，category mismatch 仍可能解释为什么某些 host paths 保持不可读或不可写。

值得注意的现代容器操作：

- `--security-opt label=disable` 可以有效地将 workload 移动到类似 `spc_t` 的 unconfined container-related type
- 使用 `:z` / `:Z` 的 bind mounts 会触发对 host path 的 relabeling，以适用于 shared/private container use
- 对 host content 进行广泛的 relabeling 本身就可能成为 security issue

本页对容器内容进行了简要介绍，以避免重复。有关 container-specific abuse cases 和 runtime examples，请参阅：

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## 参考资料

- [Red Hat 文档：使用 SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools：用于 SELinux 的 Policy analysis tools](https://github.com/SELinuxProject/setools)
- [管理 confined 和 unconfined users - RHEL 9 文档](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
