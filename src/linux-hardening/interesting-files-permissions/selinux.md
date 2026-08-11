# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux 是一种**基于 label 的强制访问控制（MAC）**系统。实际上，这意味着即使 DAC 权限、组或 Linux capabilities 看起来足以执行某项操作，内核仍然可能拒绝该操作，因为不允许**源上下文**使用请求的类/权限访问**目标上下文**。<sup>[[1]](#references)</sup>

上下文通常如下所示：<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
从 privesc 的角度来看，`type`（进程对应 domain，对象对应 type）通常是最重要的字段：<sup>[[1]](#references)</sup>

- 进程运行在某个 **domain** 中，例如 `unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t`
- 文件和 socket 具有某种 **type**，例如 `admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t`
- Policy 决定某个 domain 是否可以对另一个 domain 进行读取、写入、执行或 transition

## 快速枚举

如果启用了 SELinux，应尽早对其进行枚举，因为它可以解释常见的 Linux privesc 路径为何失败，或者为什么围绕某个“无害”的 SELinux 工具构建的特权 wrapper 实际上至关重要：<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
有用的后续检查：<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
有趣的发现：<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- `Disabled` 或 `Permissive` 模式会使 SELinux 作为边界的绝大部分价值失效。
- `unconfined_t` 通常表示系统中存在 SELinux，但它并未对该进程施加实质性限制。
- 自定义路径上的 `default_t`、`file_t` 或明显错误的标签，通常表示标签配置错误或部署不完整。
- `file_contexts.local` 中的本地覆盖项优先于默认策略，因此应仔细检查。

## 策略分析

当你能够回答以下两个问题时，SELinux 会更容易被攻击或绕过：

1. **我当前的 domain 可以访问什么？**
2. **我可以转换到哪些 domain？**

最有用的工具是 `sepolicy` 和 **SETools**（`seinfo`、`sesearch`、`sedta`）：<sup>[[2]](#references)[[9]](#references)</sup>
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
当主机使用 **confined users**，而不是将所有用户映射到 `unconfined_u` 时，这一点尤其有用。在这种情况下，请查找：<sup>[[3]](#references)</sup>

- 通过 `semanage login -l` 查看 user mappings
- 通过 `semanage user -l` 查看 allowed roles
- 可访问的 admin domains，例如 `sysadm_t`、`secadm_t`、`webadm_t`
- 使用 `ROLE=` 或 `TYPE=` 的 `sudoers` 条目

如果 `sudo -l` 包含如下条目，则 SELinux 是 privilege boundary 的一部分：<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
同时检查 `newrole` 是否可用：<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` 和 `newrole` 并不会自动带来可利用性，但如果某个特权 wrapper 或 `sudoers` 规则允许你选择更高权限的 role/type，它们就会成为高价值的提权原语。<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## 文件、重新标记和高价值错误配置

常见 SELinux 工具之间最重要的操作差异是：<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`：对特定路径临时更改 label
- `semanage fcontext`：持久化的路径到 label 规则
- `restorecon` / `setfiles`：再次应用 policy/default label

这在 privesc 期间非常重要，因为 **relabeling 不只是表面变化**。它可能将一个原本“被 policy 阻止”的文件变成“可由受限特权服务读取/执行”的文件。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

检查本地 relabel 规则和 relabel 漂移：<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
一个隐蔽但有用的细节是：普通的 `restorecon` **并不总能完全还原可疑标签**。如果目标类型位于 `customizable_types` 中，可能需要使用 `-F` 来强制完全重置。从攻击角度来看，这解释了为什么异常的 `chcon` 有时能在“我们已经运行过 restorecon”这样的清理后仍然存在。<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
在 `sudo -l`、root wrappers、自动化脚本或文件 capabilities 中重点查找的高价值命令：<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
如果出现任一 MAC capability，也请交叉检查 [Linux capabilities page](linux-capabilities.md)；Linux capabilities 文档将 `cap_mac_admin` 和 `cap_mac_override` 描述为 Smack-specific，因此不要仅凭名称就假定它们可以绕过 SELinux。<sup>[[5]](#references)</sup>

尤其值得关注：<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`：持久化更改路径应获得的 label
- `restorecon` / `setfiles`：批量重新应用这些更改
- `semodule -i`：加载 custom policy module
- `semanage permissive -a <domain_t>`：仅让一个 domain 进入 permissive 状态，而不切换整个 host
- `setsebool -P`：永久更改 policy booleans
- `load_policy`：重新加载 active policy

这些通常是**辅助原语**，而不是独立的 root exploits。它们的价值在于可以让你：<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- 让目标 domain 进入 permissive 状态
- 扩大你的 domain 与受保护 type 之间的访问权限
- 重新标记 attacker-controlled files，使 privileged service 能够读取或执行它们
- 削弱 confined service，使现有的本地 bug 变得可利用

示例检查：<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
如果你能够以 root 身份加载策略模块，通常就能控制 SELinux 边界：<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
这就是为什么在 post-exploitation 期间，应将 `audit2allow`、`semodule` 和 `semanage permissive` 视为敏感的管理员操作面。它们可以在不改变经典 UNIX 权限的情况下，悄无声息地将被阻断的链路转换为可用链路。<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## 隐藏的拒绝与模块提取

一个非常常见的 offensive 难题是：某条链路以简单的 `EACCES` 失败，但预期的 AVC denial 却从未出现。`dontaudit` 规则可能隐藏了你所需的确切权限。如果你可以通过 `sudo` 或其他特权 wrapper 运行 `semodule`，临时禁用 `dontaudit` 就能将无提示的失败转变为精确的 policy 线索：<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
这对于审查本地管理员已经进行的更改也很有用。一个小型自定义 module 或针对单个 domain 的 permissive rule，通常就是目标服务的行为比基础 policy 所暗示的宽松得多的原因。<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## 审计线索

AVC denials 通常是有价值的攻击信号，而不只是防御噪声。它们会告诉你：<sup>[[1]](#references)[[15]](#references)</sup>

- 你命中的 target object/type
- 被拒绝的 permission
- 你当前控制的 domain
- 一个小的 policy 更改是否能让整个链条生效
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
如果本地 exploit 或 persistence 尝试即使在看起来具有 root 级 DAC 权限的情况下，仍不断因 `EACCES` 或奇怪的“permission denied”错误而失败，那么在放弃该攻击向量之前，通常值得先检查 SELinux。<sup>[[1]](#references)</sup>

## SELinux 用户

除了常规 Linux 用户之外，还存在 SELinux 用户。作为 policy 的一部分，每个 Linux 用户都会映射到一个 SELinux 用户，使系统能够对不同账户施加不同的允许角色和 domain。<sup>[[3]](#references)</sup>

快速检查：<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
在许多主流系统中，用户会被映射到 `unconfined_u`，这会降低用户 confinement 的实际影响。不过，在 hardened 部署中，confined 用户可以让 `sudo`、`su`、`newrole` 和 `runcon` 变得更加值得关注，因为 **escalation path 可能取决于进入更合适的 SELinux role/type，而不仅仅是成为 UID 0**。还要记住，某些 confined 用户根本无法调用 `sudo`/`su`，除非 policy 明确允许底层的 setuid transition，因此，使用 `staff_u` + `sysadm_r` 的主机可能会将看似影响较小的 `sudo ROLE=` / `TYPE=` 规则变成真正的 privilege boundary。<sup>[[3]](#references)</sup>

## SELinux in Containers

Container runtimes 通常会在 `container_t` 等 confined domain 中启动 workloads，并将 container content 标记为 `container_file_t`。即使某个 container process 逃逸，但仍以 container label 运行，host writes 仍可能失败，因为 label boundary 仍然完好。<sup>[[1]](#references)[[17]](#references)</sup>

快速示例：<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` 部分并不是装饰。在许多 container 部署中，runtime 会动态分配 MCS categories，从而使两个以 `container_t` 运行的进程仍彼此隔离。如果 escape 使你进入 host namespace，但保留了原始 category set，category 不匹配仍可能解释为什么某些 host paths 仍然无法读取或写入。<sup>[[17]](#references)</sup>

值得注意的现代 container 操作：<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` 关闭 container 的 SELinux label 隔离
- 使用 `:z` / `:Z` 的 bind mounts 会触发对 host path 的 relabeling，以适应 shared/private container 使用场景
- 对 host content 进行广泛 relabeling 本身可能成为 security issue

本页面保持 container 内容简短，以避免重复。有关 container 特定的 abuse cases 和 runtime examples，请查看：

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Red Hat 文档：使用 SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools：SELinux 的 policy analysis tools](https://github.com/SELinuxProject/setools)
- [3] [管理 confined 和 unconfined users - RHEL 9 文档](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux manual page](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux manual page](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux manual page](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux manual page](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux manual page](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux manual page](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run 文档](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [为什么你应该在 Linux containers 中使用 Multi-Category Security](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top 文档](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux manual page](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
