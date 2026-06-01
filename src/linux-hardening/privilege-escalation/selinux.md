# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux 是一个**基于标签的 Mandatory Access Control (MAC)** 系统。实际上，这意味着即使 DAC 权限、组或 Linux capabilities 看起来足以执行某个操作，kernel 仍然可以拒绝它，因为**source context** 不被允许以请求的 class/permission 访问**target context**。

一个 context 通常看起来像这样：
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
从提权的角度来看，`type`（进程的 domain，对象的 type）通常是最重要的字段：

- 一个进程运行在某个 **domain** 中，例如 `unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t`
- 文件和 socket 有一个 **type**，例如 `admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t`
- policy 决定一个 domain 是否可以对另一个 domain 进行 read/write/execute/transition

## Fast Enumeration

如果 SELinux 已启用，尽早枚举它，因为它可以解释为什么常见的 Linux privesc 路径会失败，或者为什么一个包裹在“无害” SELinux 工具外面的特权 wrapper 实际上至关重要：
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
Interesting findings:

- `Disabled` or `Permissive` mode removes most of the value of SELinux as a boundary.
- `unconfined_t` usually means SELinux is present but not meaningfully constraining that process.
- `default_t`, `file_t`, or obviously wrong labels on custom paths often indicate mislabeling or incomplete deployment.
- Local overrides in `file_contexts.local` take precedence over policy defaults, so review them carefully.

## Policy Analysis

SELinux is much easier to attack or bypass when you can answer two questions:

1. **What can my current domain access?**
2. **What domains can I transition into?**

The most useful tools for this are `sepolicy` and **SETools** (`seinfo`, `sesearch`, `sedta`):
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
当主机使用 **confined users** 而不是把所有人都映射到 `unconfined_u` 时，这一点尤其有用。在这种情况下，检查：

- 通过 `semanage login -l` 的用户映射
- 通过 `semanage user -l` 的允许角色
- 可到达的 admin domains，例如 `sysadm_t`、`secadm_t`、`webadm_t`
- 使用 `ROLE=` 或 `TYPE=` 的 `sudoers` 条目

如果 `sudo -l` 包含类似这样的条目，SELinux 就是特权边界的一部分：
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
另外检查 `newrole` 是否可用：
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` 和 `newrole` 并不能自动被利用，但如果某个 privileged wrapper 或 `sudoers` 规则让你能够选择更好的 role/type，它们就会成为高价值的提权原语。

## Files、Relabeling 和高价值错误配置

常见 SELinux 工具之间最重要的操作差异是：

- `chcon`: 对特定路径临时修改 label
- `semanage fcontext`: 持久化的 path-to-label 规则
- `restorecon` / `setfiles`: 重新应用 policy/default label

这在 privesc 期间非常重要，因为**relabeling 不只是表面上的变化**。它可以把一个文件从“被 policy 阻止”变成“可被特权受限服务读取/执行”。

检查本地 relabel 规则和 relabel drift：
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
一个微妙但有用的细节：普通的 `restorecon` **并不总是能完全还原可疑的标签**。如果目标类型在 `customizable_types` 中，你可能需要使用 `-F` 来强制完全重置。从进攻角度看，这也解释了为什么一个异常的 `chcon` 有时会在一次随意的“我们已经运行过 restorecon 了”清理后仍然保留下来。
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
在 `sudo -l`、root wrappers、automation scripts 或 file capabilities 中要重点查找的高价值命令：
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
如果出现任一 MAC capability，也请同时交叉检查 [Linux capabilities page](linux-capabilities.md)；`cap_mac_admin` 和 `cap_mac_override` 虽然不常见，但当 SELinux 是边界的一部分时它们直接相关。

特别值得关注：

- `semanage fcontext`：持久化地更改某个 path 应该获得的 label
- `restorecon` / `setfiles`：在大规模范围内重新应用这些更改
- `semodule -i`：加载一个自定义 policy module
- `semanage permissive -a <domain_t>`：让某个 domain 变为 permissive，而不影响整个主机
- `setsebool -P`：永久更改 policy booleans
- `load_policy`：重新加载当前 active policy

这些通常是 **helper primitives**，而不是独立的 root exploits。它们的价值在于你可以用它们来：

- 让目标 domain 变为 permissive
- 扩大你的 domain 与受保护 type 之间的访问
- 重新标记由 attacker-controlled files，使特权服务可以读取或执行它们
- 削弱一个受限服务，使已有的本地 bug 变得可利用

示例检查：
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
如果你可以以 root 加载一个 policy module，你通常就能控制 SELinux 边界：
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
这就是为什么在 post-exploitation 期间，`audit2allow`、`semodule` 和 `semanage permissive` 应被视为敏感的 admin surface。它们可以在不更改经典 UNIX permissions 的情况下，悄无声息地把一条被阻止的链转换成可工作的链。

## Hidden Denials and Module Extraction

一个很常见的 offensive 挫折是，某条链以一个平淡的 `EACCES` 失败，而预期中的 AVC denial 却从未出现。`dontaudit` rules 可能正在隐藏你真正需要的那个 permission。如果你可以通过 `sudo` 或其他 privileged wrapper 运行 `semodule`，临时禁用 `dontaudit` 可以把一次静默失败变成一个精确的 policy clue：
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
这对于审查本地管理员已经做了哪些更改也很有用。一个小的自定义 module 或一个域的 permissive rule，往往就是目标 service 的行为比基础 policy 显示得宽松得多的原因。

## Audit Clues

AVC denials 往往是进攻性信号，而不只是防御性噪音。它们会告诉你：

- 你命中了哪个目标 object/type
- 哪个 permission 被拒绝了
- 你当前控制的是哪个 domain
- 一个小的 policy 更改是否能让整条链跑通
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
如果本地 exploit 或 persistence 尝试在看起来有 root 级别 DAC 权限的情况下仍然持续失败，并报 `EACCES` 或奇怪的“permission denied”错误，通常在放弃这个 vector 之前值得先检查 SELinux。

## SELinux Users

除了普通 Linux users 之外，还有 SELinux users。每个 Linux user 都会作为 policy 的一部分映射到一个 SELinux user，这让系统可以对不同账户施加不同允许的 roles 和 domains。

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
在许多主流系统上，用户会被映射到 `unconfined_u`，这会降低用户 confinement 的实际影响。不过在加固过的部署中，confined users 会让 `sudo`、`su`、`newrole` 和 `runcon` 变得有趣得多，因为**提权路径可能取决于进入一个更好的 SELinux role/type，而不仅仅是成为 UID 0**。还要记住，某些 confined users 根本不能调用 `sudo`/`su`，除非 policy 明确允许底层的 setuid transition，因此一个使用 `staff_u` + `sysadm_r` 的主机，可能会把看似很小的 `sudo ROLE=` / `TYPE=` 规则变成真正的 privilege boundary。

## SELinux in Containers

Container runtimes 通常会在一个受限 domain 中启动 workload，例如 `container_t`，并将 container 内容标记为 `container_file_t`。如果一个 container process 逃逸了，但仍然以 container label 运行，host writes 可能还是会失败，因为 label boundary 仍然保持完整。

Quick example:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
`c647,c780` 这部分不是装饰。在许多容器部署中，runtime 会动态分配 MCS categories，这样两个以 `container_t` 运行的进程仍然彼此隔离。如果一次 escape 让你进入 host namespace，但保留了原始的 category set，category 不匹配仍然可以解释为什么某些 host 路径依然不可读或不可写。

值得注意的现代容器操作：

- `--security-opt label=disable` 可以有效地把 workload 移到一个未受限的容器相关类型，比如 `spc_t`
- 带有 `:z` / `:Z` 的 bind mounts 会触发对 host path 的 relabeling，以供共享/私有容器使用
- 对 host 内容进行大范围 relabeling 本身也可能成为安全问题

本页为了避免重复，简要保留 container 内容。关于 container-specific abuse cases 和 runtime examples，请查看：

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
