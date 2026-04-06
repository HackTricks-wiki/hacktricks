# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux 是一个 **基于标签的 Mandatory Access Control (MAC)** 系统。在实践中，这意味着即使 DAC permissions、groups 或 Linux capabilities 看起来足以执行某个动作，kernel 仍可能拒绝该操作，因为 **source context** 未被允许以请求的 class/permission 访问 **target context**。

上下文通常看起来像：
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
从 privesc 角度来看，`type`（进程的 domain、对象的 type）通常是最重要的字段：

- 进程运行在一个 **domain** 中，例如 `unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t`
- 文件和套接字具有 **type**，例如 `admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t`
- 策略决定一个 domain 是否可以进行 read/write/execute/transition

## 快速枚举

如果启用了 SELinux，应尽早枚举它，因为它可以解释为什么常见的 Linux privesc 路径会失败，或为什么围绕一个 "harmless" 的 SELinux 工具的特权包装实际上至关重要：
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

- `Disabled` 或 `Permissive` 模式会移除 SELinux 作为边界的大部分价值。
- `unconfined_t` 通常表示 SELinux 存在，但对该进程没有实质性约束。
- `default_t`, `file_t`, 或者自定义路径上的明显错误标签通常表示标记错误或部署不完整。
- 本地覆盖在 `file_contexts.local` 中优先于策略默认值，因此请仔细检查它们。

## 策略分析

当你能回答以下两个问题时，攻击或绕过 SELinux 会容易得多：

1. **我的当前域可以访问什么？**
2. **我可以转换到哪些域？**

为此最有用的工具是 `sepolicy` 和 **SETools** (`seinfo`, `sesearch`, `sedta`)：
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
当主机使用 **confined users** 而不是将所有人映射到 `unconfined_u` 时，这尤其有用。在这种情况下，请检查：

- 用户映射：`semanage login -l`
- 允许的角色：`semanage user -l`
- 可到达的管理员域，例如 `sysadm_t`、`secadm_t`、`webadm_t`
- `sudoers` 中使用 `ROLE=` 或 `TYPE=` 的条目

如果 `sudo -l` 包含如下条目，SELinux 就是权限边界的一部分：
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
还要检查 `newrole` 是否可用：
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` 和 `newrole` 并非自动可被利用，但如果一个有特权的包装器或 `sudoers` 规则允许你选择更合适的 role/type，它们就会成为高价值的提权原语。

## 文件、重新标记与高价值误配置

常见 SELinux 工具之间最重要的操作差异是：

- `chcon`: 在特定路径上的临时标签更改
- `semanage fcontext`: 持久的路径到标签映射规则
- `restorecon` / `setfiles`: 重新应用策略/默认标签

这在 privesc 过程中非常重要，因为 **重新标记不仅仅是表面工作**。它可以将一个文件从“被策略阻止”变为“对受限的特权服务可读/可执行”。

检查本地的重新标记规则和重新标记漂移：
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

- `semanage fcontext`: 持久地更改一个路径应获得的标签
- `restorecon` / `setfiles`: 批量重新应用这些更改
- `semodule -i`: 加载自定义策略模块
- `semanage permissive -a <domain_t>`: 使单个域变为 permissive，而不必切换整个主机
- `setsebool -P`: 永久更改策略布尔值
- `load_policy`: 重新加载活动策略

这些通常是 **辅助原语**，而不是独立的 root exploits。它们的价值在于可以让你：

- 使目标域变为 permissive
- 放宽你的域与受保护类型之间的访问权限
- 重新标记攻击者控制的文件，使有特权的服务能够读取或执行它们
- 削弱受限服务，使现有的本地漏洞变得可利用

示例检查：
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
如果你能以 root 身份加载一个 policy module，通常就能控制 SELinux 的边界：
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
这就是为什么 `audit2allow`、`semodule` 和 `semanage permissive` 在 post-exploitation 期间应被视为敏感的管理界面。它们可以在不更改经典 UNIX 权限的情况下悄然将被阻止的链转换为可用链。

## 审计线索

AVC denials 往往是进攻信号，而不仅仅是防御噪音。它们会告诉你：

- 你命中的目标对象/类型是什么
- 哪种权限被拒绝
- 你当前控制的是哪个域
- 小幅策略更改是否能使链路生效
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
If a local exploit or persistence attempt keeps failing with `EACCES` or strange "permission denied" errors despite root-looking DAC permissions, SELinux is usually worth checking before discarding the vector.

## SELinux 用户

除了普通 Linux 用户之外，还有 SELinux 用户。每个 Linux 用户在策略中都被映射到一个 SELinux 用户，这让系统能够对不同账号施加不同的允许角色和域。

快速检查：
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
在许多主流系统上，用户被映射到 `unconfined_u`，这降低了用户限制的实际影响。但在加固的部署中，受限用户会使 `sudo`、`su`、`newrole` 和 `runcon` 更加有趣，因为 **提权路径可能依赖于进入更高的 SELinux 角色/类型，而不仅仅是成为 UID 0**。

## 容器中的 SELinux

容器运行时通常在受限域中启动工作负载（例如 `container_t`），并将容器内容标记为 `container_file_t`。如果容器进程逃逸但仍以容器标签运行，主机写入可能仍会失败，因为标签边界仍然保持完整。

快速示例：
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
值得注意的现代容器操作：

- `--security-opt label=disable` can effectively move the workload to an unconfined container-related type such as `spc_t`
- bind mounts with `:z` / `:Z` trigger relabeling of the host path for shared/private container use
- broad relabeling of host content can become a security issue on its own

为避免重复，本页对容器内容做了简略。有关容器特定的滥用场景和运行时示例，请查看：

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## 参考资料

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
