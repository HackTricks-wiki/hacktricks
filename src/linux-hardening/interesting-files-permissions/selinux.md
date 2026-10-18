# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux 是一种**基于标签的强制访问控制（MAC）**系统。实际上，这意味着即使 DAC 权限、组或 Linux capabilities 看起来足以执行某项操作，内核仍然可以拒绝该操作，因为**源上下文**未被允许以所请求的类别/权限访问**目标上下文**。<sup>[[1]](#references)</sup>

上下文通常如下所示：<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

从 privesc 的角度来看，`type`（进程对应 domain，对象对应 type）通常是最重要的字段：<sup>[[1]](#references)</sup>

- 进程运行在某个 **domain** 中，例如 `unconfined_t`、`staff_t`、`httpd_t`、`container_t`、`sysadm_t`
- 文件和 socket 具有某种 **type**，例如 `admin_home_t`、`shadow_t`、`httpd_sys_rw_content_t`、`container_file_t`
- Policy 决定一个 domain 是否能对另一个 domain 进行读取、写入、执行或转换

## 快速枚举

如果启用了 SELinux，应尽早枚举，因为它可以解释常见的 Linux privesc 路径为何失效，或者为什么一个围绕“无害” SELinux 工具的特权 wrapper 实际上至关重要：<sup>[[1]](#references)</sup>

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

有意思的发现：<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- `Disabled` 或 `Permissive` 模式会削弱 SELinux 作为边界的大部分价值。
- `unconfined_t` 通常表示 SELinux 已启用，但并未对该进程施加实质性限制。
- 自定义路径上出现 `default_t`、`file_t` 或明显错误的标签，通常表示标签配置错误或部署不完整。
- `file_contexts.local` 中的本地覆盖规则优先于策略默认值，因此应仔细检查。

## 策略分析

只要能回答以下两个问题，攻击或绕过 SELinux 就会容易得多：

1. **当前域可以访问哪些内容？**
2. **可以转换到哪些域？**

`sepolicy` 和 **SETools**（`seinfo`、`sesearch`、`sedta`）是最实用的工具：<sup>[[2]](#references)[[9]](#references)</sup>

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

当主机使用**受限用户**而不是将所有人映射到 `unconfined_u` 时，这尤其有用。在这种情况下，请检查：<sup>[[3]](#references)</sup>

- 通过 `semanage login -l` 查看用户映射
- 通过 `semanage user -l` 查看允许的角色
- 可访问的管理员域，例如 `sysadm_t`、`secadm_t`、`webadm_t`
- 使用 `ROLE=` 或 `TYPE=` 的 `sudoers` 条目

如果 `sudo -l` 包含此类条目，则 SELinux 是权限边界的一部分：<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

同时检查是否有 `newrole` 可用：<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` 和 `newrole` 本身不会自动构成可利用点，但如果特权 wrapper 或 `sudoers` 规则允许你选择权限更高的 role/type，它们就会成为高价值的权限提升原语。<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### 审计可写的转换入口点

转换图只能提供策略线索。要将其转化为攻击路径，请找出进入更有用 domain 的可执行文件类型，然后检查你是否能修改带有该标签的可执行文件，或通过其父目录替换该文件。<sup>[[9]](#references)[[20]](#references)</sup> 自动 `execve` 转换需要适用的 `type_transition` 规则、源 domain 的 execute 访问权限、目标 domain 的 `entrypoint` 访问权限，以及在 domain 之间进行转换的权限。<sup>[[20]](#references)</sup> 目标 domain 可能获得 SELinux 访问权限，但执行本身不会改变 Linux UID；请另外检查 [SUID/SGID 和 ACL](suid-sgid-and-acl-triage.md)。<sup>[[20]](#references)[[21]](#references)</sup>

使用报告的入口点类型检查底层规则，然后检查路径及其父目录是否具有写入权限。<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

将 entrypoint 类型与实际可执行文件路径对应起来。检查 DAC、ACL、文件或父目录上的 SELinux 写入权限、文件标签，以及任何条件布尔值，再判断策略边是否可达。<sup>[[20]](#references)[[22]](#references)</sup> 如果路径是被替换而非原地编辑，请验证新 inode 的上下文：文件系统标签以扩展属性形式存储，替换后的文件可能不会保留 entrypoint 类型。<sup>[[21]](#references)</sup> 支持 SELinux 的程序可以通过 `setexeccon` 请求转换，因此缺少自动 `type_transition` 规则，并不能排除所有转换。<sup>[[20]](#references)</sup>

## 文件、重新标记与高价值错误配置

常见 SELinux 工具之间最重要的实际区别是：<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`：临时更改特定路径的标签
- `semanage fcontext`：持久化的路径到标签规则
- `restorecon` / `setfiles`：再次应用策略/默认标签

在 privesc 过程中，这一点非常重要，因为**重新标记不只是表面上的变化**。它可能让文件从“被策略阻止”变成“受限特权服务可读取/执行”。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

检查本地重新标记规则和标签漂移：<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

一个细微但有用的细节：普通的 `restorecon` **并不总能完全还原可疑标签**。如果目标类型位于 `customizable_types` 中，可能需要使用 `-F` 强制完全重置。从攻击角度来看，这也解释了为什么不寻常的 `chcon` 有时能在随手执行“我们已经运行过 restorecon 了”的清理后继续存在。<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

在 `sudo -l`、root wrappers、自动化脚本或文件 capabilities 中值得重点搜寻的命令：<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

如果出现任一 MAC capability，也要交叉检查 [Linux capabilities 页面](linux-capabilities.md)；Linux capabilities 文档将 `cap_mac_admin` 和 `cap_mac_override` 描述为 Smack 专用，因此不要仅凭名称就认为它们可以绕过 SELinux。<sup>[[5]](#references)</sup>

尤其值得关注：<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`：持久更改路径应获得的标签
- `restorecon` / `setfiles`：大规模重新应用这些更改
- `semodule -i`：加载自定义策略模块
- `semanage permissive -a <domain_t>`：仅将一个 domain 设为 permissive，而不切换整个主机
- `setsebool -P`：永久更改策略布尔值
- `load_policy`：重新加载当前策略

这些通常是**辅助原语**，而非独立的 root 漏洞利用方式。它们的价值在于让你能够：<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- 将目标 domain 设为 permissive
- 扩大你的 domain 与受保护 type 之间的访问权限
- 重新标记攻击者可控的文件，使特权服务能够读取或执行它们
- 削弱受限服务的保护，使现有的本地漏洞变得可利用

检查示例：<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

如果你能以 root 身份加载策略模块，通常就能控制 SELinux 边界：<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

这就是为什么在 post-exploitation 期间，应将 `audit2allow`、`semodule` 和 `semanage permissive` 视为敏感的管理接口。它们可以在不更改传统 UNIX 权限的情况下，悄无声息地将被阻止的链条变为可用。<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## 隐藏的拒绝记录与模块提取

一种非常常见的攻击操作困扰是：某条链因普通的 `EACCES` 而失败，但预期的 AVC 拒绝记录却没有出现。`dontaudit` 规则可能隐藏了你需要的确切权限。如果你可以通过 `sudo` 或其他特权包装程序运行 `semodule`，临时禁用 `dontaudit` 就能将无声的失败变成明确的策略线索：<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

这对于检查本地管理员已经做过哪些更改也很有用。一个小型自定义模块或针对单个域的 permissive 规则，往往就是目标服务的行为比基础策略所暗示的宽松得多的原因。<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Audit Clues

AVC 拒绝记录通常是对攻击者有用的信号，而不只是防御噪声。它们会告诉你：<sup>[[1]](#references)[[15]](#references)</sup>

- 你命中了哪个目标对象/类型
- 哪项权限被拒绝
- 你当前控制着哪个域
- 小幅修改策略是否能让攻击链奏效

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

如果本地 exploit 或 persistence 尝试持续因 `EACCES` 或奇怪的“permission denied”错误而失败，尽管 DAC 权限看起来像 root，通常值得先检查 SELinux，再放弃该攻击途径。<sup>[[1]](#references)</sup>

## SELinux 用户

除了常规 Linux 用户外，还有 SELinux 用户。根据策略，每个 Linux 用户都会映射到一个 SELinux 用户，这使系统能够为不同账户施加不同的允许角色和域。<sup>[[3]](#references)</sup>

快速检查：<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

在许多主流系统中，用户会被映射到 `unconfined_u`，这会降低用户隔离在实际中的影响。不过，在经过加固的部署环境中，受限用户会让 `sudo`、`su`、`newrole` 和 `runcon` 更值得关注，因为**提权路径可能取决于进入权限更高的 SELinux role/type，而不仅仅是成为 UID 0**。还要记住，除非策略明确允许底层的 setuid 转换，否则某些受限用户根本无法调用 `sudo`/`su`。因此，使用 `staff_u` + `sysadm_r` 的主机可能会让一条看似不起眼的 `sudo ROLE=` / `TYPE=` 规则成为真正的权限边界。<sup>[[3]](#references)</sup>

## SELinux in Containers

容器运行时通常会在受限域（例如 `container_t`）中启动工作负载，并将容器内容标记为 `container_file_t`。如果容器进程逃逸，但仍以容器标签运行，那么由于标签边界仍然有效，它可能仍无法写入主机文件。<sup>[[1]](#references)[[17]](#references)</sup>

快速示例：<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

`c647,c780` 部分不是装饰。在许多容器部署中，runtime 会动态分配 MCS 类别，使两个以 `container_t` 运行的进程仍彼此隔离。如果逃逸后进入 host namespace，但保留了原来的类别集，那么类别不匹配仍可能解释为何某些 host 路径无法读取或写入。<sup>[[17]](#references)</sup>

值得注意的现代容器操作：<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` 会关闭容器的 SELinux 标签隔离
- 使用 `:z` / `:Z` 的 bind mounts 会触发重新标记，以便 host 路径供容器共享或私有使用
- 对大量 host 内容进行重新标记本身也可能造成安全问题

为避免重复，本页对容器内容从简介绍。有关容器特定的滥用案例和 runtime 示例，请查看：

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Red Hat 文档：使用 SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools：SELinux 策略分析工具](https://github.com/SELinuxProject/setools)
- [3] [管理受限和不受限用户 - RHEL 9 文档](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Linux 手册页](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Linux 手册页](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Linux 手册页](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Linux 手册页](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Linux 手册页](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Podman run 文档](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [为什么 Linux 容器应该使用 Multi-Category Security](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Podman top 文档](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [SELinux Notebook：域和对象转换](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10：使用 SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [SETools sesearch(1) 手册](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
