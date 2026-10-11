# SUID、SGID、ACL 和敏感文件

{{#include ../../banners/hacktricks-training.md}}

SUID 和 SGID 会更改已执行文件的有效身份；ACL 可以授予普通 `ls -l` 权限位未显示的访问权限。如果用户能够读取、写入或执行的内容超出了表面显示的所有者和组权限，请同时检查这两者。

## 枚举特权可执行文件

```bash
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
findmnt -no TARGET,OPTIONS
getcap -r / 2>/dev/null
```

重点关注自定义或最近更改过的可执行文件、所有者异常的文件，以及位于可写挂载点上的文件。`nosuid` 挂载选项可以禁用 set-ID 行为；文件 capabilities 是一种独立的权限机制，详见 [Linux capabilities](linux-capabilities.md)。将可疑二进制文件与其所属软件包进行比较，并检查它在提升后的身份下会执行、打开或加载什么。

对于接受调用者输入、但你不熟悉且由 root 所有的 SUID 可执行文件，可离线检查该二进制文件的副本，查看其参数处理是否存在内存安全问题，以及能否到达存在问题的代码路径。记录其 effective-ID 行为，以及栈 canary、不可执行内存、位置无关代码和地址随机化等缓解措施。不安全的函数名称或缺失的缓解措施只能作为进一步审查的线索：是否可利用取决于实际输入边界、可达的控制流，以及发生故障时的有效身份。在被动枚举期间，不要仅为测试是否会崩溃，就向正在运行的特权可执行文件发送超长参数。

熟悉的 SUID 程序本身也可能被替换或植入后门。最近的修改时间只是线索，并非证据：对于**特定的可疑软件包二进制文件**，先确定其所属软件包，再将已安装文件与软件包元数据进行比较；不要在常规枚举期间验证每个软件包：

```bash
dpkg -S /usr/bin/passwd                  # Debian-family: identify the owner
dpkg --verify passwd                     # Verify only that package
rpm -V --noscripts -f /usr/bin/passwd    # RPM-family: owning package, no verify scriptlets
```

`dpkg --verify` 只会检查软件包数据库中记录了校验和的文件内容；RPM 还会比较 mode、所有权等元数据。重点关注**特权可执行文件本身**是否不匹配：精简安装可能会报告同一软件包中其他位置的文档或 locale 文件缺失。将可疑可执行文件与可信的供应商软件包进行比较，并检查具体变更的代码。合法的本地更改、缺失的校验和以及遭到入侵的软件包元数据，都会限制这两个命令能够证明的内容。被动分诊期间，不要运行可疑的 SUID 程序或软件包验证脚本。参见 [dpkg 验证手册](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html)和 [RPM 验证手册](https://rpm.org/docs/4.20.x/man/rpm.8)。

如果 SUID 程序会调用来自可写路径的 shell、相对路径命令或库，就可能跨越信任边界。参见 [SUID shared-library and linker abuse](suid-shared-library-and-linker-abuse.md)、[PATH 指南](../linux-basics/linux-environment-variables.md#path)和 [user-ID 说明](../user-information/euid-ruid-suid.md)。对于已知的命令特定逃逸方式，请根据主机上允许使用的确切二进制文件和调用方式查询 [GTFOBins](https://gtfobins.github.io/)。

对于 set-user-ID 可执行文件，要区分调用者的**真实 UID**与文件所有者的**有效 UID**：[`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html) 会保持真实 UID 不变，并在任何 set-ID 更改后将有效 UID 复制到 saved UID。 [`system(3)`](https://man7.org/linux/man-pages/man3/system.3.html) 会通过 `/bin/sh -c` 运行命令；该路径选择的 shell 会影响子进程能否保留其有效身份。特别是，[Bash 特权模式规则](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html)规定，Bash 在未使用 `-p` 启动时，如果有效 UID 与真实 UID 不同，就会将有效 UID 重置为真实 UID。检查实际 helper 的 UID 更改和子进程调用情况，以及其所有者、可执行权限、挂载的 `nosuid` 设置和进程的 `no_new_privs` 状态。仅凭 SUID 位或 shell 调用，不能证明存在可用的高权限身份转换。

如果当前用户可以执行一个不寻常的 root-owned SUID `jjs`，应单独审查其文件访问能力。即使生成的 shell 会丢弃有效 UID，这个旧版 Nashorn 工具仍可访问 Java 文件 API；在将其视为特权读取或写入能力之前，先确认已安装 JVM 的行为、文件操作时的有效身份，以及 `nosuid`/`no_new_privs` 状态。[Oracle 已在 JDK 15 中移除 `jjs`](https://docs.oracle.com/en/java/javase/21/migrate/removed-tools-and-components.html)；已安装的路径仍可能对应旧版或单独打包的构建版本。[GTFOBins 记录了这些文件 API](https://gtfobins.org/gtfobins/jjs/)，但其中的 sudo 示例不能证明所有构建版本都具有 SUID 行为。被动枚举期间不要调用该工具。

如果低权限用户可以访问一个 root-owned SUID `gosu` 可执行文件，就应进行审查：其文档接口接受目标用户和命令，但常规容器用法是以 root 身份启动它以降权。请核实已安装构建版本的 SUID 行为、有效身份和 user-namespace 映射，以及 `nosuid` 和 `no_new_privs` 状态；容器内的 root 不代表主机上的 root。仅凭文件名或 SUID 位，不能证明存在有效的身份转换。参见[上游用法](https://github.com/tianon/gosu)和[维护者关于 SUID 的警告](https://github.com/tianon/gosu/issues/11)。被动盘点期间不要调用该 helper。

自定义 set-user-ID 备份 wrapper 可能接受调用者指定的路径，并将其插入传递给 `system(3)` 的归档命令。如果构造出的命令中该路径未加引号，子 shell 可能会应用 [tilde expansion（使用 `HOME`）、`?` 和 `*` 等路径名模式，以及换行符命令分隔](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)；仅拒绝 denylist 中常见的标点，并不能让路径变成字面值。请确认确切的参数流、继承的环境、子 shell 和有效身份、文件系统访问权限，以及调用者是否能看到归档输出。SUID 位、归档工具字符串或单独一个被阻止的 `/root` 字面值，都不能证明存在信息泄露或代码执行。被动枚举期间，应离线审查 wrapper 的副本，不要归档私有文件或发送会导致崩溃的输入。

Shell [command substitution](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)，例如 `$(...)`，也是 metacharacter denylist 可能遗漏的情况：即使允许的命令前缀是固定的，后续由调用者控制的参数仍可能通过 `/bin/sh -c` 传递。请离线验证确切的引用方式、解析器和有效身份；不要仅凭 `system()` 字符串或不完整的 denylist 就认定可以执行命令。

**调用进程树**同样重要。Web worker 可以安装限制 UID 更改系统调用的 seccomp filter；[seccomp filters 会传递给子进程并在 `execve` 后继续生效](https://docs.kernel.org/userspace-api/seccomp_filter.html)。例如，Apache 的 [mpm-itk `LimitUIDRange` 和 `LimitGIDRange` 指令](https://sources.debian.org/src/mpm-itk/2.4.7-04-2/mpm_itk.c/)可以限制其后代进程可使用的身份。`/proc/self/status` 中的 `Seccomp: 2` 只表示 filter 模式，不会显示策略内容，也不能说明这个 helper 是否能获得其所有者的身份。结合实际调用的祖先进程和有效 filter，审查其 SUID、挂载及 `no_new_privs` 条件；单独的登录会话可能采用不同策略，但仍需要其自身有效的访问路径。

自定义 SUID 可执行文件可能会调用另一个可读的 Python 脚本。如果它实际使用 **Python 2**，[`input()` 会对输入内容求值](https://docs.python.org/2/library/functions.html#input)；Python 3 的 `input()` 则会返回文本。在将源代码行视为执行路径之前，请确认 wrapper 的有效身份、解释器路径和版本、脚本路径，以及不可信输入是否会到达该调用。仅有脚本自身的 set-ID 位，或没有特权 wrapper 时单独存在 `input()` 调用，都不能证明存在相同的边界。枚举期间应检查二进制引用的路径和有限范围内的脚本源码，不要运行该程序。

如果不寻常的 SUID 可执行文件附带可读源码，请比较每次读取调用者控制文件时请求的字节数与目标缓冲区的大小，并检查后续控制流中的校验逻辑。[`fread(3)`](https://man7.org/linux/man-pages/man3/fread.3.html) 会将请求数量的项存入所提供的指针；它并不知道目标对象的容量。大小不匹配是一个静态内存安全线索，并不能证明存在可利用的权限提升：请确认源码与已安装的二进制相符、调用者可以提供输入、该上下文中的 SUID 执行有效，并且相关路径可达。枚举期间应离线审查有限范围内的源码或二进制副本，不要向特权程序发送会导致崩溃的输入。

自定义 SUID helper 可能在不打印受保护文件内容的情况下泄露该文件。如果调用者可以同时指定路径和正则表达式，而 helper 会在其有效 UID 下返回可见的匹配计数，那么锚定前缀测试可能构成逐字符 oracle。请确认 helper 的所有者、有效身份行为、可执行权限、路径限制、正则表达式语义、响应可见性，以及调用者无法通过其他方式读取的特定高权限文件。SUID 位或正则表达式库字符串本身，都不能证明上述流程成立。被动枚举期间，记录这个不寻常的可执行文件，并审查有限范围内的反汇编或源码副本；不要对在线 helper 反复尝试猜测，也不要打印恢复出的机密。

在 OpenBSD 上，如果自定义 set-user-ID reader 接受调用者指定的路径，且其有效身份可以读取 `/var/backups` 下的文件并将内容返回给调用者，那么它可能暴露这些文件。[OpenBSD 的 `changelist(5)`](https://man.openbsd.org/changelist.5)介绍了已配置路径的 `.current` 和 `.backup` 副本，但以 `+` 开头的条目存储的是 SHA-256 校验和，而不是文件内容；备份目录应归 root 所有，权限为 `0700`。helper 对 `/var` 的 [`unveil` 读取规则](https://man.openbsd.org/unveil.2)可以允许访问该路径下的内容，但本身并不会授予或证明文件访问权限。在声称存在权限提升之前，请确认实际有效 UID、当前用户的可执行权限、接受的路径、备份是否存在及其内容，以及是否存在独立的身份验证要求。被动枚举应报告 helper 和路径元数据，不要调用 reader 或打印备份数据。

自定义 SUID 程序可能会使用 [`stat(2)`](https://man7.org/linux/man-pages/man2/stat.2.html) 检查调用者指定的路径，之后再打开该路径；如果路径位于调用者可写的目录中，就可能在检查文件或符号链接之后遭遇竞态。检查针对的是较早的对象，而之后的 [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html) 可能解析到另一个对象。请确认 helper 可在有效高权限身份下执行、存在其他可达的代码路径读取指定文件，并且调用者能在检查与打开之间替换该路径；仅有 SUID 位、可写目录或 `stat` 字符串，都不足以证明这些条件成立。要构成信息泄露路径，还必须存在调用者可见的输出或调用者可读的目标位置。应离线检查二进制和路径元数据；被动枚举期间不要对在线 helper 发起竞态操作。

对 SGID wrapper 也要进行同样的依赖项审查。即使 wrapper 通过绝对路径运行 shell 或 helper，如果低权限用户可以替换该文件，它仍可能不安全；生成的代码可能会继承 wrapper 的有效组。检查确切的调用路径、其写入权限（包括 ACL）、wrapper 的有效组，以及启动子进程前是否会降权。解释器也可能丢弃继承的有效 ID，因此要区分值得审查的线索与已证实的身份转换。主机其他位置存在可写 shell，本身不能证明特权 wrapper 会调用它。

### 将 SQL 传递给 SQLite CLI 的特权 wrapper

如果自定义 SUID 程序会将用户可控的 SQL 传递给 **`sqlite3` 命令行程序**，在将其查询视为只读之前，请检查确切的命令和有效身份。CLI 的 `edit()` SQL 函数会调用编辑器（取自其第二个参数或 `VISUAL`），其 SQL `load_extension()` 函数则可在启用扩展加载时加载共享库。即使 wrapper 固定了 `PATH` 或使用绝对路径调用 `sqlite3`，这些仍可能成为以 CLI 进程身份执行代码的路径。SQL 必须确实到达这些函数，而且 CLI 必须保留相关功能；仅在二进制文件或主机上发现 `sqlite3`，并不能证明存在权限提升。SQLite **library** 默认禁用扩展加载，因此应将它与 CLI 区分开来。特权应用必须处理不可信 SQL 时，SQLite CLI 的 `--safe` 模式会禁用 `edit()`、`load_extension()` 及其他会产生副作用的函数。参见 [SQLite CLI 文档](https://www.sqlite.org/cli.html#the_edit_sql_function)、[safe-mode 文档](https://www.sqlite.org/cli.html#the_safe_command_line_option)和[扩展加载文档](https://www.sqlite.org/loadext.html#loading_an_extension)。

### 将文件传给 verbose client 的特权文件读取器

自定义 SUID/SGID wrapper 可能会检查调用者指定路径的访问权限，然后将该文件传递给另一个命令。请审查访问检查和后续打开操作时的有效身份，将所有 `../` 组件相对于真实基目录解析，并检查子进程如何处理无效输入。如果数据库客户端以 SQL 格式读取私有文件并启用了 verbose 输出，即使 SQL 无效，也可能在错误中回显文件内容。只有当子进程能读取调用者无法读取的文件、调用者可以通过 wrapper 指定该文件，而且输出对调用者可见时，这才构成跨用户信息泄露；仅出现 `mysql` 或其他客户端字符串，并不能证明这些条件成立。

### Netdata `ndsudo` 搜索路径

[CVE-2024-32019](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93)影响了某些 Netdata `ndsudo` 构建版本。这个 root-owned SUID helper 会使用调用者提供的 `PATH` 来搜索允许调用的外部命令。只有当前账户能够执行已安装的 helper 时，才应审查该 helper，包括它位于调用者常用 `PATH` 之外的情况。请确认其所有者、SUID 位、可执行权限（包括组/ACL 授权）、已安装的构建版本及供应商补丁状态，以及 `NoNewPrivs` 或 `nosuid` 挂载是否会阻止身份更改。Netdata 列出的修复版本为 `v1.45.3` 和 `v1.45.0-169`；发行版回移植补丁需要另行确认。仪表板版本或仅仅存在 `ndsudo`，都不足以证明存在可触达的权限提升。该路径问题还要求 helper 通过调用者可控的位置解析外部命令。

### Firejail join 权限边界

[CVE-2022-31214](https://seclists.org/oss-sec/2022/q2/188)影响了 Firejail 特权 `--join` 逻辑：精心构造的 join target 可能会让 setuid-root helper 接受攻击者控制的 mount namespace，并复制不安全的安全状态。被动分诊时，请确认**当前身份可以执行** root-owned setuid Firejail 二进制文件、setuid 在其挂载和进程上下文中有效，而且已安装的构建版本缺少修复。上游已在[0.9.70](https://github.com/netblue30/firejail/releases/tag/0.9.70)修复此问题；发行版软件包可能已经[回移植补丁](https://github.com/netblue30/firejail/issues/5191)，但仍显示较旧的版本。这些前提只能说明它值得审查，并不能证明 join 成功或可以获得 root shell。枚举期间不要构造 fake jail，也不要调用 `--join`。

### GNU Screen logfile 权限

[CVE-2017-5618](https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00026.html)涉及 Screen 4.5.0 在提升的权限下打开调用者指定的 logfile。SUID inventory 中出现 `screen` 或带版本后缀的二进制文件，只是审查线索：请确认 root 所有权、当前用户能否以有效 SUID 身份执行、已安装的构建版本和发行版补丁状态，以及受影响的 logfile 行为。[Debian 通过回移植补丁修复了其 4.5.0 软件包](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=852484)，因此仅凭版本字符串或文件名不能证明存在漏洞。不要将创建 logfile 作为常规枚举探测。

[CVE-2017-5899](https://ubuntu.com/security/CVE-2017-5899)影响了特权 S-nail mail-lock helper：调用者控制的路径组件可以遍历目录并导致任意文件写入。请检查当前用户能否执行已安装的 root-owned setuid helper、其 setuid 身份是否在挂载和进程策略下有效，以及确切的软件包构建版本和供应商修复情况。[Ubuntu 的安全公告](https://ubuntu.com/security/notices/USN-4820-1)列出了其 16.04 软件包的回移植修复，因此看起来像上游版本的版本号本身不能作为结论。存在 helper 并不能证明受影响的路径可达，也不能证明文件写入会导致 root 代码执行；枚举期间应检查元数据和软件包状态，不要调用 helper 或尝试竞态操作。

### snap-confine 和 tmpfiles 清理

CVE-2026-3888 是一个涉及特权 `snap-confine` 和 systemd-tmpfiles 清理 `/tmp` 的竞态问题。被动审查时，可以检查 `snap-confine` 是否设置了 setuid 或文件 capabilities，将已安装的 `snapd` 软件包与该 **Ubuntu 发行版**对应的修复版本进行比较，并检查实际生效的 `/tmp` 年龄规则和清理定时器。软件包和规则匹配只是前提，并不能证明竞态可达：运行时定时器状态、snap 布局、软件包回移植补丁和规则覆盖也会影响结果。较旧的发行版可能需要非默认配置。常规枚举期间不要运行竞态探测。有关各发行版的软件包状态，参见 [Ubuntu CVE 记录](https://ubuntu.com/security/CVE-2026-3888)；有关组件之间的交互，参见 [Qualys 公告](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root)。

## 检查 ACL 和敏感路径

```bash
getfacl -p /path/to/file /path/to/parent 2>/dev/null
namei -l /path/to/file
find /etc /opt /var -type f -writable -ls 2>/dev/null | head -80
ls -la /etc/sudoers.d /etc/ld.so.preload /etc/ld.so.conf.d 2>/dev/null
```

可写的父目录可能允许替换文件，即使文件本身归 root 所有。ACL 可能会在不易察觉的情况下授予对 sudoers drop-in 文件、服务单元、cron 脚本、库路径或凭据文件的访问权限。检查 ACL 和完整路径。如果可以任意写入特权文件，请参阅 [Arbitrary File Write to Root](write-to-root.md)；有关 linker 配置和 preload 的情况，请参阅 [`ld.so` example](ld.so.conf-example.md)。将暴露的备份文件、`.env` 文件、数据库配置、SSH 材料和历史记录视为潜在的凭据来源；是否能访问取决于每个文件的实际权限。
{{#include ../../banners/hacktricks-training.md}}
