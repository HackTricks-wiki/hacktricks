# SUID、SGID、ACL 和敏感文件

{{#include ../../banners/hacktricks-training.md}}

SUID 和 SGID 会更改已执行文件的有效身份；ACL 可以授予普通 `ls -l` 权限位未显示的访问权限。当用户似乎拥有超出所有者和组权限所示范围的读取、写入或执行权限时，请同时检查这两者。

## 枚举特权可执行文件

```bash
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
findmnt -no TARGET,OPTIONS
getcap -r / 2>/dev/null
```

重点关注自定义或近期更改过的可执行文件、所有者异常的文件，以及位于可写挂载点上的文件。`nosuid` 挂载选项可以抑制 set-ID 行为；文件 capabilities 是另一种权限机制，详见 [Linux capabilities](linux-capabilities.md)。将可疑二进制文件与其软件包进行比对，并检查它在提升后的身份下会执行、打开或加载什么。

对于接受调用者输入、但你不熟悉的 root 所有 SUID 可执行文件，应离线检查该二进制文件的副本，查看其处理参数时是否存在内存安全问题，以及能否通过代码路径触达相关处理逻辑。记录其 effective-ID 行为，以及栈 canary、不可执行内存、位置无关代码和地址随机化等缓解措施。函数名称不安全或缺少缓解措施只能作为审查线索：是否可利用取决于实际输入边界、可触达的控制流，以及发生故障时的有效身份。进行被动枚举时，不要仅为测试是否会崩溃，就向正在运行的特权可执行文件发送长参数。

即使是熟悉的 SUID 程序，也可能被替换或植入后门。修改时间较近只是线索，并非证据：对于**特定的可疑软件包二进制文件**，应确定其所属软件包，并将已安装文件与软件包元数据进行比对，而不是在常规枚举期间验证每个软件包：

```bash
dpkg -S /usr/bin/passwd                  # Debian-family: identify the owner
dpkg --verify passwd                     # Verify only that package
rpm -V --noscripts -f /usr/bin/passwd    # RPM-family: owning package, no verify scriptlets
```

`dpkg --verify` 仅在软件包数据库记录了校验和时检查文件内容；RPM 还会比较模式和所有权等元数据。重点关注**特权可执行文件本身**的不匹配：精简安装可能会报告同一软件包中其他位置缺失的文档或区域设置文件。将可疑可执行文件与可信的供应商软件包进行比较，并检查具体变更的代码。合法的本地变更、缺失的校验和以及遭到破坏的软件包元数据，都会限制这两条命令能够证明的内容。被动分诊期间，既不要运行可疑的 SUID 程序，也不要运行软件包验证脚本。请参阅 [dpkg verification manual](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html) 和 [RPM verification manual](https://rpm.org/docs/4.20.x/man/rpm.8)。

调用 shell、相对路径命令或可写路径中的库的 SUID 程序，可能越过信任边界。请参阅 [SUID shared-library and linker abuse](suid-shared-library-and-linker-abuse.md)、[PATH guidance](../linux-basics/linux-environment-variables.md#path) 和 [user-ID explanation](../user-information/euid-ruid-suid.md)。对于已知的命令特定逃逸方式，请根据主机上允许使用的确切二进制文件和调用方式查阅 [GTFOBins](https://gtfobins.github.io/)。

对于 set-user-ID 可执行文件，要区分调用者的**真实 UID**与文件所有者的**有效 UID**：[`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html) 会保持真实 UID 不变，并在发生任何 set-ID 变更后，将有效 UID 复制到保存的 UID。 [`system(3)`](https://man7.org/linux/man-pages/man3/system.3.html) 会通过 `/bin/sh -c` 运行命令；该路径选择的 shell 会影响子进程能否保留其有效身份。特别是，[Bash privileged-mode rules](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html) 规定：Bash 未使用 `-p` 启动时，如果有效 UID 与真实 UID 不同，就会将有效 UID 重置为真实 UID。检查实际 helper 的 UID 变更和子进程调用方式，同时检查其所有者、可执行权限、挂载的 `nosuid` 设置以及进程的 `no_new_privs` 状态。仅凭 SUID 位或 shell 调用，不能证明存在可用的提权转换。

如果当前用户可以执行一个不寻常的 root 所有 SUID `jjs`，应单独检查其文件访问行为。旧版 Nashorn 工具即使在启动的 shell 丢弃有效 UID 时，也可能访问 Java 文件 API；在将其视为特权读写之前，应确认已安装 JVM 的行为、文件操作的有效身份以及 `nosuid`/`no_new_privs` 状态。[Oracle removed `jjs` in JDK 15](https://docs.oracle.com/en/java/javase/21/migrate/removed-tools-and-components.html)；已安装的路径可能仍指向旧版或单独打包的构建。[GTFOBins documents the file APIs](https://gtfobins.org/gtfobins/jjs/)，但其中的 sudo 示例不能证明所有构建的 SUID 行为。被动枚举期间不要调用该工具。

如果低权限用户可以访问一个 root 所有的 SUID `gosu` 可执行文件，就应进行检查：其文档化接口接受目标用户和命令，但容器中的常规用法是以 root 身份启动它以降低权限。验证已安装构建的 SUID 行为、有效身份和 user-namespace 映射，以及 `nosuid` 和 `no_new_privs` 状态；容器内的 root 并不意味着主机上的 root。文件名或 SUID 位本身不能证明存在有效的身份转换。请参阅 [upstream usage](https://github.com/tianon/gosu) 和 [maintainer's SUID warning](https://github.com/tianon/gosu/issues/11)。被动盘点期间不要调用该 helper。

自定义的 set-user-ID 备份 wrapper 可能接受调用者指定的路径，并将其插入传递给 `system(3)` 的归档命令。如果构造的命令中该路径没有加引号，子 shell 就可能应用 [tilde expansion using `HOME`, pathname patterns such as `?` and `*`, and newline command separation](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)；仅拒绝黑名单中常见的标点，并不能保证路径按字面处理。确认确切的参数流、继承的环境、子 shell 和有效身份、文件系统访问情况，以及归档输出是否对调用者可见。SUID 位、归档工具字符串或被阻止的 `/root` 字面路径，都不能单独证明存在信息披露或代码执行。被动枚举期间，应离线检查 wrapper 的副本，而不是归档私有文件或发送会导致崩溃的输入。

像 `$(...)` 这样的 shell [command substitution](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html) 也是元字符黑名单可能遗漏的另一种情况：即使命令前缀固定且允许，仍可能将之后由调用者控制的参数传入 `/bin/sh -c`。离线验证确切的引用方式、解析器和有效身份；不要仅凭 `system()` 字符串或不完整的黑名单就认定代码已执行。

**调用进程树**同样重要。Web worker 可以安装 seccomp 过滤器，限制会更改 UID 的系统调用；[seccomp filters pass to children and survive `execve`](https://docs.kernel.org/userspace-api/seccomp_filter.html)。例如，Apache 的 [mpm-itk `LimitUIDRange` and `LimitGIDRange` directives](https://sources.debian.org/src/mpm-itk/2.4.7-04-2/mpm_itk.c/) 可以限制后代进程可使用的身份。`/proc/self/status` 中的 `Seccomp: 2` 表示过滤器模式，并不显示策略内容，也不能说明该 helper 是否能够获取其所有者的身份。应结合实际调用的祖先进程和有效过滤器，检查其 SUID、挂载和 `no_new_privs` 条件；单独的登录会话可能采用不同策略，但仍需要自身有效的访问路径。

自定义 SUID 可执行文件可能会调用一个单独且可读的 Python 脚本。如果它实际使用 **Python 2**，[`input()` evaluates the entered expression](https://docs.python.org/2/library/functions.html#input)；而 Python 3 的 `input()` 返回文本。在将源代码行视为执行路径之前，应确认 wrapper 的有效身份、解释器路径和版本、脚本路径，以及不可信输入是否会传递到该调用。脚本本身带有 set-ID 位，或在没有特权 wrapper 的情况下调用 `input()`，都不能证明存在相同的边界。枚举期间应检查二进制引用的路径和有限范围内的脚本源码，但不要运行它。

如果不寻常的 SUID 可执行文件附带可读源码，应将每处由调用者控制的文件读取所请求的字节数与目标缓冲区大小进行比较，并检查后续的控制流检查。[`fread(3)`](https://man7.org/linux/man-pages/man3/fread.3.html) 会将请求读取的项目写入给定指针；它并不知道目标对象的容量。大小不匹配是静态内存安全问题的线索，并不能证明存在可用的提权方式：应确认源码与已安装二进制相符、调用者能够提供输入、SUID 在该上下文中有效，并且相关代码路径可达。枚举期间应离线检查有限范围内的源码或二进制副本，而不是向特权程序发送会导致崩溃的输入。

自定义 SUID helper 可能在不打印受保护文件内容的情况下泄露文件信息。如果调用者可以同时选择路径名和正则表达式，而 helper 在其有效 UID 下返回可见的匹配数量，那么锚定前缀测试可能形成逐字符 oracle。确认 helper 的所有者、有效 ID 行为、可执行权限、路径名限制、正则表达式语义、响应是否可见，以及是否存在调用者无法以其他方式读取的特定高权限文件。SUID 位或正则表达式库字符串都不能单独证明这一流程。被动枚举期间，应记录该异常可执行文件，并检查有限范围内的反汇编或源码副本；不要针对在线 helper 反复猜测，也不要打印恢复出的秘密。

在 OpenBSD 上，如果自定义 set-user-ID reader 接受调用者指定的路径，那么当其有效身份能够读取 `/var/backups` 下的文件并将内容返回给调用者时，就可能暴露这些文件。[OpenBSD's `changelist(5)`](https://man.openbsd.org/changelist.5) 描述了所配置路径的 `.current` 和 `.backup` 副本，但以 `+` 开头的条目存储的是 SHA-256 校验和，而非文件内容；备份目录应由 root 所有，权限为 `0700`。helper 对 `/var` 的 [`unveil` read rule](https://man.openbsd.org/unveil.2) 可以允许访问该路径下的内容，但本身既不授予也不能证明文件访问权限。在声称存在提权之前，应确认实际有效 UID、当前用户的可执行权限、接受的路径、备份是否存在及其内容，以及是否存在独立的身份验证要求。被动枚举应报告 helper 和路径元数据，而不是调用 reader 或打印备份数据。

自定义 SUID 程序可能使用 [`stat(2)`](https://man7.org/linux/man-pages/man2/stat.2.html) 检查调用者指定的路径，之后再打开该路径；如果路径位于调用者可写的目录中，就可能发生文件或符号链接替换竞态。检查针对的是较早时刻的对象，而稍后的 [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html) 可能解析到另一个对象。确认 helper 可由调用者以提升后的有效身份执行、存在其他可达代码路径来读取所选文件，并且调用者能在检查与打开之间替换路径名；SUID 位、可写目录或 `stat` 字符串本身都不能证明这些条件。若要构成信息披露路径，还需要输出可见或目标可由调用者读取。离线检查二进制和路径元数据；被动枚举期间不要与在线 helper 竞争。

同样的依赖项检查也适用于 SGID wrapper。如果 wrapper 通过绝对路径运行 shell 或 helper，但低权限用户可以替换该文件，那么仍可能不安全；启动的代码可能继承 wrapper 的有效组。检查确切的调用路径及其写权限（包括 ACL）、wrapper 的有效组，以及它是否会在启动子进程前降权。解释器也可能丢弃继承的有效 ID，因此要区分值得检查的线索和已证实的身份转换。主机其他位置存在可写 shell，并不能证明特权 wrapper 会调用它。

### 将 SQL 传递给 SQLite CLI 的特权 wrapper

如果自定义 SUID 程序将用户控制的 SQL 传递给 **`sqlite3` 命令行程序**，在将查询视为只读之前，应检查确切命令和有效身份。CLI 的 `edit()` SQL 函数会调用编辑器（来自其第二个参数或 `VISUAL`）；其 SQL `load_extension()` 函数则能在启用了扩展加载的情况下加载共享库。即使 wrapper 固定了 `PATH` 或使用绝对路径调用 `sqlite3`，这些仍可能成为以 CLI 进程身份执行代码的路径。SQL 必须确实传递到这些函数，且 CLI 必须保留相关功能；仅在二进制文件或主机上找到 `sqlite3`，并不能证明存在提权。SQLite **库**默认禁用扩展加载，因此要将它与 CLI 区分开来。如果特权应用必须处理不可信 SQL，SQLite CLI 的 `--safe` 模式会禁用 `edit()`、`load_extension()` 和其他有副作用的函数。请参阅 [SQLite CLI documentation](https://www.sqlite.org/cli.html#the_edit_sql_function)、[safe-mode documentation](https://www.sqlite.org/cli.html#the_safe_command_line_option) 和 [extension-loading documentation](https://www.sqlite.org/loadext.html#loading_an_extension)。

### 将特权文件交给详细输出客户端的 reader

自定义 SUID/SGID wrapper 可能会检查调用者指定路径的访问权限，然后将该文件传给另一个命令。检查访问检查和之后打开文件时的有效身份，按实际基目录解析任何 `../` 组件，并检查子进程如何处理无效输入。如果数据库客户端将私有文件作为 SQL 读取并启用详细输出，即使 SQL 无效，也可能在错误信息中回显文件内容。只有当子进程能够读取调用者无法读取的文件、调用者能通过 wrapper 选择该文件，且输出可见时，这才构成跨用户信息泄露；仅出现 `mysql` 或其他客户端字符串，并不能证明这些条件成立。

### Netdata `ndsudo` 搜索路径

[CVE-2024-32019](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93) 影响了某些 Netdata `ndsudo` 构建。该 root 所有的 SUID helper 使用调用者提供的 `PATH` 搜索允许调用的外部命令。仅当当前账户能够执行该 helper 时，才应检查已安装的 helper，包括位于调用者常用 `PATH` 之外的 helper。确认其所有者、SUID 位、可执行权限（包括组/ACL 授权）、已安装的构建及供应商补丁状态，以及 `NoNewPrivs` 或 `nosuid` 挂载是否会阻止身份变更。Netdata 列出的已修复构建为 `v1.45.3` 和 `v1.45.0-169`；发行版回补需要单独确认。仪表板版本或仅仅存在 `ndsudo`，都不足以证明存在可达的提权路径。此路径问题还要求 helper 通过攻击者可控的位置解析外部命令。

### Firejail join 特权边界

[CVE-2022-31214](https://seclists.org/oss-sec/2022/q2/188) 影响了 Firejail 的特权 `--join` 逻辑：构造的 join 目标可能使 setuid-root helper 接受攻击者控制的挂载命名空间，并复制不安全的安全状态。被动分诊时，应确认**当前身份可以执行** root 所有的 setuid Firejail 二进制文件，setuid 在其挂载和进程上下文中有效，并且已安装的构建缺少修复。上游在 [0.9.70](https://github.com/netblue30/firejail/releases/tag/0.9.70) 中修复了此问题；发行版软件包可能会[回补修复](https://github.com/netblue30/firejail/issues/5191)，但仍显示旧版本。这些前提只能说明该对象值得检查，并不能证明 join 成功或获得了 root shell。枚举期间不要构造假 jail 或调用 `--join`。

### GNU Screen 日志文件权限

[CVE-2017-5618](https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00026.html) 涉及 Screen 4.5.0 以提升后的权限打开调用者指定的日志文件。SUID 清单中的 `screen` 或带版本后缀的二进制文件，只是检查线索：应确认其由 root 所有、当前用户实际能够以 SUID 身份执行、已安装的构建和发行版补丁状态，以及受影响的日志文件行为。[Debian 通过回补修复了其 4.5.0 软件包](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=852484)，因此仅凭版本字符串或文件名不能证明存在漏洞。不要将创建日志文件作为常规枚举探测。

[CVE-2017-5899](https://ubuntu.com/security/CVE-2017-5899) 影响了特权 S-nail 邮件锁 helper：当调用者控制的路径组件能够遍历目录并导致任意文件写入时，就会受到影响。检查当前用户是否能执行已安装的 root 所有 setuid helper、在挂载和进程策略下其 setuid 身份是否有效，以及确切的软件包构建和供应商修复情况。[Ubuntu's security notice](https://ubuntu.com/security/notices/USN-4820-1) 列出了其 16.04 软件包的回补修复，因此仅凭看似上游版本的信息无法得出结论。helper 的存在并不能证明受影响的路径可达，也不能证明文件写入会导致 root 代码执行；枚举期间应检查元数据和软件包状态，不要调用 helper 或尝试竞态。

### snap-confine 和 tmpfiles 清理

CVE-2026-3888 是涉及特权 `snap-confine` 和 systemd-tmpfiles 清理 `/tmp` 的竞态。被动检查可确认 `snap-confine` 是否设置了 setuid 或文件 capabilities，将已安装的 `snapd` 软件包与该 **Ubuntu 发行版**对应的修复版本比较，并检查 `/tmp` 的有效期限规则和清理定时器。匹配的软件包和规则只是必要条件，并不能证明竞态可达：运行时定时器状态、snap 布局、软件包回补以及规则覆盖也会产生影响。较旧的发行版可能需要非默认配置。常规枚举期间不要运行竞态探测。发行版对应的软件包状态请参阅 [Ubuntu CVE record](https://ubuntu.com/security/CVE-2026-3888)，组件交互说明请参阅 [Qualys advisory](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root)。

## 检查 ACL 和敏感路径

```bash
getfacl -p /path/to/file /path/to/parent 2>/dev/null
namei -l /path/to/file
find /etc /opt /var -type f -writable -ls 2>/dev/null | head -80
ls -la /etc/sudoers.d /etc/ld.so.preload /etc/ld.so.conf.d 2>/dev/null
```

可写的父目录可能允许替换文件，即使文件本身归 root 所有。ACL 可能会悄悄授予对 sudoers 配置片段、service unit、cron 脚本、库路径或凭据文件的访问权限。检查 ACL 和完整路径。如果可以任意写入特权文件，请参阅 [Arbitrary File Write to Root](write-to-root.md)；对于链接器配置和 preload 情况，请参阅 [`ld.so` 示例](ld.so.conf-example.md)。将暴露的备份、`.env` 文件、数据库配置、SSH 材料和历史记录视为可能的凭据来源，并根据每个文件的实际权限判断是否可访问。
{{#include ../../banners/hacktricks-training.md}}
