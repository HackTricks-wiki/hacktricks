# SUID、SGID、ACL 和敏感文件

{{#include ../../banners/hacktricks-training.md}}

SUID 和 SGID 会更改所执行文件的有效身份；ACL 可以授予普通 `ls -l` 权限位不会显示的访问权限。当用户能够读取、写入或执行的权限超出表面显示的所有者和组权限时，请同时检查这两者。

## 枚举特权可执行文件

```bash
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
findmnt -no TARGET,OPTIONS
getcap -r / 2>/dev/null
```

重点检查自定义或最近有变动的可执行文件、所有者异常的文件，以及位于可写挂载上的文件。`nosuid` 挂载可以抑制 set-ID 行为；文件 capabilities 是一种独立的权限机制，详见 [Linux capabilities](linux-capabilities.md)。将可疑二进制文件与其软件包进行比对，并检查它在提升后的身份下会执行、打开或加载什么。

对于接受调用者输入、但你不熟悉的 root 所有 SUID 可执行文件，离线检查该二进制文件的副本，查看其参数处理是否存在内存安全问题，以及会进入相关代码的路径。记录其 effective-ID 行为，以及栈 canary、不可执行内存、位置无关代码和地址随机化等缓解措施。函数名称不安全或缺少缓解措施只能作为进一步检查的线索：是否可利用取决于实际输入边界、可达的控制流，以及发生故障时的有效身份。在被动枚举期间，不要仅为测试是否会崩溃，就向正在运行的特权可执行文件发送很长的参数。

常见的 SUID 程序本身也可能被替换或植入后门。最近的修改时间只是线索，并非证据：对于**特定的可疑软件包二进制文件**，确认其所属软件包，并将已安装文件与软件包元数据进行比对，而不要在例行枚举时验证所有软件包：

```bash
dpkg -S /usr/bin/passwd                  # Debian-family: identify the owner
dpkg --verify passwd                     # Verify only that package
rpm -V --noscripts -f /usr/bin/passwd    # RPM-family: owning package, no verify scriptlets
```

`dpkg --verify` 仅在软件包数据库记录了校验和的文件上检查文件内容；RPM 还会比较 mode 和所有权等元数据。重点关注**特权可执行文件本身**是否不匹配：精简安装可能会报告同一软件包中其他位置的文档或 locale 文件缺失。将可疑可执行文件与可信的供应商软件包进行比较，并检查具体变更的代码。合法的本地修改、缺失的校验和以及遭入侵的软件包元数据，都会限制这两个命令能够证明的内容。在被动分流期间，不要运行可疑的 SUID 程序或软件包验证脚本。参见 [dpkg verification manual](https://manpages.debian.org/bookworm/dpkg/dpkg.1.en.html) 和 [RPM verification manual](https://rpm.org/docs/4.20.x/man/rpm.8)。

若 SUID 程序会调用来自可写路径的 shell、相对路径命令或库，就可能跨越信任边界。参见 [SUID shared-library and linker abuse](suid-shared-library-and-linker-abuse.md)、[PATH guidance](../linux-basics/linux-environment-variables.md#path) 和 [user-ID explanation](../user-information/euid-ruid-suid.md)。对于已知的特定命令逃逸方式，可在 [GTFOBins](https://gtfobins.github.io/) 中核对主机上允许使用的确切二进制文件及调用方式。

对于 set-user-ID 可执行文件，要区分调用者的**真实 UID**与文件所有者的**有效 UID**：发生任何 set-ID 变更后，[`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html) 会保持真实 UID 不变，并将有效 UID 复制到保存的 UID 中。[`system(3)`](https://man7.org/linux/man-pages/man3/system.3.html) 会通过 `/bin/sh -c` 运行命令；该路径选择的 shell 会影响子进程是否保留其有效身份。尤其是，[Bash privileged-mode rules](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html) 规定：Bash 未使用 `-p` 启动时，如果有效 UID 与真实 UID 不同，就会将有效 UID 重置为真实 UID。检查实际 helper 的 UID 变更和子进程调用情况，以及其所有者、可执行访问权限、挂载的 `nosuid` 设置和进程的 `no_new_privs` 状态。仅有 SUID 位或 shell 调用，并不能证明存在可用的更高权限转换。

如果当前用户可以执行一个不同寻常的 root-owned SUID `jjs`，应单独检查其文件访问行为。这个旧版 Nashorn 工具即使在启动的 shell 丢弃有效 UID 后，仍可能访问 Java 文件 API；在将其视为特权读写工具前，应确认已安装 JVM 的行为、文件操作的有效身份，以及 `nosuid`/`no_new_privs` 状态。[Oracle 已在 JDK 15 中移除 `jjs`](https://docs.oracle.com/en/java/javase/21/migrate/removed-tools-and-components.html)；系统中仍存在的路径可能属于旧版本或单独打包的构建。[GTFOBins 记录了相关文件 API](https://gtfobins.org/gtfobins/jjs/)，但其中的 sudo 示例不能证明所有构建版本都具有 SUID 行为。被动枚举期间不要调用该工具。

如果低权限用户可以访问一个 root-owned SUID `gosu` 可执行文件，则值得审查：其文档说明该工具接口接受目标用户和命令，但正常的容器用法是以 root 身份启动它以降低权限。请核实已安装构建版本的 SUID 行为、有效身份和 user namespace 映射，以及 `nosuid` 和 `no_new_privs` 状态；容器内的 root 并不意味着宿主机 root。文件名或 SUID 位本身不能证明权限转换有效。参见 [upstream usage](https://github.com/tianon/gosu) 和 [maintainer's SUID warning](https://github.com/tianon/gosu/issues/11)。被动清点期间不要调用该 helper。

自定义 set-user-ID 备份 wrapper 可能接受调用者选择的路径，并将其插入传给 `system(3)` 的归档命令中。如果构造命令时未给该路径加引号，子 shell 就可能执行[使用 `HOME` 的 tilde expansion、`?` 和 `*` 等 pathname pattern，以及以换行符分隔的命令](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)；仅通过 denylist 拒绝一些常见标点，并不能让路径按字面量处理。确认确切的参数流、继承的环境、子 shell 和有效身份、文件系统访问权限，以及调用者是否能看到归档输出。SUID 位、归档工具字符串或被阻止的 `/root` 字面路径，都不能单独证明存在信息泄露或代码执行。被动枚举期间，应离线审查 wrapper 的副本，而不是归档私有文件或发送崩溃输入。

shell [command substitution](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html)，例如 `$(...)`，是 metacharacter denylist 中另一个可能的漏洞：即使允许的命令前缀固定，后续调用者可控的参数仍可能被传入 `/bin/sh -c`。应离线核实确切的 quoting、parser 和有效身份；不能仅凭 `system()` 字符串或不完整的 denylist 就认定存在代码执行。

**调用进程树**也很重要。Web worker 可以安装 seccomp filter，限制更改 UID 的系统调用；[seccomp filters pass to children and survive `execve`](https://docs.kernel.org/userspace-api/seccomp_filter.html)。例如，Apache 的 [mpm-itk `LimitUIDRange` 和 `LimitGIDRange` directives](https://sources.debian.org/src/mpm-itk/2.4.7-04-2/mpm_itk.c/) 可以限制后代进程可使用的身份。`/proc/self/status` 中的 `Seccomp: 2` 表示 filter 模式，而非策略内容，也无法说明这个特定 helper 能否获得其所有者的身份。应结合实际调用的进程祖先和有效 filter，检查其 SUID、挂载及 `no_new_privs` 条件；单独的登录会话可能采用不同策略，但仍需要各自有效的访问路径。

自定义 SUID 可执行文件可能会调用一个单独且可读的 Python 脚本。如果它实际使用 **Python 2**，[`input()` 会对输入的表达式求值](https://docs.python.org/2/library/functions.html#input)；而 Python 3 的 `input()` 返回文本。在将源代码行视为执行路径之前，应确认 wrapper 的有效身份、解释器路径和版本、脚本路径，以及不可信输入是否会传入该调用。脚本本身带有 set-ID 位，或在没有特权 wrapper 的情况下调用 `input()`，都不能构成相同的边界。枚举期间，应检查二进制文件引用的路径和有限范围内的脚本源码，但不要运行它。

如果不同寻常的 SUID 可执行文件附带可读源码，应将每个由调用者控制的文件读取操作所请求的字节数，与目标缓冲区大小进行比较，并检查后续控制流检查。[`fread(3)`](https://man7.org/linux/man-pages/man3/fread.3.html) 会将请求数量的元素写入给定指针；它并不知道目标对象的容量。大小不匹配是静态内存安全问题的线索，并不能证明存在可利用的权限提升：应确认源码与已安装的二进制文件一致、调用者能提供输入、在该上下文中 SUID 执行有效，并且相关路径可达。枚举期间，应离线审查有限范围内的源码或二进制副本，而不是向特权程序发送崩溃输入。

自定义 SUID helper 可能会在不打印受保护文件内容的情况下泄露该文件。如果调用者既能选择路径，也能选择 regular expression，而 helper 会以其有效 UID 返回可见的匹配计数，那么锚定前缀测试可能构成逐字符 oracle。请确认 helper 的所有者、有效 ID 行为、可执行访问权限、路径限制、regex 语义、响应是否可见，以及是否存在调用者无法通过其他方式读取的特定高权限文件。SUID 位或 regex library 字符串本身无法证明这类数据流。被动枚举期间，应记录这个不同寻常的可执行文件，并审查有限范围内的反汇编或源码副本；不要对在线 helper 运行迭代猜测，也不要打印恢复出的秘密。

在 OpenBSD 上，如果自定义 set-user-ID reader 接受调用者选择的路径，那么当其有效身份可以读取 `/var/backups` 下的文件，且它会将内容返回给调用者时，就可能暴露这些文件。[OpenBSD 的 `changelist(5)`](https://man.openbsd.org/changelist.5) 说明了配置路径的 `.current` 和 `.backup` 副本，但以 `+` 开头的条目存储的是 SHA-256 校验和，而非文件内容；备份目录应由 root 所有，权限为 `0700`。helper 针对 `/var` 的 [`unveil` read rule](https://man.openbsd.org/unveil.2) 可以允许访问该路径下的内容，但本身既不会授予文件访问权限，也不能证明文件可访问。在声称存在权限提升前，应确认实际有效 UID、当前用户对可执行文件的权限、接受的路径、备份是否存在及其内容，以及是否有独立的身份验证要求。被动枚举应报告 helper 和路径元数据，而不是调用 reader 或打印备份数据。

自定义 SUID 程序可能先用 [`stat(2)`](https://man7.org/linux/man-pages/man2/stat.2.html) 检查调用者选择的路径，稍后再打开该路径；如果路径位于调用者可写的目录中，就可能出现文件或 symlink 变更竞态。检查针对的是先前的对象，而后续 [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html) 可能解析到另一个对象。应确认该 helper 能以提升后的有效身份执行，某条其他条件允许到达的代码路径会读取所选文件，并且调用者能在检查和打开之间替换路径；单有 SUID 位、可写目录或 `stat` 字符串，都不能证明这些条件成立。若要构成信息泄露，还需要输出可见，或目标位置可由调用者读取。应离线检查二进制文件和路径元数据；被动枚举期间不要对在线 helper 进行竞态操作。

对 SGID wrapper 也应进行相同的依赖项审查。即使 wrapper 通过绝对路径运行 shell 或 helper，只要低权限用户可以替换该文件，仍可能不安全；启动的代码可能会继承 wrapper 的有效组。检查确切的调用路径、其写入权限（包括 ACL）、wrapper 的有效组，以及启动子进程前是否会丢弃权限。解释器也可能丢弃继承的有效 ID，因此应区分待审查的对象和已证明的权限转换。主机其他位置存在可写 shell，本身不能证明特权 wrapper 会调用它。

### 将 SQL 传递给 SQLite CLI 的特权 wrapper

如果自定义 SUID 程序将用户可控的 SQL 传给 **`sqlite3` command-line program**，在认定查询是只读的之前，应检查确切的命令和有效身份。CLI 的 `edit()` SQL function 会调用编辑器（从其第二个参数或 `VISUAL` 获取），其 SQL `load_extension()` function 在启用扩展加载时可以加载 shared library。即使 wrapper 固定了 `PATH` 或使用绝对路径调用 `sqlite3`，这些也可能成为 CLI 进程身份下的代码执行路径。SQL 必须实际传入这些 functions，且 CLI 必须保留相关功能；仅在二进制文件或主机上发现 `sqlite3`，不能证明存在权限提升。SQLite **library** 默认禁用扩展加载，因此应将其与 CLI 区分开来。如果特权应用必须处理不可信 SQL，SQLite CLI 的 `--safe` mode 会禁用 `edit()`、`load_extension()` 及其他具有副作用的 functions。参见 [SQLite CLI documentation](https://www.sqlite.org/cli.html#the_edit_sql_function)、[safe-mode documentation](https://www.sqlite.org/cli.html#the_safe_command_line_option) 和 [extension-loading documentation](https://www.sqlite.org/loadext.html#loading_an_extension)。

### 将文件交给 verbose client 处理的特权 reader

自定义 SUID/SGID wrapper 可能会先检查调用者所选路径的访问权限，然后将该文件传给另一个命令。应检查访问权限检查和后续打开操作各自使用的有效身份，根据实际基目录解析任何 `../` 组件，并检查子进程如何处理无效输入。如果 database client 将私有文件作为 SQL 读取并启用 verbose 输出，那么即使 SQL 无效，也可能在错误信息中回显文件内容。只有当子进程能读取调用者无法读取的文件、调用者能通过 wrapper 选择该文件且输出可见时，才构成跨用户信息泄露；仅出现 `mysql` 或其他 client 字符串，并不能证明这些条件成立。

### Netdata `ndsudo` 搜索路径

[CVE-2024-32019](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93) 影响了部分 Netdata `ndsudo` 构建版本。这个 root-owned SUID helper 会使用调用者提供的 `PATH` 查找允许调用的外部命令。只有在当前账户可以执行已安装的 helper 时，才应审查它，包括位于调用者常用 `PATH` 之外的 helper。请确认其所有者、SUID 位、可执行访问权限（包括组权限/ACL 授权）、已安装的构建版本和供应商补丁状态，以及 `NoNewPrivs` 或 `nosuid` 挂载是否会阻止身份变更。Netdata 列出的修复版本为 `v1.45.3` 和 `v1.45.0-169`；发行版 backport 需要单独确认。Dashboard 版本或仅仅存在 `ndsudo`，都不足以证明存在可利用的权限提升。此路径问题还要求 helper 通过调用者可控的位置解析外部命令。

### Firejail join 权限边界

[CVE-2022-31214](https://seclists.org/oss-sec/2022/q2/188) 影响了 Firejail 特权 `--join` 逻辑：精心构造的 join target 可能会使 setuid-root helper 接受攻击者控制的 mount namespace，并复制不安全的安全状态。被动分流时，应确认**当前身份能够执行** root-owned setuid Firejail 二进制文件、其 setuid 在所在挂载和进程上下文中有效，并且已安装构建版本未包含修复。上游在 [0.9.70](https://github.com/netblue30/firejail/releases/tag/0.9.70) 中修复了该问题；发行版软件包可能会[反向移植修复](https://github.com/netblue30/firejail/issues/5191)，但仍显示较旧版本。这些先决条件表明该对象值得审查，并不代表成功加入了 jail 或获得了 root shell。枚举期间不要构造 fake jail，也不要调用 `--join`。

### GNU Screen logfile 权限

[CVE-2017-5618](https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00026.html) 涉及 Screen 4.5.0 以提升后的权限打开调用者指定的 logfile。SUID 清单中出现 `screen` 或带版本后缀的二进制文件，只是一个审查线索：请确认 root 所有权、当前用户执行时 SUID 是否有效、已安装的构建版本和发行版补丁状态，以及相关 logfile 行为。[Debian 通过 backport 修复了其 4.5.0 软件包](https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=852484)，因此仅凭版本字符串或文件名不能证明存在漏洞。不要在常规枚举中创建 logfile 作为探测。

[CVE-2017-5899](https://ubuntu.com/security/CVE-2017-5899) 影响了特权 S-nail mail-lock helper：调用者可控的路径组件可能遍历目录并导致任意文件写入。应检查当前用户是否能够执行已安装的 root-owned setuid helper、挂载和进程策略下 setuid 身份是否有效，以及确切的软件包构建版本和供应商修复情况。[Ubuntu 的安全公告](https://ubuntu.com/security/notices/USN-4820-1) 列出了其 16.04 软件包的 backport 修复，因此仅凭看似上游的版本号无法定论。helper 存在并不能证明受影响路径可达，也不能证明文件写入会导致 root 代码执行；枚举期间应检查元数据和软件包状态，不要调用 helper 或尝试触发竞态。

### snap-confine 和 tmpfiles 清理

CVE-2026-3888 涉及特权 `snap-confine` 与 systemd-tmpfiles 清理 `/tmp` 时的竞态。被动审查时，可检查 `snap-confine` 是否设置了 setuid 或 file capabilities，将已安装的 `snapd` 软件包与该 **Ubuntu release** 的修复版本进行比较，并检查实际生效的 `/tmp` age rule 和清理 timer。软件包和规则匹配只是先决条件，并不能证明竞态可达：运行时 timer 状态、snap 布局、软件包 backport 和规则覆盖也很重要。较旧的发行版可能需要非默认配置。常规枚举期间不要运行竞态探测。有关特定发行版的软件包状态，请参见 [Ubuntu CVE record](https://ubuntu.com/security/CVE-2026-3888)；有关组件交互，请参见 [Qualys advisory](https://blog.qualys.com/vulnerabilities-threat-research/2026/03/17/cve-2026-3888-important-snap-flaw-enables-local-privilege-escalation-to-root)。

## 检查 ACL 和敏感路径

```bash
getfacl -p /path/to/file /path/to/parent 2>/dev/null
namei -l /path/to/file
find /etc /opt /var -type f -writable -ls 2>/dev/null | head -80
ls -la /etc/sudoers.d /etc/ld.so.preload /etc/ld.so.conf.d 2>/dev/null
```

可写的父目录可能允许替换文件，即使文件本身归 root 所有。ACL 可能会悄然授予对 sudoers drop-in、service unit、cron 脚本、library path 或凭据文件的访问权限。检查 ACL 和完整路径。如果可以任意写入特权文件，请参阅 [Arbitrary File Write to Root](write-to-root.md)；有关 linker 配置和 preload 情况，请参阅 [`ld.so` 示例](ld.so.conf-example.md)。将暴露的备份文件、`.env` 文件、数据库配置、SSH 资料和历史记录视为可能的凭据来源；能否访问取决于各文件的实际权限。
{{#include ../../banners/hacktricks-training.md}}
