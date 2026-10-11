# Cron Jobs 和 Systemd Timers

{{#include ../../banners/hacktricks-training.md}}

计划任务可能以不同于当前 shell 的身份和环境运行。枚举 cron、`at`、anacron 和 systemd timers，然后沿着每个计划命令追踪其脚本、导入内容、工作目录和可写输入。

## 枚举计划任务

```bash
crontab -l 2>/dev/null
ls -la /etc/crontab /etc/cron.* /var/spool/cron* 2>/dev/null
atq 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

系统 crontab 通常包含用户字段；用户的 crontab 则不包含。检查实际调度器的有效 PATH 和环境。`run-parts --test /etc/cron.daily` 会显示该主机上会选中的文件名。控制字符可能会让条目在普通输出中被隐藏，因此如果某个计划看起来可疑，请使用 `cat -A` 或 `sed -n l`。

## 追踪特权文件和命令解析方式

```bash
systemctl cat <name>.timer <name>.service
systemctl show <name>.service -p User -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/to/scheduled/script
```

检查可写脚本链、`EnvironmentFile=` 路径、drop-in、符号链接、相对命令、通配符展开，以及由特权任务复制或执行的二进制文件。timer 可以通过其 `Unit=` 设置激活一个名称不同的 service。[PATH](../linux-basics/linux-environment-variables.md#path)、[wildcard](../interesting-files-permissions/wildcards-spare-tricks.md) 和 [file-link](../main-system-information/filesystem-links-and-file-descriptors.md) 页面介绍了主要原语。

对于定期以 root 身份运行的 `chkrootkit` 脚本，请检查已安装的源码，确认是否存在旧的 [slapper-loop quoting defect (CVE-2014-0476)](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2014-0476)：检查 `SLAPPER_FILES` 临时路径后，如果存在未加引号的 `file_port=$file_port $i`，就可能执行该文件。请核实实际脚本或供应商补丁、root 调度设置、低权限用户对确切临时路径的写入权限、该文件是否可执行，以及挂载策略。仅凭版本字符串或系统中存在 `chkrootkit`，不足以证明存在这条路径；被动审查时不要创建或运行临时文件。

如果 timer 的 root service 运行 `systemctl restart <other>.service`，还要继续追踪一跳 unit：被重启的 unit 可能会调用一个 shell，并执行低权限用户可写的脚本。请确认有效的 `User=`、`DynamicUser=`、`RootDirectory=`/`RootImage=`、确切的 `ExecStart=` 参数，以及脚本和其父路径的权限。可写脚本只是一个候选项；只有当 timer 和被重启的 service 在该执行上下文中处于活动状态时，才可能形成执行路径；请检查 unit 属性，但不要重启任一 service。

如果高权限任务通过主机名获取脚本，并将响应传给 shell，请检查谁能控制该主机名的解析，以及远程脚本本身。可写的 `/etc/hosts` 文件（包括通过组权限或 ACL 授予的访问权限）可以重定向任务在本地解析的名称；只有在实际调度命令运行该响应，且任务使用受影响的解析路径时，`curl` 响应才会形成跨用户执行路径。请核实任务的运行身份、确切 URL 和 shell pipeline、有效的代理/DNS 行为，以及文件和父目录权限。hosts 文件可写本身只是审查线索，并不能证明存在特权使用者。枚举时请检查调度设置和元数据，不要更改映射或获取脚本。

即使下载的内容不会直接执行，特权调度的 `wget` 获取操作仍会形成独立的文件写入边界。[GNU Wget 1.18 更改了 HTTP 到 FTP 重定向时的默认文件名处理方式，以修复 CVE-2016-4971](https://lists.gnu.org/archive/html/info-gnu/2016-06/msg00004.html)；受影响的旧版本可能会使用重定向后的 FTP 文件名，而 `--trust-server-names` 会显式启用该行为。如果低信任方控制 HTTP 响应和 FTP 资源，请检查任务是否跟随该重定向、实际 Wget 构建版本或供应商回移补丁、输出选项、运行身份、工作目录，以及目标文件名是否可能成为启动文件。[Wget 会加载 `WGETRC` 或 `$HOME/.wgetrc`](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Location.html)，并且[其设置可以指定 POST 来源或输出路径](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html)；之后还必须有一次特权获取操作，才可能造成信息泄露或写入。只有当调用方确实能提供任务请求的 URL 时，通过 `authbind` 访问低端口才相关。被动检查配置和日志，不要提供重定向服务或运行任务。[通过 `disk` 组访问原始块设备](../user-information/interesting-groups-linux-pe/README.md#disk-group)与此网络获取路径无关。

除了脚本，也要追踪数据文件。定时运行的模拟或编排工具可能会读取定义待启动进程的 YAML 文件；如果低权限用户能编辑该文件，而任务以另一个账户身份运行，那么这些数据就可能变成以任务身份执行的命令。要将可写 YAML 文件认定为执行路径，必须先核实确切的调度命令、有效用户、文件路径、解析器语义以及写入权限（包括父目录）。被动初步排查时，查看调度设置和文件元数据即可；枚举期间不要运行任务或修改其输入。

当高权限任务通过 `ssh -F` 使用低权限用户可以替换的文件时，SSH 客户端配置也属于可执行输入。OpenSSH 的 [`ProxyCommand`](https://man.openbsd.org/ssh_config#ProxyCommand) 会通过客户端的 shell 运行本地命令，而 `Host`/`Match` 和较早的选项会决定该指令是否生效。在认定这是跨用户执行路径之前，请结合确切的定时 SSH 调用、运行身份、所选配置路径、目录和文件写入权限，以及有效的选项顺序进行核实。检查这些记录时，不要运行任务，也不要以特权账户加载不可信配置。

如果定时任务先执行 `scp`，随后通过 `ssh` 运行已复制的脚本，而低权限用户控制目标 SSH 服务，则需要另外审查信任边界。如果该服务能将连接转发到另一台主机，特权客户端可能会向非预期端点进行身份验证；[`StrictHostKeyChecking no`](https://man.openbsd.org/ssh_config#StrictHostKeyChecking) 会削弱对主机密钥变更的保护，但仍受 OpenSSH 其他限制和有效的逐主机选项约束。请确认任务的运行身份、实际目标和身份验证方式、远程命令的有效身份，以及被重定向的主机上相同目标路径是否可写或已存在。要执行较旧或由攻击者控制的文件，还需要复制失败或未覆盖该路径，**并且**包装脚本继续执行 SSH 命令；[Bash `errexit`](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html) 和显式状态处理都会影响这一流程。弱主机密钥设置、可见的 `sshpass` 进程或可写临时目录本身，都不足以证明这条链路成立。枚举时请检查调度设置、脚本、SSH 配置和文件元数据，不要重定向服务或触发任务。

特权应用调度器可能从数据库行而非可写文件中获取任务。例如，root cron 条目调用 Laravel 的 [`php artisan schedule:run`](https://laravel.com/docs/9.x/scheduling#running-the-scheduler)，可能会执行读取任务行的应用代码。如果低权限账户能写入包含本地路径的行，而调度回调以 root 身份调用 PHP [`file_get_contents`](https://www.php.net/manual/en/function.file-get-contents.php) 并将返回内容发送到由该行指定的 webhook，这就构成特权文件泄露路径。请核实 cron 身份、实际调度回调及行到路径的数据流、数据库写入授权、读取该行后的验证，以及出站目标。能读取应用的 `.env` 文件只能提供凭据线索；Web 表单验证或数据库密码本身，都不能证明攻击者可以控制数据库行或导致信息泄露。枚举时被动检查调度设置、代码和凭据文件权限，不要查询数据库或安排任务。

事件驱动的 `incron` 任务也需要同样审查：[incrontab 条目](https://manpages.debian.org/testing/incron/incrontab.5.en.html)将受监视路径和事件与一条命令关联，该命令以表所有者的身份运行。如果应用会跟随来自可写目录的链接，并将攻击者控制的文本写入受监视目标，低权限用户就可能间接影响受监视文件。请核实实际表所有者、事件、目标及祖先路径的权限、应用跟随链接的行为，以及该文本如何变成命令参数。特别是，[GNU Mailutils 的 `mail` 接受 `--exec`](https://mailutils.org/manual/html_node/Invoking-Mail.html)，其[shell-escape 命令](https://mailutils.org/manual/html_node/Shell-Escapes.html)可以运行程序；对于该实现，如果不可信字段作为单独选项传入，就可能跨越到命令执行。其他 `mail` 实现或带引号的固定参数边界可能有不同表现。枚举时请检查调度设置、应用代码和文件元数据，不要修改受监视文件或触发任务。

受监视日志也可能通过辅助脚本跨越用户边界。如果低权限账户能写入日志，而 `incron` 所有者会从中读取字段并将其写入新的 [`sh -c` 命令字符串](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)，shell 就会以该所有者的身份再次解析这个字段。请检查确切的受监视事件、日志和父目录权限、辅助脚本路径、日志字段的转换方式，以及是否会执行最终生成的命令。仅看到可写日志和 `incron` 条目，并不能证明数据流确实存在；被动枚举时不要写入触发内容或运行辅助脚本。

证书续期任务也可能跨越相同的边界。特权辅助程序可能会读取低权限用户可写目录中证书的 X.509 subject，并将其 common name 插入新的 `bash -c` 命令字符串。[OpenSSL 可以显示证书的 subject 并检查有效期](https://docs.openssl.org/3.3/man1/openssl-x509/)；[Bash 会将 `-c` 字符串解析为 shell 输入](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)，因此在外层脚本中给变量加引号，无法保护第二次解析。认定这是命令注入之前，请确认调度身份、确切输入路径及其写入权限、续期分支，以及数据传入 `bash -c` 的流程。被动检查脚本和证书元数据；枚举时不要触发续期。

当特权调度任务从低权限用户的归档或软件包中提取名称，再通过 `xargs -I` 将其插入 `sh -c` 命令字符串时，也可能发生同样的二次解析。[GNU `xargs -I` 会在初始参数中替换占位符](https://www.gnu.org/software/findutils/manual/html_node/find_html/xargs-options.html)，而 [`sh -c` 会解释其命令字符串](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)。即使外层脚本给提取出的名称加了引号，也不能保证之后替换生成的 shell 程序是安全的。请核实任务的运行身份、确切的受理输入路径及其写入权限、归档验证和分支条件，以及名称到 shell 的数据流。可写上传目录或 `xargs` 调用本身只能算线索；枚举时请检查调度设置、脚本和路径元数据，不要提交软件包或运行任务。

定时运行的字体或图像导入器同样可能信任调用方提供的归档内部名称，即使上传文件的外部文件名受到限制也是如此。FontForge 已通过其 [针对 CVE-2024-25081 和 CVE-2024-25082 的上游更改](https://github.com/fontforge/fontforge/pull/5367)修复了归档成员名称命令注入问题。请确认高权限任务是否确实会打开低权限用户可写路径中的归档、其运行身份、确切的 FontForge 构建版本或供应商回移补丁，以及归档处理代码路径。版本字符串或允许的上传后缀都不能单独证明存在执行路径。枚举时请检查调度设置、路径权限和构建元数据，不要导入不可信归档。

定时网络扫描器可能通过另一种边界跨越：自定义脚本将远程 TLS 证书 subject 当作本地文件名。[Nmap NSE 会在无沙箱环境中运行选定脚本](https://nmap.org/book/nse-usage.html)，因此请检查实际脚本，以及它是否会在没有路径包含性检查的情况下，将不可信的 subject 字段拼接到数据目录路径中。要造成文件泄露，调度器必须会扫描某个目标，该路径必须解析到扫描器运行身份可读的文件，并且报告或日志必须会交给低权限用户读取。证书字段或已安装的扫描器本身，都不能证明这条链路成立；被动枚举时请审查调度设置、脚本、路径解析和报告目标，不要扫描新目标。

即使现有 playbook 都只读，也要检查将 shell glob（例如 `/path/to/tasks/*.yml`）传给 Ansible runner 的特权 cron 命令。对通配符匹配目录拥有写入和搜索权限的用户，可能能够创建另一个匹配的 playbook。[Ansible playbook 定义了 runner 会执行的任务](https://docs.ansible.com/projects/ansible/latest/cli/ansible-playbook.html)，但自定义包装程序可能会筛选路径或使用不同身份：在将该目录认定为执行路径之前，请核实包装程序的行为、实际 cron 用户、shell 展开、ACL、sticky bit 和挂载策略。静态检查元数据和包装程序；枚举时不要运行定时任务。

特权 cron 包装程序可能会展开 glob，并将上传目录中的文件名传给 Perl 辅助程序。Perl 的 [`<>` 菱形运算符使用双参数 `open`](https://perldoc.perl.org/perlop#The-Null-Filehandle)，因此，如果匹配的文件名被解释为管道命令，就可能以辅助程序的身份执行；[`<<>>` 会将参数视为字面文件名](https://perldoc.perl.org/perlop#The-Null-Filehandle)。请确认调度身份、包装程序的工作目录和 glob、辅助程序对 `@ARGV` 的实际处理方式、文件名限制，以及低权限用户能否通过文件系统权限或经过身份验证的上传服务放置匹配名称。cron 条目、Perl 脚本或可写 FTP 目录本身，都不能证明完整链路成立。枚举时请检查源码和元数据，不要提交特制文件名或运行任务。

如果调度账户通过路径名运行脚本，而低权限用户可以写入并遍历其非 sticky 父目录，那么即使 cron 脚本本身只读，也仍然可以被替换。请检查调度设置中的运行身份、路径中的每个组件、目录 sticky bit、ACL 和挂载策略；只审查元数据，不要移动文件或运行任务。

特权 PHP cron 包装程序可能会调用一个尚不存在的辅助程序。如果它通过 PHP [`exec()`](https://www.php.net/manual/en/function.exec.php) 调用固定的绝对辅助程序路径，那么能够在其父目录中创建该文件名的低权限用户，就可能控制后续运行时执行的内容。请确认 cron 条目确实以更高权限身份运行包装程序、确切命令字符串和 PHP 执行策略、辅助程序目录的写入和搜索权限、符号链接及 sticky bit 的行为，以及辅助程序路径是否确实不存在。可写目录或缺失的辅助程序本身都只是线索；请检查调度设置、源码和路径元数据，不要创建辅助程序或触发任务。

定时任务也可能用 `find` 发现输入脚本，并将每个脚本传给解释器。例如，[gnuplot 的 `system()` 函数会调用 shell](https://gnuplot.sourceforge.net/docs_6.0/gnuplot.pdf)，因此，如果特权任务在低权限用户可写目录中对每个 `*.plt` 文件运行 `gnuplot`，就可能以任务的身份执行命令。[目录的读取权限控制列表操作，而写入和搜索（`x`）权限控制创建文件及访问已知名称](https://www.gnu.org/software/coreutils/manual/html_node/Mode-Structure.html)；即使 `ls` 无法列出目录，也要检查其写入和搜索权限。请结合确切的调度身份和命令、解释器行为、所选文件模式以及目录权限进行核实；可写目录或已安装的解释器本身都不能证明存在提权路径。对于私有调度设置和运行时间极短的任务，可能需要在获准的情况下观察事件，因为单次进程快照可能会漏掉它们。

对于特权 PHP 任务，请将字面量 `include`/`require` 语句纳入可执行脚本链检查。[PHP 会执行被包含的文件](https://www.php.net/manual/en/function.include.php)，因此，即使主脚本只读，组可写的 `.php` 被包含文件仍可能以任务身份运行代码。请核实调度身份、有效的 include-path 解析、文件和目录权限，以及任务是否实际运行；注释中的示例 cron 条目只是线索。以 root 身份通过 `-S` 和 `-t <document-root>` 启动的 [PHP 内置服务器](https://www.php.net/commandline.webserver)也需要同样检查：即使监听地址是 loopback，本地请求仍可能触发应用 PHP 执行。枚举时检查进程和源码，不要触发任一执行路径。

特权 PHP 任务也可能通过**数据文件**跨越边界：如果低权限用户能更改传给 [`unserialize()`](https://www.php.net/manual/en/function.unserialize.php) 的确切文件，PHP 在还原对象时可能调用已加载类的 `__wakeup()` 或 `__unserialize()` 方法。请检查任务的有效身份、文件及祖先路径权限、已加载的类，以及实际方法副作用（例如由属性决定的文件写入）。可写日志或 `unserialize()` 调用本身，都不能证明存在可用路径。枚举时请检查源码和元数据，不要写入序列化输入或运行任务。

root cron 任务可能调用 PHP 应用的**CLI 页面运行器**，而非 Web 服务器。请追踪运行器所选的 document root 和 URI，直到实际 PHP 入口点；如果 Web 服务账户可写该入口点，那么即使运行器和 cron 包装程序只读，定时 CLI 请求仍可能以 root 身份执行被修改的代码。请核实调度身份、确切的 URI 到文件解析方式、有效的文件及祖先路径权限，以及入口点本身是否受完整性检查保护。枚举时请检查源码和元数据，不要调用运行器或更改页面。

由定时任务或其他用户从共享工作目录启动的 `ipython` 进程，需要审查其启动文件。[IPython 的安全发布说明](https://ipython.readthedocs.io/en/8.25.0/whatsnew/version8.html#ipython-8-0-1-cve-2022-21699)说明，修复 CVE-2022-21699 之前，受影响的构建版本会在当前目录中搜索 profile 和配置文件，包括 `profile_default/startup` 代码。请结合实际安装的构建版本或供应商补丁、命令工作目录、高权限进程身份，以及低权限用户对确切启动路径的写入和搜索权限进行核实。系统中已安装 `ipython`、目录可写或版本字符串本身，都不能证明另一个身份会加载其中的文件。枚举时请检查调度设置和路径元数据，不要启动高权限解释器。

对于调用自定义 native extension 中函数的特权 PHP 服务器，请在检查扩展之前，先追踪服务的 PHP SAPI 及其有效 `php.ini` 和已扫描的 `.ini` 文件。[PHP 会在启动时加载配置的 `extension` 库](https://www.php.net/manual/en/ini.core.php)，而 [CLI 和 Web SAPI 可能使用不同的配置文件](https://www.php.net/manual/en/configuration.file.php)。因此，可访问的登录表单或本地监听器，可能会将用户可控字符串传入以服务身份运行的编译代码。请记录 unit 的 `User=`、`ExecStart=`、工作目录、实际扩展路径和调用方可控参数；仅有 `.so` 文件或 loopback socket，不能证明存在内存破坏漏洞。请单独分析任何自定义解析器，不要在被动枚举时发送探测数据。

如果特权包装程序先按路径名对脚本计算哈希，之后又重新打开该路径执行，那么摘要只会验证首次打开时读取的对象。如果低权限用户能在两次打开之间替换脚本的目录项，即使原始脚本文件归 root 所有，后续执行也可能解析到另一个对象。FIFO 可以延长检查阶段，但这条路径是否成立取决于父目录权限是否可被替换、是否确实发生了两次独立打开、调度身份、sticky bit 和挂载规则，以及时序。将包装程序和 `namei -l` 输出作为被动线索检查；校验和正确并不能证明后续路径名受到保护。

特权备份任务也可能**泄露**数据，而不执行攻击者提供的命令。请追踪低权限用户是否能创建任务会读取的控制文件、任务随后是否会打开 `/etc/shadow` 等受保护源文件，以及攻击者选定的 URL 或可读输出是否会收到读取结果。认定存在泄露路径前，请核实这三个环节。相同脚本中的固定 shell 命令，本身并不会让该控制文件成为 shell 注入输入。检查脚本和文件权限，不要在枚举时运行任务或放置控制文件。

如果特权调度任务运行 `curl -K FILE` 或 `curl --config FILE`，[curl 会将该文件中的选项视为命令行参数](https://curl.se/docs/manpage.html)。在 curl 读取文件时控制该文件的低权限用户，可能会影响请求的 URL、本地文件输入或输出路径。请确认任务的有效身份、文件及祖先路径的写入权限、其他任务替换该文件的时机，以及配置选项与固定命令行选项的交互方式，然后再判断是否会读取或写入受保护数据。配置路径可写或能看到 `-K` 标记本身，都不能证明所选选项会生效；被动枚举时请检查调度设置和元数据，不要运行任务或获取 URL。

如果 cron 条目调用辅助脚本，也要检查辅助脚本的工作目录和归档命令。在其他用户可写目录上使用未加引号的通配符，可能会让文件名被解释为归档器选项；GNU tar 的 checkpoint 操作就是一个例子。在认定存在跨用户命令执行路径之前，请确认调度运行身份、可写输入目录、确切的归档器和选项，以及是否通过 `--` 终止选项解析。请参见 [wildcard 和 tar 行为](../interesting-files-permissions/wildcards-spare-tricks.md)。

如果特权辅助程序运行 `cd INPUT_DIR; tar ... *`，却没有检查 `cd` 是否成功，则可能导致另一种备份文件泄露。如果低权限用户能移除或替换 `INPUT_DIR`，`cd` 失败后 shell 可能仍停留在之前的目录，后续归档命令就可能读取该目录中的内容。请核实任务的初始工作目录、确实会失败的 `cd` 路径、脚本是否会退出或使用 `&&`、确切的归档器选项，以及低权限用户能否读取输出归档。可写输入目录或可读归档本身都只是线索；请检查辅助脚本和路径权限，不要更改正在运行的任务。

定时执行文件也可能只是伪装成可执行文件的 shell 脚本，并未消除其信任边界：[SHc](https://github.com/neurobin/shc) 会将加密的脚本文本封装在 native binary 中，并在运行时通过 shell 执行。`.sh.x` 后缀或不透明的 ELF 文件都只是审查线索。要评估文件名选项注入，请确认特权调度身份、辅助程序的实际工作目录和命令、低权限用户能否在那里创建匹配名称，以及未加引号的 glob 是否会传给缺少选项边界的 `rsync` 等命令。只有在使用确切命令路径时，[`rsync` remote-shell 选项](../interesting-files-permissions/wildcards-spare-tricks.md#rsync)才相关。`/proc` 可见性受限或静态解密失败，会使命令保持未知；不要仅为判断其内容而运行特权辅助程序。

进程命令行文本也是传给特权辅助程序的不可信输入。低权限用户可以选择匹配 `pgrep -f` 的进程标题或 `argv[0]`；名称匹配并不能验证可执行文件或其所有者。如果 root 脚本捕获该文本，将其中一部分改写为 `apache2ctl`/`httpd`，并在没有固定参数数组的情况下执行结果，那么攻击者选择的选项就可能指定不同的配置目录或错误日志。Apache 配置解析可能加载模块或调用已配置的辅助程序，因此枚举时不要以 root 身份验证不可信配置。请检查调度所有者、确切的辅助程序、进程身份，以及数据到参数的流向；除非另外证明能够执行 shell 元字符，否则这属于选项/配置注入。

root 运行的解析器如果将不可信文本传入 Bash 算术运算，就可能执行其中的命令替换。[提权指南](../linux-basics/linux-privilege-escalation/README.md#bash-arithmetic-expansion-injection-in-cron-log-parsers)给出了完整示例。在认定每个算术表达式都可利用之前，请确认输入来源和解析命令。

对于解析应用日志的特权任务，要追踪不可信字段第一次解析之后的流向。低权限账户可能通过当前进程组写入日志，或影响记录的请求字段；之后某条记录可能会选定图像，而图像元数据又会变成用于打开 XML 的第二个路径名。请检查任务的有效身份、实际日志写入权限、分隔符处理、规范路径包含性检查，以及所选 XML 是否由攻击者控制。如果实体扩展的结果会进入低权限用户可读的输出，外部实体扩展就可能导致特权文件泄露。[Java XML 处理安全指南](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html)介绍了外部 DTD/实体访问的控制措施；请检查已安装的解析器及其有效设置。可写日志或 XML 文件本身都只是线索。枚举时请审查代码和元数据，不要向定时解析器输入数据。

还要检查将其他用户 Git 仓库中的文件写入磁盘的特权任务。脚本可能会使用 `git ls-tree` 和 `git cat-file`，而不是 `git checkout`，但如果它将攻击者控制的 tree 路径拼接到暂存目录路径中，仍会信任这些路径。除非目标路径在写入前经过规范化并进行包含性检查，否则绝对路径和 `..` 组件可能逃出该目录。`git -c safe.directory=*` 允许访问所有者不同的仓库；但它本身不会造成任意文件写入。

root 运行的数据库备份也可能形成所有权边界。PostgreSQL [`pg_basebackup`](https://www.postgresql.org/docs/14/app-pgbasebackup.html) 会复制源数据目录中额外放置的常规文件，其默认 plain 格式会将文件作为目录树写入 `-D`。如果低权限账户能创建或修改这些源文件，请检查生成的目标文件所有权和模式、目标路径是否可遍历和可执行，以及挂载是否设置了 `nosuid`。保留了 set-ID 权限的 root 所有副本可能很危险；仅进行 tar 备份、剥除权限或目标路径不可访问，都不会形成相同路径。将备份命令视为安全发现之前，请追踪包装程序和有效用户。

## 观察短时任务

单次进程快照可能会漏掉只运行几毫秒的任务。请将 timer/cron 声明与日志进行比对，并在获得授权时使用 `pspy` 或 audit 等进程事件监控工具。关联调度所有者、确切命令行，以及任务读取或写入的文件。loopback 调度器 Web UI 是另一个独立接口；请参见 [Crontab UI 示例](../linux-basics/linux-privilege-escalation/README.md#crontab-ui-alseambusher-running-as-root--web-based-scheduler-privesc)。
{{#include ../../banners/hacktricks-training.md}}
