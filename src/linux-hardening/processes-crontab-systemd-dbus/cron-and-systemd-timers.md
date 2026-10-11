# Cron 任务与 Systemd 定时器

{{#include ../../banners/hacktricks-training.md}}

计划任务可以使用与当前 shell 不同的身份和环境运行。枚举 cron、`at`、anacron 和 systemd 定时器，然后沿着每条计划命令追踪其脚本、导入项、工作目录和可写输入。

## 枚举计划任务

```bash
crontab -l 2>/dev/null
ls -la /etc/crontab /etc/cron.* /var/spool/cron* 2>/dev/null
atq 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

系统 crontab 通常包含用户字段；用户的 crontab 则没有。检查实际调度程序生效的 PATH 和环境变量。`run-parts --test /etc/cron.daily` 会显示该主机上会被选中的文件名。控制字符可能会在常规输出中隐藏条目，因此如果某个计划看起来可疑，请使用 `cat -A` 或 `sed -n l`。

## 跟踪特权文件和命令的解析过程

```bash
systemctl cat <name>.timer <name>.service
systemctl show <name>.service -p User -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/to/scheduled/script
```

检查可写的脚本链、`EnvironmentFile=` 路径、drop-in 文件、符号链接、相对命令、通配符展开，以及由特权任务复制或执行的二进制文件。Timer 可以通过 `Unit=` 设置激活名称不同的 service。[PATH](../linux-basics/linux-environment-variables.md#path)、[wildcard](../interesting-files-permissions/wildcards-spare-tricks.md) 和 [file-link](../main-system-information/filesystem-links-and-file-descriptors.md) 页面介绍了主要原语。

对于定时以 root 身份运行的 `chkrootkit` 脚本，检查已安装源码中旧版 [slapper-loop quoting defect (CVE-2014-0476)](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2014-0476)：在检查 `SLAPPER_FILES` 临时路径后，未加引号的 `file_port=$file_port $i` 可能执行该文件。确认实际脚本或供应商补丁、root 调度配置、低权限用户对确切临时路径的写入权限、该路径是否可执行，以及挂载策略。仅凭版本字符串或系统中存在 `chkrootkit`，无法证明这条路径成立；被动审查期间不要创建或运行临时文件。

如果 Timer 的 root service 运行 `systemctl restart <other>.service`，还要继续追踪一跳 unit：被重启的 unit 可能调用 shell，并运行低权限用户可写的脚本。确认生效的 `User=`、`DynamicUser=`、`RootDirectory=`/`RootImage=`、确切的 `ExecStart=` 参数，以及脚本和其父路径的权限。可写脚本只是候选条件，只有 Timer 和被重启的 service 在该执行上下文中处于活动状态时，路径才可能成立；检查 unit 属性时不要重启任何 service。

如果高权限任务按主机名获取脚本，并将响应传给 shell，除了远程脚本，还要检查谁控制该主机名的解析。可写的 `/etc/hosts` 文件（包括通过组权限或 ACL 获得的访问权限）可能重定向任务在本地解析的名称；只有实际的定时命令会执行该响应，且任务使用了受影响的解析路径时，`curl` 响应才会构成跨用户执行路径。确认任务的运行身份、确切 URL 和 shell pipeline、生效的代理/DNS 行为，以及文件和父目录权限。仅发现 hosts 文件可写，只是审查线索，不能证明存在特权使用者。枚举期间只检查调度配置和元数据，不要更改映射或获取脚本。

即使下载的内容不会被直接执行，特权定时 `wget` 获取文件也构成单独的文件写入边界。[GNU Wget 1.18 更改了 HTTP 到 FTP 重定向时的默认文件名处理方式，以修复 CVE-2016-4971](https://lists.gnu.org/archive/html/info-gnu/2016-06/msg00004.html)；较旧的受影响构建可能使用重定向后的 FTP 文件名，而 `--trust-server-names` 会显式请求此行为。如果低信任方控制 HTTP 响应和 FTP 资源，请检查任务是否跟随该重定向、实际 Wget 构建或供应商回补、输出选项、运行身份、工作目录，以及目标文件名是否可能成为启动文件。[Wget 会加载 `WGETRC` 或 `$HOME/.wgetrc`](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Location.html)，且[其设置可以指定 POST 来源或输出路径](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html)；后续的特权获取是可能发生信息泄露或写入的另一个必要条件。只有当调用方能实际提供任务请求的 URL 时，通过 `authbind` 访问低端口才相关。被动检查配置和日志，不要提供重定向或运行任务。[通过 `disk` 组访问原始块设备](../user-information/interesting-groups-linux-pe/README.md#disk-group)与此网络获取路径无关。

脚本之外，也要追踪数据文件。定时运行的模拟或编排工具可能会读取定义待启动进程的 YAML 文件；如果低权限用户能编辑该文件，且任务以另一个账户身份运行其中的内容，这些数据就可能变成以任务身份执行的命令。确认确切的定时命令、生效用户、文件路径、解析器语义，以及写入权限（包括父目录权限），再判断可写 YAML 文件是否构成执行路径。被动初筛只需读取调度配置和文件元数据；枚举期间不要运行任务或修改其输入。

当高权限任务使用 `ssh -F`，加载低权限用户可替换的文件时，SSH 客户端配置也属于可执行输入。OpenSSH 的 [`ProxyCommand`](https://man.openbsd.org/ssh_config#ProxyCommand) 会通过客户端 shell 运行本地命令，而 `Host`/`Match` 和前序选项会决定该指令是否适用。将确切的定时 SSH 调用、运行身份、选定的配置路径、目录和文件写入权限，以及生效的选项顺序进行关联，再判断这是否构成跨用户执行路径。审查这些记录时，不要运行任务，也不要以特权账户加载不受信任的配置。

定时 `scp` 后再通过 `ssh` 运行复制过去的脚本时，如果低权限用户控制目标 SSH 服务，还需要额外审查信任边界。若该服务能将连接转发到另一台主机，特权客户端可能会向意外端点进行身份验证；[`StrictHostKeyChecking no`](https://man.openbsd.org/ssh_config#StrictHostKeyChecking) 会削弱对主机密钥变更的保护，但仍受 OpenSSH 其余限制和生效的每主机选项约束。确认任务的运行身份、实际目标和认证方式、远程命令的生效身份，以及重定向后的主机上同一目标路径是否可写或已存在。要执行旧文件或攻击者控制的文件，还需要复制失败或未覆盖该路径，**并且**包装脚本继续执行 SSH 命令；[Bash `errexit`](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html) 和显式状态处理会影响这一流程。主机密钥设置较弱、能看到 `sshpass` 进程或存在可写临时目录，都不足以证明这条链成立。枚举期间检查调度配置、脚本、SSH 配置和文件元数据，不要重定向服务或触发任务。

特权应用调度器可能从数据库记录读取任务，而不是从可写文件读取。例如，调用 Laravel [`php artisan schedule:run`](https://laravel.com/docs/9.x/scheduling#running-the-scheduler) 的 root cron 条目，可能执行会读取任务记录的应用代码。如果低权限账户能写入一条包含本地路径的记录，且定时回调在 root 下调用 PHP 的 [`file_get_contents`](https://www.php.net/manual/en/function.file-get-contents.php) 读取该路径，并将返回内容发送到记录指定的 webhook，就会形成特权文件泄露路径。确认 cron 身份、实际调度回调及记录到路径的数据流、数据库写入授权、读取记录后的校验，以及出站目标。能读取应用 `.env` 文件只能提供凭据线索；表单校验或数据库密码本身不能证明记录可被控制或数据会泄露。枚举期间只被动检查调度配置、代码和凭据文件权限，不要查询数据库或安排任务。

事件驱动的 `incron` 任务也需要同样审查：[incrontab 条目](https://manpages.debian.org/testing/incron/incrontab.5.en.html)将监视路径和事件关联到以表所有者身份运行的命令。如果应用会跟随可写目录中的链接，并将攻击者控制的文本写入被监视的目标，低权限用户就可能间接影响该文件。确认实际表所有者、事件、目标及其祖先目录的权限、应用跟随链接的行为，以及文本如何变成命令参数。特别是，[GNU Mailutils `mail` 接受 `--exec`](https://mailutils.org/manual/html_node/Invoking-Mail.html)，其 [shell-escape 命令](https://mailutils.org/manual/html_node/Shell-Escapes.html)可以运行程序；如果该实现将不受信任字段作为独立选项传入，就可能跨越到命令执行。其他 `mail` 实现或带引号且参数边界固定的调用方式可能表现不同。枚举期间检查调度配置、应用代码和文件元数据，不要修改被监视文件或触发任务。

被监视的日志也可能通过辅助脚本跨越用户边界。如果低权限账户能写入日志，而 `incron` 所有者会从日志中读取字段并将其放入新的 [`sh -c` 命令字符串](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)，shell 就会以该所有者身份再次解析该字段。检查确切的监视事件、日志和父目录权限、辅助脚本路径、日志字段的转换方式，以及后续命令是否会执行。仅发现日志可写且存在 `incron` 条目，不能证明数据流成立；被动枚举期间不要写入触发内容或运行辅助脚本。

证书续期任务也可能跨越相同边界。特权辅助程序可能从低权限用户可写目录中的证书读取 X.509 subject，并将其 common name 插入新的 `bash -c` 命令字符串。[OpenSSL 可以显示证书的 subject 并检查其到期时间](https://docs.openssl.org/3.3/man1/openssl-x509/)；[`bash -c` 会将命令字符串作为 shell 输入解析](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)，因此在外层脚本中给变量加引号并不能防止第二次解析。确认调度身份、确切输入路径及其写入权限、续期分支，以及数据流入 `bash -c` 的方式，再判断是否构成命令注入。被动检查脚本和证书元数据；枚举期间不要触发续期。

当特权定时任务从低权限用户的归档或软件包中提取名称，并通过 `xargs -I` 将其插入 `sh -c` 命令字符串时，也可能发生相同的二次解析。[GNU `xargs -I` 会在初始参数中替换占位符](https://www.gnu.org/software/findutils/manual/html_node/find_html/xargs-options.html)，而 [`sh -c` 会解释其命令字符串](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)。即使外层脚本给提取出的名称加了引号，也不能保证之后替换得到的 shell 程序是安全的。确认任务的运行身份、确切的输入路径及其写入权限、归档校验和分支条件，以及名称到 shell 的数据流。可写上传目录或 `xargs` 调用本身只是线索；枚举期间检查调度配置、脚本和路径元数据，不要提交软件包或运行任务。

定时字体或图像导入器也可能信任调用方提供的归档内部名称，即使上传文件的外部文件名受到限制。FontForge 在其 [CVE-2024-25081 和 CVE-2024-25082 上游修复中](https://github.com/fontforge/fontforge/pull/5367)修复了归档成员名称导致的命令注入。确认高权限任务确实会打开低权限用户可写路径中的归档、任务运行身份、确切的 FontForge 构建或供应商回补，以及归档处理代码路径。版本字符串或允许的上传后缀本身不能证明代码会执行。枚举期间检查调度配置、路径权限和构建元数据，不要导入不受信任的归档。

定时网络扫描器可能通过另一种边界：自定义脚本将远程 TLS 证书 subject 当作本地文件名。[Nmap NSE 运行选定脚本时没有沙箱](https://nmap.org/book/nse-usage.html)，因此要检查实际脚本是否会将不受信任的 subject 字段与数据目录拼接，且缺少路径包含性检查。文件泄露需要满足以下条件：调度器会扫描目标、解析后的路径指向扫描器运行身份可读的文件，以及报告或日志会发送给低权限用户。证书字段或已安装扫描器本身不能证明这条链成立；被动枚举期间检查调度配置、脚本、路径解析和报告目标，不要扫描新目标。

即使所有现有 playbook 都是只读的，特权 cron 命令若将 shell 通配符（如 `/path/to/tasks/*.yml`）传给 Ansible runner，也应检查目录权限。对通配符匹配目录具有写入和搜索权限的用户，可能可以创建另一个匹配的 playbook。[Ansible playbook 定义了由 runner 执行的任务](https://docs.ansible.com/projects/ansible/latest/cli/ansible-playbook.html)，但自定义包装脚本可能会筛选路径或使用不同身份：在判断该目录是否构成执行路径之前，先确认包装脚本的行为、实际 cron 用户、shell 展开、ACL、sticky bit 和挂载策略。静态检查元数据和包装脚本；枚举期间不要运行定时任务。

特权 cron 包装脚本可能先展开通配符，再将上传目录中的文件名传给 Perl 辅助程序。Perl 的 [`<>` diamond operator 使用双参数 `open`](https://perldoc.perl.org/perlop#The-Null-Filehandle)，因此匹配到的文件名若被解释为管道命令，可能会以辅助程序的身份执行；[`<<>>` 会将参数视为字面文件名](https://perldoc.perl.org/perlop#The-Null-Filehandle)。确认调度器身份、包装脚本的工作目录和通配符、辅助程序实际处理 `@ARGV` 的方式、文件名限制，以及低权限身份能否通过文件系统权限或已认证的上传服务放置匹配名称。单凭 cron 条目、Perl 脚本或可写 FTP 目录，不能证明完整链条。枚举期间检查源码和元数据，不要提交特制文件名或运行任务。

只读 cron 脚本仍可能被替换：如果计划任务按路径运行脚本，而低权限用户能写入并遍历其非 sticky 父目录，就可能替换脚本。检查调度配置中的运行身份、路径中的每个组成部分、目录 sticky bit、ACL 和挂载策略；只审查元数据，不要移动文件或运行任务。

特权 PHP cron 包装脚本还可能调用一个尚不存在的辅助程序。如果它使用 PHP [`exec()`](https://www.php.net/manual/en/function.exec.php) 调用固定的绝对辅助程序路径，而低权限用户能在其父目录中创建该名称，就可能控制后续运行时执行的内容。确认 cron 条目确实以高权限身份运行该包装脚本、确切命令字符串和 PHP 执行策略、辅助程序目录的写入和搜索权限、符号链接与 sticky bit 行为，以及辅助程序路径是否仍不存在。可写目录或缺失的辅助程序本身只是线索；枚举期间检查调度配置、源码和路径元数据，不要创建辅助程序或触发任务。

定时任务也可能使用 `find` 发现输入脚本，并将每个脚本传给解释器。例如，[gnuplot 的 `system()` 函数会调用 shell](https://gnuplot.sourceforge.net/docs_6.0/gnuplot.pdf)，因此，如果特权任务在低权限用户可写的目录中对每个 `*.plt` 文件运行 `gnuplot`，就可能以任务身份执行命令。[目录的读取权限控制能否列出内容，而写入和搜索（`x`）权限控制能否创建和访问已知名称](https://www.gnu.org/software/coreutils/manual/html_node/Mode-Structure.html)；即使 `ls` 无法列出目录，也要检查写入和搜索权限。关联确切的调度身份和命令、解释器行为、所选文件模式以及目录权限；可写目录或已安装解释器本身不能证明提权路径成立。私有调度配置和短时运行的任务可能需要经授权的事件监控，因为单次进程快照可能会漏掉它们。

对于特权 PHP 任务，也要检查可执行脚本链中的字面 `include`/`require` 语句。[PHP 会执行被包含的文件](https://www.php.net/manual/en/function.include.php)，因此，即使主脚本是只读的，组可写的 `.php` 文件也可能以任务身份运行代码。确认调度身份、生效的 include-path 解析结果、文件和目录权限，以及任务是否实际运行；注释中的 cron 示例行只能作为线索。以 `-S` 和 `-t <document-root>` 启动的 root 所有 [PHP 内置服务器](https://www.php.net/commandline.webserver)也适用相同审查：即使只监听 loopback，本地请求仍可能执行应用 PHP。枚举期间检查进程和源码，不要触发任一入口。

特权 PHP 任务还可能通过**数据文件**跨越边界：如果低权限用户能更改传给 [`unserialize()`](https://www.php.net/manual/en/function.unserialize.php) 的确切文件，PHP 可能会在还原对象时调用已加载类的 `__wakeup()` 或 `__unserialize()` 方法。检查任务的生效身份、文件和祖先目录权限、已加载的类，以及方法的实际副作用（例如由属性选择的文件写入）。可写日志或调用 `unserialize()` 本身不能证明存在可利用路径。枚举期间检查源码和元数据，不要写入序列化输入或运行任务。

root cron 任务可能调用 PHP 应用的**CLI 页面运行器**，而不是 Web 服务器。追踪运行器选定的 document root 和 URI，找到实际 PHP 入口文件；如果 Web 服务账户可写该入口文件，即使运行器和 cron 包装脚本是只读的，定时 CLI 请求仍可能以 root 身份执行被更改的代码。确认调度身份、确切的 URI 到文件解析方式、生效的文件和祖先目录权限，以及完整性检查是否保护该入口文件。枚举期间检查源码和元数据，不要调用运行器或更改页面。

如果 `ipython` 由定时任务或其他用户从共享工作目录启动，应检查启动文件。[IPython 安全发布说明](https://ipython.readthedocs.io/en/8.25.0/whatsnew/version8.html#ipython-8-0-1-cve-2022-21699)指出，CVE-2022-21699 修复前，受影响的构建会在当前目录中搜索 profile 和配置，包括 `profile_default/startup` 代码。关联实际安装的构建或供应商补丁、命令工作目录、高权限进程身份，以及低权限用户对确切启动路径的写入和搜索权限。仅仅安装了 `ipython`、存在可写目录或看到版本字符串，都不能证明另一个身份会从该路径加载文件。检查调度配置和路径元数据，不要启动高权限解释器。

对于调用自定义原生扩展函数的特权 PHP 服务器，检查扩展前先追踪 service 的 PHP SAPI、生效的 `php.ini` 和扫描加载的 `.ini` 文件。[PHP 会在启动时加载配置的 `extension` 库](https://www.php.net/manual/en/ini.core.php)，而 [CLI 和 Web SAPI 可能使用不同的配置文件](https://www.php.net/manual/en/configuration.file.php)。因此，可访问的登录表单或本地监听器可能会将用户控制的字符串传入以 service 身份运行的编译代码。记录 unit 的 `User=`、`ExecStart=`、工作目录、实际扩展路径和调用方可控参数；仅存在 `.so` 或 loopback socket，不能证明存在内存破坏漏洞。被动枚举期间应单独分析任何自定义解析器，不要发送探测内容。

如果特权包装脚本先按路径对脚本进行哈希，之后又按该路径重新打开并执行，那么摘要只验证第一次打开时读取的对象。如果低权限用户能在两次打开之间替换脚本的目录项，即使原脚本文件属于 root，之后的执行也可能解析到不同对象。FIFO 可以延长检查阶段，但这条路径取决于可替换的父目录权限、是否确实发生了两次独立打开、调度器身份、sticky bit 和挂载规则，以及时序。将包装脚本和 `namei -l` 输出作为被动线索检查；校验和匹配本身不能证明后续按路径打开受到保护。

特权备份任务即使不执行攻击者提供的命令，也可能**泄露**数据。追踪低权限用户能否创建任务读取的控制文件，任务随后是否会打开 `/etc/shadow` 等受保护源文件，以及结果是否会发送到攻击者指定的 URL 或可读输出位置。确认这三个环节后，才能判断是否存在泄露路径。同一脚本中的固定 shell 命令本身不会使控制文件成为 shell 注入输入。枚举期间检查脚本和文件权限，不要运行任务或放置控制文件。

如果特权定时任务运行 `curl -K FILE` 或 `curl --config FILE`，[curl 会将该文件中的选项视为命令行参数](https://curl.se/docs/manpage.html)。如果低权限用户能在 curl 读取该文件时控制它，就可能影响请求的 URL、本地文件输入或输出路径。确认任务的生效身份、文件和祖先目录的写入权限、其他任务替换该文件的时机，以及配置选项与固定命令行选项的交互方式，然后再判断是否会读取或写入受保护对象。配置路径可写或能看到 `-K` 标志本身，不能证明所选选项会生效；被动枚举期间检查调度配置和元数据，不要运行任务或获取 URL。

如果 cron 条目调用辅助脚本，也要检查辅助脚本的工作目录和归档命令。对其他用户可写目录使用未加引号的通配符，可能会让文件名被解释为归档器选项；GNU tar 的 checkpoint 操作就是一个例子。在判断是否存在跨用户命令路径之前，确认计划任务的运行身份、可写输入目录、确切的归档器和选项，以及是否使用 `--` 结束选项解析。参见 [wildcard and tar behavior](../interesting-files-permissions/wildcards-spare-tricks.md)。

如果特权辅助程序运行 `cd INPUT_DIR; tar ... *`，却不检查 `cd` 是否成功，还可能导致另一种备份文件泄露。如果低权限用户能删除或替换 `INPUT_DIR`，`cd` 失败后 shell 可能仍留在先前的目录中，后续归档命令就可能读取那里内容。确认任务的初始工作目录、确实可触发的 `cd` 失败路径、脚本是否退出或使用 `&&`、确切的归档器选项，以及低权限用户能否读取输出归档。可写输入目录或可读归档本身都只是线索；检查辅助脚本和路径权限，不要更改正在运行的任务。

定时可执行文件可能只是隐藏了 shell 脚本，并未消除其信任边界：[SHc](https://github.com/neurobin/shc) 会将加密脚本内容封装在原生二进制中，并在运行时通过 shell 执行。`.sh.x` 后缀或不透明的 ELF 文件只能作为审查线索。要评估文件名选项注入，先确认特权调度器身份、辅助程序的实际工作目录和命令、低权限用户能否在那里创建匹配名称，以及未加引号的通配符是否会传给 `rsync` 等命令，且命令前没有选项边界。只有确实使用该命令路径时，[`rsync` remote-shell 选项](../interesting-files-permissions/wildcards-spare-tricks.md#rsync)才相关。`/proc` 可见性受限或静态解密失败，意味着命令仍未知；不要仅为判断其内容而运行特权辅助程序。

进程命令行文本也可能是特权辅助程序的不受信任输入。低权限用户可以选择匹配 `pgrep -f` 的进程标题或 `argv[0]`；名称匹配并不能验证可执行文件或其所有者。如果 root 运行的脚本捕获该文本、将部分内容改写为 `apache2ctl`/`httpd`，然后不使用固定参数数组直接执行，攻击者选择的选项就可能指定不同的配置目录或错误日志。Apache 配置解析可能加载模块或调用已配置的辅助程序，因此枚举期间不要以 root 身份验证不受信任的配置。检查调度器所有者、确切的辅助程序、进程身份，以及数据到参数的流向；除非另行证明 shell 元字符会执行，否则这属于选项/配置注入。

将不受信任的文本传入 Bash 算术运算的 root 解析器，可能会执行文本中的命令替换。[权限提升指南](../linux-basics/linux-privilege-escalation/README.md#bash-arithmetic-expansion-injection-in-cron-log-parsers)提供了一个完整示例。在认定每个算术表达式都可利用之前，先确认输入来源和解析命令。

对于解析应用日志的特权任务，要追踪不受信任字段在首次解析后的流向。低权限账户可能通过当前进程组写入日志，或影响记录的请求字段；记录可能会选择一张图像，而图像元数据又成为用于打开 XML 的第二个路径。检查任务的生效身份、实际日志写入权限、分隔符处理、规范化路径包含性检查，以及所选 XML 是否由攻击者控制。如果外部实体展开的结果会进入低权限用户可读的输出，就可能通过第二次读取泄露特权文件。[Java XML processing security guide](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html)介绍了限制外部 DTD/实体访问的控制措施；检查已安装的解析器及其生效设置。日志或 XML 文件可写本身只是线索。枚举期间检查代码和元数据，不要向定时解析器提供输入。

还要检查特权任务如何从其他用户的 Git 仓库生成文件。脚本可能使用 `git ls-tree` 和 `git cat-file`，而不是 `git checkout`，但如果它将攻击者控制的树路径与暂存目录拼接，仍可能信任这些路径。除非写入前对目标路径进行规范化并检查其包含关系，否则绝对路径和 `..` 组件可能逃出该目录。`git -c safe.directory=*` 允许访问所有权不同的仓库；它本身不会造成任意文件写入。

以 root 身份运行的数据库备份还可能形成另一条所有权边界。PostgreSQL [`pg_basebackup`](https://www.postgresql.org/docs/14/app-pgbasebackup.html) 会复制源数据目录中的其他普通文件，其默认 plain 格式会将文件作为目录树写入 `-D`。如果低权限账户能在源目录中创建或修改这些文件，请检查生成的目标文件所有权和模式、目标路径是否可遍历和可执行，以及挂载是否设置了 `nosuid`。保留了 set-ID 权限的 root 所有副本可能造成危险；仅生成 tar 备份、权限被剥除或目标不可访问，则不能证明存在相同路径。认定备份命令构成问题前，要追踪包装脚本和生效用户。

## Observe short-lived work

单次进程快照可能会漏掉只运行几毫秒的任务。将 Timer/cron 声明与日志进行比较，并在获得授权时使用 `pspy` 或 audit 等进程事件监控手段。关联计划任务所有者、确切命令行，以及任务读取或写入的文件。监听 loopback 的调度器 Web UI 属于独立接口；参见 [Crontab UI example](../linux-basics/linux-privilege-escalation/README.md#crontab-ui-alseambusher-running-as-root--web-based-scheduler-privesc)。
{{#include ../../banners/hacktricks-training.md}}
