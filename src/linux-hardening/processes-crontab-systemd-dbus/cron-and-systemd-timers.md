# Cron 任务与 systemd 定时器

{{#include ../../banners/hacktricks-training.md}}

计划任务可以使用与当前 shell 不同的身份和环境运行。枚举 cron、`at`、anacron 和 systemd 定时器，然后逐一追踪每条计划命令涉及的脚本、导入项、工作目录和可写输入。

## 枚举计划任务

```bash
crontab -l 2>/dev/null
ls -la /etc/crontab /etc/cron.* /var/spool/cron* 2>/dev/null
atq 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

System crontab 通常包含用户字段；用户的 crontab 则没有。检查实际调度器生效的 PATH 和环境变量。`run-parts --test /etc/cron.daily` 会显示该主机上会被选中的文件名。控制字符可能会在普通输出中隐藏条目，因此如果某个计划任务看起来可疑，请使用 `cat -A` 或 `sed -n l`。

## 追踪特权文件和命令的解析方式

```bash
systemctl cat <name>.timer <name>.service
systemctl show <name>.service -p User -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/to/scheduled/script
```

检查可写脚本链、`EnvironmentFile=` 路径、drop-in、符号链接、相对命令、通配符展开，以及由特权任务复制或执行的二进制文件。Timer 可以通过 `Unit=` 设置激活名称不同的 service。[PATH](../linux-basics/linux-environment-variables.md#path)、[wildcard](../interesting-files-permissions/wildcards-spare-tricks.md) 和 [file-link](../main-system-information/filesystem-links-and-file-descriptors.md) 页面介绍了主要原语。

对于定时以 root 身份运行的 `chkrootkit` 脚本，应检查已安装源码中是否存在旧版 [slapper-loop quoting defect (CVE-2014-0476)](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2014-0476)：检查 `SLAPPER_FILES` 临时路径后，未加引号的 `file_port=$file_port $i` 可能执行该文件。核实实际脚本或厂商补丁、root 调度、低权限用户对该确切临时路径的写入权限、文件是否可执行，以及挂载策略。仅凭版本字符串或系统中存在 `chkrootkit`，无法确认这条路径；被动审查期间不要创建或运行临时文件。

如果 timer 的 root service 运行 `systemctl restart <other>.service`，还要追踪额外一跳：被重启的 unit 可能会调用一个 shell，而该 shell 使用低权限用户可写的脚本。确认生效的 `User=`、`DynamicUser=`、`RootDirectory=`/`RootImage=`、确切的 `ExecStart=` 参数，以及脚本和其父路径的权限。只有在 timer 和被重启的 service 都处于该执行上下文并已激活时，可写脚本才是候选路径；检查 unit 属性时不要重启任何一个 service。

如果高权限任务按主机名获取脚本，并将响应传给 shell，除了远程脚本，还要检查谁能控制该主机名的解析。可写的 `/etc/hosts` 文件（包括通过组权限或 ACL 获得的访问权限）可以重定向任务在本地解析的名称；只有当实际计划命令会运行该响应，且任务使用受影响的解析路径时，`curl` 响应才会构成跨用户执行路径。核实任务的运行身份、确切 URL 和 shell pipeline、生效的代理/DNS 行为，以及文件和父目录权限。单独存在可写 hosts 文件只是审查线索，并不能证明有特权消费者。枚举时只检查调度信息和元数据，不要更改映射或获取脚本。

即使下载内容不会被直接执行，特权计划任务中的 `wget` 获取操作仍然是一个独立的文件写入边界。[GNU Wget 1.18 修改了 HTTP 到 FTP 重定向的默认文件名处理方式，以修复 CVE-2016-4971](https://lists.gnu.org/archive/html/info-gnu/2016-06/msg00004.html)；较旧的受影响版本可能会使用重定向后的 FTP 文件名，而 `--trust-server-names` 会明确要求采用这种行为。如果低信任方能控制 HTTP 响应和 FTP 资源，应检查任务是否跟随该重定向、实际 Wget 构建版本或厂商回移补丁、输出选项、运行身份、工作目录，以及目标文件名是否可能成为启动文件。[Wget 会加载 `WGETRC` 或 `$HOME/.wgetrc`](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Location.html)，而[其设置可以指定 POST 来源或输出路径](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html)；任何由此导致的泄露或写入，还需要后续特权获取操作作为独立前提。只有当调用者确实能提供任务所请求的 URL 时，通过 `authbind` 访问低端口才相关。被动检查配置和日志；不要提供重定向或运行任务。[通过 `disk` 组访问原始块设备](../user-information/interesting-groups-linux-pe/README.md#disk-group)与这条网络获取路径无关。

脚本之外，也要追踪数据文件。计划任务中的仿真或编排工具可能会读取定义待启动进程的 YAML 文件；如果低权限用户能编辑该文件，且任务以其他账户身份运行，那么其中的数据可能会在任务身份下变成命令。要认定可写 YAML 文件构成执行路径，必须核实确切的计划命令、生效用户、文件路径、解析器语义，以及写入权限（包括父目录）。被动初步排查只需读取调度信息和文件元数据；枚举时不要运行任务或修改其输入。

如果高权限任务通过 `ssh -F` 使用低权限用户可替换的配置文件，那么 SSH 客户端配置也是可执行输入。OpenSSH 的 [`ProxyCommand`](https://man.openbsd.org/ssh_config#ProxyCommand) 会通过客户端的 shell 运行本地命令，而 `Host`/`Match` 和较早出现的选项会决定该指令是否生效。在将其认定为跨用户执行路径之前，应对照确切的计划 SSH 调用、运行身份、所选配置路径、目录和文件写入权限，以及实际生效的选项顺序。检查这些记录时，不要运行任务，也不要以特权账户加载不可信配置。

计划任务先运行 `scp`，再通过 SSH 运行复制后的脚本时，如果低权限用户控制目标 SSH service，还需要进行第二次信任边界审查。如果该 service 能将连接转发到其他主机，特权客户端可能会向非预期端点进行认证；[`StrictHostKeyChecking no`](https://man.openbsd.org/ssh_config#StrictHostKeyChecking) 会削弱对主机密钥变更的防护，但仍受 OpenSSH 的其他限制和生效的逐主机选项约束。确认任务的运行身份、实际目标和认证方式、远程命令的生效身份，以及重定向后的主机上相同目标路径是否可写或已存在。若要执行旧文件或攻击者控制的文件，还需要复制失败或未命中该路径，**并且**包装脚本继续执行 SSH 命令；[Bash `errexit`](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html) 和显式状态处理会影响这一流程。弱主机密钥设置、可见的 `sshpass` 进程或可写临时目录，单独都不能证明这条链路。枚举时检查调度信息、脚本、SSH 配置和文件元数据；不要重定向 service 或触发任务。

特权应用调度器可能从数据库行而不是可写文件中读取任务。例如，root cron 条目调用 Laravel 的 [`php artisan schedule:run`](https://laravel.com/docs/9.x/scheduling#running-the-scheduler)，可能会执行读取任务行的应用代码。如果低权限账户能写入包含本地路径的行，而计划回调在 root 身份下调用 PHP 的 [`file_get_contents`](https://www.php.net/manual/en/function.file-get-contents.php)，并将读取的内容发送到由该行指定的 webhook，这就构成特权文件泄露路径。核实 cron 身份、实际调度回调及行到路径的数据流、数据库写入授权、读取该行后的验证，以及出站目标。应用的 `.env` 可读只是凭据线索；Web 表单验证或数据库密码本身不能证明攻击者能控制行或导致泄露。枚举时被动检查调度信息、代码和凭据文件权限；不要查询数据库或安排任务。

事件驱动的 `incron` 任务也应同样审查：[incrontab 条目](https://manpages.debian.org/testing/incron/incrontab.5.en.html)会将受监控路径和事件关联到以表所有者身份运行的命令。如果应用会跟随可写目录中的链接，并将攻击者控制的文本写入受监控目标，低权限用户可能间接影响受监控文件。核实实际表所有者、事件、目标和祖先目录权限、应用跟随链接的行为，以及文本如何变成命令参数。特别是，[GNU Mailutils `mail` 接受 `--exec`](https://mailutils.org/manual/html_node/Invoking-Mail.html)，其 [shell-escape 命令](https://mailutils.org/manual/html_node/Shell-Escapes.html)可以运行程序；传给该实现的独立选项形式的不可信字段可能导致命令执行。其他 `mail` 实现或带引号的固定参数边界可能有不同表现。枚举时检查调度信息、应用代码和文件元数据；不要修改受监控文件或触发任务。

受监控日志也可能通过辅助脚本跨越用户边界。如果低权限账户能写入日志，而 `incron` 所有者会从日志中读取字段并将其拼接到新的 [`sh -c` 命令字符串](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)，shell 就会以所有者身份再次解析该字段。检查确切的受监控事件、日志及父目录权限、辅助脚本路径、日志字段的转换方式，以及是否会执行到生成的命令。仅看到可写日志和 `incron` 条目并不能证明存在数据流；被动枚举期间不要写入触发内容或运行辅助脚本。

证书续期任务也可能跨越同样的边界。特权辅助程序可能从低权限用户可写目录中的证书读取 X.509 subject，并将其 common name 插入新的 `bash -c` 命令字符串。[OpenSSL 可以显示证书 subject 并检查其过期时间](https://docs.openssl.org/3.3/man1/openssl-x509/)；[Bash 会将 `-c` 字符串解析为 shell 输入](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)，因此在外层脚本中给变量加引号无法保护第二次解析。要认定为命令注入，须确认计划任务身份、确切输入路径及其写入权限、续期分支，以及数据流是否进入 `bash -c`。被动检查脚本和证书元数据；枚举时不要触发续期。

当特权计划任务从低权限用户的归档或软件包中提取名称，并通过 `xargs -I` 将其插入 `sh -c` 命令字符串时，也会发生同样的第二次解析。[GNU `xargs -I` 会在初始参数中替换占位符](https://www.gnu.org/software/findutils/manual/html_node/find_html/xargs-options.html)，而 [`sh -c` 会解释其命令字符串](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)。即使外层脚本给提取的名称加了引号，也不能保证之后替换生成的 shell 程序安全。核实任务运行身份、确切接受的输入路径及其写入权限、归档验证和分支条件，以及名称到 shell 的数据流。可写上传目录或 `xargs` 调用本身都只是线索；枚举时检查调度信息、脚本和路径元数据，不要提交软件包或运行任务。

计划任务中的字体或图像导入器也可能信任调用者提供的归档内部名称，即使上传文件的外部文件名受限也是如此。FontForge 已在修复 CVE-2024-25081 和 CVE-2024-25082 的[上游改动](https://github.com/fontforge/fontforge/pull/5367)中修复归档成员名称命令注入问题。确认高权限任务确实会打开低权限用户可写路径中的归档、任务运行身份、确切的 FontForge 构建版本或厂商回移补丁，以及归档处理代码路径。版本字符串或允许的上传后缀本身都不能证明会执行代码。枚举时检查调度信息、路径权限和构建元数据；不要导入不可信归档。

计划网络扫描器可能通过另一种方式跨越边界：自定义脚本将远程 TLS 证书 subject 当作本地文件名处理。[Nmap NSE 执行选定脚本时没有沙箱](https://nmap.org/book/nse-usage.html)，因此应检查实际脚本，以及它是否在缺少路径包含性检查的情况下将不可信 subject 字段拼接到数据目录路径中。要造成文件泄露，必须同时满足：调度器会扫描目标、解析后的路径指向扫描器运行身份可读的文件，并且扫描报告或日志会交付给低权限用户。证书字段或已安装的扫描器单独都不能证明存在这条链路；被动枚举时检查调度信息、脚本、路径解析和报告目的地，不要扫描新目标。

特权 cron 命令若将 `/path/to/tasks/*.yml` 这类 shell glob 传给 Ansible runner，即使现有 playbook 都是只读的，也应检查目录权限。对 glob 匹配目录具有写入和搜索权限的用户可能能够创建另一个匹配的 playbook。[Ansible playbook 定义了 runner 会执行的任务](https://docs.ansible.com/projects/ansible/latest/cli/ansible-playbook.html)，但自定义包装脚本可能会筛选路径或使用不同身份；在将该目录认定为执行路径之前，应核实包装脚本行为、实际 cron 用户、shell 展开、ACL、sticky bit 和挂载策略。静态检查元数据和包装脚本；枚举时不要运行计划任务。

特权 cron 包装脚本可能会展开 glob，再将上传目录中的文件名传给 Perl 辅助程序。Perl 的 [`<>` 菱形操作符使用双参数 `open`](https://perldoc.perl.org/perlop#The-Null-Filehandle)，因此，被解释为管道命令的匹配文件名可能会以辅助程序的身份执行；[`<<>>` 会将参数视为字面文件名](https://perldoc.perl.org/perlop#The-Null-Filehandle)。确认调度器身份、包装脚本的工作目录和 glob、辅助程序实际如何处理 `@ARGV`、文件名限制，以及低权限用户是否能通过文件系统权限或已认证的上传服务放置匹配名称。单独存在 cron 条目、Perl 脚本或可写 FTP 目录，都不能证明完整链路。枚举时检查源码和元数据；不要提交构造的文件名或运行任务。

如果计划账户按路径名运行只读 cron 脚本，而低权限用户能写入并遍历其位于非 sticky 父目录中的路径，那么该脚本仍可被替换。检查调度任务的运行身份、路径中的每一级目录、目录 sticky bit、ACL 和挂载策略；只检查元数据，不要移动文件或运行任务。

特权 PHP cron 包装脚本可能会调用一个尚不存在的辅助程序。如果它通过固定的绝对路径调用 PHP [`exec()`](https://www.php.net/manual/en/function.exec.php)，能在该路径的父目录中创建该名称的低权限用户，就可能控制后续运行时执行的内容。确认 cron 条目确实以高权限身份运行包装脚本、确切的命令字符串和 PHP 执行策略、辅助程序目录的写入及搜索权限、符号链接和 sticky bit 行为，以及辅助程序路径目前是否仍不存在。可写目录或缺失的辅助程序单独都只是线索；枚举时检查调度信息、源码和路径元数据，不要创建辅助程序或触发任务。

计划任务还可能通过 `find` 发现输入脚本，并将每个脚本传给解释器。例如，[gnuplot 的 `system()` 函数会调用 shell](https://gnuplot.sourceforge.net/docs_6.0/gnuplot.pdf)，因此，如果特权任务对低权限用户可写目录中的每个 `*.plt` 文件运行 `gnuplot`，就可能以任务身份执行命令。[目录读取权限控制列出目录内容的能力，而写入和搜索 (`x`) 权限控制创建和访问已知名称的能力](https://www.gnu.org/software/coreutils/manual/html_node/Mode-Structure.html)；即使 `ls` 无法列出目录，也要检查写入和搜索权限。结合确切的调度身份和命令、解释器行为、选定的文件模式及目录权限进行判断；可写目录或已安装的解释器单独都不能证明存在提权路径。私有调度任务和短时任务可能需要在获授权的情况下进行事件观察，因为单次进程快照可能会漏掉它们。

对于特权 PHP 任务，还应将字面 `include`/`require` 语句视为可执行脚本链的一部分。[PHP 会执行被包含的文件](https://www.php.net/manual/en/function.include.php)，因此，即使主脚本只读，组可写的被包含 `.php` 文件仍可能以任务身份运行代码。核实计划任务身份、生效的 include-path 解析、文件和目录权限，以及任务是否确实会运行；注释中的示例 cron 行只是线索。同样的审查也适用于以 `-S` 和 `-t <document-root>` 启动的 root-owned [PHP built-in server](https://www.php.net/commandline.webserver)：即使监听器只绑定 loopback，也仍可能会为本地请求执行应用 PHP。枚举时检查进程和源码，不要触发任一操作。

特权 PHP 任务也可能通过**数据文件**跨越边界：如果低权限用户能修改传给 [`unserialize()`](https://www.php.net/manual/en/function.unserialize.php) 的确切文件，PHP 在还原对象时可能会调用已加载类的 `__wakeup()` 或 `__unserialize()` 方法。检查任务的生效身份、文件及其祖先目录权限、已加载的类，以及方法的实际副作用（例如由属性选择的文件写入）。可写日志或调用 `unserialize()` 本身，都不能证明存在可用路径。枚举时检查源码和元数据；不要写入序列化输入或运行任务。

root cron 任务可能调用 PHP 应用的 **CLI page runner**，而不是 Web 服务器。追踪 runner 选定的 document root 和 URI，直到实际 PHP 入口文件；如果 Web service 账户可写该入口文件，那么计划中的 CLI 请求就可能以 root 身份执行被修改的代码，即使 runner 和 cron 包装脚本是只读的。核实调度任务身份、URI 到文件的确切解析方式、生效的文件及祖先目录权限，以及是否有完整性检查保护入口文件。枚举时检查源码和元数据；不要调用 runner 或修改页面。

对于计划任务或其他用户从共享工作目录启动的 `ipython` 进程，应检查启动文件。[IPython 安全发布说明](https://ipython.readthedocs.io/en/8.25.0/whatsnew/version8.html#ipython-8-0-1-cve-2022-21699)指出，修复 CVE-2022-21699 之前，受影响版本会从当前目录搜索配置文件和配置，包括 `profile_default/startup` 代码。结合实际安装版本或厂商补丁、命令工作目录、高权限进程身份，以及低权限用户对确切启动路径的写入和搜索权限进行检查。仅有已安装的 `ipython`、可写目录或版本字符串，都不能证明另一身份会在那里加载文件。枚举时检查调度信息和路径元数据；不要启动高权限解释器。

对于调用自定义 native extension 函数的特权 PHP server，在审查扩展前，应先追踪 service 使用的 PHP SAPI、生效的 `php.ini` 和扫描的 `.ini` 文件。[PHP 会在启动时加载已配置的 `extension` 库](https://www.php.net/manual/en/ini.core.php)，而 [CLI 和 Web SAPI 可能使用不同的配置文件](https://www.php.net/manual/en/configuration.file.php)。因此，可访问的登录表单或本地监听器可能会将用户可控字符串传入以 service 身份运行的编译代码。记录 unit 的 `User=`、`ExecStart=`、工作目录、实际扩展路径和调用方可控参数；单独存在 `.so` 或 loopback socket，不能证明存在内存破坏漏洞。被动枚举时应单独分析自定义解析器，不要发送探测数据。

如果特权包装脚本按路径名对脚本计算哈希，随后又通过该路径名打开并执行脚本，那么摘要只认证了第一次打开时读取的对象。如果低权限用户能在两次打开之间替换脚本目录项，即使原脚本文件属于 root，后续执行仍可能解析到不同对象。FIFO 可以延长检查阶段，但这条路径取决于可替换的父目录权限、实际发生的独立打开操作、调度任务身份、sticky bit 和挂载规则，以及时序。将包装脚本和 `namei -l` 输出作为被动线索检查；校验和成功本身不能证明后续路径名受到保护。

特权备份任务也可能**泄露**数据，而不执行攻击者提供的命令。追踪低权限用户是否能创建任务会读取的控制文件，任务是否随后打开 `/etc/shadow` 等受保护源文件，以及结果是否发送到攻击者选择的 URL 或低权限用户可读的输出。只有确认这三个环节，才能称为泄露路径。同一脚本中的固定 shell 命令本身，并不会使该控制文件成为 shell 注入输入。枚举时检查脚本和文件权限；不要运行任务或放置控制文件。

如果特权计划任务运行 `curl -K FILE` 或 `curl --config FILE`，[curl 会将该文件中的选项视为命令行参数](https://curl.se/docs/manpage.html)。如果低权限用户能在 curl 读取时控制该确切文件，就可能影响请求的 URL、本地文件输入或输出路径。要声称存在受保护文件读取或写入，必须确认任务的生效身份、文件及祖先目录的写入权限、其他任务替换该文件的时机，以及配置选项如何与固定命令行选项交互。可写配置路径或可见的 `-K` 标志单独都不能证明所选选项会生效；被动枚举时检查调度信息和元数据，不要运行任务或获取 URL。

如果 cron 条目调用辅助脚本，还要检查辅助脚本的工作目录和归档命令。对其他用户可写目录使用未加引号的通配符，可能会让文件名变成归档器选项；GNU tar 的 checkpoint action 就是一例。要认定为跨用户命令路径，须确认计划任务的运行身份、可写输入目录、确切的归档器和选项，以及是否使用 `--` 终止选项解析。参见 [wildcard and tar behavior](../interesting-files-permissions/wildcards-spare-tricks.md)。

如果特权辅助程序运行 `cd INPUT_DIR; tar ... *` 却不检查 `cd` 是否成功，还可能发生独立的备份文件泄露。如果低权限用户能删除或替换 `INPUT_DIR`，`cd` 失败可能会使 shell 留在先前的目录中，后续归档命令就可能读取该目录。核实任务的初始工作目录、实际的 `cd` 失败路径、脚本是否退出或使用 `&&`、确切的归档器选项，以及低权限用户是否能读取输出归档。可写输入目录或可读归档单独都只是线索；检查辅助脚本和路径权限，不要更改正在运行的任务。

计划任务中的可执行文件可能只是被包装起来的 shell 脚本，并不会因此消除信任边界：[SHc](https://github.com/neurobin/shc) 会将加密脚本文本包装进 native binary，并在运行时通过 shell 执行。`.sh.x` 后缀或不透明 ELF 只能作为审查线索。要评估文件名选项注入，必须确认特权调度器身份、辅助程序的实际工作目录和命令、低权限用户能否在那里创建匹配名称，以及未加引号的 glob 是否会传给缺少选项边界的 `rsync` 等命令。只有在使用了该确切命令路径时，[`rsync` remote-shell 选项](../interesting-files-permissions/wildcards-spare-tricks.md#rsync)才相关。若 `/proc` 可见性受限或静态解密失败，命令仍然未知；不要仅为判断而运行特权辅助程序。

进程命令行文本也可能是传给特权辅助程序的不可信输入。低权限用户可以选择能匹配 `pgrep -f` 的进程标题或 `argv[0]`；匹配的名称不能验证可执行文件或其所有者。如果 root 脚本捕获该文本，将其中一部分改写为 `apache2ctl`/`httpd`，并在没有使用固定参数数组的情况下执行生成的结果，攻击者选择的选项就可能指定不同的配置目录或错误日志。Apache 配置解析可能会加载模块或调用已配置的辅助程序，因此枚举时不要以 root 身份验证不可信配置。检查调度器所有者、确切辅助程序、进程身份，以及数据到参数的流向；除非另有证据证明 shell 元字符会被执行，否则这属于选项/配置注入。

将不可信文本传入 Bash 算术运算的 root 解析器可能会执行文本中的命令替换。[提权指南](../linux-basics/linux-privilege-escalation/README.md#bash-arithmetic-expansion-injection-in-cron-log-parsers)提供了完整示例。在认定所有算术表达式都可利用之前，应先确认输入来源和解析命令。

对于解析应用日志的特权任务，应追踪不可信字段的后续流向，而不只关注首次解析。低权限账户可能通过当前进程组写入日志，或影响被记录的请求字段；随后，某条记录可能选中一张图像，而其元数据又成为打开 XML 的第二个路径名。检查任务的生效身份、实际日志写入权限、分隔符处理、规范路径包含性检查，以及所选 XML 是否由攻击者控制。如果展开后的结果会写入低权限用户可读的输出，外部实体展开可能导致特权文件泄露。[Java XML 处理安全指南](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html)介绍了控制外部 DTD/实体访问的方法；检查已安装解析器及其生效设置。可写日志或 XML 文件单独都只是线索。枚举时审查代码和元数据；不要向计划解析器提供输入。

还要检查从其他用户的 Git repository 中提取文件的特权任务。脚本可能使用 `git ls-tree` 和 `git cat-file` 而非 `git checkout`，但在将攻击者控制的 tree 路径拼接到暂存目录时仍可能信任这些路径。除非对目标路径进行规范化并检查其是否仍在目标目录内，否则绝对路径和 `..` 组件可能逃出该目录。`git -c safe.directory=*` 允许访问由不同所有者持有的 repository；它本身不会造成任意文件写入。

root-run 数据库备份也可能形成所有权边界。PostgreSQL [`pg_basebackup`](https://www.postgresql.org/docs/14/app-pgbasebackup.html) 会复制源数据目录中的其他普通文件，而其默认 plain 格式会将文件以目录树形式写入 `-D`。如果低权限账户能在这些源文件中创建或修改内容，应检查生成文件的目标所有权和模式、路径是否可遍历和可执行，以及挂载是否设置了 `nosuid`。保留了 set-ID 权限的 root-owned 副本可能造成危险；仅生成 tar 的备份、权限被移除的副本或不可访问的目标，并不构成同一路径。将备份命令视为发现项之前，应追踪计划包装脚本和生效用户。

## Observe short-lived work

单次进程快照可能会漏掉只运行数毫秒的任务。将 timer/cron 声明与日志对照；在获授权的情况下，可使用 `pspy` 或 audit 等进程事件监控。关联计划任务所有者、确切命令行，以及任务读取或写入的文件。loopback scheduler Web UI 是另一个独立接口；参见 [Crontab UI example](../linux-basics/linux-privilege-escalation/README.md#crontab-ui-alseambusher-running-as-root--web-based-scheduler-privesc)。
{{#include ../../banners/hacktricks-training.md}}
