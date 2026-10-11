# Cron Jobs 和 Systemd 定时器

{{#include ../../banners/hacktricks-training.md}}

计划任务运行时使用的身份和环境可能与当前 shell 不同。枚举 cron、`at`、anacron 和 systemd 定时器，然后沿着每条计划命令追踪其脚本、导入项、工作目录和可写输入。

## 枚举计划任务

```bash
crontab -l 2>/dev/null
ls -la /etc/crontab /etc/cron.* /var/spool/cron* 2>/dev/null
atq 2>/dev/null
systemctl list-timers --all 2>/dev/null
```

系统 crontab 通常包含用户字段；用户的 crontab 则没有。检查实际调度器的有效 PATH 和环境。`run-parts --test /etc/cron.daily` 会显示该主机上会选中哪些文件名。控制字符可能会在普通输出中隐藏条目，因此当某个计划看起来可疑时，请使用 `cat -A` 或 `sed -n l`。

## 跟踪特权文件和命令的解析方式

```bash
systemctl cat <name>.timer <name>.service
systemctl show <name>.service -p User -p ExecStart -p EnvironmentFiles -p WorkingDirectory
namei -l /path/to/scheduled/script
```

检查可写的脚本链、`EnvironmentFile=` 路径、drop-in、symlink、相对命令、wildcard expansion，以及由特权任务复制或执行的 binaries。Timer 可能通过其 `Unit=` 设置激活一个名称不同的 service。[PATH](../linux-basics/linux-environment-variables.md#path)、[wildcard](../interesting-files-permissions/wildcards-spare-tricks.md) 和 [file-link](../main-system-information/filesystem-links-and-file-descriptors.md) 页面介绍了主要原语。

对于定时以 root 运行的 `chkrootkit` 脚本，检查已安装的源码，确认是否存在旧版 [slapper-loop quoting defect (CVE-2014-0476)](https://bugzilla.redhat.com/show_bug.cgi?id=CVE-2014-0476)：在检查 `SLAPPER_FILES` 临时路径后，未加引号的 `file_port=$file_port $i` 可能会执行该文件。验证实际脚本或供应商补丁、root 调度、低权限用户对该确切临时路径的写入权限、该路径的可执行状态，以及 mount policy。仅凭版本字符串或系统中存在 `chkrootkit`，无法证明这条路径成立；被动检查期间不要创建或运行临时文件。

如果定时运行的 root service 执行 `systemctl restart <other>.service`，还要继续追踪一个 unit hop：被重启的 unit 可能会调用一个 shell，并执行低权限用户可写的脚本。确认生效的 `User=`、`DynamicUser=`、`RootDirectory=`/`RootImage=`、确切的 `ExecStart=` 参数，以及脚本和其父路径的权限。可写脚本在 timer 和被重启的 service 确实处于该执行上下文中运行之前，只是一个候选线索；检查 unit 属性时不要重启任一 service。

如果高权限任务通过主机名获取脚本，并将响应传给 shell，除了远程脚本，还要检查谁能控制该主机名的解析。可写的 `/etc/hosts` 文件（包括通过 group 或 ACL 获得的访问权限）可能会重定向任务在本机解析的名称；只有实际调度的命令会运行 `curl` 响应，且任务使用受影响的 resolver 路径时，才构成跨用户执行路径。验证任务的 run-as identity、确切 URL 和 shell pipeline、生效的 proxy/DNS 行为，以及文件和父目录权限。仅有可写的 hosts 文件只是检查线索，并不能证明存在特权使用者。枚举期间应检查调度和 metadata，不要更改映射或获取脚本。

即使下载的内容不会被直接执行，特权计划任务中的 `wget` 获取操作仍然是一个独立的文件写入边界。[GNU Wget 1.18 changed the default HTTP-to-FTP redirect filename handling to fix CVE-2016-4971](https://lists.gnu.org/archive/html/info-gnu/2016-06/msg00004.html)；较早的受影响版本可能会采用重定向后的 FTP 文件名，而 `--trust-server-names` 会显式请求此行为。如果较低信任方能控制 HTTP 响应和 FTP 资源，应检查任务是否跟随该重定向、实际 Wget build 或供应商 backport、输出选项、run-as identity、工作目录，以及目标文件名是否可能成为 startup file。[Wget loads `WGETRC` or `$HOME/.wgetrc`](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Location.html)，且[其设置可指定 POST 来源或输出路径](https://www.gnu.org/software/wget/manual/html_node/Wgetrc-Commands.html)；之后是否有特权获取操作，是任何后续泄露或写入的独立前提。只有调用者确实能够提供任务请求的 URL 时，通过 `authbind` 访问低端口才相关。被动检查配置和日志，不要提供重定向服务或运行任务。[通过 `disk` group 访问原始块设备](../user-information/interesting-groups-linux-pe/README.md#disk-group)与这条网络获取路径无关。

数据文件和脚本都要追踪。计划运行的模拟或编排工具可能会读取定义待启动进程的 YAML 文件；如果低权限用户能编辑该文件，且任务以另一个账户运行它，那么这些数据可能会在任务的 identity 下变成命令。在将可写 YAML 文件视为执行路径之前，先验证确切的计划命令、生效用户、文件路径、解析器语义，以及写入权限（包括父目录）。被动分类只需读取调度信息和文件 metadata；枚举期间不要运行任务或修改其输入。

当高权限任务使用 `ssh -F` 运行低权限用户可替换的文件时，SSH client 配置也是可执行输入。OpenSSH 的 [`ProxyCommand`](https://man.openbsd.org/ssh_config#ProxyCommand) 会通过 client 的 shell 运行本地命令，而 `Host`/`Match` 和较早的选项会决定该指令是否生效。在将其认定为跨用户执行路径之前，应核对确切的计划 SSH 调用、run-as identity、选定的配置路径、目录和文件写入权限，以及有效的选项顺序。检查这些记录时，不要运行任务，也不要以特权账户加载不可信配置。

如果计划任务先运行 `scp`，再通过 `ssh` 运行复制的脚本，那么当低权限用户控制目标 SSH service 时，还需要审查第二个信任边界。如果该 service 能把连接转发到另一台主机，特权 client 可能会向非预期 endpoint 进行身份验证；[`StrictHostKeyChecking no`](https://man.openbsd.org/ssh_config#StrictHostKeyChecking) 会削弱对 host key 变更的保护，但仍受 OpenSSH 其他限制和生效的 per-host 选项影响。确认任务的 run-as identity、实际目标和认证方式、远程命令的生效 identity，以及被重定向主机上的同一目标路径是否可写或已存在。要执行旧文件或攻击者控制的文件，还要求复制失败或未覆盖该路径，**并且** wrapper 继续执行其 SSH 命令；[Bash `errexit`](https://www.gnu.org/software/bash/manual/html_node/The-Set-Builtin.html) 和显式状态处理都会影响这一流程。弱 host-key 设置、可见的 `sshpass` 进程或可写临时目录，单独来看都不能证明这条链路成立。枚举期间检查调度、脚本、SSH 配置和文件 metadata，不要重定向 service 或触发任务。

特权应用 scheduler 可能从 database rows 而不是可写文件中读取任务。例如，root cron entry 调用 Laravel 的 [`php artisan schedule:run`](https://laravel.com/docs/9.x/scheduling#running-the-scheduler)，可能会执行读取 task rows 的应用代码。如果低权限账户能写入包含本地路径的 row，且计划 callback 以 root 身份调用 PHP 的 [`file_get_contents`](https://www.php.net/manual/en/function.file-get-contents.php) 并将返回内容发送到由 row 指定的 webhook，这就构成特权文件泄露路径。验证 cron identity、实际 scheduler callback 和 row-to-path 数据流、database 写入授权、读取 row 后的验证，以及出站目标。可读的应用 `.env` 只能提示可能存在凭据；web form validation 或 database password 本身都不能证明 row 可控或存在泄露。被动检查调度、代码和 credential file 权限；枚举期间不要查询 database 或安排任务。

Event-driven `incron` job 也需要同样的检查：[incrontab entries](https://manpages.debian.org/testing/incron/incrontab.5.en.html) 将监视路径和事件关联到以 table owner identity 运行的命令。当应用跟随可写目录中的 link，并将攻击者控制的文本写入被监视的目标时，低权限用户可能间接影响被监视文件。验证实际 table owner、事件、目标及其祖先目录的权限、应用是否会跟随 link，以及文本如何变成命令参数。特别是，[GNU Mailutils `mail` accepts `--exec`](https://mailutils.org/manual/html_node/Invoking-Mail.html)，其 [shell-escape command](https://mailutils.org/manual/html_node/Shell-Escapes.html) 可以运行程序；传给该实现的独立选项中的不可信字段，可能导致命令执行。其他 `mail` 实现，或经过引用且边界固定的参数，行为可能不同。枚举期间检查调度、应用代码和文件 metadata，不要修改被监视文件或触发任务。

被监视的日志也可能通过 helper script 跨越用户边界。如果低权限账户能写入日志，而 `incron` owner 将日志中的某个字段读入新的 [`sh -c` command string](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)，shell 会在 owner 的 identity 下再次解析该字段。检查确切的被监视事件、日志和父目录权限、helper 路径、日志字段的转换方式，以及最终命令是否会执行。仅看到可写日志和 `incron` entry，并不能证明数据流成立；被动枚举期间不要写入触发记录或运行 helper。

证书续期任务也可能跨越同样的边界。特权 helper 可能会读取低权限用户可写目录中的证书所含 X.509 subject，并将其 common name 插入新的 `bash -c` command string。[OpenSSL can display a certificate's subject and check its expiry](https://docs.openssl.org/3.3/man1/openssl-x509/)；[Bash 会将 `-c` 字符串解析为 shell 输入](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)，因此在外层脚本中引用变量，并不能保护第二次解析。将其认定为 command injection 前，确认计划任务的 identity、确切输入路径及写入权限、续期分支，以及数据流是否进入 `bash -c`。被动检查脚本和证书 metadata；枚举期间不要触发续期。

当特权计划任务从低权限用户的 archive 或 package 中提取名称，并通过管道传给 `xargs -I`，将其插入 `sh -c` command string 时，也可能发生同样的二次解析。[GNU `xargs -I` 会在初始参数中替换占位符](https://www.gnu.org/software/findutils/manual/html_node/find_html/xargs-options.html)，而 [`sh -c` 会解释其 command string](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/sh.html)。即使外层脚本引用了提取出的名称，也无法保证后续替换出的 shell 程序是安全的。验证任务的 run-as identity、确切的受理输入路径及其写入权限、archive validation 和分支条件，以及名称到 shell 的数据流。可写上传目录或 `xargs` 调用本身都只是线索；枚举期间检查调度、脚本和路径 metadata，不要提交 package 或运行任务。

即使上传的外部文件名受到限制，计划运行的字体或图像导入器也可能信任用户提供的 archive *内部*名称。FontForge 已在其 [upstream change for CVE-2024-25081 and CVE-2024-25082](https://github.com/fontforge/fontforge/pull/5367) 中修复 archive 成员名称导致的 command injection。确认高权限任务是否确实会打开低权限用户可写路径中的 archive、任务的 run-as identity、确切的 FontForge build 或供应商 backport，以及 archive 处理代码路径。版本字符串或允许的上传后缀本身都不能证明会执行。枚举期间检查调度、路径权限和 build metadata，不要导入不可信 archive。

计划运行的网络扫描器在自定义脚本将远程 TLS certificate subject 当作本地文件名时，可能跨越另一种边界。[Nmap NSE runs selected scripts without a sandbox](https://nmap.org/book/nse-usage.html)，因此要检查实际脚本是否会将不可信 subject 字段拼接到数据目录路径中，且未进行 containment checks。要泄露文件，必须存在调度器会扫描的目标、一个可解析到扫描器 run-as identity 可读文件的路径，以及一个会将报告或日志交给低权限读取者的输出位置。certificate field 或已安装的扫描器本身都不能证明这条链路成立；被动枚举期间检查调度、脚本、路径解析和报告目标，不要扫描新目标。

即使所有现有 playbook 都是只读的，特权 cron 命令只要将 shell glob（例如 `/path/to/tasks/*.yml`）传给 Ansible runner，就值得检查目录权限。对 glob 匹配目录有写入和 search 权限的用户，可能能够创建另一个匹配的 playbook。[Ansible playbooks define tasks that the runner executes](https://docs.ansible.com/projects/ansible/latest/cli/ansible-playbook.html)，但自定义 wrapper 可能会过滤路径或使用不同的 identity：将该目录视为执行路径之前，应验证 wrapper 行为、实际 cron 用户、shell expansion、ACL、sticky bit 和 mount policy。静态检查 metadata 和 wrapper；枚举期间不要运行计划任务。

特权 cron wrapper 可能会先展开 glob，再将上传目录中的文件名传给 Perl helper。Perl 的 [`<>` diamond operator uses two-argument `open`](https://perldoc.perl.org/perlop#The-Null-Filehandle)，因此匹配的文件名若被解释为 pipe command，就可能以 helper 的 identity 执行；[`<<>>` treats arguments as literal filenames](https://perldoc.perl.org/perlop#The-Null-Filehandle)。确认 scheduler identity、wrapper 工作目录和 glob、helper 实际如何处理 `@ARGV`、文件名限制，以及低权限 identity 是否能通过文件系统权限或已认证的上传服务放置匹配名称。cron line、Perl script 或可写 FTP 目录本身都不能证明完整链路成立。枚举期间检查源码和 metadata，不要提交特制文件名或运行任务。

如果计划任务账户通过路径名运行脚本，那么即使 cron 脚本本身只读，只要低权限用户能写入并遍历其非 sticky 父目录，脚本仍可被替换。检查调度的 run-as identity、路径中的每一级目录、directory sticky bit、ACL 和 mount policy；只检查 metadata，不要移动文件或运行任务。

特权 PHP cron wrapper 可能会调用一个尚不存在的 helper。如果它通过 PHP [`exec()`](https://www.php.net/manual/en/function.exec.php) 调用固定的绝对 helper 路径，那么能在其父目录中创建该名称的低权限用户，可能控制后续运行时执行的内容。确认 cron entry 确实以更高权限运行 wrapper、确切的 command string 和 PHP execution policy、helper 目录的写入及 search 权限、symlink 和 sticky-bit 行为，以及 helper 路径是否仍不存在。可写目录或缺失的 helper 单独来看都只是线索；枚举期间检查调度、源码和路径 metadata，不要创建 helper 或触发任务。

计划任务还可能通过 `find` 发现输入脚本，并将每个脚本传给解释器。例如，[gnuplot's `system()` function invokes a shell](https://gnuplot.sourceforge.net/docs_6.0/gnuplot.pdf)，因此，如果特权任务对低权限用户可写目录中的每个 `*.plt` 文件运行 `gnuplot`，就可能以任务的 identity 执行命令。[Directory read permission controls listing, while write and search (`x`) control creating and accessing known names](https://www.gnu.org/software/coreutils/manual/html_node/Mode-Structure.html)；即使 `ls` 无法列出目录，也要检查写入和 search 权限。结合核对确切的 scheduler identity 和命令、解释器行为、所选文件模式及目录权限；可写目录或已安装的解释器本身都不能证明存在提权路径。私有调度任务和短时任务可能需要在授权情况下使用事件监控，因为单次进程快照可能会漏掉它们。

对于特权 PHP job，还要将字面量 `include`/`require` 语句纳入可执行脚本链检查。[PHP evaluates included files](https://www.php.net/manual/en/function.include.php)，因此，即使主脚本只读，group-writable 的被包含 `.php` 文件仍可能以任务的 identity 执行代码。验证计划任务的 identity、生效的 include-path 解析、文件和目录权限，以及任务是否实际运行；注释中的 cron 示例只是线索。同样的检查也适用于使用 `-S` 和 `-t <document-root>` 启动的 root-owned [PHP built-in server](https://www.php.net/commandline.webserver)：即使 listener 只绑定 loopback，本地请求仍可能执行应用 PHP。枚举期间检查进程和源码，不要触发任一执行路径。

特权 PHP job 也可能通过**数据文件**跨越边界：如果低权限用户能更改传给 [`unserialize()`](https://www.php.net/manual/en/function.unserialize.php) 的确切文件，PHP 在还原对象时可能调用已加载类的 `__wakeup()` 或 `__unserialize()` 方法。检查任务的生效 identity、文件和祖先目录权限、已加载的类，以及实际方法副作用（例如由属性选择的文件写入）。可写日志或调用 `unserialize()` 本身都不能证明存在可用路径。枚举期间检查源码和 metadata，不要写入序列化输入或运行任务。

root cron task 可能调用 PHP 应用的 **CLI page runner**，而不是 web server。追踪 runner 选定的 document root 和 URI，确定实际 PHP entrypoint；如果 web-service account 可写该 entrypoint，那么即使 runner 和 cron wrapper 只读，计划的 CLI 请求仍可能以 root 身份执行被修改的代码。确认 scheduler identity、确切的 URI 到文件解析方式、生效的文件和祖先目录权限，以及 integrity check 是否保护 entrypoint 本身。枚举期间检查源码和 metadata，不要调用 runner 或修改页面。

从共享工作目录启动的计划任务或其他用户的 `ipython` 进程，值得检查 startup file。[IPython's security release notes](https://ipython.readthedocs.io/en/8.25.0/whatsnew/version8.html#ipython-8-0-1-cve-2022-21699) 说明，在修复 CVE-2022-21699 之前，受影响的 build 会从当前目录搜索 profiles 和配置，包括 `profile_default/startup` 代码。结合核对实际安装的 build 或供应商补丁、命令工作目录、更高权限进程的 identity，以及低权限用户对确切 startup 路径的写入和 search 权限。已安装 `ipython`、可写目录或版本字符串本身，都不能证明另一个 identity 会加载该处文件。检查调度和路径 metadata，不要启动高权限解释器。

对于调用自定义 native extension 函数的特权 PHP server，在检查 extension 前，先追踪 service 的 PHP SAPI、生效的 `php.ini` 和扫描的 `.ini` 文件。[PHP loads configured `extension` libraries at startup](https://www.php.net/manual/en/ini.core.php)，且 [CLI and web SAPIs can use different configuration files](https://www.php.net/manual/en/configuration.file.php)。因此，可访问的登录表单或本地 listener 可能会将用户控制的字符串传入以 service identity 运行的编译代码。记录 unit 的 `User=`、`ExecStart=`、工作目录、实际 extension 路径和调用者可控参数；仅存在 `.so` 或 loopback socket，并不能证明存在内存破坏漏洞。单独分析任何自定义 parser；被动枚举期间不要发送探测数据。

当特权 wrapper 先按路径名对脚本计算 hash，之后又按同一路径打开并执行时，digest 只会认证第一次打开时读取的对象。如果低权限用户能在两次打开之间替换脚本的目录项，那么之后执行时可能会解析到不同对象，即使原始脚本文件归 root 所有。FIFO 可以延长检查阶段，但这条路径取决于可替换的父目录权限、是否确实发生了两次独立打开、scheduler identity、sticky-bit 和 mount 规则，以及时机。将检查 wrapper 和 `namei -l` 输出作为被动线索；校验和成功本身并不能证明后续路径名受到保护。

特权 backup job 也可能**泄露**数据，而不执行攻击者提供的命令。追踪低权限用户能否创建任务读取的 control file、任务是否随后打开 `/etc/shadow` 等受保护源，以及攻击者选择的 URL 或可读输出是否会收到结果。认定存在泄露路径前，确认这三个环节。相同脚本中的固定 shell command 并不会自动使 control file 成为 shell-injection 输入。枚举期间检查脚本和文件权限，不要运行任务或植入 control file。

如果特权计划任务运行 `curl -K FILE` 或 `curl --config FILE`，[curl treats options in that file as command-line arguments](https://curl.se/docs/manpage.html)。在 curl 读取确切文件时能够控制它的低权限用户，可能会影响请求的 URL、本地文件输入或输出路径。声称可能读取或写入受保护内容之前，确认任务的生效 identity、文件和祖先路径的写入权限、任何替换文件的其他任务的运行时机，以及配置选项与固定命令行选项的交互方式。可写配置路径或可见的 `-K` flag 本身都不能证明所选选项会生效；被动枚举期间检查调度和 metadata，不要运行任务或获取 URL。

如果 cron entry 调用 helper script，还要检查 helper 的工作目录和 archive 命令。对其他用户可写目录使用未加引号的 wildcard，可能会让文件名被解释为 archiver 选项；GNU tar 的 checkpoint actions 就是一个例子。认定存在跨用户命令路径之前，应确认计划任务的 run-as identity、可写输入目录、确切的 archiver 和选项，以及是否使用 `--` 终止选项解析。参见 [wildcard and tar behavior](../interesting-files-permissions/wildcards-spare-tricks.md)。

如果特权 helper 运行 `cd INPUT_DIR; tar ... *` 却不检查 `cd` 是否成功，还可能导致另一种 backup-file 泄露。如果低权限用户能删除或替换 `INPUT_DIR`，`cd` 失败后 shell 可能留在先前目录，后续 archive command 就可能读取该目录。验证任务的初始工作目录、实际的 `cd` 失败路径、脚本是否退出或使用 `&&`、确切的 archiver 选项，以及低权限用户能否读取输出 archive。可写输入目录或可读 archive 单独来看都只是线索；检查 helper 和路径权限，不要更改正在运行的任务。

计划执行文件可能只是伪装成 executable 的 shell script，并没有消除信任边界：[SHc](https://github.com/neurobin/shc) 会将加密的脚本文本封装进 native binary，并在运行时通过 shell 执行。`.sh.x` 后缀或不透明的 ELF 只能作为检查线索。要评估 filename option injection，先确认特权 scheduler identity、helper 的实际工作目录和命令、低权限用户能否在其中创建匹配文件名，以及未加引号的 glob 是否会传给 `rsync` 等没有 option boundary 的命令。只有实际使用该确切命令路径时，[`rsync` remote-shell option](../interesting-files-permissions/wildcards-spare-tricks.md#rsync) 才相关。`/proc` 可见性受限或静态解密失败，都意味着命令内容仍未知；不要只为判断其行为而运行特权 helper。

进程命令行文本也可能成为特权 helper 的另一种不可信输入。低权限用户可以选择能匹配 `pgrep -f` 的 process title 或 `argv[0]`；名称匹配并不能验证 executable 或其所有者。如果 root-run script 捕获该文本，将其中一部分改写为 `apache2ctl`/`httpd`，再执行生成的内容而没有固定的参数数组，攻击者选择的选项就可能指定不同的配置目录或 error log。Apache 配置解析可能加载模块或调用已配置的 helper，因此枚举期间不要以 root 身份验证不可信配置。检查 scheduler owner、确切的 helper、进程 identity，以及数据到参数的流向；除非另有证据证明会执行 shell metacharacter，否则这属于 option/configuration injection。

root-run parser 如果将不可信文本输入 Bash arithmetic，就可能执行文本中的 substitutions。[提权指南](../linux-basics/linux-privilege-escalation/README.md#bash-arithmetic-expansion-injection-in-cron-log-parsers)给出了一个完整示例。在将每个 arithmetic expression 都视为可利用之前，先确认输入来源和解析命令。

对于解析应用日志的特权任务，要追踪不可信字段的后续处理。低权限账户可能通过当前 process group 写入日志，或影响被记录的请求字段；一条记录随后可能选择一张图像，而其 metadata 又可能成为打开 XML 文件时使用的第二个路径。检查任务的生效 identity、实际日志写入权限、delimiter handling、canonical path containment，以及被选中的 XML 是否由攻击者控制。如果展开后的结果会进入低权限用户可读的输出，external-entity expansion 就可能导致特权文件泄露。[Java XML processing security guide](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html)介绍了控制 external DTD/entity 访问的方法；检查已安装的 parser 及其生效设置。可写日志或 XML 文件单独来看都只是线索。枚举期间检查代码和 metadata，不要向计划任务使用的 parser 提供输入。

还要检查会从其他用户的 Git repository 中生成文件的特权任务。脚本可能使用 `git ls-tree` 和 `git cat-file` 而不是 `git checkout`，但仍然可能信任攻击者控制的 tree 路径，并将其与 staging 目录拼接。除非写入前先规范化目标路径并检查其 containment，否则绝对路径和 `..` 组件都可能逃出该目录。`git -c safe.directory=*` 允许访问所有权不同的 repository；它本身并不会造成任意写入。

root-run database backup 也会形成另一种所有权边界。PostgreSQL [`pg_basebackup`](https://www.postgresql.org/docs/14/app-pgbasebackup.html) 会复制源 data directory 中额外放置的 regular files；其默认的 plain format 会将文件以目录树形式写入 `-D`。如果低权限账户能创建或修改这些源文件，应检查生成的目标文件所有权和 mode、目标路径是否可遍历和可执行，以及 mount 是否设置了 `nosuid`。保留 set-ID permissions 的 root-owned 副本可能带来危险；仅进行 tar backup、清除 permissions，或目标路径不可访问，都不能证明存在相同路径。将 backup command 视为发现项之前，要追踪计划 wrapper 和生效用户。

## Observe short-lived work

单次进程快照可能会漏掉只运行几毫秒的任务。将 timer/cron 声明与日志进行比对；在获得授权的情况下，还可以使用 `pspy` 或 audit 等进程事件监控。关联计划任务的 owner、确切命令行，以及任务读取或写入的文件。loopback scheduler web UI 是一个独立接口；参见 [Crontab UI example](../linux-basics/linux-privilege-escalation/README.md#crontab-ui-alseambusher-running-as-root--web-based-scheduler-privesc)。
{{#include ../../banners/hacktricks-training.md}}
