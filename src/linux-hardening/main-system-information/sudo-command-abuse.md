# Sudo 命令滥用

{{#include ../../banners/hacktricks-training.md}}

## Sudo 允许的解释器

如果 `sudo -l` 允许用户以 root 身份运行解释器，应将其视为直接代码执行。解释器就是为执行任意代码而设计的，因此，允许运行 `python3`、`perl`、`ruby`、`lua`、`node` 或类似二进制文件的规则，通常等同于允许执行 root 命令，除非参数受到严格限制并经过验证。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

常见的审查流程：先列出用户的权限，然后使用解释器的 `-c` 选项执行一条 Python 语句。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

其他解释器示例如下；所列解释器的文档介绍了内联代码执行或子进程 API。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

路径必须完全一致。如果 sudo 规则允许 `/usr/bin/python3`，验证时就使用这个确切路径。<sup>[[2]](#references)</sup>

像 `/usr/bin/python*` 这样的 sudo 可执行文件 glob 也可能允许使用 Python 2 运行针对 Python 3 编写的脚本。如果脚本执行到 `input()`，且文本由调用者控制，[Python 2 会将该文本求值为表达式](https://docs.python.org/2/library/functions.html#input)；显式调用解释器会覆盖脚本的 shebang。在将其视为代码执行路径之前，请确认已安装且匹配的二进制文件、有效的 RunAs 和参数策略、拒绝规则，以及可触达的输入。

sudo 规则中固定的脚本路径，并不能限制脚本会执行什么。对于可读的 Bash wrapper，请检查它的第一条可执行命令是否将未加引号的位置参数（如 `$1`）用作**命令词**，同时 sudo 是否允许调用者选择参数。请确认有效的 RunAs 身份、密码和参数策略、后续拒绝规则，以及实际执行的脚本分支；`NOEXEC`、固定的安全参数列表，或会验证命令的 wrapper 都可能改变结果。枚举时静态检查这个短脚本，不要通过传入测试命令来调用它。

允许以 root 身份不受限制地运行 `dotnet` 的 sudo 规则也值得检查其解释器能力。如果安装了 .NET SDK，[`dotnet fsi` 可以交互式运行 F# 代码或运行脚本](https://learn.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/)，而 [`dotnet run` 可以从源代码执行项目](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run)。请先确认有效的 RunAs 身份和确切的参数策略：限定为某个特定安全子命令或可信应用程序的规则属于不同的授权；仅安装运行时的环境可能没有 SDK 命令。可执行文件名称只是需要审查的线索，并不能证明可以执行代码。

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## Sudo-allowed editors

如果 `sudo -l` 允许用户以 root 身份运行交互式编辑器，应将其视为命令执行入口，而不是无害的文件编辑权限。编辑器通常可以执行 shell 命令、读取任意文件、写入任意文件，或在编辑器内调用外部辅助程序。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

常见的检查流程：列出用户的权限，然后通过 sudo 调用每个允许使用的编辑器或分页器。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```

### Nano 命令执行

如果允许通过 sudo 使用 `nano`，则可以从编辑器界面执行命令。<sup>[[12]](#references)</sup>

```text
Ctrl+R
Ctrl+X
```

然后在 nano 命令提示符中输入诸如 `id` 或 `/bin/sh` 这样的命令。<sup>[[12]](#references)</sup>

```bash
id
/bin/sh
```

如果交互式 shell 没有可用的终端流，此重定向形式会将其标准输出和标准错误映射到文件描述符 0。<sup>[[15]](#references)</sup>

```bash
reset; /bin/sh 1>&0 2>&0
```

具体按键序列可能因 nano 版本和构建选项而异，但安全问题相同：编辑器以 root 身份运行，并且可以调用外部命令。<sup>[[1]](#references)[[12]](#references)</sup>

### 其他常见的编辑器逃逸方式

Vim 风格的编辑器通常通过 `:!` 提供命令执行功能。<sup>[[13]](#references)</sup>

```text
:!/bin/sh
```

类似 `less` 的 pager 也可能暴露 shell 执行功能。<sup>[[14]](#references)</sup>

允许以 root 身份运行 `apport-cli` 的 sudo 规则也应检查 pager。受影响的 Apport 版本可能会用 `less` 打开崩溃报告，并允许攻击者调整终端大小；如果满足特定的 sudo 和 pager 条件，pager 随后可能提供 root shell。在认定某个版本存在漏洞之前，请检查生效的 sudo 规则、pager 配置以及发行版的软件包修复情况。被动枚举期间，请读取软件包和策略元数据，不要生成崩溃，也不要打开特权报告。[Ubuntu 的 CVE 记录](https://ubuntu.com/security/CVE-2023-1326)列出了针对不同发行版版本的已修复软件包版本，其中包括回移修复。

```text
!/bin/sh
```

## 其他 sudo 和 doas 规则的风险

从 `sudo -l`、`sudo -V` 以及任何适用的 `doas` 策略开始检查。综合查看允许执行的命令、RunAs 用户、参数、环境和默认设置。即使只允许以非 root 服务账户身份运行，也可能暴露该账户的文件，或提供通往 root 的路径。

即使 sudo 只允许运行固定的 Python 脚本，只要脚本把交互式、由调用者控制的输入拼接到 [`os.system()`](https://docs.python.org/3/library/os.html#os.system)，仍可能以 RunAs 身份执行 shell 命令。仅靠 shell 标点符号的 denylist 不足以证明安全：[shell 也会识别 `$(...)` 命令替换](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html)。确认允许的参数确实能到达输入分支、输入未经安全验证便传入 shell 命令，以及有效 sudo 策略允许目标 RunAs 用户。脚本路径或 `os.system()` 调用本身只能作为审查线索；应检查源码，不要调用特权脚本。

有效的 root sudo 授权若允许运行 `chattr`，可以移除文件的 immutable (`i`) 属性，但这本身不会授予写入权限或新的身份。[`chattr` 手册](https://man7.org/linux/man-pages/man1/chattr.1.html)说明，该属性会阻止修改，只有 root 或具有 `CAP_LINUX_IMMUTABLE` 的进程才能更改它。检查确切的 sudo 参数策略和文件系统支持情况，然后单独验证清除属性后调用者是否能写入文件，以及更高权限的使用方是否会使用该文件。例如，替换登录 shell 还需要目标账户接受相应凭据，并且确实通过该 shell 登录。枚举期间只检查策略、文件属性和权限，不要修改它们。

如果 sudo 同时要求密码和一次性验证码，应将这些前提与命令授权分开看待。可读的 `.google_authenticator` 文件包含敏感种子材料；旧应用或数据库中的密码哈希则只是当前账户密码的候选值，二者都不能证明有效 PAM 配置会接受另一项验证因素。获准检查后，应核实确切的 RunAs 和参数：对 RubyGems `gem` 的无限制 root 授权可能暴露其编辑器命令（[GTFOBins](https://gtfobins.github.io/gtfobins/gem/)），但受限授权或认证失败则不会。被动枚举应报告路径和策略，不要打印种子、破解密码、生成验证码或调用特权命令。

对 Chef 的 `knife`，无限制且具备 root 能力的 sudo 授权值得进行解释器级审查：[Chef 文档说明，`knife exec -E` 会在本地执行 Ruby 字符串](https://docs.chef.io/workstation/26/tools/knife/knife_exec/)。确认有效 sudo 规则允许 `exec` 子命令和调用者提供的 `-E` 参数、目标 RunAs 身份，以及任何匹配的命令拒绝项或固定参数。已安装该二进制，或规则仅限其他子命令，都只能算线索。被动枚举应报告规则，不要调用 `knife`。

对交互式 `msfconsole` 的精确 root-capable sudo 授权同样敏感：[GTFOBins 记录了它的 `irb` 控制台](https://gtfobins.org/gtfobins/msfconsole/)，该控制台可能继承 sudo 身份。确认有效 RunAs 用户、允许的参数列表、命令拒绝项、`NOEXEC` 或其他限制、已安装控制台的行为，以及调用者能否提供交互输入。仅仅看到路径高亮只能作为审查线索；被动枚举时不要启动控制台。

在 FreeBSD 上，即使 sudo 规则仅允许以 root 身份运行 `pkg update` 和 `pkg install *`，也值得审查仓库信任情况。检查调用者是否能写入 `/etc/hosts`，以及*有效的*启用仓库配置是否使用带有 `signature_type: none` 的 HTTP 主机名。[FreeBSD 的 `pkg.conf` 手册](https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5)说明，`none` 会禁用签名检查；仅有 `pkg+http` 并不能证明这一点。软件包可能包含安装脚本（[FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/pkg-files/)），因此，如果调用者确实能控制仓库端点并选择软件包，就可能跨越 root 边界。得出结论前，应核实仓库覆盖项、SRV/镜像解析、有效 sudo 参数、软件包选择和脚本执行情况。枚举时检查策略和较小的本地配置文件，不要重定向名称或运行 `pkg`。

如果 sudo 保留调用者可控的 `http_proxy`，那么具备 root 能力的 `apt-get update` 和 `apt-get upgrade` sudo 规则也需要审查仓库信任情况。检查有效的 APT 代理配置是否实际使用该变量，以及它可能影响哪些启用的仓库请求；代理本身无法替换由受信任签名密钥认证的归档内容。[APT 的 HTTP transport 手册](https://manpages.debian.org/experimental/apt/apt-transport-http.1.en.html)说明了代理优先级，[apt-secure](https://manpages.debian.org/experimental/apt/apt-secure.8.en.html)则说明了签名检查、不安全仓库覆盖项，以及对未认证软件包的确认要求。确认确切的 sudo RunAs 和参数、仓库认证策略、是否需要交互式确认，以及所选升级是否会以 root 身份运行软件包脚本。被动检查策略和本地配置；枚举时不要重定向软件包流量或运行升级。

如果 root-capable sudo 规则允许调用者选择本地 snap，并使用宽松的安装模式，那么 `snap install` 可能形成从软件包到代码的边界。[Snap 文档](https://snapcraft.io/docs/explanation/snap-development/install-modes/)说明，`--dangerous` 会跳过本地 snap 的 assertion 检查，`--devmode` 会放宽 confinement；[安装 hook 可在初次安装时运行](https://snapcraft.io/docs/reference/development/supported-snap-hooks/)。在声称可以访问受保护的主机文件前，应检查确切的 sudo 参数/RunAs 策略、谁控制 snap 文件、已安装的 snapd 是否接受这些模式，以及 hook 的有效身份和 confinement。仅有 `snap` 二进制或看似宽泛的规则，并不能证明这条攻击链成立。被动枚举时不要安装软件包或执行其 hook。

对于精确授予的、以**非 root**账户运行的自定义凭据读取二进制，先检查获准的二进制及其文件权限，不要运行它。内嵌的密码门可能只有在提取宽字符时才可见；[GNU `strings` 文档说明了 16 位小端提取方式](https://sourceware.org/binutils/docs/binutils/strings.html)。可见字符串不能证明它就是有效密码，也不能证明成功分支会暴露当前凭据。应分别确认二进制行为、目标账户对受保护数据的访问权限、凭据有效性，以及后续账户或组身份转换。如果该账户属于 `docker` 组，应核实其 socket 访问权限及 daemon 使用 rootful 还是 rootless 身份，再判断能否访问主机 root；[Docker 文档说明了该组的 root 级影响](https://docs.docker.com/engine/install/linux-postinstall/)。常规枚举应报告 sudo 规则和组成员身份，不要执行二进制或转储其字符串。

针对应用维护脚本的通配符 sudo 规则，审查范围不应止于脚本路径。检查允许的脚本是否接受不受限制的参数，或是否读取可由低权限应用账户写入的设置，然后追踪这些值是否流入 shell 命令或子进程环境。例如，ZoneMinder 的 [`zmupdate.pl` 会拼接 `mysqldump` 命令并通过 `qx` 执行](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmupdate.pl.in)，而 [`zmdc.pl` 会在启动 daemon 前将 `ZM_LD_PRELOAD` 设置复制到 `LD_PRELOAD`](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmdc.pl.in)。如果相应输入可控，且能到达已安装版本中的这段代码，那么允许以 root 身份运行任一脚本的 sudo 规则就可能跨越信任边界。检查有效 sudo 规则、应用配置权限和脚本源码；通配符或设置本身只能作为审查线索，并非执行证明。

- `SETENV`、`env_keep`、`secure_path` 和 `LD_PRELOAD` 可能把原本受限的命令变成导入、库或 PATH 劫持。参见[环境变量指南](../linux-basics/linux-environment-variables.md)和 [SUID/linker 滥用](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md)。

如果某个 root-capable `SETENV` 精确授权允许调用 shell wrapper，而且 wrapper 会使用字面量 import 启动固定 Python 脚本，也值得检查这一跳调用。`secure_path` 限制的是 shell 命令查找，不是 Python 的 [`PYTHONPATH` 模块搜索](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH)；[`-E` 和 `-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-E) 会让 Python 忽略该环境变量。将其视为代码执行路径前，应确认有效 sudo tags 和拒绝项、wrapper 分支、解释器选项、import 解析情况，以及调用者是否能写入搜索目录。静态检查短脚本；不要调用特权 wrapper。

即使 sudo 默认设置保留调用者可控的 `XDG_CONFIG_HOME`，精确授权运行 `neofetch ""` 的 root-capable sudo 规则仍可能加载 shell 配置。[Neofetch 的配置加载器](https://github.com/dylanaraps/neofetch/blob/master/neofetch)会从该目录下加载 `neofetch/config.conf` 或 `neofetch/config`；空参数列表不会阻止这次查找。确认已安装版本的加载器、有效 RunAs 和参数策略、任何命令拒绝项、sudo 对该命令是否确实保留所选变量，以及调用者是否控制可读的配置路径。变量被保留或已安装 Neofetch 本身都只能作为审查线索。检查策略和文件元数据，不要调用特权命令或打印配置内容；另见 [sudoers 环境处理](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)。

对无限制且具备 root 能力的 `facter` sudo 规则，应单独审查 custom fact。[Puppet 文档](https://help.puppet.com/core/current/Content/PuppetCore/loading_custom_facts.htm)说明，`--custom-dir` 会从指定目录加载 Ruby fact 文件。检查确切的 sudo 规则是否允许该选项、已安装的 Facter 是否接受它，以及调用者是否控制该目录。固定参数授权、显式命令拒绝项或已禁用的 custom fact 都可能改变结果。被动枚举应报告这一策略候选项，不要调用 Facter 或读取 fact 内容。

对于带 `SETENV` 的精确 root-capable sudo 脚本授权，应检查 `find` 等裸命令名称，以及经过 sudo 策略和脚本初始化后生效的 `PATH`。被 source 的 Bash 文件也可能运行 `enable -n [`：[此后 Bash 会在 `PATH` 中查找外部的 `[` 命令](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)，供脚本后续调用。确认适用的 [sudoers 环境和 `secure_path` 规则](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)、任何 `NOSETENV`/`NOEXEC` 或拒绝项、脚本及被 source 文件的执行流程，以及调用者可控目录是否既可写又可执行。可读脚本中出现裸命令只能作为审查线索，并非特权执行的证明；检查脚本，不要调用 sudo 规则。
- 即使特权脚本通过 `curl` 获取固定 URL，如果适用的 sudo 规则保留了 `http_proxy`，且请求通过该代理发送，调用者仍可能控制响应。如果脚本随后将响应交给会解析外部实体的 XML parser，恶意响应可能泄露特权进程可读的文件。检查确切的 sudo 环境策略、`no_proxy` 排除项、请求的 URL、parser 配置和输出目的地；仅有代理变量或 XML parser 并不构成漏洞。[curl 的代理环境文档](https://everything.curl.dev/usingcurl/proxies/env.html)说明了变量行为。被动枚举期间不要发起网络请求或解析恶意 XML。
- 如果具备 root 能力的 sudo 脚本根据调用者影响的数据构造 PostScript 文件，然后运行 `ps2pdf -dNOSAFER`，则应单独检查输入流。Ghostscript 文档说明，该标志会禁用 SAFER，直到执行 `.setsafe`；此期间 PostScript 可在进程的 OS 权限范围内进行文件操作。根据调用者参数拼接的 SQL 查询可能将攻击者控制的行传入 PostScript 模板，但仅有查询字符串或 `ps2pdf` 调用，并不能证明数据会进入可执行的 PostScript 语法。确认有效 sudo 规则、从确切输入到模板的路径、是否进行了转义、已安装的 Ghostscript 行为，以及解释文档前是否重新启用 SAFER。被动枚举期间不要调用特权转换程序。参见 [Ghostscript 的 `-dNOSAFER` 文档](https://ghostscript.readthedocs.io/en/master/Use.html)。
- 对于运行 shell 脚本的 sudo 规则，应将保留的变量与脚本本身一起审查。类似 `if $CHECK_CONTENT; then` 的语句会将展开后的值作为命令运行，因此即使脚本路径和参数固定，保留 `CHECK_CONTENT` 也可能允许命令执行。是否能到达该分支，以及环境是否确实保留，必须针对具体规则检查。<sup>[[2]](#references)[[22]](#references)</sup>
- sudo 允许运行的 Python 脚本可能从可写目录或缓存的 `.pyc` 文件中导入代码。[提权指南](../linux-basics/linux-privilege-escalation/README.md)详细介绍了缓存情形。
- 固定且获准通过 sudo 以 root 身份运行的 Python 脚本仍可能暴露交互式 debugger。如果调用者能到达断点或异常处理程序，**并控制 debugger 的输入流**，那么 `pdb.set_trace()` 或 `pdb.post_mortem()` 等调用允许在被调试进程的上下文中执行 Python 语句。检查确切的 sudo RunAs 规则、认证和分支条件、异常可达性、终端/输入的所有权，以及 debugger 是否运行在同一特权进程中。触发异常的 socket 请求本身，并不能授予对附着在另一终端上的 debugger 的访问权。[Python 文档说明了 debugger 的语句求值和 post-mortem 模式](https://docs.python.org/3/library/pdb.html)；枚举时应静态检查脚本，不要触发特权处理程序。
- 获准通过 sudo 运行的固定 Python 脚本，也可能从数据库或 Unix socket 读取 profile 字段，并将其追加到之后成为 `str.format()` **格式字符串**的字符串中。[替换字段可以访问属性和 mapping key](https://docs.python.org/3/library/string.html#format-string-syntax)，因此，如果攻击者控制的字段被传入 `format()` 的对象中，且结果被打印或存储在调用者可读的位置，就可能检查这些对象并泄露其可访问的数据。检查有效 sudo RunAs 身份、对特定记录的写权限、数据流是否进入格式字符串、传入了哪些对象，以及输出是否可见。这并非自动代码执行；可信的字面量格式字符串搭配攻击者控制的*值*则是另一种情况。只有目标账户接受泄露的秘密时，它才能引发 OS 账户身份转换。检查脚本和 socket 权限，不要调用特权操作。
- 具备 root 能力的 Python wrapper 可能会把调用者选定的 URL 传给 GitPython 的 `Repo.clone_from`。如果 wrapper 还启用了 Git 的 `protocol.ext.allow=always`，`ext::` remote 就能调用外部 helper。检查确切的 sudo 参数、URL 的来源、GitPython 软件包版本及厂商补丁状态，以及 wrapper 是否明确选择不安全协议。GitPython 在 3.1.30 中加入了[默认的不安全协议防护](https://github.com/gitpython-developers/GitPython/commit/2625ed9)；`git` 可执行文件的版本是另一项独立信息。被动审查只应查看规则和范围受限的源码，不要调用 clone。
- 跨用户的 sudo 授权若允许运行仓库克隆 CLI，可能暴露另一条 shell 字符串注入路径。追踪调用者选择的仓库参数是否未经安全的参数分隔，便传入 Node.js [`child_process.exec`](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback) 或其他 shell 命令构造器；Node 的 `exec` 会将命令字符串交给 shell。确认确切的 RunAs 用户、允许的子命令和参数、已安装的 wrapper 代码，以及输入验证情况。仅有仓库工具名称或无限制 sudo 规则，并不能证明存在命令注入。枚举期间检查 wrapper，但不要调用特权 clone。
- 自定义的 root-owned wrapper 可能看似安全，因为其二进制和脚本均不可写；但它是否执行特权操作，可能取决于非特权用户能更改的标志、本地 API 值或服务状态。追踪每个门控条件的输入来源和授权检查。枚举期间检查配置和权限，不要改变运行状态；只有当门控条件可被影响时，wrapper 中的 `systemd-run` 调用才相关。
- 通过 sudo 以 root 身份运行的备份客户端可能接受调用者选择的配置文件（例如 `npbackup-cli -c`）。检查确切的 RunAs 用户和允许的参数，然后确认调用者是否控制配置路径、备份源路径，以及仓库或读取/恢复选项。可读配置中的加密仓库密钥仍可能被客户端使用，但仅有规则并不能证明可以访问仓库或泄露 root 文件。验证授权时不要运行备份或转储其内容。
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst)支持 `--password-command`，该选项会调用程序获取仓库密码。如果 sudo 规则允许低权限用户以 root 身份运行 restic，并使用调用者指定的密码命令及需要密码的子命令，那么 helper 可能会以 root 身份运行。审查确切的 sudo 参数和排除项；不要仅为枚举这一条件而调用 helper 或备份命令。
- 如果具备 root 能力的 `restic backup` 授权允许调用者同时选择源和其日后可读取并解密的仓库，也可能跨越文件读取边界。[Sudoers 参数通配符可以匹配空格和斜杠](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)，因此应检查末尾通配符，不要假设固定的仓库前缀会限制源路径。[Restic 可以备份到本地和远程仓库](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html)，但本地仓库可能包含新写入的 root-only 对象；在将其视为信息泄露前，应确认有效 sudo 策略、后端访问权限、仓库密码和生成对象的权限。备份的 SSH key 只有在目标账户接受它时才能授予访问权限。被动审查时不要运行备份进行测试。
- 不受限制的自定义维护或备份命令可能接受输出路径，或提供自己的 job scheduler。对于文件写入路径，应确认确切的 sudo 规则和 RunAs 用户，然后检查调用者是否同时控制数据和目标位置。对于定时命令路径，应确认 scheduler 的执行身份、命令输入，以及是否存在额外的密码或授权门控。命令名称或 `NOPASSWD` 本身都不能证明任一路径成立。参见[写入 root-owned 文件](../interesting-files-permissions/write-to-root.md)和 [cron 与 systemd timers](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md)。
- 固定的 sudo 命令仍可能从共享可写目录加载可预测的配置文件。追踪调用者能否替换该文件，以及其中的源和目标字段是否控制特权 fetch 或 copy。本地文件 URL 可能暴露只有 sudo RunAs 账户可读的数据；调用者可控的源和受保护的目标组合，则可能形成写入路径。确认已安装程序的 URL 处理、目标路径检查、有效 sudo 规则和输出可访问性。仅有可写的 `/tmp` 配置路径只能作为审查线索；检查二进制和文件元数据，不要调用特权传输。
- `git apply` 的 sudo 规则可能使 RunAs 账户写入由调用者控制的 patch 所指定的文件。[CVE-2023-23946](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh)允许精心构造的 patch 创建 symlink，然后写出工作树范围，即使命令不接受 `--unsafe-paths` 也可能发生。检查有效 sudo 参数规则、patch 来源、RunAs 账户对工作目录的访问权限，以及已安装 Git 是否包含修复或厂商回移补丁。允许 `--unsafe-paths` 的无限制规则是另一项明确的选项风险；仅有 Git 版本或 `git apply` 权限，并不能证明可以修改受保护文件。被动枚举时不要应用不可信 patch。
- 如果低权限用户可以提供 DMG 镜像，且已安装 parser 受可能通过 debug 输出泄露文件内容的 [CVE-2023-20052](https://blog.clamav.net/2023/02/clamav-01038-01052-and-101-patch.html)影响，那么具备 root 能力的 `clamscan --debug` 规则就可能跨越读取边界。确认确切的允许参数和扫描路径、输入控制权、有效 RunAs 账户、引擎补丁/回移状态，以及调用者是否能看到输出。如果更宽泛的规则允许 `--file-list`/`-f`，应单独审查该文件列表行为；固定为 `--debug <scan-path>` 的策略并不允许使用它。枚举时只检查策略和软件包元数据，不要扫描特制文件或打印受保护的输出。
- 如果一条具备 root 能力的 sudo 规则可打开调用者选择的加密磁盘镜像，另一条规则可挂载生成的 mapper，那么调用者控制的文件就可能被导入主机的 mount namespace。确认两条有效规则及其参数、对镜像和 mapper 名称的控制权、实际挂载目标，以及生成文件的所有者和权限。若要通过 set-user-ID 进行身份转换，还需要存在可访问的可执行文件、支持该位的挂载选项（`nosuid` 会阻止）以及适用的进程或 MAC 策略；单独打开或挂载镜像只能作为审查线索。通过现有备份的另一条路径则需要实际可用的 key，以及其中有用且可读的秘密。被动枚举时只检查策略和路径，不要打开或挂载镜像。参见 [`cryptsetup` 手册](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)和 [mount 选项](https://man7.org/linux/man-pages/man8/mount.8.html)。
- 如果具备 root 能力的 sudo shell 或 Python 脚本调用 `./helper`，却没有先切换到固定目录，则应审查工作目录。传给 `subprocess.run` 的 Python 列表（如 `['./helper']`）也可能受调用者选择的工作目录影响。调用者可能选择可写目录，并在那里放置同名可执行文件；脚本中的绝对路径不会保护这次调用。在将其视为代码执行前，应确认有效规则、`runchdir` 或其他改变目录的策略、脚本流程及分支可达性、目录是否可写且可执行，以及挂载/`NOEXEC` 限制。若脚本不可读，在通过授权途径审查源码前，行为仍属未知。静态审查脚本，不要运行 helper。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)说明了工作目录策略。
- 固定且具备 root 能力的 Python validator 仍可能求值调用者选择的数据文件。[Python 的 `eval()` 文档警告不要使用不可信输入](https://docs.python.org/3/library/functions.html#eval)：如果剩余表达式最终仍传入 `eval`，那么输入后缀检查、算术前缀或验证分支都不是 sandbox。应确认有效 sudo 规则、调用者能否选择并控制确切文件、parser 的分支条件和表达式构造方式，以及特权进程身份，再将其认定为执行路径。可读脚本中出现 `eval` 只能作为审查提示；枚举时检查源码和文件权限，不要运行 validator 或提交测试表达式。
- 如果具备 root 能力的 sudo Ruby wrapper 读取相对 YAML 文件名，例如 `YAML.load(File.read("dependencies.yml"))`，那么除非 wrapper 或 sudo 策略固定了工作目录，否则它可能从调用者的当前目录读取输入。检查确切的允许参数、目录和文件权限，以及已安装 Psych 的行为：旧版 `YAML.load` 实现可能反序列化任意 Ruby 对象，而新版默认会限制类。静态调用点只能作为审查线索；应确认文件确实来自调用者可写目录，且已安装的 loader 接受危险类。对不可信输入，优先使用带显式最小类 allowlist 的 `safe_load`。参见 [Ruby 3.0 Psych 文档](https://docs.ruby-lang.org/en/3.0/Psych.html)和 [Ruby 3.1 Psych 文档](https://ruby-doc.org/core-3.1.2/Psych.html)。

- 如果精确的 root-capable sudo 授权允许运行 `sudo go run /absolute/file.go`，而 Go 源码会读取相对路径的 WASM 文件，并可能在检查结果后运行相对路径 shell 脚本，则应审查工作目录。确认有效 RunAs、命令参数和拒绝项、调用者可写的当前目录、从 WASM 到分支的数据流，以及该分支是否调用 helper。固定的 sudo `runchdir`、`os.Chdir` 或 [`exec.Cmd.Dir`](https://pkg.go.dev/os/exec) 都可能改变查找位置。仅仅静态地发现这些要素并存只能作为候选线索；检查源码，不要运行 Go、WASM 或 helper。
- `sudoedit` 和参数通配符需要检查确切版本和规则；[检查清单](linux-privilege-escalation-checklist.md)包含 sudoedit 文件编辑问题。对于跨用户、路径包含通配符的 `sudoedit` 授权，应检查有效的 `sudoedit_follow` 或 `FOLLOW` 设置、`sudoedit_checkdir`、解析后的目标，以及谁能替换每个父目录条目。前者可能允许跟随 symlink，禁用后者则会取消对可写目录的检查；但这两个设置单独都不能证明能写入其他用户的文件。下结论前，应确认已安装 sudo 的策略及实际匹配的参数。参见 [sudoers 选项定义](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)。
- 在 sudoers 命令规则中，参数通配符既能匹配路径字符，也能匹配空白字符。对于可读取文件的命令，带有 `/restricted/*` 这类参数的规则可能允许在匹配前缀后追加文件参数。审查确切的 RunAs 用户、命令路径、参数模式和后续拒绝项；证明可以读取文件并不意味着可以执行命令。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)区分了参数 glob 和命令路径 glob。
- 看起来像路径的参数 glob 也可能匹配 `../`。例如，具备 root 能力的 `node /opt/scripts/*.js` 规则可能允许调用者控制 `/opt/scripts` 之外的 JavaScript 文件，只要提供的路径仍以 `/opt/scripts/` 开头，并通过父目录片段解析到目标。这是**参数** glob；Node 可执行文件的命令路径 glob 对斜杠有不同的匹配规则。在认定可执行代码前，应检查有效规则、后续拒绝项、路径解析、目标文件控制权，以及 sudoers 的正则表达式或 digest 限制。参见 [sudoers 通配符规则](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)和 [Node 命令行文档](https://nodejs.org/api/cli.html)。
- 归档工具和其他实用程序可能带有执行 hook。应根据[GTFOBins](https://gtfobins.github.io/)检查确切允许的参数，不要假设只有 shell 或解释器才会执行命令。
- 不受限制且具备 root 能力的 `qpdf` 规则可能通过 PDF 附件暴露特权文件：qpdf 10.2 及更高版本支持 `--empty` 和 `--add-attachment file ... --`，并可输出 PDF。如果特权进程能读取所选源文件，并能将 PDF 写入调用者可访问的路径，该输出就可能包含源文件字节。下结论认为可能泄露文件前，应审查有效 sudo 参数和排除项、qpdf 版本、源文件访问权限和输出路径。只有在 key 有效且允许 root SSH 认证时，读取 root SSH key 才有助于登录。参见 [qpdf 附件选项](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments)。
- sudo 时间戳复用取决于缓存策略、所有者用户、终端/会话和权限。[提权指南](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens)介绍了相关检查。
- `doas` 有自己的规则和配置。请按 [doas 部分](../linux-basics/linux-privilege-escalation/README.md#doas)中的说明检查允许的命令和可写配置路径。

### 通过 sudo 运行构建和软件包工具

即使 RunAs 身份是另一位非 root 用户，对 Foundry 的 `forge` 进行无限制 sudo 授权也可能造成影响。`--use` 等编译器选项可以选择本地可执行文件，而 `forge flatten -o` 可以选择输出文件。将授权视为可利用之前，应检查已安装的 Forge 版本、确切的 sudo 参数、可访问的项目和编译器路径、输出权限以及有效环境。通过 `PATH` 找到相对路径 helper 可执行文件的路线依赖版本和环境，不能假定适用于所有 Forge 构建。<sup>[[23]](#references)[[24]](#references)</sup>

不受限制且具备 root 能力的 `pacman` 授权允许的不只是查询软件包：`-U` 接受本地软件包，软件包可以包含安装脚本，`--hookdir` 还能指定其他 hook 目录。测试前应审查有效 sudo 规则、参数限制和排除项；被动枚举无需安装软件包或运行 hook。<sup>[[25]](#references)[[26]](#references)</sup>

固定的 sudo shell wrapper 也可能安装指定的 npm dependency，然后启动 Node 应用。检查其确切的 RunAs 规则、软件包是否已安装、有效的 `HOME` 和 npm `userconfig`、项目配置或命令行覆盖项，以及低权限用户是否控制该名称对应的 registry 或软件包。[npm 文档说明了按用户和按项目查找 `.npmrc`](https://docs.npmjs.com/cli/v6/configuring-npm/npmrc/)；sudo 的 `HOME` 行为取决于已安装策略和发行版，因此特权 npm 进程是否会读取用户可写的 `.npmrc` 不能一概而论。如果新安装的软件包被特权应用导入，其模块代码就能以该应用的身份运行。安装时脚本则是独立路径，其行为依赖版本和配置；[npm 文档说明了生命周期和用户处理方式](https://docs.npmjs.com/cli/v6/using-npm/scripts/)。仅有 `.npmrc` 路径或 `npm install` 行只能作为审查线索。被动枚举时检查规则、简短 wrapper、配置路径和软件包来源，不要安装软件包或启动应用。

如果 root-capable `pip` 或 `pip3 download` 授权允许调用者选择不可信源分发包，即使 URL 模式将其限制在本地服务和 `.tar.gz` 后缀，也应作为软件包构建审查线索。`pip download` 接受归档 URL 并解析软件包元数据；准备 sdist 时，可能会在归档仅仅保存下来之前调用其 build backend 或旧式 `setup.py` 代码。确认确切的 sudo RunAs 和参数规则、调用者是否能发布或替换所选归档，以及该 pip 版本是否确实会准备其元数据。固定且可信的归档或 wheel 并不能证明这条路径成立。被动枚举时不要获取或构建不可信软件包。参见 pip 的 [download 命令](https://pip.pypa.io/en/stable/cli/pip_download/)、[build-system 接口](https://pip.pypa.io/en/stable/reference/build-system/)和[安全安装指南](https://pip.pypa.io/en/stable/topics/secure-installs/)。

如果 sudo 规则允许使用调用者选择的本地项目路径运行 `pip install`，则存在更直接的构建边界。[pip 接受本地项目目录](https://pip.pypa.io/en/stable/topics/local-project-installs/)并会调用其构建系统；[build backend 会运行项目控制的构建 hook](https://pip.pypa.io/en/stable/reference/build-system/)。在将该规则视为特权代码执行前，应确认有效 RunAs 身份、确切的参数限制和拒绝项、所选项目的控制权，以及已安装 pip/backend 的行为。固定且可信的项目，或排除了调用者指定路径的规则，都不能证明这条路径成立。被动枚举时检查规则和项目元数据，不要安装软件包。

不受限制且具备 root 能力的 `easy_install` 授权是相关的旧式软件包构建线索。[Setuptools 文档](https://setuptools.pypa.io/en/stable/deprecated/easy_install.html)说明，Easy Install 接受本地项目目录并构建源分发包；调用者控制的项目可能在 sudo 身份下构建时执行其 `setup.py`。确认有效 RunAs 账户、确切命令和参数限制（包括后续拒绝项）、所选项目的控制权，以及已安装工具的行为。固定且可信的项目，或不允许调用者选择源的策略，都不能证明这条路径成立。枚举时检查规则和项目元数据，不要安装软件包。

通过 sudo 获准运行、使用 `setuptools.package_index.PackageIndex.download` 并接受调用者选择 URL 的 Python wrapper，与 `pip download` 是不同的审查情形：[setuptools GHSA-5rjg-fvgr-3xxf](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf)描述了受影响的 78.1.1 之前版本中，URL 派生的文件名逃出预期下载目录，并以进程权限写入文件的情况。确认有效 sudo RunAs 和参数规则、wrapper 是否将调用者的 URL 传给这一确切 API、已安装版本或厂商回移补丁，以及结果路径最终解析到哪里。仅凭版本字符串或可写下载目录，并不能证明存在任意写入。枚举时检查简短 wrapper 和软件包元数据，不要获取 URL 或写入文件。

sudo 允许的构建 wrapper 如果将调用者选择的 `.spec` 文件传给 PyInstaller，也需要进行信任边界审查。PyInstaller spec 是在**构建期间**执行的 Python，其 `datas` 条目可以将构建身份可读的文件打包进产物。确认确切 RunAs 用户、sudo 参数和拒绝规则、wrapper 的路径和分支处理、调用者对所选 spec 文件的控制权，以及对生成产物的访问权限。仅仅允许 `.py` 输入或发现已安装 PyInstaller，都不能证明调用者能控制 spec 文件或执行特权代码。被动审查只应读取有限范围的 wrapper 文件和元数据，不应运行构建。参见 [PyInstaller spec 文件文档](https://pyinstaller.org/en/stable/spec-files.html)。

### 通过 sudo 运行 preset 和 plugin loader

接受调用者选择的 preset 或 plugin 目录的 Python 工具，可能会以 sudo 授予的权限导入代码。例如，BBOT 可通过 `-p` 接受 preset，其 [custom module 文档](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#load-modules-from-custom-locations)介绍了通过 `module_dirs` 条目选择其他 Python 模块目录的方式。如果有效 sudo 规则允许调用者选择 preset，且调用者控制所选目录中的模块，那么导入时就可能以特权用户身份执行代码，甚至可能早于工具拒绝无效模块。检查已安装版本、确切的 sudo RunAs 和参数策略，以及 preset 和模块路径的所有权；枚举期间不要加载模块。

### 通过 sudo 运行 Backdrop 命令行工具

[Bee](https://github.com/backdrop-contrib/bee) 是 Backdrop CMS 的 PHP 命令行工具。它的 `eval`（`php-eval`）和 `php-script` 命令可以运行调用者提供的 PHP。如果 sudo 规则允许以 root 身份、使用不受限制的参数运行 Bee，那么当 Bee 能够初始化 Backdrop 安装时，就可能获得 root 代码执行。从站点目录运行，或使用全局 `--root=<directory>` 选项选择站点；仅仅发现 Bee 或 Backdrop 的 `settings.php` 文件，并不能证明存在 sudo 权限、可用站点或成功初始化。测试前应审查有效 sudo 规则、任何命令排除项、可执行文件的身份以及对站点的访问权限。被动枚举时检查规则和文件路径，不要调用 Bee。参见 [Bee 命令变更日志](https://github.com/backdrop-contrib/bee/blob/1.x-1.x/CHANGELOG.md)，其中记录了 PHP 命令的添加情况。

### 通过 sudo 运行 terminal server

`mosh-server` 会以调用者身份启动交互式 terminal server。它会选择一个高位 UDP 端口和 session key，将二者报告给调用者，并且通常会在客户端连接时启动该用户的登录 shell。因此，即使 server 命令本身会脱离终端运行，无限制且具备 root 能力的 `mosh-server` sudo 授权仍是 shell 审查候选项。检查有效 RunAs 身份、允许的参数和排除项、已安装的二进制、shell、客户端可用性和 UDP 访问。被动枚举时只检查 sudo 规则，不要启动 server 或打印任何有效 session key。参见 [Mosh server 手册](https://manpages.debian.org/unstable/mosh/mosh-server.1.en.html)和[上游设计说明](https://github.com/mobile-shell/mosh#how-it-works)。

### 会重写调用者任务文件的特权备份 wrapper

以 root 身份运行的 shell wrapper 可能接受调用者指定的任务文件、从源路径中删除 `../`、检查结果是否以允许的目录开头、重写任务文件，然后将其*路径名*传给备份程序。应在完整规范化解析后检查转换后的路径：单次字符串替换可能暴露新的目录遍历序列，从而通过词法前缀检查。还应检查备份程序读取的是转换后的内存数据，还是会重新打开文件。如果它重新打开文件，重写失败时原始输入可能仍未改变。

在 Linux 上，`fs.protected_regular` 可能会阻止进程通过 `O_CREAT` 写入其他用户在 world-writable sticky 目录中的常规文件。这种拒绝具有保护作用，但如果 shell wrapper 忽略写入错误，仍可能继续使用原始任务文件。确认该设置、文件所有者和目录，以及 wrapper 是否会在失败时停止。只有当有效 sudo 规则允许以特权用户身份运行 wrapper、调用者控制任务输入和可读备份目标，且备份工具确实包含受保护源文件时，这条路径才是文件泄露候选项。枚举时检查这些条件，不要运行备份。

### 特权 packet tool 的参数通配符

在 `tcpdump` 的 sudo 规则中，**参数模式**里的 `*` 可以匹配空白字符和斜杠，因此看似限制路径的模式仍可能允许附加选项文本。这与命令可执行文件路径中的通配符不同；应检查完整的 RunAs 规则和任何后续拒绝项。如果选项可被注入，那么允许的调用方式和已安装的 [`tcpdump` 选项语义](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)将决定 `-F`、`-V`、`-r`、`-w` 或 `-Z` 是否能提供有用的读取/写入原语。`-V` 读取的是捕获文件名列表，不是任意通用文件转储。即使 sudo 允许命令，AppArmor 或其他 MAC 策略仍可能阻止文件访问；磁盘上的 profile 文件不能证明它已加载或正在强制执行。下结论前应被动审查授权和策略。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)介绍了通配符差异。

如果具备 root 能力的 sudo 规则只列出 `tcpdump` 可执行文件而没有限制参数，也值得审查。[tcpdump 手册](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)说明，当 `-C` 或 `-G` 轮转保存的 capture 时，`-z` 会指定轮转后的命令；在该命令运行前，`-Z` 或编译时默认值可能会先降低权限。将该规则视为提权路径前，应核实有效 sudo 规则、已安装构建、降权行为，以及是否会发生轮转。高亮显示的规则只是候选项，并不能证明能以 root 身份执行命令。

### 通过 sudo 运行 Nmap wrapper

如果 sudo 允许的 `nmap` 路径实际上是 shell wrapper，应检查确切允许的路径以及它转发的每个选项。屏蔽常见的 `--script` 拼写不一定能阻止加载 NSE 代码：Nmap 的 [`--datadir`](https://nmap.org/book/man-misc-options.html) 可以指定数据文件，而启用 scripting 时，NSE 会从选定的数据目录加载 [`nse_main.lua`](https://nmap.org/book/nse-implementation.html)。某些已安装的构建还接受其他长选项拼写，因此应将规则限制与该二进制的实际 parser 进行对照。[`--excludefile`](https://nmap.org/book/man-target-specification.html)是另一个文件读取面；parser 错误可能泄露文本。枚举时应检查有效 sudo 规则、wrapper 逻辑、Nmap 版本、目录控制权和 MAC 策略，不要运行扫描。

### 通过 sudo 运行 Mercurial pull hook

固定的 `sudo hg pull /fixed/source` 仍会使用当前工作目录中的仓库作为**接收端**，除非命令通过 `-R` 固定仓库位置。调用者控制的接收仓库可以在 `.hg/hgrc` 中定义 hook，而 hook 可能以 sudo RunAs 用户身份运行。[Mercurial 会忽略由不可信用户或组拥有的仓库配置](https://mercurial-scm.org/help/topics/config)，因此在将其视为代码执行前，应检查 RunAs 账户的受信任用户/组和确切工作目录。被动审查只需读取策略和配置；枚举时不要执行 pull 或调用 hook。

### 通过 sudo 运行 Git pull hook

对于精确的 root-capable `sudo git pull` 授权，还应检查由工作目录选中的**接收端**仓库。调用者拥有的仓库可以包含可执行的 `post-merge` hook；当 pull 实际执行成功合并时，该 hook 会以 Git 进程的身份运行。[Git 文档介绍了该 hook](https://git-scm.com/docs/githooks)和 [pull 的 merge/rebase 行为](https://git-scm.com/docs/git-pull)。核实有效 sudo 规则和 CWD、活动 hook 路径及其权限，以及是否可能执行带有新提交的合并。失败、无操作或仅进行 rebase 的 pull 并不能证明这条 hook 路径成立。检查策略和仓库元数据，不要运行特权 pull。

### 通过 sudo 运行 rsync 归档复制

对于 `sudo rsync -a ... /writable/source/* /fixed/destination/`，**sudoers 参数模式**中的 `*` 可以匹配空白字符，从而允许在源和目标之间插入额外选项。这与 shell 对文件名进行展开不同。如果调用者能填充源目录，且特权 rsync 进程可以写入目标目录，那么 [`--chown`](https://download.samba.org/pub/rsync/rsync.1) 就可能要求设置特权所有权，而 archive 模式会保留权限位，从而可能创建归调用者所有的 SetUID 文件。检查确切的 [sudoers 通配符语义](https://man7.org/linux/man-pages/man5/sudoers.5.html)、rsync 版本、后续拒绝项、文件系统的 `nosuid` 和 MAC 策略。匹配的规则只能作为审查候选项，并不能证明提权成功。

### 通过 sudo 导出 packet-filter 规则

如果同时存在针对 `iptables` 和 `iptables-save`（或对应 `ip6tables` 组合）的无限制 root-capable 授权，就值得审查文件写入路径。`comment` match 接受调用者选择的规则文本，而 `iptables-save -f` 会将序列化后的规则集写入指定路径。<sup>[[20]](#references)[[21]](#references)</sup>能否构造有用的 payload，取决于已安装 backend 如何序列化注释，以及目标文件是否接受导出内容中的其他行；单独使用 `iptables-save` 并不能提供任意选择内容的能力。检查确切的 sudo RunAs 身份、参数和排除项、可用的 match extension、backend 以及目标权限。枚举期间检查授权，不要修改防火墙规则或写入文件。

### 特权 Below 日志目录

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w)影响了 0.9.0 之前会创建 world-writable `/var/log/below` 目录的 Below 版本。如果 service 或获准的 sudo 命令以 root 身份运行了受影响的构建，那么能写入并遍历非 sticky 日志目录的用户，可能会在特权进程打开日志条目之前将其替换为 symlink。检查已安装软件包的补丁状态、确切的特权执行路径、有效目录访问权限、sticky bit 和 ACL，以及 `/var/log/below/error_root.log` 的元数据。仅有 world-writable 路径或 sudo 规则，并不能证明整个攻击链成立。sticky 目录或厂商回移补丁会改变评估结果。被动枚举只需检查元数据；无需创建链接或运行特权程序。

### 从可写输入收集特权 support bundle

获准通过 `sudo` 运行的 support-profile 脚本可能会以 root 身份读取固定日志路径，并将其内容复制到 profile 归档中。检查实际脚本是否会读取文件，然后确认调用者能否将源路径或其任一父目录条目替换为 symlink。如果特权读取会跟随该链接，且生成的归档可由调用者读取，就可能泄露受保护文件。必须同时存在 sudo 授权、可写源路径、特权读取和可读输出；仅有可写日志或 profile 文件名并不足够。枚举时检查有效权限和链接元数据，不要替换文件或生成 profile。[Nagios XI support 指南](https://support.nagios.com/forum/viewtopic.php?t=62758)介绍了其 root-run profile 脚本和输出归档，说明这类 bundle 为什么需要限制输入和输出访问。

### Root-run Python 归档恢复脚本

即使 sudo 规则严格限定了 Python 恢复脚本，也仍需审查其归档输入。如果调用者能选择或替换归档，而脚本以 root 身份通过 `tarfile.extractall(filter="data")` 解压，则应检查解释器是否已安装安全更新，再决定是否信任该 filter。CPython 在 3.9.23、3.10.18、3.11.13、3.12.11 和 3.13.4 中修复了多个 symlink 和 hard-link filter 绕过问题，包括 CVE-2025-4517。发行版的回移补丁也可能修复较早版本，因此显示的解释器版本本身不能证明存在风险。<sup>[[16]](#references)[[17]](#references)</sup>

被动审查时，读取确切的 sudo 命令和脚本，追踪哪个参数选择归档，并检查当前用户是否可以写入归档或其所在目录。分别确认已安装版本的厂商补丁和解压目标；`filter="data"` 并不意味着所有不可信归档都是安全的。<sup>[[16]](#references)[[17]](#references)</sup>

### 通过 sudo 运行 machine-learning model loader

如果 sudo 规则允许调用者选择 `.pt`、`.pth` 或 `.ckpt` 文件，而特权脚本会将该文件传给 [`torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load.html)、`pickle.load` 或其他基于 pickle 的 loader，则值得审查。检查有效 RunAs 规则、调用者能否创建或替换所选 model，以及参数如何经过 shell wrapper 流入 Python helper。`.pth` 扩展名也用于与模型加载无关的 Python site 配置文件，因此扩展名本身并不能证明发生了 model 加载。归档扫描或静态 pickle 扫描也不能证明后续加载是安全的；应检查 loader [依赖版本的 `weights_only` 行为](https://docs.pytorch.org/docs/stable/notes/serialization.html)及任何 allowlist。参见 [ML pickle 和 Fickling 说明](../../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)。被动枚举时绝不要加载或解包 model。

### 通过 sudo 解析已存储输入中的表达式

通过 sudo 以 root 身份运行的固定 Python 脚本，仍可能求值低权限用户能存入应用数据库的文本。在 TensorFlow 中，调用 `preprocess_input_exprs_arg_string(value, safe=False)` 会选择 `eval` 路径；[TensorFlow 安全公告](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-75c9-jrh4-79mc)介绍了不安全的 parser，以及对其命令行调用方的修复。即使命令行调用方已修补，应用程序显式使用 `safe=False` 的调用仍需单独审查。检查有效 sudo 规则、谁能修改确切输入行、过滤或打分逻辑是否允许该行到达调用点，以及已安装函数的行为。仅有 TensorFlow 版本、sudo 授权或硬编码模型文件，都不能证明整条攻击链成立。被动检查脚本和数据流；枚举时不要运行特权 helper 或提交测试表达式。

### 通过 sudo 加载 needrestart 配置

`needrestart -c` 会加载调用者选择的 Perl 配置文件并执行其中内容。如果 `sudo -l` 允许以 root 身份运行 `needrestart`，且参数允许使用 `-c`，而调用者能在可写位置选择一个可读配置文件，该权限就可能导致 root 代码执行。检查确切的 sudo RunAs 和参数规则；只允许固定参数列表的规则可能会阻止这条路径。这与 needrestart 的 interpreter-scanning 漏洞不同：更新软件包或禁用 `interpscan`，并不会使不受限制的 root `-c` 授权变得安全。<sup>[[2]](#references)[[18]](#references)[[19]](#references)</sup>

### 通过 sudo 以另一账户身份运行 Python import

固定的 Python 入口点仍可能导入调用者能编辑或替换的模块，包括 sudo 以**非 root**服务用户运行脚本的情况。对于字面量 `from utils import status`，应检查本地 `utils/__init__.py` 和 `utils/status.py`，以及 package 目录权限。将可写文件视为执行路径前，应确认脚本的 import path、确切的允许 sudo 参数，以及相关操作是否会到达该 import。枚举期间检查文件和权限，不要 import 或运行脚本。<sup>[[2]](#references)[[3]](#references)</sup>

对于精确授权 `python3 /absolute/script.py` 的 sudo 规则，只要求脚本可读；文件不必可执行，也不必有 shebang。还应检查**缺失的**本地模块：如果脚本导入的模块，其文件名可以在调用者可写的脚本目录中创建，Python 就可能以 RunAs 身份加载该文件。确认有效 sudo 规则、解释器实际的[模块搜索路径](https://docs.python.org/3/library/sys_path_init.html)、该模块是否内置或冻结，以及 import 是否会被执行。直接针对脚本的 sudo 规则有不同的可执行位和 shebang 要求。另一个 wrapper 如果在 `sudo -u account` 后追加调用者提供的 token，也需要检查参数流：这些 token 中的另一个 `-u` 只有在被调用的 sudo 策略允许最终身份时才有影响。仅靠静态字符串不能证明任一路径成立。

### 通过 sudo 使用调用者可控配置运行 Apache

如果 sudo 规则允许以特权身份运行 `apachectl`、`apache2ctl` 或 `httpd`，并通过 `-f` 指定调用者控制的配置文件，则应检查该文件及其父目录的权限。Apache 的 [`LoadModule`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadmodule) 指令接受模块名和**模块文件名**；[`LoadFile`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadfile) 也会加载文件。[`Include` 和 `IncludeOptional`](https://httpd.apache.org/docs/2.4/mod/core.html#include) 可扩展配置，或通过错误暴露文件内容。自定义 wrapper 可能会验证这些路径、降权或限制参数，因此单独存在可写配置文件只能作为审查候选项，并不能证明代码执行。下结论前应检查路径规范化、symlink 和指令解析。

### 通过 sudo 使用调用者可控配置运行 nginx

不受限制且具备 root 能力的 `nginx` 规则可能允许通过 [`-c` 选择其他配置](https://nginx.org/en/docs/switches.html)。审查确切的 sudo 参数和排除项、调用者能否提供配置，以及生成的 master 或 worker 是否仍能访问受保护路径。选择 `root` 并启用 `autoindex`，可能通过新 listener 暴露文件；[`dav_methods PUT`](https://nginx.org/en/docs/http/ngx_http_dav_module.html) 可能提供特权文件写入路径，但 DAV module 默认并非内置，必须检查其是否存在、listener 是否可达、文件权限和临时文件行为。[`error_log` 指令](https://nginx.org/en/docs/ngx_core_module.html#error_log)也可指定文件；要将日志写入 `/etc/ld.so.preload` 等敏感配置文件，必须同时具备有效的特权写入能力和可控日志记录，才能构成提权路径。`sudo -l` 中的可执行文件高亮只能作为审查线索，不能证明这些路径中的任何一条可行。被动枚举时不要启动或重新配置 nginx。

### 特权 Bash prompt 中的模式比较

如果 sudo 允许运行的 Bash 脚本会读取调用者输入的值，并通过 `[[ "$expected" == $entered ]]` 进行检查，那么 Bash 会把未加引号的右侧操作数解释为模式。因此，即使不知道期望值，通配符也可能通过比较。给操作数加引号（`[[ "$expected" == "$entered" ]]`）可进行字面字符串比较。检查确切 sudo 规则、prompt 是否可达，以及比较后脚本会做什么；仅凭语法本身不能证明存在可利用路径。枚举时不要打印期望值。参见 [Bash 条件结构参考](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)。

### 通过 sudo 运行会下载并执行文件的 helper

如果自定义 helper 接受调用者选择的 URL，将响应写入磁盘，随后又通过解释器或 shell 执行该文件，那么对其进行不受限制且具备 root 能力的 sudo 授权就值得检查数据流。[Sudoers 规定，命令条目不列出参数时，可接受任意参数](https://man7.org/linux/man-pages/man5/sudoers.5.html)；固定的可执行文件路径并不限制参数能选择的内容。确认已安装 helper 中的实际 URL 验证、输出路径、成功分支和后续执行流程。仅有匹配的 libcurl import 或可打印字符串，不能证明这条攻击链成立。

即使输出文件名固定，只要 helper 在调用者可控的工作目录中使用**相对路径**，文件仍可能在写入和执行之间被替换。在目录中重命名或替换 root-owned 文件，取决于目录的写入/搜索权限以及任何 sticky-bit 限制，而不只是文件本身的 mode；参见 [`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html)。检查 helper 后续是重新打开路径，还是使用已打开的 descriptor，以及它是否在写入前切换到受信任目录。被动检查 sudo 策略、helper 和目录元数据；枚举时不要调用特权下载或进行竞态攻击。

以 root 身份运行的 sudo 下载 helper 若构造了 `curl <caller input> -o <fixed output>` 这样的 Bash 命令字符串，也可能暴露**参数**注入。拒绝空白字符的过滤器仍无法阻止 [Bash brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html)：未加引号、以逗号分隔的元素可能变成多个 curl 参数。如果输入在固定的 `-o` 之前传给 curl，调用者提供的输出选项就可能以 helper 的身份指定第一个 URL 的目标；[curl 会按顺序将输出选项与 URL 关联](https://curl.se/docs/manpage.html#-o)。确认确切的 shell、引号、输入验证、有效 sudo 规则、curl 参数顺序和支持的 URL scheme，以及调用者是否控制获取的字节或能读取结果。PyInstaller 打包的可执行文件可能包含 Python 应用逻辑，但打包标记或 `curl` 字符串本身并不能证明数据流成立。获准时检查范围受限的离线副本；常规枚举不要运行 helper 或获取攻击者选择的数据。

以 root 身份运行的 sudo shell 脚本如果调用 [`mktemp -u` / `--dry-run`](https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html)，只会选择一个未使用的名称；它**不会**创建文件。如果脚本稍后在其他用户能影响的目录中创建该名称，重新打开文件，并将其内容追加到 root 的 `authorized_keys` 等受保护目标，则应审查潜在的临时文件竞态。确认确切的 sudo 规则、目录和文件所有权、创建及重新打开的顺序、内核防护，以及特权写入是否确实使用了攻击者控制的字节。仅有 `mktemp -u` 字符串或可写的 `/tmp`，并不能证明存在竞态。枚举时检查脚本和路径元数据，不要运行脚本或争抢其临时文件。

## 防御说明

- 避免通过 sudo 授权运行解释器或交互式编辑器。<sup>[[1]](#references)</sup>
- 优先使用由 root 拥有、只执行单一狭窄管理操作的固定 wrapper。<sup>[[1]](#references)[[2]](#references)</sup>
- 如果无法避免使用解释器，应限制确切脚本路径，并阻止用户控制的参数、可写 import、`PYTHONPATH` 以及不安全的环境保留。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- 如果必须编辑文件，应限制确切文件路径，并考虑搭配已修补的 sudo 版本和严格环境处理使用 `sudoedit`。<sup>[[1]](#references)[[2]](#references)</sup>
- 审查 `SETENV`、`env_keep`、可写工作目录、可写模块/import 路径、`NOEXEC`、`use_pty` 和日志记录，但不要将它们视为完整的 sandbox。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [命令行和环境 — Python 文档](https://docs.python.org/3/using/cmdline.html)
- [4] [os — 杂项操作系统接口 — Python 文档](https://docs.python.org/3/library/os.html)
- [5] [perlrun — 如何执行 Perl 解释器](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl 文档](https://perldoc.perl.org/functions/exec)
- [7] [Ruby 命令行选项](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby 文档](https://ruby-doc.org/3.4/Kernel.html)
- [9] [命令行 API — Node.js 文档](https://nodejs.org/api/cli.html)
- [10] [子进程 — Node.js 文档](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua 手册页](https://www.lua.org/manual/5.4/lua.html)
- [12] [GNU nano 文本编辑器](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [重定向 — Bash 参考手册](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [16] [Python 3.9.23–3.13.4 安全版本](https://discuss.python.org/t/python-3-13-4-3-12-11-3-11-13-3-10-18-and-3-9-23-are-now-available/94367)
- [17] [tarfile 解压过滤器 — Python 文档](https://docs.python.org/3/library/tarfile.html#extraction-filters)
- [18] [needrestart 配置选项和求值 — 上游源码](https://github.com/liske/needrestart/blob/master/needrestart)
- [19] [needrestart 命令行为 — GTFOBins](https://gtfobins.org/gtfobins/needrestart/)
- [20] [iptables-save(8) — netfilter 手册页](https://www.man7.org/linux/man-pages/man8/iptables-save.8.html)
- [21] [iptables-extensions(8)：comment match — netfilter 手册页](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [22] [简单命令展开 — Bash 参考手册](https://www.gnu.org/s/bash/manual/html_node/Simple-Command-Expansion.html)
- [23] [Forge 编译器选项 — Foundry 文档](https://getfoundry.sh/forge/reference/forge-inspect/)
- [24] [Forge flatten — Foundry 文档](https://getfoundry.sh/forge/reference/forge-flatten/)
- [25] [pacman(8) — Arch 手册页](https://man.archlinux.org/man/pacman.8.en)
- [26] [PKGBUILD(5) 安装脚本 — Arch 手册页](https://man.archlinux.org/man/core/pacman/PKGBUILD.5.en)
{{#include ../../banners/hacktricks-training.md}}
