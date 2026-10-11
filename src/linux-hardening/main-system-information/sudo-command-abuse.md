# Sudo 命令滥用

{{#include ../../banners/hacktricks-training.md}}

## Sudo 允许的解释器

如果 `sudo -l` 允许用户以 root 身份运行解释器，应将其视为直接 code execution。解释器本身就是为执行任意代码而设计的，因此，允许运行 `python3`、`perl`、`ruby`、`lua`、`node` 或类似二进制文件的规则，通常等同于允许执行 root 命令，除非参数受到严格限制和验证。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

常见的审查流程：先列出用户的权限，然后使用解释器的 `-c` 选项执行一条 Python 语句。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

其他解释器示例如下；所列解释器文档介绍了 inline-code 执行或子进程 API。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

路径必须完全一致。如果 sudo 规则允许 `/usr/bin/python3`，验证时就使用该确切路径。<sup>[[2]](#references)</sup>

像 `/usr/bin/python*` 这样的 sudo 可执行文件 glob 也可能允许使用 Python 2 运行为 Python 3 编写的脚本。如果脚本在调用方可控的文本到达 `input()` 时执行，[Python 2 会将该文本作为表达式求值](https://docs.python.org/2/library/functions.html#input)；显式调用解释器会覆盖脚本的 shebang。应核实已安装且匹配的二进制文件、有效的 RunAs 和参数策略、拒绝规则，以及可触达的输入，再将其视为一种执行路径。

可通过 sudo 以 root 身份执行的固定脚本路径，并不会限制脚本实际执行的内容。对于可读的 Bash 包装脚本，如果 sudo 允许调用方选择参数，应检查它的第一个可执行命令是否将未加引号的位置参数（如 `$1`）用作**命令词**。确认有效的 RunAs 身份、密码和参数策略、后续拒绝规则，以及脚本实际进入的分支；`NOEXEC`、固定的安全参数列表，或会验证命令的包装脚本都可能改变结果。在枚举期间静态检查这个短脚本，不要用测试命令调用它。

允许以 root 身份不受限制地执行 `dotnet` 的 sudo 规则也值得检查其解释器功能。安装了 .NET SDK 时，[`dotnet fsi` 可交互式运行 F# 代码，也可从脚本运行](https://learn.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/)，而 [`dotnet run` 可从源代码运行项目](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run)。应先确认有效的 RunAs 身份和确切的参数策略：限定为特定安全子命令或受信任应用程序的规则属于另一种授权；仅安装运行时的环境可能不具备 SDK 命令。可执行文件名称本身只是需要审查的提示，不能证明代码执行能力。

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## Sudo 允许的编辑器

如果 `sudo -l` 允许用户以 root 身份运行交互式编辑器，请将其视为命令执行入口，而不是无害的文件编辑权限。编辑器通常可以执行 shell 命令、读取任意文件、写入任意文件，或在编辑器内部调用外部辅助程序。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

常见的审查流程：列出用户的权限，然后通过 sudo 调用每个允许使用的编辑器或分页器。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```

### Nano 命令执行

如果允许通过 sudo 使用 `nano`，则可能可以从编辑器界面执行命令。<sup>[[12]](#references)</sup>

```text
Ctrl+R
Ctrl+X
```

然后在 nano 命令提示符中输入类似 `id` 或 `/bin/sh` 的命令。<sup>[[12]](#references)</sup>

```bash
id
/bin/sh
```

如果交互式 shell 没有可用的终端流，此重定向形式会将其标准输出和错误输出映射到文件描述符 0。<sup>[[15]](#references)</sup>

```bash
reset; /bin/sh 1>&0 2>&0
```

具体按键序列可能因 nano 版本和构建选项而异，但安全问题相同：编辑器以 root 身份运行，并且可以调用外部命令。<sup>[[1]](#references)[[12]](#references)</sup>

### 其他常见的编辑器逃逸方式

Vim 风格的编辑器通常可以通过 `:!` 执行命令。<sup>[[13]](#references)</sup>

```text
:!/bin/sh
```

像 `less` 这样的 pager 也可能暴露 shell 执行功能。<sup>[[14]](#references)</sup>

如果 sudo 规则允许以 root 身份运行 `apport-cli`，也应同样检查 pager。受影响的 Apport 版本可能会在 `less` 中打开崩溃报告，并允许攻击者调整终端大小；若满足特定的 sudo 和 pager 条件，pager 随后可能提供 root shell。在仅凭版本号判定其存在漏洞之前，请检查有效的 sudo 规则、pager 配置以及发行版的软件包修复情况。被动枚举时，应读取软件包和策略元数据，不要生成崩溃或打开特权报告。[Ubuntu 的 CVE 记录](https://ubuntu.com/security/CVE-2023-1326)列出了针对各发行版的已修复软件包版本，其中包括回移植的修复。

```text
!/bin/sh
```

## 其他 sudo 和 doas 规则风险

从 `sudo -l`、`sudo -V` 和适用的 `doas` 策略开始检查。综合查看允许执行的命令、运行身份、参数、环境和默认设置。即使只允许以非 root 服务账户身份运行，也可能暴露该账户的文件，或提供通往 root 的途径。

固定为 sudo 允许执行的 Python 脚本，如果把交互式、由调用者控制的输入拼接到 [`os.system()`](https://docs.python.org/3/library/os.html#os.system)，仍可能以其 RunAs 身份运行 shell 命令。仅禁止部分 shell 标点不足以证明安全：[shell 也会识别 `$(...)` 命令替换](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html)。确认允许的参数能否到达输入分支、输入是否未经安全验证便传入 shell 命令，以及生效的 sudo 策略是否允许目标 RunAs 用户。脚本路径或 `os.system()` 调用本身只是审查线索；应检查源码，不要调用特权脚本。

授予 root 身份下有效的 `chattr` sudo 权限，可以移除文件的 immutable（`i`）属性，但这本身并不会授予写入权限或切换身份的能力。[`chattr` 手册](https://man7.org/linux/man-pages/man1/chattr.1.html)指出，该属性会阻止修改，且只有 root 或拥有 `CAP_LINUX_IMMUTABLE` 的进程才能更改它。检查精确的 sudo 参数策略和文件系统支持情况，然后另行确认清除属性后调用者是否能写入文件，以及更高权限的使用方是否会使用该文件。例如，替换登录 shell 还要求目标账户接受相应凭据，并且确实通过该 shell 登录。枚举期间只审查策略、文件属性和权限，不要修改它们。

如果 sudo 同时要求密码和一次性验证码，请将这些前置条件与命令授权分开看待。可读的 `.google_authenticator` 文件包含敏感种子材料；旧应用或数据库中的密码哈希也只是当前账户密码的候选值。两者都不能证明生效的 PAM 配置接受另一种因素。获准后，检查精确的 RunAs 身份和参数：允许以 root 身份不受限制地运行 RubyGems `gem`，可能暴露其 editor 命令（[GTFOBins](https://gtfobins.github.io/gtfobins/gem/)）；但受限授权或认证失败则不会。被动枚举应报告路径和策略，不要打印种子、破解密码、生成验证码或调用特权命令。

允许以 root 身份不受限制地运行 Chef 的 `knife`，值得进行解释器级审查：[Chef 文档说明，`knife exec -E` 会在本地求值 Ruby 字符串](https://docs.chef.io/workstation/26/tools/knife/knife_exec/)。确认生效的 sudo 规则允许 `exec` 子命令和调用者提供的 `-E` 参数、目标 RunAs 身份，以及任何匹配的命令拒绝规则或固定参数。已安装的二进制文件，或仅允许其他子命令的规则，都只是审查线索。被动枚举应报告规则，不要调用 `knife`。

允许以 root 身份精确运行交互式 `msfconsole` 的 sudo 授权同样敏感：[GTFOBins 记录了它的 `irb` 控制台](https://gtfobins.org/gtfobins/msfconsole/)，该控制台可能继承 sudo 身份。确认生效的 RunAs 用户、允许的参数列表、命令拒绝规则、`NOEXEC` 或其他限制、已安装控制台的行为，以及调用者能否提供交互式输入。仅仅在路径上看到高亮只是审查线索；被动枚举时不要启动控制台。

在 FreeBSD 上，即使 sudo 规则仅允许 root 执行 `pkg update` 和 `pkg install *`，也值得审查仓库信任。检查调用者是否能写入 `/etc/hosts`，以及*生效的*已启用仓库配置是否使用设置为 `signature_type: none` 的 HTTP 主机名。[FreeBSD 的 `pkg.conf` 手册](https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5)说明，`none` 会禁用签名检查；仅有 `pkg+http` 并不能证明这一点。软件包可以包含安装脚本（[FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/pkg-files/)），因此，只有调用者实际控制仓库端点并能选择软件包时，才可能越过 root 边界。得出结论前，应验证仓库覆盖配置、SRV/镜像解析、生效的 sudo 参数、软件包选择和脚本执行情况。检查策略和较小的本地配置文件；枚举时不要重定向名称或运行 `pkg`。

如果 sudo 会保留由调用者控制的 `http_proxy`，允许以 root 身份运行 `apt-get update` 和 `apt-get upgrade` 的 sudo 规则也需要审查仓库信任。检查生效的 APT 代理配置是否确实使用该变量，以及它可能影响哪些已启用仓库请求；仅有代理并不能替换由可信签名密钥认证的归档内容。[APT 的 HTTP transport 手册](https://manpages.debian.org/experimental/apt/apt-transport-http.1.en.html)说明了代理优先级，[apt-secure](https://manpages.debian.org/experimental/apt/apt-secure.8.en.html)则说明了签名检查、不安全仓库覆盖设置，以及对未认证软件包的确认要求。确认精确的 sudo RunAs 身份和参数、仓库认证策略、是否需要交互式确认，以及所选升级是否会以 root 身份运行软件包脚本。被动检查策略和本地配置；枚举期间不要重定向软件包流量或运行升级。

允许以 root 身份运行 `snap install` 的 sudo 规则，如果参数允许调用者选择本地 snap 并使用宽松安装模式，就可能形成从软件包到代码的边界。[Snap 文档](https://snapcraft.io/docs/explanation/snap-development/install-modes/)说明，`--dangerous` 会跳过本地 snap 的 assertion 检查，`--devmode` 会放宽隔离；[安装钩子可以在首次安装时运行](https://snapcraft.io/docs/reference/development/supported-snap-hooks/)。在声称可访问受保护的主机文件之前，应检查精确的 sudo 参数/RunAs 策略、谁控制 snap 文件、已安装的 snapd 是否接受这些模式，以及钩子的有效身份和隔离状态。仅有 `snap` 二进制文件或看似包含通配符的规则，并不能证明这条链路成立。被动枚举时不要安装软件包或执行其钩子。

对于精确授权以**非 root**账户身份运行自定义凭据读取二进制文件的 sudo 规则，应先在不运行该文件的情况下检查其内容和文件权限。内嵌的密码门槛可能只有在提取宽字符时才可见；[GNU `strings` 文档介绍了 16 位小端格式提取](https://sourceware.org/binutils/docs/binutils/strings.html)。可见字符串不能证明它就是有效密码，也不能证明成功分支会暴露当前凭据。应分别确认二进制文件的行为、目标账户对受保护数据的访问权、凭据有效性，以及后续账户或组身份转换。如果该账户属于 `docker` 组，应验证 socket 访问权限以及 daemon 使用 rootful 还是 rootless 身份，再判断能否访问主机 root；[Docker 文档说明了该组的 root 级影响](https://docs.docker.com/engine/install/linux-postinstall/)。常规枚举只应报告 sudo 规则和组成员关系，不要执行二进制文件或转储其字符串。

应用维护脚本的通配符 sudo 规则，审查范围不应仅限于脚本路径。检查允许的脚本是否接受不受限制的参数，或是否读取低权限应用账户可写的设置；然后追踪这些值是否流入 shell 命令或子进程环境。例如，ZoneMinder 的 [`zmupdate.pl` 会组装 `mysqldump` 命令并通过 `qx` 执行](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmupdate.pl.in)，而 [`zmdc.pl` 会在启动 daemon 前将 `ZM_LD_PRELOAD` 设置复制到 `LD_PRELOAD`](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmdc.pl.in)。如果调用者能控制相应输入，并且这些输入在已安装版本中到达相关代码，那么允许以 root 身份运行任一脚本的 sudo 规则就可能越过信任边界。检查生效的 sudo 规则、应用配置的写入权限和脚本源码；通配符或设置本身只是审查线索，并非执行的证明。

- `SETENV`、`env_keep`、`secure_path` 和 `LD_PRELOAD` 可能使原本范围狭窄的命令遭受 import、库或 PATH 劫持。参见[环境变量指南](../linux-basics/linux-environment-variables.md)和 [SUID/linker 滥用](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md)。

如果一个精确允许以 root 身份运行、带有 `SETENV` 的 sudo 授权会启动 shell wrapper，且该 wrapper 用字面量 import 启动固定 Python 脚本，那么也值得审查这条单跳链路。`secure_path` 会限制 shell 的命令查找，但不会限制 Python 的 [`PYTHONPATH` 模块搜索](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH)；[`-E` 和 `-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-E) 会让 Python 忽略该环境变量。在将其视为代码执行之前，应确认生效的 sudo tags 和拒绝规则、wrapper 分支、解释器选项、import 解析方式，以及调用者是否拥有可写的搜索目录。静态检查简短脚本，不要调用特权 wrapper。

即使精确的 root 身份 `neofetch ""` sudo 授权允许的参数为空，只要适用的 sudo 默认设置保留了由调用者控制的 `XDG_CONFIG_HOME`，它仍可能加载 shell 配置。[Neofetch 的配置加载器](https://github.com/dylanaraps/neofetch/blob/master/neofetch)会从该目录下加载 `neofetch/config.conf` 或 `neofetch/config`；空参数列表不会阻止这项查找。确认已安装版本的加载器、生效的 RunAs 和参数策略、任何命令拒绝规则、sudo 对该命令是否确实保留所选变量，以及调用者是否控制可读取的配置路径。保留变量或已安装 Neofetch 本身只是审查线索。检查策略和文件元数据，不要调用特权命令或打印配置内容；另见 [sudoers 环境处理](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)。

允许以 root 身份不受限制地运行 `facter` 的 sudo 规则值得单独审查 custom fact。[Puppet 文档](https://help.puppet.com/core/current/Content/PuppetCore/loading_custom_facts.htm)说明，`--custom-dir` 会从所选目录加载 Ruby fact 文件。检查精确的 sudo 规则是否允许该选项、已安装的 Facter 是否接受该选项，以及调用者是否控制该目录。固定参数授权、明确的命令拒绝规则或已禁用的 custom facts 都可能改变结果。被动枚举应报告候选策略，不要调用 Facter 或读取 fact 内容。

对于带 `SETENV`、精确允许以 root 身份运行脚本的 sudo 授权，应检查 `find` 等裸命令名称，以及 sudo 策略和脚本初始化后生效的 `PATH`。被 source 的 Bash 文件也可以运行 `enable -n [`：[之后 Bash 会在 `PATH`](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)中查找外部 `[`，供脚本稍后调用。确认适用的 [sudoers 环境和 `secure_path` 规则](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)、任何 `NOSETENV`/`NOEXEC` 或拒绝条目、脚本及被 source 文件的执行流程，以及调用者控制的可执行搜索目录。可读脚本中出现裸命令只是审查线索，并不能证明会执行特权操作；应检查脚本，不要调用 sudo 规则。
- 即使脚本只用 `curl` 从固定 URL 获取内容，只要适用的 sudo 规则保留 `http_proxy`，且请求通过该代理发送，特权脚本仍可能接受调用者选择的响应。如果脚本随后把响应交给会解析外部实体的 XML parser，恶意响应可能泄露特权进程可读取的文件。检查精确的 sudo 环境策略、`no_proxy` 排除项、请求的 URL、parser 配置和输出位置；仅有代理变量或 XML parser 并非漏洞。[curl 代理环境文档](https://everything.curl.dev/usingcurl/proxies/env.html)说明了变量的行为。被动枚举时不要发起网络请求或解析恶意 XML。
- 如果有一条可用 root 权限的 sudo 脚本根据调用者影响的数据生成 PostScript 文件，然后运行 `ps2pdf -dNOSAFER`，就值得单独审查输入流。Ghostscript 文档说明，该标志会禁用 SAFER，直到调用 `.setsafe`，因此进程可按自身 OS 权限执行 PostScript 文件操作。由调用者参数组装的 SQL 查询可能会将攻击者控制的行传入 PostScript 模板，但仅有查询字符串或 `ps2pdf` 调用并不能证明这些数据会进入可执行的 PostScript 语法。确认生效的 sudo 规则、从输入到模板的精确路径、任何转义处理、已安装的 Ghostscript 行为，以及文档解释前是否重新启用 SAFER。被动枚举时不要调用特权转换命令。参见 [Ghostscript 的 `-dNOSAFER` 文档](https://ghostscript.readthedocs.io/en/master/Use.html)。
- 对于运行 shell 脚本的 sudo 规则，应结合脚本内容检查被保留的变量。类似 `if $CHECK_CONTENT; then` 的结构会把展开后的值作为命令运行，因此即使脚本路径和参数固定，保留 `CHECK_CONTENT` 也可能允许命令执行。必须针对具体规则确认该分支是否可达，以及环境是否确实会被保留。<sup>[[2]](#references)[[22]](#references)</sup>
- sudo 允许运行的 Python 脚本可能从可写目录或缓存的 `.pyc` 文件导入代码。[权限提升指南](../linux-basics/linux-privilege-escalation/README.md)详细介绍了缓存相关情况。
- 固定且由 sudo 允许运行的 Python 脚本仍可能暴露交互式 debugger。如果调用者能到达断点或异常处理器，**并控制 debugger 的输入流**，那么 `pdb.set_trace()` 或 `pdb.post_mortem()` 等调用会允许在被调试进程的上下文中执行 Python 语句。检查精确的 sudo RunAs 规则、认证和分支条件、异常是否可触发、终端/输入的所有权，以及 debugger 是否运行在同一特权进程中。触发异常的 socket 请求本身，并不能让调用者访问连接到另一终端的 debugger。[Python 文档介绍了 debugger 的语句求值和 post-mortem 模式](https://docs.python.org/3/library/pdb.html)；枚举时应静态检查脚本，而不是触发特权处理器。
- 固定且由 sudo 允许运行的 Python 脚本还可能从数据库或 Unix socket 读取配置文件字段，并将其追加到字符串中，随后用作 `str.format()` 的**格式字符串**。[替换字段可以访问属性和 mapping 键](https://docs.python.org/3/library/string.html#format-string-syntax)，因此，如果攻击者能控制该字段，它就可能检查传给 `format()` 的对象，并暴露这些对象可访问的数据，前提是结果会被打印或存储到调用者可读取的位置。检查生效的 sudo RunAs 身份、对特定记录的写入权限、数据流是否进入格式字符串、传入了哪些对象，以及输出是否可见。这不会自动造成代码执行；使用字面量可信格式字符串、只由攻击者控制*值*，是另一种情况。只有在某账户接受所泄露的 secret 时，它才可能促成 OS 账户身份转换。审查脚本和 socket 权限，不要调用特权操作。
- 可获得 root 权限的 Python wrapper 可能会将调用者选择的 URL 传给 GitPython 的 `Repo.clone_from`。如果 wrapper 还启用了 Git 的 `protocol.ext.allow=always`，那么 `ext::` 远程地址就可能调用外部 helper。检查精确的 sudo 参数、URL 来源、GitPython 软件包版本和供应商补丁状态，以及 wrapper 是否明确启用了不安全协议。GitPython 在 3.1.30 中加入了[默认的不安全协议防护](https://github.com/gitpython-developers/GitPython/commit/2625ed9)；`git` 可执行文件的版本则是另一项独立信息。被动审查只应读取规则和有限范围的源码，不要调用 clone。
- 跨用户 sudo 授权某个仓库克隆 CLI，可能暴露另一条 shell 字符串注入路径。追踪调用者选择的仓库参数是否未经安全的参数分隔，直接传入 Node.js [`child_process.exec`](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback) 或其他 shell 命令构造器；Node 的 `exec` 会把命令字符串传给 shell。确认精确的 RunAs 用户、允许的子命令和参数、已安装的 wrapper 代码，以及输入验证情况。仅有仓库工具名称或不受限制的 sudo 规则，并不能证明存在命令注入。枚举期间应检查 wrapper，不要调用特权 clone。
- 自定义的 root 所有 wrapper 可能看似安全，因为其二进制文件和脚本均不可写，但它是否执行特权操作可能取决于低权限用户能够更改的标志、本地 API 值或服务状态。追踪每个条件的输入及授权检查。枚举期间检查配置和权限，不要更改运行状态；只有当 wrapper 中的 `systemd-run` 调用所依赖的条件可被影响时，该调用才有意义。
- 允许通过 sudo 以 root 身份运行的备份客户端，可能接受调用者选择的配置文件（例如 `npbackup-cli -c`）。检查精确的运行身份和允许参数，然后确认调用者是否控制配置路径、备份源路径，以及仓库或读取/还原选项。可读配置中的加密仓库 secret 仍可能被客户端使用，但该规则本身并不能证明调用者可访问仓库或泄露 root 文件。应在不运行备份或转储其内容的情况下验证授权。
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst) 支持 `--password-command`，该选项会调用程序以获取仓库密码。如果 sudo 规则允许低权限用户以 root 身份运行 restic，并指定自选密码命令及需要密码的子命令，那么该 helper 可能以 root 身份运行。审查精确的 sudo 参数和排除规则；不要仅为枚举这一条件而调用 helper 或备份命令。
- 如果可用 root 权限的 `restic backup` sudo 参数模式允许调用者同时选择源以及其之后能够读取和解密的仓库，也可能越过文件读取边界。[sudoers 参数通配符可以匹配空白字符和斜杠](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)，因此应检查末尾的通配符，不要假设固定仓库前缀就能限制源路径。[Restic 可以备份到本地和远程仓库](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html)，但本地仓库可能包含新写入的、仅 root 可访问的对象；在将其视为泄露之前，应确认生效的 sudo 策略、后端访问权限、仓库密码和生成对象的权限。备份的 SSH key 只有在目标账户接受该 key 时才有用。被动审查时不要运行备份进行测试。
- 不受限制的自定义维护或备份命令可能接受输出路径，或提供自己的作业调度器。对于文件写入路径，应确认精确的 sudo 规则和运行身份，然后确认调用者是否同时控制数据和目标位置。对于定时命令路径，应确认调度器的执行身份、命令输入，以及是否存在其他密码或授权门槛。命令名称或 `NOPASSWD` 本身都不能证明任一途径成立。参见[写入 root 所有文件](../interesting-files-permissions/write-to-root.md)和 [cron 与 systemd timers](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md)。
- 固定 sudo 命令仍可能从共享可写目录加载可预测的配置文件。追踪调用者是否能替换该文件，以及其中的源和目标字段是否会控制特权 fetch 或 copy 操作。本地文件 URL 可能暴露仅 sudo RunAs 账户可读取的数据；调用者控制的源配合受保护的目标，则可能形成写入路径。确认已安装程序对 URL 的处理方式、目标路径检查、生效的 sudo 规则和输出可访问性。仅有可写的 `/tmp` 配置路径只是审查线索；应检查二进制文件和文件元数据，不要调用特权传输操作。
- `git apply` 的 sudo 规则可能让 RunAs 账户写入由调用者控制的补丁选定的文件。[CVE-2023-23946](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh)允许精心构造的补丁创建符号链接，再越出工作树写入，即使命令不接受 `--unsafe-paths` 也会如此。检查生效的 sudo 参数规则、补丁来源、RunAs 账户对工作目录的访问权限，以及已安装 Git 是否包含修复或供应商回补。允许 `--unsafe-paths` 的不受限制规则是另一项明确的选项风险；仅凭 Git 版本或 `git apply` 权限，都不能证明受保护文件可以被修改。被动枚举时不要应用不可信补丁。
- 如果低权限用户可以提供 DMG 镜像，且已安装的 parser 受可能通过 debug 输出泄露文件内容的 [CVE-2023-20052](https://blog.clamav.net/2023/02/clamav-01038-01052-and-101-patch.html)影响，那么可用 root 权限的 `clamscan --debug` 规则可能越过读取边界。确认精确的允许参数和扫描路径、输入控制权、有效的 RunAs 账户、引擎修复/回补情况，以及调用者是否能看到输出。如果更宽泛的规则允许 `--file-list`/`-f`，应单独审查该文件列表行为；固定为 `--debug <scan-path>` 的策略并不允许这些选项。枚举时检查策略和软件包元数据，不要扫描特制文件或打印受保护输出。
- 如果一条可用 root 权限的 sudo 规则会打开调用者选择的加密磁盘镜像，另一条规则又会挂载生成的 mapper，那么调用者控制的文件可能被导入主机的 mount namespace。确认两条生效规则及其参数、对镜像和 mapper 名称的控制权、实际挂载目标，以及生成文件的所有者和模式。额外的 set-user-ID 身份转换还要求存在可访问的可执行文件、支持该属性的挂载选项（`nosuid` 会阻止它），并且适用的进程或 MAC 策略允许；仅打开或挂载镜像只是审查线索。通过现有备份实现的另一条途径，还需要实际的 key，以及其中有用且可读取的 secret。被动枚举时只检查策略和路径，不要打开或挂载镜像。参见 [cryptsetup 手册](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)和 [mount 选项](https://man7.org/linux/man-pages/man8/mount.8.html)。
- 如果脚本未先切换到固定目录，却调用 `./helper`，则可用 root 权限的 shell 或 Python 脚本 sudo 规则值得审查工作目录。传给 `subprocess.run` 的 Python 列表 `['./helper']` 也可能受到调用者选择工作目录的影响。调用者可能选择一个可写目录，并在那里放置名为该相对路径的可执行文件；脚本中其他位置使用绝对路径并不能保护这次调用。在将其视为代码执行之前，应确认生效的规则、`runchdir` 或其他切换目录的策略、脚本流程和分支可达性、目录的可写和可执行权限，以及 mount/`NOEXEC` 限制。若脚本不可读，在通过授权途径审查源码前，行为仍属未知。静态审查脚本，不要运行 helper。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)介绍了工作目录策略。
- 可用 root 权限的固定 Python validator 仍可能对调用者选择的数据文件进行求值。[Python 的 `eval()` 文档警告不要使用不可信输入](https://docs.python.org/3/library/functions.html#eval)：如果输入的剩余部分能进入 `eval`，后缀检查、算术前缀或验证分支都不能构成 sandbox。在将其称为执行途径前，应确认生效的 sudo 规则、调用者是否能选择并控制特定文件、parser 的分支条件和表达式构造方式，以及特权进程身份。可读脚本中出现 `eval` 只是审查提示；枚举时应检查源码和文件权限，不要运行 validator 或提交测试表达式。
- 可用 root 权限的 sudo Ruby wrapper 如果读取相对 YAML 文件名（例如 `YAML.load(File.read("dependencies.yml"))`），而 wrapper 或 sudo 策略未固定工作目录，就可能从调用者的当前工作目录读取输入。检查精确的允许参数、目录和文件权限，以及已安装的 Psych 行为：较旧的 `YAML.load` 实现可能会反序列化任意 Ruby 对象，而较新的版本默认会限制类。静态调用点只是审查线索；应确认文件确实来自调用者可写目录，并且已安装的 loader 接受危险类。对不可信输入，优先使用带明确、精简类 allowlist 的 `safe_load`。参见 [Ruby 3.0 Psych 文档](https://docs.ruby-lang.org/en/3.0/Psych.html)和 [Ruby 3.1 Psych 文档](https://ruby-doc.org/core-3.1.2/Psych.html)。

- 对于精确允许以 root 身份执行 `sudo go run /absolute/file.go` 的规则，如果 Go 源码会读取相对路径的 WASM 文件，并可能在检查其结果后运行相对路径 shell 脚本，那么值得审查工作目录。确认生效的 RunAs 身份、命令参数和拒绝规则、调用者可写的当前目录、WASM 到分支的数据流，以及该分支是否会调用 helper。固定的 sudo `runchdir`、`os.Chdir` 或 [`exec.Cmd.Dir`](https://pkg.go.dev/os/exec) 都可能改变查找位置。静态共现只能作为候选线索；检查源码，不要运行 Go、WASM 或 helper。
- `sudoedit` 和参数通配符需要检查精确版本和规则；[检查清单](linux-privilege-escalation-checklist.md)包含 sudoedit 文件编辑问题。对于匹配通配符路径的跨用户 `sudoedit` 授权，应检查生效的 `sudoedit_follow` 或 `FOLLOW` 设置、`sudoedit_checkdir`、解析后的目标，以及谁能替换各级父目录条目。前者可能允许跟随符号链接；禁用后者会取消对可写目录的检查；但这两项设置都不能单独证明可写入其他用户的文件。得出结论前，应确认已安装的 sudo 策略和实际匹配的参数。参见 [sudoers 选项定义](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)。
- 在 sudoers 命令规则中，参数通配符既可匹配路径字符，也可匹配空白字符。对于允许读取文件的命令，如果参数类似 `/restricted/*`，匹配前缀后可能还允许额外的文件参数。审查精确的 RunAs 用户、命令路径、参数模式和后续拒绝规则；证明可以读取文件，并不意味着可以执行命令。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)区分了参数 glob 和命令路径 glob。
- 看起来像路径的参数 glob 也可能匹配 `../`。例如，可用 root 权限运行 `node /opt/scripts/*.js` 的规则，可能允许调用者选择 `/opt/scripts/` 以该前缀开头、但通过父目录段解析到 `/opt/scripts` 之外的 JavaScript 文件。这是**参数** glob；Node 可执行文件的命令路径 glob 使用不同的斜杠匹配规则。在判定能否执行代码前，应检查生效规则、后续拒绝规则、路径解析、目标文件控制权，以及 sudoers 正则表达式或 digest 限制。参见 [sudoers 通配符规则](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)和 [Node 命令行文档](https://nodejs.org/api/cli.html)。
- 归档工具和其他实用程序可能带有执行钩子。应根据[GTFOBins](https://gtfobins.github.io/)检查精确的允许参数，不要假设只有 shell 或解释器才会执行命令。
- 不受限制的、可用 root 权限运行 `qpdf` 的规则，可能通过 PDF 附件暴露特权文件：qpdf 10.2 及更高版本支持 `--empty` 和 `--add-attachment file ... --`，并接受输出 PDF。如果特权进程能读取所选源文件，且能将 PDF 写入调用者可访问的路径，那么该输出就可能包含源文件字节。在判定文件是否可能泄露前，应审查生效的 sudo 参数和排除规则、qpdf 版本、源文件访问权限和输出路径。只有当 root SSH key 有效且允许 root SSH 认证时，读取它才对登录有用。参见 [qpdf 附件选项](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments)。
- sudo timestamp 的复用取决于缓存策略、所有者用户、终端/会话和权限。[权限提升指南](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens)介绍了相关检查。
- `doas` 有自己的规则和配置。请按 [doas 部分](../linux-basics/linux-privilege-escalation/README.md#doas)所述，检查允许的命令和可写配置路径。

### 通过 sudo 运行的构建与软件包工具

即使 RunAs 身份是另一个非 root 用户，对 Foundry 的 `forge` 不受限制的 sudo 授权也可能很重要。`--use` 等编译器选项可以选择本地可执行文件，而 `forge flatten -o` 可以指定输出文件。在将授权视为可利用之前，应检查已安装的 Forge 版本、精确的 sudo 参数、项目和编译器路径的可访问性、输出权限以及生效的环境。通过 `PATH` 找到相对路径 helper 可执行文件，是取决于版本和环境的途径，不应假定所有 Forge 构建都具备此特性。<sup>[[23]](#references)[[24]](#references)</sup>

允许以 root 身份不受限制地运行 `pacman`，不仅能查询软件包：`-U` 接受本地软件包，软件包可能包含安装脚本，`--hookdir` 可以指定其他钩子目录。测试前应审查生效的 sudo 规则、参数限制和排除项；被动枚举无需安装软件包或运行钩子。<sup>[[25]](#references)[[26]](#references)</sup>

固定的 sudo shell wrapper 也可能安装指定的 npm 依赖项，然后启动 Node 应用程序。检查其精确的 RunAs 规则、软件包是否已安装、生效的 `HOME` 和 npm `userconfig`、项目配置或命令行覆盖项，以及低权限用户是否控制该名称对应的软件包所用的 registry，或返回的软件包内容。[npm 文档介绍了逐用户和逐项目的 `.npmrc` 查找方式](https://docs.npmjs.com/cli/v6/configuring-npm/npmrc/)；sudo 的 `HOME` 行为取决于已安装的策略和发行版，因此特权 npm 进程是否会读取用户可写的 `.npmrc` 并不确定。如果新安装的软件包被特权应用导入，其模块代码就能以该应用的身份运行。安装时脚本是另一条取决于版本和配置的途径；[npm 文档介绍了其生命周期和用户处理方式](https://docs.npmjs.com/cli/v6/using-npm/scripts/)。仅有 `.npmrc` 路径或 `npm install` 语句只是审查线索。被动枚举时应检查规则、简短 wrapper、配置路径和软件包来源，不要安装依赖或启动应用程序。

如果 root 权限下的 `pip` 或 `pip3 download` 参数允许调用者选择不可信源码分发包，那么这也是软件包构建审查线索，即使 URL 模式将其限制为本地服务和 `.tar.gz` 后缀也是如此。`pip download` 接受归档 URL 并解析软件包元数据；准备 sdist 时，可能会在归档仅仅被保存之前调用其 build backend 或旧式 `setup.py` 代码。确认精确的 sudo RunAs 身份和参数规则、调用者是否能发布或替换所选归档，以及该 pip 版本是否确实会准备其元数据。固定且可信的归档或 wheel 并不能证明这条途径成立。被动枚举时不要获取或构建不可信软件包。参见 pip 的 [`download` 命令](https://pip.pypa.io/en/stable/cli/pip_download/)、[build-system 接口](https://pip.pypa.io/en/stable/reference/build-system/)和[安全安装指南](https://pip.pypa.io/en/stable/topics/secure-installs/)。

如果 sudo 规则允许 `pip install` 使用调用者选择的本地项目路径，就存在更直接的构建边界。[pip 接受本地项目目录](https://pip.pypa.io/en/stable/topics/local-project-installs/)并会调用其构建系统；[build backend 会运行项目控制的构建钩子](https://pip.pypa.io/en/stable/reference/build-system/)。在将该规则视为特权代码执行之前，应确认生效的 RunAs 身份、精确的参数限制和拒绝规则、对所选项目的控制权，以及已安装的 pip/backend 行为。固定且可信的项目，或排除调用者选择路径的规则，都不能证明这条途径成立。被动枚举时应审查规则和项目元数据，不要安装软件包。

允许以 root 身份不受限制地运行 `easy_install` 的 sudo 授权，是相关的旧版软件包构建审查线索。[Setuptools 文档](https://setuptools.pypa.io/en/stable/deprecated/easy_install.html)说明，Easy Install 接受本地项目目录并会构建源码分发包；调用者控制的项目可能在 sudo 身份下构建时执行其 `setup.py`。确认生效的 RunAs 账户、精确的命令和参数限制（包括后续拒绝规则）、对所选项目的控制权，以及已安装工具的行为。固定且可信的项目，或不允许调用者选择源码的策略，都不能证明这条途径成立。枚举时检查规则和项目元数据，不要安装软件包。

使用 `setuptools.package_index.PackageIndex.download` 并接受调用者选择 URL 的 sudo 允许 Python wrapper，与 `pip download` 是不同的审查情况：[setuptools GHSA-5rjg-fvgr-3xxf](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf)描述了受影响的 78.1.1 之前版本中，URL 派生的文件名如何逃逸预期下载目录，并以进程权限写入文件。确认生效的 sudo RunAs 身份和参数规则、wrapper 是否将调用者的 URL 传给这个特定 API、已安装版本或供应商回补情况，以及结果路径的解析位置。仅有版本字符串或可写的下载目录，并不能证明存在任意写入。被动枚举时检查简短 wrapper 和软件包元数据，不要获取 URL 或写入文件。

允许 sudo 运行的构建 wrapper 如果将调用者选择的 `.spec` 文件传给 PyInstaller，也需要进行相同的信任边界审查。PyInstaller spec 是在**构建期间**求值的可执行 Python，其 `datas` 项可将构建身份可读取的文件打包进制品。确认精确的 RunAs 用户、sudo 参数和拒绝规则、wrapper 对路径和分支的处理、对所选 spec 文件的控制权，以及对生成制品的访问权限。仅允许 `.py` 输入或发现已安装 PyInstaller，并不能证明调用者能控制 spec 文件或执行特权代码。被动审查只应读取有限范围的 wrapper 文件和元数据，不要运行构建。参见 [PyInstaller spec 文件文档](https://pyinstaller.org/en/stable/spec-files.html)。

### 通过 sudo 运行的 preset 和 plugin loader

接受调用者选择的 preset 或 plugin 目录的 Python 工具，可能以 sudo 授予的权限导入代码。例如，BBOT 可通过 `-p` 接受 preset，其 [custom-module 文档](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#load-modules-from-custom-locations)介绍了可用于选择额外 Python 模块目录的 `module_dirs` 条目。如果生效的 sudo 规则允许调用者选择 preset，且调用者控制所选目录中的模块，那么该模块的 import 就可能以特权用户身份执行代码，甚至可能发生在工具拒绝无效模块之前。在枚举期间检查已安装版本、精确的 sudo 运行身份和参数策略，以及 preset 和模块路径的所有权，不要加载该模块。

### 通过 sudo 运行的 Backdrop 命令行工具

[Bee](https://github.com/backdrop-contrib/bee) 是供 Backdrop CMS 使用的 PHP 命令行工具。它的 `eval`（`php-eval`）和 `php-script` 命令可以运行调用者提供的 PHP。如果一条 sudo 规则允许以 root 身份执行 Bee，且参数不受限制，那么当 Bee 能够引导启动 Backdrop 安装时，就可能暴露 root 代码执行。可从站点目录运行它，或使用全局 `--root=<directory>` 选项选择站点；仅仅发现 Bee 或 Backdrop 的 `settings.php` 文件，并不能证明 sudo 权限、站点可用或引导启动成功。测试前应审查生效的 sudo 规则、任何命令排除项、可执行文件的身份，以及对站点的访问权限。被动枚举期间检查规则和文件路径，不要调用 Bee。参见 [Bee 命令变更日志](https://github.com/backdrop-contrib/bee/blob/1.x-1.x/CHANGELOG.md)，了解 PHP 命令的新增情况。

### 通过 sudo 运行的终端服务器

`mosh-server` 会以调用用户身份启动交互式终端服务器。它会选择一个高位 UDP 端口和会话密钥，并将两者报告给调用者；客户端连接时，通常会启动该用户的登录 shell。因此，即使命令本身会脱离终端运行，可用 root 权限、不受限制地运行 `mosh-server` 的 sudo 授权仍值得作为 shell 风险候选进行审查。检查生效的 RunAs 身份、允许的参数和排除项、已安装的二进制文件、shell、客户端是否可用，以及 UDP 访问权限。被动枚举应检查 sudo 规则，不要启动服务器或打印任何实时会话密钥。参见 [Mosh server 手册](https://manpages.debian.org/unstable/mosh/mosh-server.1.en.html)和[上游设计说明](https://github.com/mobile-shell/mosh#how-it-works)。

### 会重写调用者任务文件的特权备份 wrapper

以 root 身份运行的 shell wrapper 可能接受调用者选择的任务文件，剥离源路径中的 `../`，检查结果是否以允许目录开头，重写任务文件，然后把该文件的*路径名*传给备份程序。应在完全规范化解析后检查转换后的路径：一次字符串替换可能产生新的路径遍历序列，而词法前缀检查可能会接受该序列。还应检查备份程序是读取转换后的内存数据，还是重新打开文件。如果它重新打开文件，重写失败后原始输入可能仍然保留。

在 Linux 上，`fs.protected_regular` 可以拒绝对 world-writable sticky 目录中其他用户拥有的普通文件执行带 `O_CREAT` 的写入。该拒绝机制具有保护作用，但若 shell wrapper 忽略写入错误，仍可能继续使用原始任务文件。确认该设置、文件所有者和目录，以及 wrapper 是否会在失败时停止。只有当生效的 sudo 规则允许以特权用户身份运行 wrapper、调用者控制任务输入和可读取的备份目标，而且备份工具确实会包含受保护的源文件时，这条路径才构成文件泄露候选。枚举时检查这些条件，不要运行备份。

### 特权 packet tool 的参数通配符

在 `tcpdump` 的 sudo 规则中，**参数模式**里的 `*` 可以匹配空白字符和斜杠，因此看起来像路径限制的模式仍可能允许额外的选项文本。这与命令可执行文件路径中的通配符不同；应检查完整的 RunAs 规则和任何后续拒绝规则。如果可以注入选项，应根据允许的调用形式和已安装的 [`tcpdump` 选项语义](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)，判断 `-F`、`-V`、`-r`、`-w` 或 `-Z` 是否能提供有用的读写原语。`-V` 会读取捕获文件名列表，并非任意通用文件转储。即使 sudo 允许命令，AppArmor 或其他 MAC 策略仍可能阻止文件访问；磁盘上存在 profile 文件并不能证明它已加载或处于强制执行状态。得出结论前应被动审查授权和策略。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)介绍了这种通配符区别。

即使可用 root 权限的 sudo 规则只列出 `tcpdump` 可执行文件、不限制参数，也值得审查。[tcpdump 手册](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)说明，当 `-C` 或 `-G` 轮转保存的捕获文件时，`-z` 会指定轮转后的命令；`-Z` 或编译时默认设置可能会在该命令运行前降权。在将该规则视为权限提升途径之前，应验证生效的 sudo 规则、已安装的构建版本、降权行为，以及是否可以触发轮转。规则高亮只是候选线索，并不能证明可以执行 root 命令。

### 通过 sudo 运行的 Nmap wrapper

如果 sudo 允许的 `nmap` 路径是 shell wrapper，应检查精确的允许路径和它转发的每个选项。禁用熟悉的 `--script` 写法，并不一定能阻止加载 NSE 代码：Nmap 的 [`--datadir`](https://nmap.org/book/man-misc-options.html) 可以选择数据文件，而启用 scripting 时，NSE 会从所选数据目录加载 [`nse_main.lua`](https://nmap.org/book/nse-implementation.html)。有些已安装版本还接受其他长选项写法，因此应将限制规则与该二进制文件的实际 parser 进行比对。[`--excludefile`](https://nmap.org/book/man-target-specification.html) 是另一个读取文件的攻击面；parser 错误可能泄露文本。在枚举期间不要运行扫描；应检查生效的 sudo 规则、wrapper 逻辑、Nmap 版本、目录控制权和 MAC 策略。

### 通过 sudo 运行的 Mercurial pull hook

即使 `sudo hg pull /fixed/source` 的源固定，除非命令使用 `-R` 固定接收仓库，否则**接收端**仓库仍由当前工作目录决定。调用者控制的接收仓库可以在 `.hg/hgrc` 中定义 hooks，而且 hook 可能以 sudo RunAs 用户身份运行。[Mercurial 会忽略不受信任用户或组拥有的仓库配置](https://mercurial-scm.org/help/topics/config)，因此，在将其视为代码执行之前，应检查 RunAs 账户的受信任用户/组和精确工作目录。被动审查时读取策略和配置即可；枚举时不要执行 pull 或调用 hook。

### 通过 sudo 运行的 Git pull hook

对于精确允许以 root 身份执行 `sudo git pull` 的规则，也应检查由工作目录选定的**接收端**仓库。调用者拥有的仓库可以包含可执行的 `post-merge` hook；当 pull 实际执行了成功的 merge 时，该 hook 会以 Git 进程的身份运行。[Git 文档介绍了该 hook](https://git-scm.com/docs/githooks)以及 [pull 的 merge 与 rebase 行为](https://git-scm.com/docs/git-pull)。确认生效的 sudo 规则和当前工作目录、活动 hook 路径及其权限，以及是否可能执行包含新提交的 merge。失败、无操作或仅 rebase 的 pull 并不能证明这条 hook 路径成立。检查策略和仓库元数据，不要运行特权 pull。

### 通过 sudo 运行的 rsync 归档复制

对于 `sudo rsync -a ... /writable/source/* /fixed/destination/`，**sudoers 参数模式**中的 `*` 可以匹配空白字符，从而允许在源和目标之间插入额外选项。这与 shell 对文件名进行展开不同。如果调用者能填充源目录，而且特权 rsync 进程可写入目标目录，那么 [`--chown`](https://download.samba.org/pub/rsync/rsync.1) 就可以请求更改文件所有权；归档模式又会保留权限位，因此可能创建所有者为特权账户的 SetUID 文件。检查精确的 [sudoers 通配符语义](https://man7.org/linux/man-pages/man5/sudoers.5.html)、rsync 版本、后续拒绝规则、文件系统的 `nosuid` 和 MAC 策略。匹配的规则只是审查候选，并不能证明权限提升成功。

### 通过 sudo 运行的 packet-filter 规则导出

允许以 root 身份不受限制地运行 `iptables` 和 `iptables-save`（或对应的 `ip6tables` 组合）的授权，值得审查文件写入风险。`comment` match 接受调用者选择的规则文本，而 `iptables-save -f` 会将序列化后的规则集写入所选路径。<sup>[[20]](#references)[[21]](#references)</sup>要构造有效 payload，取决于已安装后端如何序列化注释，以及目标文件是否会接受导出内容中的其他行；单独的 `iptables-save` 并不提供任意自选内容。检查精确的 sudo RunAs 身份、参数和排除项、可用的 match extension、后端和目标权限。枚举时检查授权，不要更改防火墙规则或写入文件。

### 特权 Below 日志目录

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w)影响了 0.9.0 之前会创建 world-writable `/var/log/below` 目录的 Below 版本。如果服务或获准的 sudo 命令以 root 身份运行受影响的构建，那么能够写入并遍历非 sticky 日志目录的用户，可能在特权进程打开日志项之前将其替换为符号链接。检查已安装软件包的修复状态、精确的特权执行路径、生效的目录访问权限、sticky bit 和 ACL，以及 `/var/log/below/error_root.log` 的元数据。仅有 world-writable 路径或 sudo 规则并不能证明完整链路成立。sticky 目录或供应商回补会改变评估结果。被动枚举只需检查元数据；无需创建链接或运行特权程序。

### 从可写输入收集特权 support bundle

sudo 允许运行的 support-profile 脚本可能会以 root 身份读取固定日志路径，并将内容复制到 profile archive 中。检查实际脚本会读取哪些文件，然后确认调用者是否能替换源路径，或替换任何父目录条目以插入符号链接。如果特权读取会跟随该链接，且调用者可以读取生成的 archive，就可能泄露受保护文件。必须同时存在 sudo 授权、可写源路径、特权读取和可读输出；仅有可写日志或 profile 文件名并不足够。枚举期间检查生效权限和链接元数据，不要替换文件或生成 profile。[Nagios XI support 指南](https://support.nagios.com/forum/viewtopic.php?t=62758)介绍了其 root 运行的 profile 脚本和输出 archive，说明此类 bundle 的输入和输出为何需要受限。

### 以 root 身份运行的 Python archive restore 脚本

即使 Python restore 脚本的 sudo 规则范围很窄，也仍需审查其 archive 输入。如果调用者可以选择或替换 archive，且脚本以 root 身份使用 `tarfile.extractall(filter="data")` 解压，那么在信任该 filter 前，应检查 interpreter 的安全更新情况。CPython 在 3.9.23、3.10.18、3.11.13、3.12.11 和 3.13.4 中修复了多个符号链接和硬链接 filter 绕过问题，包括 CVE-2025-4517。发行版回补可能修复了更早的版本，因此显示的 interpreter 版本本身并不能证明存在漏洞。<sup>[[16]](#references)[[17]](#references)</sup>

被动审查时，读取精确的 sudo 命令和脚本，追踪哪个参数选择 archive，并检查当前用户是否能写入 archive 或其所在目录。分别确认已安装版本的供应商补丁和解压目标位置；`filter="data"` 并不能让所有不可信 archive 都变得安全。<sup>[[16]](#references)[[17]](#references)</sup>

### 通过 sudo 运行的 machine-learning 模型 loader

如果一条 sudo 规则允许调用者选择 `.pt`、`.pth` 或 `.ckpt` 文件，且特权脚本会把该文件传给 [`torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load.html)、`pickle.load` 或其他基于 pickle 的 loader，就值得审查。检查生效的 RunAs 规则、调用者是否能创建或替换所选模型，以及参数如何经 shell wrapper 流入 Python helper。`.pth` 扩展名也用于无关的 Python site 配置文件，因此仅凭扩展名不能证明程序加载了模型。扫描 archive 或静态扫描 pickle，都不能证明后续加载是安全的；应检查 loader 中[因版本而异的 `weights_only` 行为](https://docs.pytorch.org/docs/stable/notes/serialization.html)及任何 allowlist。参见 [ML pickle 和 Fickling 说明](../../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)。被动枚举时绝不要加载或解包模型。

### 通过 sudo 运行的存储输入表达式求值

通过 sudo 以 root 身份运行的固定 Python 脚本，仍可能求值低权限用户能够写入应用数据库的文本。在 TensorFlow 中，调用 `preprocess_input_exprs_arg_string(value, safe=False)` 会选择 `eval` 路径；[TensorFlow 公告](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-75c9-jrh4-79mc)介绍了不安全的 parser，以及对其命令行调用方的修复。即使命令行调用方已打补丁，应用程序显式调用 `safe=False` 仍需单独审查。检查生效的 sudo 规则、谁能修改准确的输入记录、过滤或评分是否允许该记录到达调用点，以及已安装函数的行为。TensorFlow 版本、sudo 授权或硬编码模型文件本身，都不能证明完整链路成立。被动检查脚本和数据流；枚举时不要运行特权 helper 或提交测试表达式。

### 通过 sudo 允许运行的 needrestart 配置

`needrestart -c` 会加载调用者选择的 Perl 配置文件并对其内容进行求值。如果 `sudo -l` 允许以 root 身份运行 `needrestart`，且参数允许 `-c`，而调用者能在可写位置选择一个可读配置文件，那么该授权可能导致 root 代码执行。检查精确的 sudo 运行身份和参数规则；只允许固定参数列表的规则可能会阻断这条途径。这与 needrestart 的 interpreter 扫描漏洞不同：更新软件包或禁用 `interpscan`，并不能让不受限制的 root `-c` 授权变得安全。<sup>[[2]](#references)[[18]](#references)[[19]](#references)</sup>

### 以另一账户身份通过 sudo 运行 Python import

固定的 Python 入口点仍可能导入调用者能够编辑或替换的模块；即使 sudo 以**非 root**服务用户身份运行脚本，也可能如此。对于字面量 `from utils import status`，除了检查软件包目录权限，还应检查本地的 `utils/__init__.py` 和 `utils/status.py`。在将可写文件视为执行途径之前，应确认脚本的 import 路径、精确的允许 sudo 参数，以及相关操作是否会到达该 import。枚举时只检查文件和权限，不要 import 或运行脚本。<sup>[[2]](#references)[[3]](#references)</sup>

精确允许 `python3 /absolute/script.py` 的 sudo 规则只要求脚本可读；文件不需要可执行，也不需要 shebang。还应检查**缺失的**本地模块：如果脚本 import 的模块，其文件名可在调用者可写的脚本目录中创建，Python 就可能以 RunAs 身份加载该文件。确认生效的 sudo 规则、解释器实际的[模块搜索路径](https://docs.python.org/3/library/sys_path_init.html)、该模块是否为 built-in 或 frozen，以及 import 是否可达。直接针对脚本的 sudo 规则，对 execute bit 和 shebang 的要求不同。另有一种独立情形：wrapper 会在 `sudo -u account` 后追加调用者提供的 tokens，这需要审查参数流；只有在被调用的 sudo 策略允许最终指定的身份时，其中另一个 `-u` 才有意义。仅凭静态字符串无法证明任一途径成立。

### 通过 sudo 运行 Apache 并使用调用者控制的配置

如果 sudo 规则允许带调用者控制的 `-f` 配置文件运行特权 `apachectl`、`apache2ctl` 或 `httpd`，应检查该文件及其父目录权限。Apache 的 [`LoadModule`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadmodule) 指令接受模块名和**模块文件名**；[`LoadFile`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadfile) 也会加载文件。[`Include` 和 `IncludeOptional`](https://httpd.apache.org/docs/2.4/mod/core.html#include) 可以扩展配置或通过错误暴露文件内容。自定义 wrapper 可能会验证这些路径、降权或限制参数，因此仅有可写配置只是审查候选，并不能证明存在代码执行。得出结论前应检查路径规范化、符号链接和指令解析情况。

### 通过 sudo 运行 nginx 并使用调用者控制的配置

可用 root 权限、不受限制的 `nginx` 规则可能允许使用 [`-c` 选择其他配置](https://nginx.org/en/docs/switches.html)。审查精确的 sudo 参数和排除项、调用者是否能提供配置，以及生成的 master 或 worker 是否仍可访问受保护路径。选择 `root` 配合 `autoindex` 可能通过新 listener 暴露文件；[`dav_methods PUT`](https://nginx.org/en/docs/http/ngx_http_dav_module.html) 可能提供特权文件写入途径，但 DAV 模块默认不会构建，必须检查它是否存在、listener 是否可访问、文件权限及临时文件行为。[`error_log` 指令](https://nginx.org/en/docs/ngx_core_module.html#error_log) 也能指定目标文件；要将日志写入 `/etc/ld.so.preload` 等敏感配置文件，必须存在有效的特权写入者和可控日志记录，才会形成权限提升途径。`sudo -l` 中可执行文件的高亮只是审查提示，并不能证明这些途径中的任何一条可行。被动枚举时不要启动或重新配置 nginx。

### 特权 Bash prompt 中的模式匹配

如果 sudo 允许运行的 Bash 脚本从调用者读取值，并使用 `[[ "$expected" == $entered ]]` 检查，Bash 会将未加引号的右侧操作数解释为模式。因此，无需知道预期值，通配符也可能满足比较。将操作数加引号（`[[ "$expected" == "$entered" ]]`）会执行字面字符串比较。检查精确的 sudo 规则、prompt 是否可达，以及比较后脚本会做什么；仅凭这段语法并不能证明存在可利用路径。枚举时不要打印预期值。参见 [Bash 条件结构参考](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)。

### 通过 sudo 运行会下载并执行文件的 helper

如果可用 root 权限运行的自定义 helper 接受调用者选择的 URL、将响应写入磁盘，之后再通过 interpreter 或 shell 调用该文件，那么值得审查其数据流。[如果命令条目未指定参数，sudoers 允许任意参数](https://man7.org/linux/man-pages/man5/sudoers.5.html)；固定的可执行文件路径并不能限制参数可以选择什么。确认已安装 helper 中实际的 URL 验证、输出路径、成功分支和后续执行行为。仅有匹配的 libcurl import 或可打印字符串，并不能证明这条链路成立。

如果 helper 在**调用者控制的工作目录中使用相对路径**，即使输出 basename 固定，也可能在写入和执行之间被替换。root 所有文件能否被重命名或替换，取决于目录的写入/搜索权限及任何 sticky bit 限制，而不只是文件模式；参见 [`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html)。检查 helper 之后是重新打开该路径，还是使用已经打开的 descriptor，以及它是否会先切换到可信目录。被动检查 sudo 策略、helper 和目录元数据；枚举时不要调用特权下载或尝试 race。

如果 root sudo 下载 helper 会组装类似 `curl <caller input> -o <fixed output>` 的 Bash 命令字符串，还可能存在**参数**注入。即使过滤器拒绝空白字符，[Bash brace expansion](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html)仍可利用：未加引号、以逗号分隔的元素可能被展开成多个 curl 参数。如果输入在固定的 `-o` 之前传给 curl，那么调用者提供的输出选项可能会以 helper 身份为第一个 URL 选择目标路径；[curl 会按顺序将输出选项与 URL 关联](https://curl.se/docs/manpage.html#-o)。确认精确的 shell、引用方式、输入验证、生效的 sudo 规则、curl 参数顺序和支持的 URL scheme，以及调用者是否控制获取的数据或能读取结果。使用 PyInstaller 打包的可执行文件可能包含 Python 应用逻辑，但仅凭打包标记或 `curl` 字符串不能证明这条数据流。获准时审查范围有限的离线副本；常规枚举时不要运行 helper 或获取攻击者选择的数据。

如果 root sudo shell 脚本只调用 [`mktemp -u` / `--dry-run`](https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html)，它只会选择一个未使用的名称，**不会**创建文件。如果脚本之后在其他用户可以影响的目录中创建该名称，重新打开它，再将其内容追加到 root 的 `authorized_keys` 等受保护目标，就值得审查临时文件 race。确认精确的 sudo 规则、目录和文件所有权、创建与重新打开的顺序、内核保护，以及特权写入是否确实会使用攻击者控制的字节。仅有 `mktemp -u` 字符串或可写的 `/tmp` 并不能证明存在 race。枚举时检查脚本和路径元数据，不要运行脚本或对其临时文件进行 race。

## 防御说明

- 避免通过 sudo 授予 interpreter 或交互式 editor 的权限。<sup>[[1]](#references)</sup>
- 优先使用固定、由 root 所有且只执行一项狭窄管理操作的 wrapper。<sup>[[1]](#references)[[2]](#references)</sup>
- 如果无法避免使用 interpreter，应限制精确的脚本路径，并阻止用户控制参数、可写 import、`PYTHONPATH` 和不安全的环境保留。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- 如果需要编辑文件，应限制精确的文件路径，并考虑使用已打补丁的 sudo 版本和严格的环境处理配置下的 `sudoedit`。<sup>[[1]](#references)[[2]](#references)</sup>
- 审查 `SETENV`、`env_keep`、可写工作目录、可写模块/import 路径、`NOEXEC`、`use_pty` 和日志记录，但不要将它们视为完整的 sandbox。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Python documentation](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Miscellaneous operating system interfaces — Python documentation](https://docs.python.org/3/library/os.html)
- [5] [perlrun — how to execute the Perl interpreter](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl documentation](https://perldoc.perl.org/functions/exec)
- [7] [Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby documentation](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Node.js documentation](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js documentation](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua man page](https://www.lua.org/manual/5.4/lua.html)
- [12] [The GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux manual page](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [16] [Python 3.9.23–3.13.4 security releases](https://discuss.python.org/t/python-3-13-4-3-12-11-3-11-13-3-10-18-and-3-9-23-are-now-available/94367)
- [17] [tarfile extraction filters — Python documentation](https://docs.python.org/3/library/tarfile.html#extraction-filters)
- [18] [needrestart configuration option and evaluation — upstream source](https://github.com/liske/needrestart/blob/master/needrestart)
- [19] [needrestart command behavior — GTFOBins](https://gtfobins.org/gtfobins/needrestart/)
- [20] [iptables-save(8) — netfilter manual page](https://www.man7.org/linux/man-pages/man8/iptables-save.8.html)
- [21] [iptables-extensions(8): comment match — netfilter manual page](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [22] [Simple Command Expansion — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Simple-Command-Expansion.html)
- [23] [Forge compiler options — Foundry documentation](https://getfoundry.sh/forge/reference/forge-inspect/)
- [24] [Forge flatten — Foundry documentation](https://getfoundry.sh/forge/reference/forge-flatten/)
- [25] [pacman(8) — Arch manual pages](https://man.archlinux.org/man/pacman.8.en)
- [26] [PKGBUILD(5) install scripts — Arch manual pages](https://man.archlinux.org/man/core/pacman/PKGBUILD.5.en)
{{#include ../../banners/hacktricks-training.md}}
