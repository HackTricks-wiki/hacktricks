# Sudo 命令滥用

{{#include ../../banners/hacktricks-training.md}}

## Sudo 允许的解释器

如果 `sudo -l` 允许用户以 root 身份运行解释器，应将其视为可直接执行代码。解释器本来就是为执行任意代码而设计的，因此，允许运行 `python3`、`perl`、`ruby`、`lua`、`node` 或类似二进制文件的规则，通常等同于允许执行 root 命令，除非参数受到严格限制和验证。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

常见的检查流程：先列出用户的权限，然后使用解释器的 `-c` 选项执行一条 Python 语句。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

其他解释器示例如下；所列解释器的文档介绍了行内代码执行或子进程 API。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

确切路径很重要。如果 sudo 规则允许 `/usr/bin/python3`，验证时就使用这个确切路径。<sup>[[2]](#references)</sup>

像 `/usr/bin/python*` 这样的 sudo 可执行文件 glob 也可能允许使用 Python 2 执行为 Python 3 编写的脚本。如果脚本在调用 `input()` 时接收了调用者可控的文本，[Python 2 会将该文本作为表达式求值](https://docs.python.org/2/library/functions.html#input)；显式调用解释器会覆盖脚本的 shebang。在将其视为执行路径之前，请确认已安装且匹配的二进制文件、有效的 RunAs 和参数策略、拒绝规则，以及是否能触达该输入。

root 权限 sudo 规则中固定的脚本路径，并不能限制脚本执行什么。对于可读的 Bash wrapper，请检查它的第一个可执行命令是否将未加引号的位置参数（例如 `$1`）用作**命令词**，同时 sudo 是否允许调用者自行选择参数。确认有效的 RunAs 身份、密码和参数策略、后续拒绝规则，以及脚本实际进入的分支；`NOEXEC`、固定的安全参数列表，或会验证命令的 wrapper 都可能改变结果。枚举时应静态检查短脚本，而不是用测试命令调用它。

允许不受限制地以 root 权限运行 `dotnet` 的 sudo 规则也值得检查其解释器能力。安装了 .NET SDK 时，[`dotnet fsi` 可以交互式运行 F# 代码，也可以运行脚本](https://learn.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/)，而 [`dotnet run` 可以从源代码执行项目](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run)。首先确认有效的 RunAs 身份和确切的参数策略：固定为特定安全子命令或可信应用的规则，属于不同的授权；仅安装 runtime 的环境可能没有 SDK 命令。可执行文件的名称只是审查线索，并不能证明可以执行代码。

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## Sudo-允许的 `tee`：任意特权文件写入

GNU `tee` 会将标准输入复制到作为文件操作数提供的每个路径。因此，允许以 root 身份执行 `/usr/bin/tee` 且参数由调用者控制的 sudo 规则，授予了任意创建或覆盖 root 文件的能力。添加 `-a` 会将此能力改为追加。`PASSWD:` 标签涉及 sudo 身份验证；它本身不会限制目标路径或从标准输入读取的字节。<sup>[[2]](#references)[[27]](#references)[[28]](#references)</sup>

首先检查确切的规则。在获准测试的系统上，仅使用可安全创建的临时目标来验证此能力。最后的 `>/dev/null` 只会抑制 `tee` 向标准输出的复制。<sup>[[28]](#references)</sup>

```bash
sudo -l
printf '%s\n' 'controlled-write' | sudo /usr/bin/tee /root/tee-proof >/dev/null
printf '%s\n' 'appended-line' | sudo /usr/bin/tee -a /root/tee-proof >/dev/null
```

在 producer 前加上 `sudo` 并不会提升后续 shell 重定向的权限，因为是调用者的 shell 打开目标文件。必须让特权进程负责写入，如上面的管道所示。<sup>[[1]](#references)[[15]](#references)</sup>

确认写入成功后，从 [Arbitrary File Write to Root](../interesting-files-permissions/write-to-root.md) 中选择合适的 root 代码执行入口。曾观察到一种利用链：使用 root 权限的 `tee` 在 `/etc/cron.d/` 下创建一个短暂存在的文件，通过用户可控的脚本启动后门，并在执行后删除 cron 文件。删除 cron 文件可防止它成为长期持久化入口，但系统日志仍会保留活动证据。<sup>[[27]](#references)</sup>

## Sudo 允许使用的编辑器

如果 `sudo -l` 允许用户以 root 身份运行交互式编辑器，应将其视为命令执行入口，而不是无害的文件编辑权限。编辑器通常可以执行 shell 命令、读取任意文件、写入任意文件，或在编辑器内调用外部辅助程序。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

常见的审查流程：列出用户的权限，然后通过 sudo 调用每个获准使用的编辑器或 pager。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

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

然后向 nano 命令提示符输入诸如 `id` 或 `/bin/sh` 这样的命令。<sup>[[12]](#references)</sup>

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

Vim 风格的编辑器通常可以通过 `:!` 执行命令。<sup>[[13]](#references)</sup>

```text
:!/bin/sh
```

像 `less` 这样的分页器也可能暴露 shell 执行功能。<sup>[[14]](#references)</sup>

允许以 root 身份运行 `apport-cli` 的 sudo 规则，同样需要检查其分页器设置。受影响的 Apport 版本可能会使用 `less` 打开崩溃报告，且终端大小可由攻击者调整；如果满足特定的 sudo 和分页器条件，分页器就可能提供 root shell。在仅凭版本号判断其是否存在漏洞之前，请检查生效的 sudo 规则、分页器配置以及发行版的软件包修复情况。被动枚举时，请读取软件包和策略元数据，不要生成崩溃，也不要打开特权报告。[Ubuntu 的 CVE 记录](https://ubuntu.com/security/CVE-2023-1326)列出了各发行版对应的已修复软件包版本，其中包括回移植的修复。

```text
!/bin/sh
```

## 其他 sudo 和 doas 规则的风险

从 `sudo -l`、`sudo -V` 以及任何适用的 `doas` 策略开始。结合查看允许执行的命令、RunAs 用户、参数、环境和默认设置。即使只能以非 root 服务账户运行命令，也可能访问该账户的文件，或找到通往 root 的途径。

固定为 sudo 允许执行的 Python 脚本，如果把交互式、由调用者控制的输入拼接到 [`os.system()`](https://docs.python.org/3/library/os.html#os.system) 中，仍可能以 RunAs 身份运行 shell 命令。仅靠 shell 标点符号 denylist 不足以证明安全：[shell 还会识别 `$(...)` 命令替换](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html)。确认允许的参数是否会进入该输入分支、输入是否未经安全验证就进入 shell 命令，以及有效 sudo 策略是否允许目标 RunAs 用户。脚本路径或对 `os.system()` 的调用本身只是审查线索；检查源码时不要运行特权脚本。

有效的 root sudo 授权若允许运行 `chattr`，可以移除文件的 immutable（`i`）属性，但仅此并不会授予写权限或新的身份。[`chattr` 手册](https://man7.org/linux/man-pages/man1/chattr.1.html)指出，该属性会阻止修改，且只有 root 或具有 `CAP_LINUX_IMMUTABLE` 的进程才能更改它。检查确切的 sudo 参数策略和文件系统支持情况，然后另外确认清除属性后调用者是否可以写入该文件，以及是否有更高权限的使用者会读取或使用它。例如，替换登录 shell 还要求目标账户接受相应凭据，并且确实通过该 shell 登录。枚举时只审查策略、文件属性和权限，不要修改它们。

如果 sudo 同时要求输入密码和一次性验证码，应将这些前置条件与命令授权分开考虑。可读的 `.google_authenticator` 文件包含敏感种子材料，而旧应用或数据库中的密码哈希只能作为当前账户密码的候选；两者都不能证明有效的 PAM 配置会接受另一个因子。获得授权后，再审查确切的 RunAs 和参数：允许不受限制地以 root 运行 RubyGems `gem`，可能暴露其 editor 命令（[GTFOBins](https://gtfobins.github.io/gtfobins/gem/)）；但受限授权或认证失败则不会。被动枚举应报告路径和策略，不要打印种子、破解密码、生成验证码或调用特权命令。

允许以 root 身份运行的无限制 sudo 授权若涉及 Chef 的 `knife`，应进行解释器级审查：[Chef 文档说明，`knife exec -E` 会在本地执行 Ruby 字符串](https://docs.chef.io/workstation/26/tools/knife/knife_exec/)。确认有效 sudo 规则是否允许 `exec` 子命令和调用者提供的 `-E` 参数、目标 RunAs 身份，以及是否存在匹配的命令拒绝规则或固定参数。安装了该二进制，或规则仅允许其他子命令，都只是审查线索。被动枚举应报告规则，不要调用 `knife`。

允许以 root 身份运行精确命令 `msfconsole` 同样敏感：[GTFOBins 记录了它的 `irb` 控制台](https://gtfobins.org/gtfobins/msfconsole/)，该控制台可能继承 sudo 身份。确认有效的 RunAs 用户、允许的参数列表、命令拒绝规则、`NOEXEC` 或其他限制、已安装控制台的行为，以及调用者能否提供交互式输入。仅仅在路径上看到高亮只是审查线索；被动枚举不要启动控制台。

在 FreeBSD 上，即使 sudo 规则仅允许以 root 身份运行 `pkg update` 和 `pkg install *`，也应审查仓库信任。检查调用者是否能写入 `/etc/hosts`，以及*有效的*启用仓库配置是否使用 `signature_type: none` 的 HTTP 主机名。[FreeBSD 的 `pkg.conf` 手册](https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5)指出，`none` 会禁用签名检查；仅有 `pkg+http` 并不能证明这一点。软件包可以包含安装脚本（[FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/pkg-files/)），因此，如果调用者确实能控制仓库端点并选择软件包，就可能越过 root 边界。下结论前，确认仓库覆盖设置、SRV/镜像解析、有效 sudo 参数、软件包选择和脚本执行情况。检查策略和小型本地配置文件即可；枚举时不要重定向名称或运行 `pkg`。

如果 sudo 保留由调用者控制的 `http_proxy`，允许以 root 身份运行 `apt-get update` 和 `apt-get upgrade` 的 sudo 规则也需要审查仓库信任。检查有效的 APT 代理配置是否实际使用该变量，以及它可能影响哪些已启用仓库请求；单靠代理无法替换由受信任签名密钥认证的归档。[APT 的 HTTP 传输手册](https://manpages.debian.org/experimental/apt/apt-transport-http.1.en.html)说明了代理优先级，[apt-secure](https://manpages.debian.org/experimental/apt/apt-secure.8.en.html)则说明了签名检查、不安全仓库覆盖设置，以及对未认证软件包的确认要求。确认确切的 sudo RunAs 和参数、仓库认证策略、是否需要交互式确认，以及所选升级是否会以 root 身份运行软件包脚本。被动检查策略和本地配置；枚举时不要重定向软件包流量或运行升级。

允许以 root 身份运行 `snap install` 的 sudo 规则，如果参数允许调用者选择本地 snap 并使用宽松安装模式，就可能形成从软件包到代码的边界。[Snap 文档](https://snapcraft.io/docs/explanation/snap-development/install-modes/)指出，`--dangerous` 会跳过本地 snap 的 assertion 检查，`--devmode` 会放宽隔离；[安装 hook 可以在首次安装时运行](https://snapcraft.io/docs/reference/development/supported-snap-hooks/)。在声称能够访问受保护的主机文件之前，先确认确切的 sudo 参数/RunAs 策略、谁控制 snap 文件、已安装的 snapd 是否接受这些模式，以及 hook 的有效身份和隔离情况。仅有 `snap` 二进制或看似包含通配符的规则并不能证明这一链条。被动枚举不要安装软件包或执行其 hook。

对于精确授权以 sudo 运行某个**非 root**账户的自定义凭据读取二进制，首先在不运行它的前提下检查获授权的二进制及其文件权限。嵌入式密码门控可能只有以宽字符形式才能看到；[GNU `strings` 文档说明了 16 位小端序提取](https://sourceware.org/binutils/docs/binutils/strings.html)。可见字符串不能证明它就是有效密码，也不能证明成功分支会暴露当前凭据。分别确认二进制行为、目标账户对受保护数据的访问权限、凭据有效性，以及后续账户或组身份转换。如果该账户属于 `docker` 组，需确认其是否能访问 socket，以及 daemon 使用 rootful 还是 rootless 身份，然后再判断是否能访问主机 root 权限；[Docker 说明了该组可能带来的 root 级影响](https://docs.docker.com/engine/install/linux-postinstall/)。常规枚举应报告 sudo 规则和组成员身份，不要执行该二进制或转储其字符串。

应用维护脚本的 sudo 通配符规则需要审查脚本路径以外的内容。检查允许的脚本是否接受不受限制的参数，或是否会读取可由低权限应用账户写入的设置，然后追踪这些值是否进入 shell 命令或子进程环境。例如，ZoneMinder 的 [`zmupdate.pl` 会拼接 `mysqldump` 命令并通过 `qx` 执行](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmupdate.pl.in)，而 [`zmdc.pl` 会将 `ZM_LD_PRELOAD` 设置复制到 `LD_PRELOAD`](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmdc.pl.in)，再启动 daemon。如果对应输入可控且会进入已安装版本中的相关代码，允许以 root 身份运行任一脚本的 sudo 规则就可能越过信任边界。检查有效 sudo 规则、应用配置权限和脚本源码；通配符或设置本身只是审查线索，并非执行证据。

- `SETENV`、`env_keep`、`secure_path` 和 `LD_PRELOAD` 可能让原本受限的命令变成 import、库或 PATH 劫持。参见[环境变量指南](../linux-basics/linux-environment-variables.md)和[SUID/链接器滥用](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md)。

如果精确的 root 级 `SETENV` 授权允许运行 shell wrapper，而该 wrapper 以字面 import 启动固定 Python 脚本，也应审查这一跳。`secure_path` 限制的是 shell 的命令查找，而非 Python 的 [`PYTHONPATH` 模块搜索](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH)；[`-E` 和 `-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-E) 会让 Python 忽略该环境变量。在将其视为代码执行之前，确认有效 sudo 标签和拒绝规则、wrapper 分支、解释器选项、import 解析情况，以及是否存在调用者可写的搜索目录。静态检查简短脚本；不要调用特权 wrapper。

即使精确的 root 级 sudo 授权只允许 `neofetch ""`，只要适用的 sudo 默认设置保留由调用者控制的 `XDG_CONFIG_HOME`，它仍可能加载 shell 配置。[Neofetch 的配置加载器](https://github.com/dylanaraps/neofetch/blob/master/neofetch)会从该目录下加载 `neofetch/config.conf` 或 `neofetch/config`；空参数列表不会阻止该查找。确认已安装版本的加载器、有效 RunAs 和参数策略、任何命令拒绝规则、sudo 是否确实为该命令保留所选变量，以及调用者是否控制可读的配置路径。保留该变量或安装了 Neofetch 都只是审查线索。检查策略和文件元数据，不要调用特权命令或打印配置内容；参见[sudoers 环境处理](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)。

允许以 root 身份运行的无限制 `facter` sudo 规则，需要单独审查自定义 fact。[Puppet 文档](https://help.puppet.com/core/current/Content/PuppetCore/loading_custom_facts.htm)指出，`--custom-dir` 会从所选目录加载 Ruby fact 文件。检查确切的 sudo 规则是否允许该选项、已安装的 Facter 是否接受它，以及调用者是否控制该目录。固定参数授权、明确的命令拒绝规则或禁用自定义 fact 都可能改变结果。被动枚举应报告策略风险候选，不要调用 Facter 或读取 fact 内容。

对于带有 `SETENV` 的精确 root 级 sudo 脚本授权，检查 `find` 等不带路径的命令名称，以及 sudo 策略和脚本初始化后的有效 `PATH`。被 source 的 Bash 文件还可能运行 `enable -n [`：之后脚本使用该命令时，[Bash 会在 `PATH` 中搜索外部的 `[` 命令](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)。确认适用的[sudoers 环境和 `secure_path` 规则](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)、任何 `NOSETENV`/`NOEXEC` 或拒绝条目、脚本和被 source 文件的执行流程，以及调用者可控制的可执行搜索目录。可读脚本中出现不带路径的命令只是审查线索，并不能证明会以特权身份执行；检查时不要触发 sudo 规则。
- 通过 sudo 获准的特权脚本若使用 `curl` 获取固定 URL，只要适用的 sudo 规则保留 `http_proxy`，且请求会通过该代理发送，仍可能接受由调用者选择的响应。如果脚本随后把响应交给会解析外部实体的 XML 解析器，恶意响应就可能泄露特权进程可读的文件。检查确切的 sudo 环境策略、`no_proxy` 排除项、请求的 URL、解析器配置和输出目标；仅有代理变量或 XML 解析器并不构成漏洞。[curl 代理环境文档](https://everything.curl.dev/usingcurl/proxies/env.html)说明了相关变量的行为。被动枚举时不要发起网络请求或解析恶意 XML。
- 如果具备 root 权限的 sudo 脚本使用受调用者影响的数据构造 PostScript 文件，然后运行 `ps2pdf -dNOSAFER`，应单独审查输入流。Ghostscript 文档指出，该标志会禁用 SAFER，直到调用 `.setsafe`；在此期间，PostScript 可在进程的 OS 权限范围内执行文件操作。由调用者参数拼接的 SQL 查询可能将攻击者可控的行传入 PostScript 模板，但仅有查询字符串或 `ps2pdf` 调用并不能证明这些数据会进入可执行的 PostScript 语法。确认有效 sudo 规则、从输入到模板的确切路径、任何转义处理、已安装 Ghostscript 的行为，以及文档被解释之前是否重新启用 SAFER。被动枚举时不要调用特权转换命令。参见[Ghostscript 的 `-dNOSAFER` 文档](https://ghostscript.readthedocs.io/en/master/Use.html)。
- 对于运行 shell 脚本的 sudo 规则，应将保留的变量与脚本本身对照检查。例如，`if $CHECK_CONTENT; then` 这样的结构会把展开后的值作为命令运行；即使脚本路径和参数固定，保留 `CHECK_CONTENT` 也可能允许命令执行。必须针对具体规则确认分支是否可达，以及环境变量是否确实被保留。<sup>[[2]](#references)[[22]](#references)</sup>
- 允许通过 sudo 运行的 Python 脚本可能从可写目录或缓存的 `.pyc` 文件导入代码。[权限提升指南](../linux-basics/linux-privilege-escalation/README.md)详细介绍了缓存文件的情况。
- 固定的 sudo 允许执行的 Python 脚本仍可能暴露交互式 debugger。如果调用者能到达断点或异常处理器，**并能控制 debugger 的输入流**，那么 `pdb.set_trace()` 或 `pdb.post_mortem()` 等调用就允许在被调试进程的上下文中执行 Python 语句。检查确切的 sudo RunAs 规则、认证和分支条件、异常可达性、终端/输入所有权，以及 debugger 是否运行在同一特权进程中。触发异常的 socket 请求本身并不能让调用者访问附着在另一终端上的 debugger。[Python 文档说明了 debugger 的语句求值和 post-mortem 模式](https://docs.python.org/3/library/pdb.html)；枚举时应静态检查脚本，不要触发特权处理器。
- 固定的 sudo 允许执行的 Python 脚本还可能从数据库或 Unix socket 中读取配置文件字段，并将其附加到之后成为 `str.format()` **格式字符串**的字符串中。[替换字段可以访问属性和映射键](https://docs.python.org/3/library/string.html#format-string-syntax)，因此攻击者控制的字段可能检查传入 `format()` 的对象，并暴露这些对象可访问的数据；前提是结果会被打印，或存储到调用者可读的位置。检查有效 sudo RunAs 身份、对特定记录的写入权限、数据进入格式字符串的流程、传入的对象以及输出可见性。这并非自动构成代码执行；受信任的字面格式字符串加上攻击者控制的*值*则是另一种情况。只有当泄露的秘密能被相应账户接受时，它才会成为 OS 账户切换途径。审查脚本和 socket 权限，不要调用特权操作。
- 有 root 权限的 Python wrapper 可能会将调用者选定的 URL 传给 GitPython 的 `Repo.clone_from`。如果 wrapper 同时启用了 Git 的 `protocol.ext.allow=always`，`ext::` 远程地址就可能调用外部 helper。检查确切的 sudo 参数、URL 的来源、GitPython 软件包版本和供应商补丁状态，以及 wrapper 是否明确启用了不安全协议。GitPython 在 3.1.30 中加入了[默认的不安全协议保护](https://github.com/gitpython-developers/GitPython/commit/2625ed9)；`git` 可执行文件的版本则是另一项独立信息。被动审查时只读取规则和范围受限的源码，不要调用 clone。
- 跨用户的 sudo 授权若涉及克隆仓库的 CLI，可能暴露另一条 shell 字符串注入路径。追踪调用者选定的仓库参数是否会进入 Node.js [`child_process.exec`](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback) 或其他 shell 命令构造器，且没有经过安全的参数分离；Node 的 `exec` 会把命令字符串交给 shell。确认确切的 RunAs 用户、允许的子命令和参数、已安装的 wrapper 代码以及输入验证。仓库工具名称或不受限制的 sudo 规则本身不能证明存在命令注入。枚举时检查 wrapper，不要调用特权 clone。
- 自定义的 root 所有 wrapper 可能看似安全，因为其二进制和脚本不可写，但它是否执行特权操作可能取决于非特权用户能够更改的标志、本地 API 值或服务状态。沿每个判断条件追溯其输入和授权检查。枚举时检查配置和权限，不要更改运行状态；wrapper 中的 `systemd-run` 调用只有在其门控条件可被影响时才有意义。
- 允许通过 sudo 以 root 身份运行的备份客户端，可能接受调用者选定的配置文件（例如 `npbackup-cli -c`）。检查确切的 RunAs 用户和允许的参数，然后确认调用者是否控制配置路径、备份源路径以及仓库或读取/还原选项。可读配置中的加密仓库密钥仍可能被客户端使用，但仅有该规则并不能证明能够访问仓库或泄露 root 文件。不要通过运行备份或转储内容来验证授权。
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst)支持 `--password-command`，它会调用一个程序来获取仓库密码。如果 sudo 规则允许低权限用户以 root 身份运行 restic，并指定调用者选择的密码命令和需要密码的子命令，该 helper 就可能以 root 身份运行。审查确切的 sudo 参数和排除规则；枚举时不要仅为确认条件而调用 helper 或备份命令。
- 如果 sudo 参数规则允许调用者选择备份源和一个其之后可以读取并解密的仓库，特权 `restic backup` 授权也可能越过文件读取边界。[sudoers 参数通配符可以匹配空白和斜杠](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)，因此要检查尾部通配符，不要假设固定仓库前缀就能限制源路径。[Restic 可备份到本地和远程仓库](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html)，但本地仓库可能包含新写入的 root 专属对象；将其视为泄露前，应确认有效 sudo 策略、后端访问权限、仓库密码和生成对象的权限。备份的 SSH 密钥只有在目标账户接受该密钥时才能用于访问。被动审查时不要运行备份测试。
- 不受限制的自定义维护或备份命令可能接受输出路径，或提供自己的任务调度器。对于文件写入路径，确认确切的 sudo 规则和 RunAs 用户，然后检查调用者是否同时控制数据和目标路径。对于计划命令路径，确认调度器的执行身份、命令输入，以及是否还需要密码或其他授权门控。仅有命令名称或 `NOPASSWD` 都不能证明存在任一途径。参见[写入 root 所有文件](../interesting-files-permissions/write-to-root.md)以及[cron 和 systemd 计时器](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md)。
- 固定的 sudo 命令仍可能从共享可写目录加载可预测的配置文件。追踪调用者是否能替换该文件，以及其中的源和目标字段是否控制特权 fetch 或 copy。本地文件 URL 可能暴露只有 sudo RunAs 账户可读的数据；调用者可控的源配合受保护的目标则可能形成写入路径。确认已安装程序对 URL 的处理方式、目标路径检查、有效 sudo 规则以及输出可访问性。可写的 `/tmp` 配置路径本身只是审查线索；检查二进制和文件元数据，不要调用特权传输。
- `git apply` 的 sudo 规则可能让 RunAs 账户将文件写入调用者控制的补丁所指定的位置。[CVE-2023-23946](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh)允许精心构造的补丁创建符号链接，再写出工作树范围，即使命令不接受 `--unsafe-paths` 也可能发生。检查有效 sudo 参数规则、补丁来源、RunAs 账户对工作目录的访问权限，以及已安装 Git 的修复或供应商回移补丁。允许 `--unsafe-paths` 的无限制规则则是另一种明确的选项风险；仅有 Git 版本或 `git apply` 权限都不能证明受保护文件能够被修改。被动枚举时不要应用不可信补丁。
- 如果低权限用户能提供 DMG 镜像，且已安装解析器受[可能通过调试输出泄露文件内容的 CVE-2023-20052](https://blog.clamav.net/2023/02/clamav-01038-01052-and-101-patch.html)影响，那么具备 root 权限的 sudo `clamscan --debug` 规则就可能越过读取边界。确认确切的允许参数和扫描路径、输入控制能力、有效 RunAs 账户、引擎补丁/回移补丁，以及调用者能否看到输出。如果更宽泛的规则允许 `--file-list`/`-f`，应单独审查其文件列表行为；固定为 `--debug <scan-path>` 的策略并不允许使用这些参数。枚举时检查策略和软件包元数据，不要扫描精心构造的文件或打印受保护输出。
- 如果一条具备 root 权限的 sudo 规则用于打开调用者选定的加密磁盘镜像，另一条规则用于挂载生成的 mapper，那么它们可能将调用者控制的文件导入主机挂载命名空间。确认两条有效规则及其参数、镜像和 mapper 名称是否由调用者控制、实际挂载目标，以及最终文件的所有者和模式。要发生 SetUID 身份转换，还需要存在可访问的可执行文件、支持该功能的挂载选项（`nosuid` 会阻止它），以及适用的进程或 MAC 策略；仅仅打开或挂载镜像只是审查线索。通过现有备份获取数据是另一条途径，但需要实际密钥以及其中有用且可读的秘密。被动枚举时检查策略和路径，不要打开或挂载镜像。参见[`cryptsetup` 手册](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)和[挂载选项](https://man7.org/linux/man-pages/man8/mount.8.html)。
- 如果 root 权限 sudo 规则用于运行 shell 或 Python 脚本，而脚本会在未先切换到固定目录的情况下调用 `./helper`，就应审查工作目录。传给 `subprocess.run` 的 Python 列表 `['./helper']` 也可能受到调用者所选工作目录的影响。调用者可能选择一个可写目录，并在其中放置同名可执行文件；脚本中的其他绝对路径并不能保护这次调用。将其视为代码执行之前，需确认有效规则、`runchdir` 或其他目录切换策略、脚本流程和分支可达性、目录是否可写且可执行，以及挂载/`NOEXEC` 限制。脚本不可读时，行为仍属未知，需通过授权途径审查源码。静态审查脚本，不要运行 helper。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)介绍了工作目录策略。
- 固定的 root 权限 Python validator 仍可能对调用者选定的数据文件进行求值。[Python 的 `eval()` 文档警告不要使用不可信输入](https://docs.python.org/3/library/functions.html#eval)：如果剩余表达式仍会进入 `eval`，输入后缀检查、算术前缀或验证分支都不能构成沙箱。在将其认定为执行路径之前，确认有效 sudo 规则、调用者能否选择并控制确切文件、解析器的分支条件和表达式构造方式，以及特权进程身份。可读脚本中出现 `eval` 只是审查线索；枚举时检查源码和文件权限，不要运行 validator 或提交测试表达式。
- 如果具备 root 权限的 sudo Ruby wrapper 会读取相对 YAML 文件名，例如 `YAML.load(File.read("dependencies.yml"))`，那么除非 wrapper 或 sudo 策略固定了目录，否则输入可能来自调用者的当前工作目录。检查确切的允许参数、目录和文件权限，以及已安装的 Psych 行为：旧版 `YAML.load` 实现可以反序列化任意 Ruby 对象，而新版本默认会限制类。静态调用点只是审查线索；需确认文件确实来自调用者可写的目录，且已安装的 loader 接受危险类。对于不可信输入，优先使用带有明确最小类 allowlist 的 `safe_load`。参见[Ruby 3.0 Psych 文档](https://docs.ruby-lang.org/en/3.0/Psych.html)和[Ruby 3.1 Psych 文档](https://ruby-doc.org/core-3.1.2/Psych.html)。

- 如果精确的 root 级授权命令为 `sudo go run /absolute/file.go`，而 Go 源码会读取相对路径的 WASM 文件，并可能在检查其结果后运行相对路径 shell 脚本，就应审查工作目录。确认有效 RunAs、命令参数和拒绝规则、调用者可写的当前目录、WASM 到分支的数据流，以及该分支是否调用 helper。固定的 sudo `runchdir`、`os.Chdir` 或 [`exec.Cmd.Dir`](https://pkg.go.dev/os/exec) 都可以改变查找位置。静态共现只是候选线索；检查源码时不要运行 Go、WASM 或 helper。
- `sudoedit` 和参数通配符需要根据确切版本和规则进行检查；[检查清单](linux-privilege-escalation-checklist.md)包含 sudoedit 文件编辑问题。对于跨用户、针对通配符路径的 `sudoedit` 授权，检查有效的 `sudoedit_follow` 或 `FOLLOW` 设置、`sudoedit_checkdir`、解析后的目标，以及谁能替换每个父目录条目。前者可能允许跟随符号链接；禁用后者则会取消对可写目录的检查。但这两个设置单独都不能证明能写入其他用户的文件。下结论前，确认已安装 sudo 的策略和确切匹配的参数。参见[sudoers 选项定义](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)。
- 在 sudoers 命令规则中，参数通配符既能匹配空白，也能匹配路径字符。对于允许读取的命令，如果参数类似 `/restricted/*`，匹配前缀后可能还会允许额外的文件参数。审查确切的 RunAs 用户、命令路径、参数模式和后续拒绝规则；证明能读取文件并不代表能执行命令。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)区分了参数 glob 和命令路径 glob。
- 看似限制路径的参数 glob 也可能匹配 `../`。例如，root 权限的 `node /opt/scripts/*.js` 规则可能允许调用者指定 `/opt/scripts/` 开头但通过父目录段解析到目录外部的 JavaScript 文件。这里的通配符是**参数**通配符；Node 可执行文件的命令路径 glob 具有不同的斜杠匹配规则。下结论认定存在代码执行之前，应检查有效规则、后续拒绝规则、路径解析、目标文件控制权，以及任何 sudoers 正则表达式或摘要限制。参见[sudoers 通配符规则](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)和[Node 命令行文档](https://nodejs.org/api/cli.html)。
- 归档程序和其他工具程序可能具有执行 hook。使用 [GTFOBins](https://gtfobins.github.io/) 检查确切允许的参数，不要假设只有 shell 或解释器能执行命令。
- 不受限制的 root 权限 `qpdf` 规则可能通过 PDF 附件暴露特权文件：qpdf 10.2 及更高版本支持 `--empty` 和 `--add-attachment file ... --`，并可输出 PDF。如果特权进程能读取所选源文件，且能将 PDF 写入调用者可访问的路径，输出就可能包含源文件字节。在断定可能泄露文件之前，审查有效 sudo 参数和排除规则、qpdf 版本、源文件访问权限及输出路径。读取 root SSH 密钥只有在该密钥有效且允许 root SSH 认证时才有助于登录。参见[qpdf 附件选项](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments)。
- sudo 时间戳复用取决于缓存策略、所有者、终端/会话和权限。[权限提升指南](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens)介绍了相关检查。
- `doas` 有自己的规则和配置。按照[doas 章节](../linux-basics/linux-privilege-escalation/README.md#doas)的说明，检查允许的命令和可写配置路径。

### 通过 sudo 运行构建和软件包工具

即使 RunAs 身份是另一名非 root 用户，不受限制的 sudo 授权若允许使用 Foundry 的 `forge` 也可能产生影响。`--use` 等编译器选项可以指定本地可执行文件，`forge flatten -o` 可以选择输出文件。在将授权视为可利用之前，检查已安装 Forge 的版本、确切的 sudo 参数、可访问的项目和编译器路径、输出权限以及有效环境。通过 `PATH` 找到相对路径 helper 可执行文件属于依赖版本和环境的途径，不能假定每个 Forge 构建都具有此属性。<sup>[[23]](#references)[[24]](#references)</sup>

具备 root 权限的无限制 `pacman` 授权允许执行的不仅是软件包查询：`-U` 接受本地软件包，软件包可能包含安装脚本，而 `--hookdir` 可选择其他 hook 目录。测试前应审查有效 sudo 规则、参数限制和排除规则；被动枚举不需要安装软件包或运行 hook。<sup>[[25]](#references)[[26]](#references)</sup>

固定的 sudo shell wrapper 也可能安装指定的 npm 依赖，然后启动 Node 应用。审查确切的 RunAs 规则、软件包是否已安装、有效的 `HOME` 和 npm `userconfig`、项目配置或命令行覆盖项，以及低权限用户是否控制该名称对应的软件包或 registry。[npm 文档介绍了按用户和项目查找 `.npmrc`](https://docs.npmjs.com/cli/v6/configuring-npm/npmrc/)；sudo 的 `HOME` 行为取决于已安装策略和发行版，因此提权进程运行的 npm 可能会读取，也可能不会读取用户可写的 `.npmrc`。如果特权应用会导入新安装的软件包，其模块代码就可能以该应用的身份运行。安装阶段脚本是另一条独立途径，具体取决于版本和配置；[npm 文档介绍了它们的生命周期和用户处理方式](https://docs.npmjs.com/cli/v6/using-npm/scripts/)。`.npmrc` 路径或 `npm install` 语句本身只是审查线索。被动枚举时检查规则、简短的 wrapper、配置路径和软件包来源，不要安装软件包或启动应用。

当 root 权限 `pip` 或 `pip3 download` 的参数允许调用者选择不可信的源分发包时，即使 URL 模式将其限制为本地服务和 `.tar.gz` 后缀，也应将此授权视为软件包构建审查线索。`pip download` 接受归档 URL 并解析软件包元数据；准备 sdist 时，可能会在仅保存归档之前调用其构建后端或旧式 `setup.py` 代码。确认确切的 sudo RunAs 和参数规则、调用者是否能发布或替换所选归档，以及该 pip 版本是否确实会准备其元数据。固定的受信任归档或 wheel 并不能证明存在这条途径。被动枚举时不要获取或构建不可信软件包。参见 pip 的[下载命令](https://pip.pypa.io/en/stable/cli/pip_download/)、[构建系统接口](https://pip.pypa.io/en/stable/reference/build-system/)和[安全安装指南](https://pip.pypa.io/en/stable/topics/secure-installs/)。

允许 `pip install` 并接受调用者选择的本地项目路径的 sudo 规则，会形成更直接的构建边界。[pip 接受本地项目目录](https://pip.pypa.io/en/stable/topics/local-project-installs/)并调用其构建系统；[构建后端会运行由项目控制的构建 hook](https://pip.pypa.io/en/stable/reference/build-system/)。在将该规则视为特权代码执行之前，确认有效的 RunAs 身份、确切的参数限制和拒绝规则、所选项目是否由调用者控制，以及已安装 pip/后端的行为。固定的受信任项目或排除调用者所选路径的规则并不能证明存在此途径。被动枚举时检查规则和项目元数据，不要安装软件包。

不受限制的 root 权限 `easy_install` 授权也是相关的旧式软件包构建审查线索。[Setuptools 文档](https://setuptools.pypa.io/en/stable/deprecated/easy_install.html)指出，Easy Install 接受本地项目目录并构建源分发包；由调用者控制的项目可能在该构建过程中以 sudo 身份执行其 `setup.py`。确认有效的 RunAs 账户、确切命令和参数限制（包括后续拒绝规则）、所选项目是否由调用者控制，以及已安装工具的行为。固定的受信任项目或不允许调用者选择源的策略并不能证明存在此途径。枚举时检查规则和项目元数据，不要安装软件包。

允许通过 sudo 运行的 Python wrapper 若使用 `setuptools.package_index.PackageIndex.download`，且接受调用者选择的 URL，这与 `pip download` 是不同的审查情形：[setuptools GHSA-5rjg-fvgr-3xxf](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf)指出，在受影响的 78.1.1 之前版本中，源自 URL 的文件名可以逃逸预期下载目录，并以进程权限写入文件。确认有效 sudo RunAs 和参数规则、wrapper 是否将调用者的 URL 传给这一确切 API、已安装的构建版本或供应商回移补丁，以及结果路径最终解析到何处。版本字符串或可写下载目录本身都不能证明存在任意写入。枚举时检查简短的 wrapper 和软件包元数据，不要获取该 URL 或写入文件。

允许通过 sudo 运行的构建 wrapper 若将调用者选定的 `.spec` 文件传给 PyInstaller，也需要进行同样的信任边界审查。PyInstaller spec 是在**构建期间**执行的 Python，且其 `datas` 条目可以将构建身份可读的文件打包进产物。确认确切的 RunAs 用户、sudo 参数和拒绝规则、wrapper 的路径和分支处理方式、所选 spec 文件是否由调用者控制，以及产物是否可访问。仅仅允许输入 `.py` 文件或发现已安装 PyInstaller，并不能证明调用者能控制 spec 文件或执行了特权代码。被动审查只应读取范围受限的 wrapper 文件和元数据；不要运行构建。参见[PyInstaller spec 文件文档](https://pyinstaller.org/en/stable/spec-files.html)。

### 通过 sudo 运行 preset 和 plugin loader

Python 工具如果接受调用者选择的 preset 或 plugin 目录，可能会以 sudo 授予的权限导入代码。例如，BBOT 可通过 `-p` 接受 preset，其[自定义模块文档](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#load-modules-from-custom-locations)介绍了用于选择其他 Python 模块目录的 `module_dirs` 条目。如果有效 sudo 规则允许调用者选择 preset，且调用者控制所选目录中的模块，那么该 import 就可能以特权用户身份执行代码，甚至可能早于工具拒绝无效模块。检查已安装版本、确切的 sudo RunAs 和参数策略，以及 preset 和模块路径的所有权；枚举时不要加载模块。

### 通过 sudo 运行 Backdrop 命令行工具

[Bee](https://github.com/backdrop-contrib/bee) 是 Backdrop CMS 的 PHP 命令行工具。其 `eval`（`php-eval`）和 `php-script` 命令可以运行调用者提供的 PHP。因此，如果 sudo 规则允许以 root 身份运行 Bee 并接受不受限制的参数，那么在 Bee 能启动 Backdrop 安装的情况下，就可能暴露 root 代码执行。可以从站点目录运行它，或使用全局 `--root=<directory>` 选项选择站点；仅仅发现 Bee 或 Backdrop 的 `settings.php` 文件，并不能证明 sudo 授权有效、站点可用或引导成功。测试前应审查有效 sudo 规则、任何命令排除项、可执行文件身份以及站点访问权限。被动枚举时检查规则和文件路径，不要调用 Bee。参见[Bee 命令变更日志](https://github.com/backdrop-contrib/bee/blob/1.x-1.x/CHANGELOG.md)，了解新增的 PHP 命令。

### 通过 sudo 运行终端服务器

`mosh-server` 会以调用者身份启动交互式终端服务器。它会选择一个高位 UDP 端口和会话密钥，将两者报告给调用者，并通常在客户端连接时启动该用户的登录 shell。因此，即使服务器命令本身会脱离终端，以 root 身份运行 `mosh-server` 的无限制 sudo 授权也值得作为 shell 风险候选进行审查。检查有效的 RunAs 身份、允许的参数和排除规则、已安装的二进制、shell、客户端是否可用，以及 UDP 访问情况。被动枚举应检查 sudo 规则，不要启动服务器或打印任何有效会话密钥。参见[Mosh server 手册](https://manpages.debian.org/unstable/mosh/mosh-server.1.en.html)和[上游设计说明](https://github.com/mobile-shell/mosh#how-it-works)。

### 会改写调用者任务文件的特权备份 wrapper

以 root 身份运行的 shell wrapper 可能接受调用者选择的任务文件，从源路径中删除 `../`，检查结果是否以允许的目录开头，改写任务文件，然后将其*路径名*传给备份程序。审查完整规范化后的转换路径：单次字符串替换可能暴露出新的路径遍历序列，而词法前缀检查仍会接受它。还应检查备份程序读取的是改写后的内存数据，还是会再次打开该文件。如果它会重新打开文件，改写失败可能导致原始输入仍然保留。

在 Linux 上，`fs.protected_regular` 可能会阻止在其他用户拥有的、位于 world-writable sticky 目录中的普通文件上进行 `O_CREAT` 写入。这种拒绝具有保护作用，但如果 shell wrapper 忽略写入错误，它仍可能继续使用原始任务文件。确认该设置、文件所有者和目录，以及 wrapper 是否会在失败时停止。只有在有效 sudo 规则允许以特权用户身份运行 wrapper、调用者控制任务输入和可读的备份目标，并且备份工具确实会包含受保护源文件时，该路径才属于文件泄露候选。枚举时检查这些条件，不要运行备份。

### 特权网络工具的参数通配符

在 `tcpdump` 的 sudo 规则中，**参数模式**中的 `*` 可以匹配空白和斜杠，因此看似限制路径的模式仍可能允许添加额外选项文本。这与命令可执行文件路径中的通配符不同；应检查完整的 RunAs 规则和任何后续拒绝规则。如果可以注入选项，获准的调用方式和已安装 [`tcpdump` 的选项语义](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)将决定 `-F`、`-V`、`-r`、`-w` 或 `-Z` 是否能提供有用的读/写原语。`-V` 会读取捕获文件名列表，并非任意通用文件转储。即使 sudo 允许该命令，AppArmor 或其他 MAC 策略仍可能阻止文件访问；磁盘上存在 profile 文件并不能证明它已加载或正在强制执行。下结论前，被动审查授权和策略。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)说明了通配符之间的区别。

如果一条具有 root 权限的 sudo 规则只列出 `tcpdump` 可执行文件而没有限制参数，也值得审查。[tcpdump 手册](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)说明，使用 `-C` 或 `-G` 轮换保存的捕获文件时，`-z` 会指定轮换后的命令；`-Z` 或编译时默认设置可能会在该命令运行前降权。将该规则视为权限提升途径之前，应确认有效 sudo 规则、已安装构建版本、降权行为，以及是否能够触发轮换。高亮显示的规则只是候选线索，并不能证明能以 root 身份执行命令。

### 通过 sudo 运行 Nmap wrapper

如果 sudo 允许的 `nmap` 路径是 shell wrapper，应检查确切允许的路径和它转发的每个选项。阻止常见的 `--script` 写法并不一定能阻止加载 NSE 代码：Nmap 的 [`--datadir`](https://nmap.org/book/man-misc-options.html) 可以选择数据文件；启用脚本功能时，NSE 会从所选数据目录[加载 `nse_main.lua`](https://nmap.org/book/nse-implementation.html)。某些已安装构建版本还接受其他长选项写法，因此应将限制与该二进制实际使用的解析器进行对照。[`--excludefile`](https://nmap.org/book/man-target-specification.html)是另一个独立的文件读取面；解析器错误可能泄露文本。枚举时检查有效 sudo 规则、wrapper 逻辑、Nmap 版本、目录控制权和 MAC 策略；不要运行扫描。

### 通过 sudo 运行 Mercurial pull hook

即使使用固定源 `sudo hg pull /fixed/source`，除非通过 `-R` 固定接收仓库，否则接收仓库仍由当前工作目录决定。由调用者控制的接收仓库可以在 `.hg/hgrc` 中定义 hook，而该 hook 可能以 sudo RunAs 用户身份运行。[Mercurial 会忽略由不受信任用户或组拥有的仓库配置](https://mercurial-scm.org/help/topics/config)，因此将其视为代码执行之前，应检查 RunAs 账户的受信任用户/组和确切工作目录。被动审查只需读取策略和配置；枚举时不要执行 pull 或调用 hook。

### 通过 sudo 运行 Git pull hook

对于精确的 root 级 `sudo git pull` 授权，还应检查由工作目录选定的**接收仓库**。由调用者拥有的仓库可以设置可执行的 `post-merge` hook；当 pull 实际完成一次成功合并时，该 hook 会以 Git 进程的身份运行；[Git 文档说明了此 hook](https://git-scm.com/docs/githooks)和[pull 的 merge 与 rebase 行为](https://git-scm.com/docs/git-pull)。确认有效 sudo 规则和当前工作目录（CWD）、活动 hook 的路径和权限，以及包含新提交的合并是否可达。失败、无操作或仅执行 rebase 的 pull 并不能证明这条 hook 路径存在。检查策略和仓库元数据，不要运行特权 pull。

### 通过 sudo 运行 rsync 归档复制

对于 `sudo rsync -a ... /writable/source/* /fixed/destination/`，**sudoers 参数模式**中的 `*` 可以匹配空白，从而允许在源和目标之间插入额外选项。这不同于 shell 对文件名的展开。如果调用者可以填充源目录，且特权 rsync 进程可以写入目标目录，那么 [`--chown`](https://download.samba.org/pub/rsync/rsync.1) 就可以请求特权所有权，同时归档模式保留权限位，可能创建归该身份所有的 SetUID 文件。检查确切的[sudoers 通配符语义](https://man7.org/linux/man-pages/man5/sudoers.5.html)、rsync 版本、后续拒绝规则、文件系统的 `nosuid` 和 MAC 策略。匹配的规则只是审查候选，并不证明权限提升成功。

### 通过 sudo 运行数据包过滤器规则导出

如果有权以 root 身份不受限制地运行 `iptables` 和 `iptables-save`（或对应的 `ip6tables` 组合），就应审查文件写入风险。`comment` 匹配模块接受调用者选择的规则文本，而 `iptables-save -f` 会将序列化后的规则集写入指定路径。<sup>[[20]](#references)[[21]](#references)</sup>有效载荷是否有用，取决于已安装后端如何序列化注释，以及目标文件是否会接受导出中的其他行；仅靠 `iptables-save` 并不能提供任意自选内容。检查确切的 sudo RunAs 身份、参数和排除规则、可用的匹配扩展、后端以及目标权限。枚举时检查授权，不要更改防火墙规则或写入文件。

### 特权 Below 日志目录

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w)影响了 0.9.0 之前会创建 world-writable `/var/log/below` 目录的 Below 版本。如果服务或获准的 sudo 命令以 root 身份运行受影响的构建版本，那么能够写入并遍历非 sticky 日志目录的用户，可能会在特权进程打开日志条目前将其替换成符号链接。检查已安装软件包的修复状态、确切的特权执行路径、有效目录访问权限、sticky bit 和 ACL，以及 `/var/log/below/error_root.log` 的元数据。仅有 world-writable 路径或 sudo 规则不能证明整条链成立。sticky 目录或供应商回移补丁会改变风险评估。被动枚举只需检查元数据，无需创建链接或运行特权程序。

### 从可写输入收集特权 support bundle

允许通过 `sudo` 运行的 support profile 脚本可能以 root 身份读取固定日志路径，并将内容复制到 profile 归档中。检查脚本实际读取的文件，然后确认调用者是否能将源路径或任何父目录条目替换为符号链接。如果特权读取会跟随该链接，且生成的归档可由调用者读取，那么就可能泄露受保护文件。sudo 授权、可写源路径、特权读取和可读输出必须同时存在；仅有可写日志或 profile 文件名并不足够。枚举时检查有效权限和链接元数据，不要替换文件或生成 profile。[Nagios XI 支持指南](https://support.nagios.com/forum/viewtopic.php?t=62758)介绍了其以 root 身份运行的 profile 脚本和输出归档，说明为何这类归档的输入和输出访问都需要限制。

### 以 root 身份运行的 Python 归档还原脚本

针对 Python 还原脚本的严格限定 sudo 规则，仍需审查其归档输入。如果调用者能选择或替换归档，而脚本以 root 身份调用 `tarfile.extractall(filter="data")` 解压，就应先检查解释器的安全更新情况，再信任该过滤器。CPython 修复了多个 symlink 和 hard-link 过滤器绕过问题，包括 CVE-2025-4517；相关修复已包含在 3.9.23、3.10.18、3.11.13、3.12.11 和 3.13.4 中。发行版可能回移补丁，因此显示的解释器版本本身不能证明存在风险。<sup>[[16]](#references)[[17]](#references)</sup>

进行被动审查时，读取确切的 sudo 命令和脚本，追踪哪个参数选择归档，并检查当前用户是否能写入归档或其所在目录。分别确认已安装版本的供应商补丁和解压目标；`filter="data"` 并不能保证所有不可信归档都安全。<sup>[[16]](#references)[[17]](#references)</sup>

### 通过 sudo 运行机器学习模型加载器

如果 sudo 规则允许调用者选择 `.pt`、`.pth` 或 `.ckpt` 文件，且特权脚本会将其传给 [`torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load.html)、`pickle.load` 或其他基于 pickle 的 loader，就值得审查。检查有效的 RunAs 规则、调用者能否创建或替换所选模型，以及参数是否经由 shell wrapper 实际传递给 Python helper。`.pth` 扩展名也用于无关的 Python site 配置文件，因此仅凭扩展名不能证明加载的是模型。归档扫描或静态 pickle 扫描都不能证明之后的加载是安全的；应检查 loader[依赖版本的 `weights_only` 行为](https://docs.pytorch.org/docs/stable/notes/serialization.html)及任何 allowlist。参见[ML pickle 和 Fickling 说明](../../generic-methodologies-and-resources/python/keras-model-deserialization-rce-and-gadget-hunting.md)。被动枚举时绝不要加载或解包模型。

### 通过 sudo 对存储的输入进行表达式解析

通过 sudo 以 root 身份运行的固定 Python 脚本，仍可能对低权限用户能够存入应用数据库的文本进行求值。在 TensorFlow 中，调用 `preprocess_input_exprs_arg_string(value, safe=False)` 会选择 `eval` 路径；[TensorFlow 安全公告](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-75c9-jrh4-79mc)介绍了不安全解析器，以及对其命令行调用方的修复。即使该命令行调用方已修复，应用显式调用 `safe=False` 仍需单独审查。检查有效 sudo 规则、谁能修改确切的输入记录、过滤或评分逻辑是否会让该记录到达此调用，以及已安装函数的行为。TensorFlow 版本、sudo 授权或硬编码模型文件本身都不能证明整条链成立。被动检查脚本和数据流；枚举时不要运行特权 helper 或提交测试表达式。

### 通过 sudo 允许的 needrestart 配置

`needrestart -c` 会加载调用者选择的 Perl 配置文件并执行其内容。如果 `sudo -l` 允许以 root 身份运行 `needrestart`，且参数允许使用 `-c`，而调用者能在可写位置选择可读配置文件，那么该权限可能导致 root 代码执行。检查确切的 sudo RunAs 和参数规则；仅允许固定参数列表的规则可能会阻止这条路径。这与 needrestart 的解释器扫描漏洞无关：更新软件包或禁用 `interpscan` 并不能让不受限制的 root `-c` 授权变得安全。<sup>[[2]](#references)[[18]](#references)[[19]](#references)</sup>

### 通过 sudo 以其他账户身份运行 Python import

固定的 Python 入口点仍可能导入调用者能够编辑或替换的模块，即使 sudo 以**非 root**服务用户身份运行脚本也一样。对于字面导入 `from utils import status`，应同时检查本地 `utils/__init__.py`、`utils/status.py` 和软件包目录权限。在将可写文件视为执行路径之前，确认脚本的 import 路径、确切允许的 sudo 参数，以及相关操作是否会到达该 import。枚举时检查文件和权限，不要 import 或运行脚本。<sup>[[2]](#references)[[3]](#references)</sup>

对 `python3 /absolute/script.py` 的精确 sudo 规则只要求脚本可读；文件不需要可执行，也不需要 shebang。还应审查**缺失的**本地模块：如果脚本导入的模块对应的文件可以在调用者可写的脚本目录中创建，Python 可能会以 RunAs 身份加载该文件。确认有效 sudo 规则、解释器实际的[模块搜索路径](https://docs.python.org/3/library/sys_path_init.html)、该模块是否为内置或冻结模块，以及是否会执行相关 import。直接针对脚本的 sudo 规则对执行位和 shebang 的要求不同。另一个单独的 wrapper 若在 `sudo -u account` 后追加调用者提供的 token，也需要审查参数流：只有当调用的 sudo 策略允许最终指定的身份时，这些 token 中另一个 `-u` 才有影响。仅凭静态字符串无法证明任一途径成立。

### 通过 sudo 使用调用者控制配置的 Apache

如果 sudo 规则允许以特权身份运行 `apachectl`、`apache2ctl` 或 `httpd`，并接受调用者控制的 `-f` 配置文件，应检查该文件及其父目录权限。Apache 的 [`LoadModule`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadmodule) 指令接受模块名称和**模块文件名**；[`LoadFile`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadfile) 也会加载文件。[`Include` 和 `IncludeOptional`](https://httpd.apache.org/docs/2.4/mod/core.html#include) 可以扩展配置，或通过错误暴露文件内容。自定义 wrapper 可能会验证这些路径、降权或限制参数，因此仅有可写配置只是审查候选，并不能证明代码执行。下结论前检查路径规范化、符号链接和指令解析方式。

### 通过 sudo 使用调用者控制配置的 nginx

不受限制的 root 权限 `nginx` 规则可能允许使用 [`-c` 选择其他配置](https://nginx.org/en/docs/switches.html)。审查确切的 sudo 参数和排除规则、调用者能否提供配置，以及生成的 master 或 worker 是否仍能访问受保护路径。指定 `root` 并启用 `autoindex` 可能通过新的监听器暴露文件；[`dav_methods PUT`](https://nginx.org/en/docs/http/ngx_http_dav_module.html) 可能提供特权文件写入路径，但 DAV 模块默认并不构建，必须检查其是否存在、监听器是否可达、文件权限和临时文件行为。[`error_log` 指令](https://nginx.org/en/docs/ngx_core_module.html#error_log)也可以指定文件；将日志写入敏感配置文件（例如 `/etc/ld.so.preload`），只有在写入进程实际具备特权且日志记录内容可控时，才会成为权限提升路径。`sudo -l` 中可执行文件的高亮只是审查线索，并不能证明这些途径中的任意一种可行。被动枚举不要启动或重新配置 nginx。

### 特权 Bash 提示符中的模式比较

当 sudo 允许运行的 Bash 脚本读取调用者输入，并使用 `[[ "$expected" == $entered ]]` 进行检查时，Bash 会将未加引号的右操作数解释为模式。因此，无需知道预期值，通配符也可能通过比较。给操作数加引号（`[[ "$expected" == "$entered" ]]`）可进行字面字符串比较。审查确切的 sudo 规则、提示是否可达，以及比较后脚本会执行什么；仅凭语法本身不能证明存在可利用路径。枚举时不要打印预期值。参见[Bash 条件结构参考](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)。

### 通过 sudo 运行下载并执行文件的 helper

如果自定义 helper 接受调用者选择的 URL、将响应写入磁盘，之后再通过解释器或 shell 调用该文件，那么不受限制的 root 权限 sudo 授权值得进行数据流审查。[sudoers 允许未列出命令参数的命令条目接受任意参数](https://man7.org/linux/man-pages/man5/sudoers.5.html)；可执行文件路径固定，并不会限制参数能够选择的内容。确认已安装 helper 中实际的 URL 验证、输出路径、成功分支和后续执行逻辑。仅有 libcurl import 或可打印字符串并不能证明这条链成立。

即使输出 basename 固定，如果 helper 使用**位于调用者控制工作目录中的相对路径**，也可能在写入和执行之间被替换。重命名或替换 root 所有文件取决于目录的写入/搜索权限和任何 sticky bit 限制，而不只是文件模式；参见[`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html)。检查 helper 之后会重新打开该路径还是使用已打开的文件描述符，以及写入前是否切换到受信任目录。被动检查 sudo 策略、helper 和目录元数据；枚举时不要调用特权下载或进行竞争操作。

通过 sudo 以 root 身份运行的下载 helper，如果构造了诸如 `curl <caller input> -o <fixed output>` 的 Bash 命令字符串，还可能暴露**参数**注入。即使过滤器拒绝空白，仍可能利用 [Bash 花括号展开](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html)：未加引号、以逗号分隔的元素可以变成多个 curl 参数。如果输入先于固定的 `-o` 到达 curl，调用者提供的输出选项就可能以 helper 身份为第一个 URL 指定目标；[curl 会按顺序将输出选项与 URL 关联](https://curl.se/docs/manpage.html#-o)。确认确切的 shell、引号处理、输入验证、有效 sudo 规则、curl 参数顺序和支持的 URL scheme，以及调用者是否控制获取的字节或能够读取结果。PyInstaller 打包的可执行文件可能包含 Python 应用逻辑，但仅凭其打包标记或 `curl` 字符串不能证明存在这条数据流。获得授权后，可离线审查范围受限的副本；常规枚举不要运行 helper 或获取攻击者选定的数据。

以 root 身份运行的 sudo shell 脚本如果调用 [`mktemp -u` / `--dry-run`](https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html)，只会选择一个尚未使用的名称；它**不会**创建文件。如果脚本之后在其他用户能够影响的目录中创建该名称，随后重新打开文件，并将其内容附加到 root 的 `authorized_keys` 等受保护目标，就应审查可能存在的临时文件竞争条件。确认确切的 sudo 规则、目录和文件所有权、创建与重新打开的顺序、内核保护，以及特权写入是否确实使用了攻击者控制的字节。仅有 `mktemp -u` 字符串或可写的 `/tmp` 并不能证明存在竞争条件。检查脚本和路径元数据；枚举时不要运行它或对临时文件进行竞争操作。

## 防御说明

- 避免通过 sudo 授权运行解释器或交互式编辑器。<sup>[[1]](#references)</sup>
- 不要对 `tee` 等通用文件写入工具授予不受限制的操作数。使用 root 所有的 wrapper 来选择固定目标，并拒绝由调用者控制的路径。<sup>[[2]](#references)</sup>
- 优先使用固定的、由 root 所有的 wrapper，只执行单一且范围狭窄的管理操作。<sup>[[1]](#references)[[2]](#references)</sup>
- 如果无法避免使用解释器，应限制确切的脚本路径，防止用户控制参数、可写 import、`PYTHONPATH` 和不安全的环境保留。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- 如果确实需要编辑文件，应限制确切的文件路径，并考虑使用 `sudoedit`，同时确保 sudo 版本已修补且严格处理环境。<sup>[[1]](#references)[[2]](#references)</sup>
- 检查 `SETENV`、`env_keep`、可写工作目录、可写模块/import 路径、`NOEXEC`、`use_pty` 和日志记录，但不要将它们视为完整的沙箱。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
- [18] [needrestart 配置选项和执行 — 上游源码](https://github.com/liske/needrestart/blob/master/needrestart)
- [19] [needrestart 命令行为 — GTFOBins](https://gtfobins.org/gtfobins/needrestart/)
- [20] [iptables-save(8) — netfilter 手册页](https://www.man7.org/linux/man-pages/man8/iptables-save.8.html)
- [21] [iptables-extensions(8)：comment 匹配 — netfilter 手册页](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
- [22] [简单命令展开 — Bash 参考手册](https://www.gnu.org/s/bash/manual/html_node/Simple-Command-Expansion.html)
- [23] [Forge 编译器选项 — Foundry 文档](https://getfoundry.sh/forge/reference/forge-inspect/)
- [24] [Forge flatten — Foundry 文档](https://getfoundry.sh/forge/reference/forge-flatten/)
- [25] [pacman(8) — Arch 手册页](https://man.archlinux.org/man/pacman.8.en)
- [26] [PKGBUILD(5) 安装脚本 — Arch 手册页](https://man.archlinux.org/man/core/pacman/PKGBUILD.5.en)
- [27] [Volexity — VerdantBamboo：防火墙中的又一个 BRICKSTORM](https://www.volexity.com/blog/2026/06/04/verdantbamboo-just-another-brickstorm-in-the-firewall/)
- [28] [GNU Coreutils — `tee`：将输出重定向到多个文件或进程](https://www.gnu.org/software/coreutils/manual/html_node/tee-invocation.html)
{{#include ../../banners/hacktricks-training.md}}
