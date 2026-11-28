# Sudo 命令滥用

{{#include ../../banners/hacktricks-training.md}}

## Sudo 允许使用的解释器

如果 `sudo -l` 允许用户以 root 身份运行解释器，应将其视为可直接执行代码。解释器的用途就是执行任意代码，因此，允许使用 `python3`、`perl`、`ruby`、`lua`、`node` 或类似二进制文件的规则，通常等同于允许执行 root 命令，除非参数受到严格限制并经过验证。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

常见的审查流程：先列出用户的权限，然后使用解释器的 `-c` 选项执行一条 Python 语句。<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```

其他解释器示例如下；列出的解释器文档介绍了内联代码执行或子进程 API。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```

路径必须完全一致。如果 sudo 规则允许 `/usr/bin/python3`，验证时就使用这个确切路径。<sup>[[2]](#references)</sup>

像 `/usr/bin/python*` 这样的 sudo 可执行文件 glob 也可能允许 Python 2 运行原本为 Python 3 编写的脚本。如果脚本执行到 `input()` 并接收调用者可控的文本，[Python 2 会将该文本作为表达式求值](https://docs.python.org/2/library/functions.html#input)；显式调用解释器会覆盖脚本的 shebang。在将其视为一条执行路径之前，请确认已安装且匹配的二进制文件、有效的 RunAs 和参数策略、拒绝规则，以及可访问的输入。

root-capable sudo 规则中固定的脚本路径，并不能限制脚本实际执行的内容。对于可读取的 Bash wrapper，请检查其第一个可执行命令是否将未加引号的位置参数（例如 `$1`）用作**命令词**，同时 sudo 是否允许调用者自行选择参数。请确认有效的 RunAs 身份、密码和参数策略、后续拒绝规则，以及脚本实际进入的分支；`NOEXEC`、固定的安全参数列表，或会验证命令的 wrapper，都可能改变结果。枚举期间应静态检查这个短脚本，而不要用测试命令调用它。

允许不受限制地以 root 权限运行 `dotnet` 的 sudo 规则，也值得检查其解释器能力。安装了 .NET SDK 时，[`dotnet fsi` 可交互式运行 F# 代码或运行脚本](https://learn.microsoft.com/en-us/dotnet/fsharp/tools/fsharp-interactive/)，而 [`dotnet run` 可从源代码运行项目](https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-run)。请先确认有效的 RunAs 身份和确切的参数策略：限定为特定安全子命令或可信应用程序的规则，属于不同的授权；而仅安装运行时的环境可能没有 SDK 命令。可执行文件名称本身只是审查线索，并不能证明能够执行代码。

```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```

## Sudo-allowed `tee`：任意特权文件写入

GNU `tee` 会将标准输入复制到作为文件操作数提供的每个路径。因此，允许以 root 身份执行 `/usr/bin/tee` 且参数由调用者控制的 sudo 规则，会赋予任意 root 文件创建或覆盖能力。添加 `-a` 会将该能力改为追加写入。`PASSWD:` 标签与 sudo 身份验证有关；它本身不会限制目标路径或从标准输入读取的字节。<sup>[[2]](#references)[[27]](#references)[[28]](#references)</sup>

首先检查确切的规则。在经过授权的测试系统上，只使用可安全创建的临时目标验证该能力。最后的 `>/dev/null` 仅会抑制 `tee` 向标准输出的复制内容。<sup>[[28]](#references)</sup>

```bash
sudo -l
printf '%s\n' 'controlled-write' | sudo /usr/bin/tee /root/tee-proof >/dev/null
printf '%s\n' 'appended-line' | sudo /usr/bin/tee -a /root/tee-proof >/dev/null
```

在 producer 前加上 `sudo` 并不会提升后续 shell 重定向的权限，因为是调用者的 shell 打开目标文件。必须让特权进程负责写入，如上面的管道所示。<sup>[[1]](#references)[[15]](#references)</sup>

确认可以写入后，从 [Arbitrary File Write to Root](../interesting-files-permissions/write-to-root.md) 中选择合适的 root 代码执行入口。一条已观察到的利用链使用 root 权限的 `tee` 在 `/etc/cron.d/` 下创建一个短暂存在的文件，通过用户可控的脚本启动后门，并在执行后删除 cron 文件。删除 cron 文件可避免它成为长期持久化入口，不过系统日志仍会保留活动痕迹。<sup>[[27]](#references)</sup>

## Sudo-allowed editors

如果 `sudo -l` 允许用户以 root 身份运行交互式编辑器，应将其视为命令执行入口，而不是无害的文件编辑权限。编辑器通常可以执行 shell 命令、读取任意文件、写入任意文件，或在编辑器内调用外部辅助程序。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

常见的检查流程：列出用户的权限，然后通过 sudo 调用每个获准使用的编辑器或 pager。<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

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

然后在 nano 命令提示符中输入一个命令，例如 `id` 或 `/bin/sh`。<sup>[[12]](#references)</sup>

```bash
id
/bin/sh
```

如果交互式 shell 没有可用的终端流，这种重定向形式会将其标准输出和标准错误映射到文件描述符 0。<sup>[[15]](#references)</sup>

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

允许以 root 身份运行 `apport-cli` 的 sudo 规则也应进行同样的分页器检查。受影响版本的 Apport 可以在 `less` 中打开崩溃报告，并允许攻击者调整终端大小；如果满足特定的 sudo 和分页器条件，分页器随后可能提供 root shell。在仅凭版本号判断其是否存在漏洞之前，应先检查实际生效的 sudo 规则、分页器配置以及发行版的软件包修复情况。在被动枚举期间，应读取软件包和策略元数据，不要生成崩溃报告或打开特权报告。[Ubuntu 的 CVE 记录](https://ubuntu.com/security/CVE-2023-1326)列出了特定发行版本对应的修复软件包版本，其中包括回移的修复。

```text
!/bin/sh
```

## 其他 sudo 和 doas 规则风险

从 `sudo -l`、`sudo -V` 以及任何适用的 `doas` 策略开始。综合查看允许的命令、运行身份、参数、环境和默认设置。允许以非 root 服务账户身份运行命令，仍可能暴露该账户的文件，或提供一条通往 root 的路径。

即使 sudo 只允许运行固定的 Python 脚本，如果交互式、由调用者控制的输入被拼接进 [`os.system()`](https://docs.python.org/3/library/os.html#os.system)，脚本仍可在其 RunAs 身份下运行 shell 命令。仅靠 shell 标点符号的 denylist 不足以证明安全：[shell 也会识别 `$(...)` 命令替换](https://pubs.opengroup.org/onlinepubs/9799919799/utilities/V3_chap02.html)。确认允许的参数确实能进入输入分支、输入未经安全验证就到达 shell 命令，并且生效的 sudo 策略允许使用预期的 RunAs 用户。脚本路径或一次 `os.system()` 调用本身都只是审查线索；应检查源代码，而不要调用特权脚本。

具有 root 权限的有效 sudo 授权若允许运行 `chattr`，可以移除文件的 immutable (`i`) 属性，但这本身并不授予写入权限或新的身份。[`chattr` 手册](https://man7.org/linux/man-pages/man1/chattr.1.html)指出，该属性会阻止修改，且只有 root 或具有 `CAP_LINUX_IMMUTABLE` 的进程才能更改它。检查确切的 sudo 参数策略和文件系统支持情况，然后另行确认属性清除后调用者是否能写入文件，以及更高权限的使用者是否会使用该文件。例如，要替换登录 shell，还需要目标账户接受相应凭据，并且确实通过该 shell 登录。枚举期间应审查策略、文件属性和权限，不要对它们作出更改。

如果 sudo 同时要求密码和一次性验证码，应将这些前置条件与命令授权分开处理。可读的 `.google_authenticator` 文件包含敏感种子材料，而旧的应用程序或数据库密码哈希只是当前账户密码的候选值；两者都不能证明另一因素会被有效的 PAM 配置接受。获得授权后，再审查确切的 RunAs 和参数：不受限制的 root 授权若允许运行 RubyGems `gem`，可能会暴露其编辑器命令（[GTFOBins](https://gtfobins.github.io/gtfobins/gem/)），但受限授权或认证失败则不会。被动枚举应报告路径和策略，不要打印种子、破解密码、生成验证码或调用特权命令。

对 Chef 的 `knife`，若其 sudo 授权可不受限制地以 root 身份运行，值得从解释器层面审查：[Chef 文档说明，`knife exec -E` 会在本地求值 Ruby 字符串](https://docs.chef.io/workstation/26/tools/knife/knife_exec/)。确认生效的 sudo 规则允许 `exec` 子命令和调用者提供的 `-E` 参数、预期的 RunAs 身份，以及任何匹配的命令拒绝规则或固定参数。仅发现已安装的二进制文件，或只允许其他子命令的规则，都只是线索。被动枚举应报告规则，不要调用 `knife`。

对交互式 `msfconsole` 的精确 root 权限 sudo 授权同样敏感：[GTFOBins 记录了其 `irb` 控制台](https://gtfobins.org/gtfobins/msfconsole/)，该控制台可能继承 sudo 身份。确认有效的 RunAs 用户、允许的参数列表、命令拒绝规则、`NOEXEC` 或其他限制、已安装控制台的行为，以及调用者能否提供交互式输入。仅看到路径高亮只是审查线索；被动枚举时不要启动控制台。

在 FreeBSD 上，即使 sudo 规则仅允许以 root 身份运行 `pkg update` 和 `pkg install *`，也值得审查仓库信任。检查调用者能否写入 `/etc/hosts`，以及*生效的*启用仓库配置是否使用 `signature_type: none` 的 HTTP 主机名。[FreeBSD 的 `pkg.conf` 手册](https://man.freebsd.org/cgi/man.cgi?query=pkg.conf&sektion=5)指出，`none` 会禁用签名检查；仅有 `pkg+http` 并不能证明这一点。软件包可以包含安装脚本（[FreeBSD Porter's Handbook](https://docs.freebsd.org/en/books/porters-handbook/pkg-files/)），因此，如果调用者确实控制仓库端点并能选择软件包，就可能跨越 root 权限边界。下结论前，应确认仓库覆盖配置、SRV/镜像解析、生效的 sudo 参数、软件包选择和脚本执行情况。枚举时检查策略和本地小型配置文件，不要重定向名称或运行 `pkg`。

如果 sudo 会保留由调用者控制的 `http_proxy`，对具有 root 权限的 `apt-get update` 和 `apt-get upgrade` 授权也需要审查仓库信任。检查生效的 APT 代理配置是否实际使用该变量，以及它会影响哪些启用仓库的请求；单凭代理无法替换由可信签名密钥认证的归档。[APT 的 HTTP 传输手册](https://manpages.debian.org/experimental/apt/apt-transport-http.1.en.html)说明了代理优先级，[apt-secure](https://manpages.debian.org/experimental/apt/apt-secure.8.en.html)说明了签名检查、不安全仓库覆盖设置，以及对未认证软件包的确认要求。确认确切的 sudo RunAs 和参数、仓库认证策略、是否需要交互式确认，以及所选升级是否会以 root 身份运行软件包脚本。被动检查策略和本地配置；枚举时不要重定向软件包流量或运行升级。

如果 root 权限 sudo 规则允许 `snap install`，且其参数让调用者可以选择本地 snap 并使用宽松安装模式，那么这可能形成从软件包到代码的边界。[Snap 文档](https://snapcraft.io/docs/explanation/snap-development/install-modes/)指出，`--dangerous` 会跳过本地 snap 断言检查，`--devmode` 会放宽隔离；[安装钩子可在首次安装时运行](https://snapcraft.io/docs/reference/development/supported-snap-hooks/)。在声称可以访问受保护的主机文件之前，应检查确切的 sudo 参数/RunAs 策略、谁控制 snap 文件、已安装的 snapd 是否接受这些模式，以及钩子的有效身份和隔离情况。仅有 `snap` 二进制文件或看似包含通配符的规则并不能证明这条链路成立。被动枚举时不要安装软件包或执行其钩子。

对精确授权以非 root 账户身份运行自定义凭据读取二进制文件的 sudo 规则，首先应在不运行它的情况下检查获授权的二进制文件及其文件权限。嵌入式密码门控可能只有宽字符形式才能看见；[GNU `strings` 文档说明了 16 位小端提取方式](https://sourceware.org/binutils/docs/binutils/strings.html)。可见字符串并不能证明它就是被接受的密码，也不能证明成功分支会暴露当前凭据。应分别确认二进制文件的行为、目标账户访问受保护数据的能力、凭据有效性，以及后续的账户或组身份转换。如果该账户属于 `docker` 组，应确认 socket 访问权限以及守护进程采用 rootful 还是 rootless 身份，然后再推断是否能访问主机 root；[Docker 说明了该组可能带来的 root 级影响](https://docs.docker.com/engine/install/linux-postinstall/)。常规枚举应报告 sudo 规则和组成员身份，不要执行二进制文件或转储其字符串。

对应用维护脚本的通配符 sudo 规则，审查范围不能仅限于脚本路径。检查获准的脚本是否接受不受限制的参数，或是否会读取低权限应用账户可写的设置，然后追踪这些值是否进入 shell 命令或子进程环境。例如，ZoneMinder 的 [`zmupdate.pl` 会拼接 `mysqldump` 命令，并通过 `qx` 执行](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmupdate.pl.in)，而 [`zmdc.pl` 会在启动守护进程前，将 `ZM_LD_PRELOAD` 设置复制到 `LD_PRELOAD`](https://github.com/ZoneMinder/ZoneMinder/blob/master/scripts/zmdc.pl.in)。如果相应输入可被控制，并且在已安装版本中能到达相关代码，那么允许以 root 身份运行其中任一脚本的 sudo 规则就可能跨越信任边界。检查生效的 sudo 规则、应用配置权限和脚本源代码；通配符或设置本身只是审查线索，并不能证明代码会执行。

- `SETENV`、`env_keep`、`secure_path` 和 `LD_PRELOAD` 可能让原本受限的命令变成导入、库或 PATH 劫持入口。参见[环境变量指南](../linux-basics/linux-environment-variables.md)和[SUID/链接器滥用](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md)。

如果精确的 root 权限 `SETENV` 授权允许运行 shell 包装器，而该包装器使用字面量导入来启动固定的 Python 脚本，那么也值得审查这一跳。`secure_path` 限制的是 shell 命令查找，不是 Python 的 [`PYTHONPATH` 模块搜索](https://docs.python.org/3/using/cmdline.html#envvar-PYTHONPATH)；[`-E` 和 `-I`](https://docs.python.org/3/using/cmdline.html#cmdoption-E) 会让 Python 忽略该环境变量。在将其视为代码执行之前，应确认生效的 sudo 标签和拒绝规则、包装器分支、解释器选项、导入解析，以及调用者是否能写入搜索目录。静态检查简短脚本，不要调用特权包装器。

即使精确的 root 权限 `neofetch ""` sudo 授权没有其他参数，只要适用的 sudo 默认设置会保留由调用者控制的 `XDG_CONFIG_HOME`，仍可能加载 shell 配置。[Neofetch 的配置加载器](https://github.com/dylanaraps/neofetch/blob/master/neofetch)会从该目录下加载 `neofetch/config.conf` 或 `neofetch/config`；空参数列表并不会阻止此查找。确认已安装加载器的行为、有效的 RunAs 和参数策略、任何命令拒绝规则、sudo 是否确实为此命令保留所选变量，以及调用者是否控制一个可读的配置路径。保留的变量或已安装的 Neofetch 本身都只是审查线索。检查策略和文件元数据，不要调用特权命令或打印配置内容；参见[sudoers 环境处理](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)。

对 `facter` 的不受限制的 root 权限 sudo 规则，值得单独审查自定义 fact。[Puppet 文档](https://help.puppet.com/core/current/Content/PuppetCore/loading_custom_facts.htm)说明，`--custom-dir` 会从指定目录加载 Ruby fact 文件。检查确切的 sudo 规则是否允许该选项、已安装的 Facter 是否接受该选项，以及调用者是否控制该目录。固定参数授权、明确的命令拒绝规则或已禁用的自定义 fact 都可能改变结果。被动枚举应报告该策略候选项，不要调用 Facter 或读取 fact 内容。

对于带有 `SETENV` 的精确 root 权限 sudo 脚本授权，应检查 `find` 等未使用完整路径的命令，以及 sudo 策略和脚本初始化后生效的 `PATH`。被 source 的 Bash 文件也可以运行 `enable -n [`：[Bash 随后会通过 `PATH` 搜索](https://www.gnu.org/software/bash/manual/html_node/Bash-Builtins.html)外部的 `[`，供脚本稍后调用。确认适用的 [sudoers 环境和 `secure_path` 规则](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)、任何 `NOSETENV`/`NOEXEC` 或拒绝条目、脚本及被 source 文件的执行流程，以及调用者是否能控制可执行的搜索目录。可读脚本中含有未限定路径的命令只是审查线索，并非特权执行的证明；检查脚本时不要调用 sudo 规则。
- 特权脚本即使使用 `curl` 获取固定 URL，只要适用的 sudo 规则会保留 `http_proxy`，且请求通过该代理发送，仍可能接受由调用者选择的响应。如果脚本随后把响应传给会解析外部实体的 XML 解析器，恶意响应就可能泄露特权进程可读的文件。检查确切的 sudo 环境策略、`no_proxy` 排除项、请求的 URL、解析器配置和输出位置；仅有代理变量或 XML 解析器并不构成漏洞。[curl 代理环境文档](https://everything.curl.dev/usingcurl/proxies/env.html)说明了变量的行为。被动枚举时不要发起网络请求或解析恶意 XML。
- 如果 root 权限 sudo 脚本会根据调用者影响的数据构建 PostScript 文件，然后运行 `ps2pdf -dNOSAFER`，则值得单独审查输入流。Ghostscript 文档说明，该标志会禁用 SAFER，直到执行 `.setsafe`；在此期间，PostScript 文件操作受进程的操作系统权限限制。由调用者参数拼接而成的 SQL 查询可能将攻击者控制的行送入 PostScript 模板，但仅有查询字符串或 `ps2pdf` 调用并不能证明这些数据会到达可执行的 PostScript 语法。确认生效的 sudo 规则、从输入到模板的确切路径、是否进行了转义、已安装的 Ghostscript 行为，以及文档解释前是否重新启用了 SAFER。被动枚举时不要调用特权转换程序。参见[Ghostscript 的 `-dNOSAFER` 文档](https://ghostscript.readthedocs.io/en/master/Use.html)。
- 对运行 shell 脚本的 sudo 规则，应将保留的变量与脚本本身对照检查。例如，`if $CHECK_CONTENT; then` 这样的结构会把展开后的值作为命令运行，因此即使脚本路径和参数固定，只要保留 `CHECK_CONTENT`，也可能允许命令执行。应针对具体规则检查该分支是否可达，以及环境是否确实会被保留。<sup>[[2]](#references)[[22]](#references)</sup>
- sudo 允许运行的 Python 脚本可能会从可写目录或缓存的 `.pyc` 文件导入代码。[权限提升指南](../linux-basics/linux-privilege-escalation/README.md)详细介绍了缓存文件这一情况。
- 固定的 sudo 允许运行的 Python 脚本仍可能暴露交互式调试器。如果调用者能够到达断点或异常处理器，**并控制调试器的输入流**，那么 `pdb.set_trace()` 或 `pdb.post_mortem()` 等调用就允许在被调试进程的上下文中执行 Python 语句。检查确切的 sudo RunAs 规则、认证和分支条件、异常是否可达、终端/输入的所有权，以及调试器是否运行在同一特权进程中。触发异常的 socket 请求本身，并不能让调用者访问附着在另一个终端上的调试器。[Python 文档说明了调试器的语句求值和事后分析模式](https://docs.python.org/3/library/pdb.html)；枚举时应静态检查脚本，不要触发特权处理器。
- 固定的 sudo 允许运行的 Python 脚本也可能从数据库或 Unix socket 读取用户资料字段，并将其追加到随后成为 `str.format()` **格式字符串**的字符串中。[替换字段可以访问属性和映射键](https://docs.python.org/3/library/string.html#format-string-syntax)，因此，如果攻击者可控制该字段，它就可能检查传给 `format()` 的对象，并暴露其中可访问的数据，前提是结果会被打印，或存储在调用者可读的位置。检查有效的 sudo RunAs 身份、对特定记录的写入权限、数据流是否进入格式字符串、传入了哪些对象，以及输出是否可见。这不会自动导致代码执行；使用可信字面格式字符串、但由攻击者控制*值*，则是另一种情况。只有当账户接受泄露出的秘密时，该秘密才可能带来操作系统账户身份转换。检查脚本和 socket 权限，不要调用特权操作。
- 具有 root 权限的 Python 包装器可能会将调用者选择的 URL 传给 GitPython 的 `Repo.clone_from`。如果包装器还启用了 Git 的 `protocol.ext.allow=always`，那么 `ext::` 远端可能调用外部 helper。检查确切的 sudo 参数、URL 的来源、GitPython 软件包版本和供应商补丁状态，以及包装器是否明确启用了不安全协议。GitPython 在 3.1.30 中添加了[默认的不安全协议防护](https://github.com/gitpython-developers/GitPython/commit/2625ed9)；`git` 可执行文件的版本是另一项独立信息。被动审查时只读取规则和有限范围的源代码，不要调用 clone。
- 跨用户 sudo 授权的仓库克隆 CLI 可能暴露另一条 shell 字符串注入路径。追踪调用者选择的仓库参数是否未经安全的参数分离，就进入 Node.js [`child_process.exec`](https://nodejs.org/api/child_process.html#child_processexeccommand-options-callback) 或其他 shell 命令构造器；Node 的 `exec` 会将命令字符串传给 shell。确认确切的 RunAs 用户、允许的子命令和参数、已安装的包装器代码，以及输入验证情况。仅有仓库工具的名称或不受限制的 sudo 规则，不能证明存在命令注入。枚举时检查包装器，不要调用特权 clone。
- 自定义的 root 所有包装器看似安全，因为其二进制文件和脚本不可写，但它运行特权操作的决定可能取决于非特权用户可更改的标志、本地 API 值或服务状态。追踪每个门控条件的输入来源和授权检查。枚举时应检查配置和权限，不要更改运行状态；只有门控条件可以被影响时，包装器中的 `systemd-run` 调用才相关。
- 允许通过 sudo 以 root 身份运行的备份客户端，可能接受调用者选择的配置文件（例如 `npbackup-cli -c`）。检查确切的运行身份和允许的参数，然后确认调用者是否控制配置路径、备份源路径，以及仓库或读取/恢复选项。可读配置中的加密仓库密钥仍可能被客户端使用，但单凭规则并不能证明可以访问仓库或泄露 root 文件。不要运行备份或转储其内容来验证授权。
- [Restic](https://github.com/restic/restic/blob/master/doc/030_preparing_a_new_repo.rst) 支持 `--password-command`，该选项会调用程序来获取仓库密码。如果 sudo 规则允许低权限用户以 root 身份运行 restic，并可选择密码命令和需要该密码的子命令，那么该 helper 可能会以 root 身份运行。审查确切的 sudo 参数和排除规则；不要仅为枚举这一情况而调用 helper 或备份命令。
- 如果 sudo 参数模式允许调用者同时选择源文件，以及其之后能够读取和解密的仓库，那么具有 root 权限的 `restic backup` 授权也可能跨越文件读取边界。[Sudoers 参数通配符可以匹配空白和斜杠](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)，因此应检查结尾的通配符，不要假设固定的仓库前缀能限制源路径。[Restic 可以备份到本地和远程仓库](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html)，但本地仓库可能包含刚写入的 root 专属对象；在将其视为信息泄露之前，应确认有效的 sudo 策略、后端访问权限、仓库密码和生成对象的权限。备份的 SSH 密钥只有在目标账户接受该密钥时才有用。被动审查时不要运行备份进行测试。
- 不受限制的自定义维护或备份命令，可能接受输出路径或提供自己的作业调度器。对于文件写入路径，应确认确切的 sudo 规则和运行身份，然后检查调用者是否能同时控制数据和目标位置。对于计划任务路径，应确认调度器的执行身份、命令输入，以及是否存在其他密码或授权门控。命令名称或 `NOPASSWD` 本身都不能证明任一路径成立。参见[写入 root 所有的文件](../interesting-files-permissions/write-to-root.md)和[cron 与 systemd 定时器](../processes-crontab-systemd-dbus/cron-and-systemd-timers.md)。
- 固定的 sudo 命令仍可能从共享的可写目录加载可预测的配置文件。追踪调用者是否能替换该文件，以及文件中的源和目标字段是否能控制特权抓取或复制操作。本地文件 URL 可能暴露只有 sudo RunAs 账户才能读取的数据；调用者可控制的源路径与受保护的目标路径配合，则可能形成写入途径。确认已安装程序的 URL 处理方式、目标路径检查、生效的 sudo 规则和输出是否可访问。可写的 `/tmp` 配置路径本身只是审查线索；检查二进制文件和文件元数据，不要调用特权传输。
- 允许运行 `git apply` 的 sudo 规则可能使 RunAs 账户写入由调用者控制的补丁所选定的文件。[CVE-2023-23946](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh) 允许精心构造的补丁创建符号链接，随后在工作树之外写入，即使命令没有接受 `--unsafe-paths` 也可能如此。检查生效的 sudo 参数规则、补丁来源、RunAs 账户对工作目录的访问权限，以及已安装 Git 的修复或供应商回补情况。允许 `--unsafe-paths` 的不受限制规则，是另一个明确的选项风险；Git 版本或 `git apply` 权限本身都不能证明可以更改受保护文件。被动枚举时不要应用不可信补丁。
- 如果低权限用户可以提供 DMG 镜像，且已安装的解析器受到 [CVE-2023-20052](https://blog.clamav.net/2023/02/clamav-01038-01052-and-101-patch.html) 影响，那么具有 root 权限的 sudo 规则若允许运行 `clamscan --debug`，就可能通过调试输出跨越读取边界并泄露文件内容。确认确切的允许参数和扫描路径、输入控制权、有效的 RunAs 账户、引擎修复/回补情况，以及调用者是否能看到输出。如果更宽泛的规则允许 `--file-list`/`-f`，应单独审查文件列表行为；固定为 `--debug <scan-path>` 的策略并不允许使用它。枚举时检查策略和软件包元数据，不要扫描精心构造的文件或打印受保护的输出。
- 如果一条具有 root 权限的 sudo 规则允许打开调用者选择的加密磁盘映像，另一条规则允许挂载生成的 mapper，那么可能将调用者控制的文件导入主机的挂载命名空间。确认两条规则及其参数均有效、调用者能否控制映像和 mapper 名称、实际挂载目标，以及生成文件的所有者和模式。要实现 set-user-ID 身份转换，还需要有可访问的可执行文件、会遵循该属性的挂载选项（`nosuid` 会阻止它），以及适用的进程或 MAC 策略；仅打开或挂载映像只是审查线索。另一条通过现有备份的路径，则需要实际密钥和其中有用且可读的秘密。被动审查时检查策略和路径，不要打开或挂载映像。参见[cryptsetup 手册](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)和[mount 选项](https://man7.org/linux/man-pages/man8/mount.8.html)。
- 如果 root 权限 sudo 规则允许运行 shell 或 Python 脚本，而且脚本在未先切换到固定目录的情况下调用 `./helper`，则值得审查工作目录。传给 `subprocess.run` 的 Python 列表 `['./helper']` 也可能受到调用者选择工作目录的影响。调用者可能选择一个可写目录，并在其中放置名为该相对路径的可执行文件；脚本其他位置使用绝对路径并不能保护此调用。在将其视为代码执行之前，应确认生效的规则、`runchdir` 或其他目录切换策略、脚本流程和分支可达性、目录是否可写且可执行，以及挂载/`NOEXEC` 限制。脚本不可读时，在通过获授权的途径审查其源代码前，行为仍属未知。静态审查脚本，不要运行 helper。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)说明了工作目录策略。
- 固定的 root 权限 Python 验证器仍可能对调用者选择的数据文件执行求值。[Python 的 `eval()` 文档警告不要使用不可信输入](https://docs.python.org/3/library/functions.html#eval)：如果剩余表达式最终传给 `eval`，那么输入后缀检查、算术前缀或验证分支都不能构成沙箱。在将其视为执行路径之前，应确认生效的 sudo 规则、调用者能否选择并控制确切文件、解析器的分支条件和表达式构造方式，以及特权进程身份。可读脚本中出现 `eval` 本身只是审查提示；枚举时检查源代码和文件权限，不要运行验证器或提交测试表达式。
- 具有 root 权限的 sudo Ruby 包装器如果读取相对 YAML 文件名，例如 `YAML.load(File.read("dependencies.yml"))`，那么除非包装器或 sudo 策略固定目录，否则输入可能来自调用者的当前工作目录。检查确切的允许参数、目录和文件权限，以及已安装的 Psych 行为：旧版 `YAML.load` 实现可能会反序列化任意 Ruby 对象，而较新的版本默认会限制类。静态调用点只是审查线索；应确认文件确实来自调用者可写的目录，并且已安装的加载器会接受危险类。对不可信输入，优先使用带有明确最小类 allowlist 的 `safe_load`。参见[Ruby 3.0 Psych 文档](https://docs.ruby-lang.org/en/3.0/Psych.html)和[Ruby 3.1 Psych 文档](https://ruby-doc.org/core-3.1.2/Psych.html)。

- 如果精确的 root 权限 `sudo go run /absolute/file.go` 授权中，Go 源代码会读取相对路径的 WASM 文件，并可能在检查其结果后运行相对路径的 shell 脚本，那么值得审查工作目录。确认有效的 RunAs、命令参数和拒绝规则、调用者可写的当前目录、从 WASM 到分支的数据流，以及该分支是否会调用 helper。固定的 sudo `runchdir`、`os.Chdir` 或 [`exec.Cmd.Dir`](https://pkg.go.dev/os/exec) 都可能改变查找位置。静态共现只是候选线索；检查源代码，不要运行 Go、WASM 或 helper。
- `sudoedit` 和参数通配符需要根据确切版本和规则进行检查；[检查清单](linux-privilege-escalation-checklist.md)包含 sudoedit 文件编辑问题。对于路径包含通配符的跨用户 `sudoedit` 授权，应检查生效的 `sudoedit_follow` 或 `FOLLOW` 设置、`sudoedit_checkdir`、解析后的目标，以及谁能替换每一层父目录条目。前者可能允许跟随符号链接，而禁用后者会移除对可写目录的检查；但任何一项设置单独来看，都不能证明能够写入其他用户的文件。得出结论前，确认已安装的 sudo 策略和实际匹配的参数。参见[sudoers 选项定义](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)。
- 在 sudoers 命令规则中，参数通配符除了匹配路径字符外，也可能匹配空白字符。对于带有 `/restricted/*` 这类参数的可读取命令规则，匹配前缀后可能还允许额外的文件参数。应审查确切的运行身份、命令路径、参数模式和后续拒绝规则；证明可以读取文件并不意味着可以执行命令。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)区分了参数 glob 与命令路径 glob。
- 看起来像路径的参数 glob 也可能匹配 `../`。例如，具有 root 权限的 `node /opt/scripts/*.js` 规则可能允许调用者控制 `/opt/scripts` 之外的 JavaScript 文件，前提是所提供的路径名仍以 `/opt/scripts/` 开头，并通过父目录片段解析到该文件。这是**参数** glob；Node 可执行文件的命令路径 glob 遵循不同的斜杠匹配规则。得出代码执行结论前，应检查生效的规则、后续拒绝规则、路径解析、目标文件控制权，以及任何 sudoers 正则表达式或摘要限制。参见[sudoers 通配符规则](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)和[Node 命令行文档](https://nodejs.org/api/cli.html)。
- 归档工具和其他实用程序可能带有执行钩子。应针对确切的允许参数检查 [GTFOBins](https://gtfobins.github.io/)，不要假设只有 shell 或解释器才能执行命令。
- 不受限制的 root 权限 `qpdf` 规则可能通过 PDF 附件暴露特权文件：qpdf 10.2 及更高版本支持将 `--empty` 和 `--add-attachment file ... --` 与输出 PDF 配合使用。如果特权进程能读取所选源文件并将 PDF 写入调用者可访问的路径，那么输出就可能携带源文件字节。在确认文件泄露是否可能之前，应审查生效的 sudo 参数和排除规则、qpdf 版本、源文件访问权限以及输出路径。只有当 root SSH 认证允许且密钥有效时，读取 root SSH 密钥才对登录有用。参见[qpdf 附件选项](https://qpdf.readthedocs.io/en/stable/cli.html#embedded-files-attachments)。
- sudo 时间戳复用取决于缓存策略、所有者、终端/会话和权限。[权限提升指南](../linux-basics/linux-privilege-escalation/README.md#reusing-sudo-tokens)介绍了相关检查。
- `doas` 有自己的规则和配置。按照 [doas 章节](../linux-basics/linux-privilege-escalation/README.md#doas)所述，检查允许的命令和可写配置路径。

### 通过 sudo 运行构建和软件包工具

即使 RunAs 身份是另一个非 root 用户，对 Foundry 的 `forge` 的不受限制 sudo 授权也可能带来风险。`--use` 等编译器选项可以选择本地可执行文件，而 `forge flatten -o` 可以选择输出文件。在将该授权视为可利用之前，应检查已安装的 Forge 版本、确切的 sudo 参数、可访问的项目和编译器路径、输出权限，以及生效的环境。通过 `PATH` 找到相对路径 helper 可执行文件，是依赖版本和环境的路径，不应假设所有 Forge 构建都具备此特性。<sup>[[23]](#references)[[24]](#references)</sup>

不受限制的 root 权限 `pacman` 授权不只允许查询软件包：`-U` 接受本地软件包，软件包可以包含安装脚本，而 `--hookdir` 可以选择其他钩子目录。测试前应审查生效的 sudo 规则、参数限制和排除规则；被动枚举不需要安装软件包或运行钩子。<sup>[[25]](#references)[[26]](#references)</sup>

固定的 sudo shell 包装器也可能安装一个命名的 npm 依赖，然后启动 Node 应用程序。检查其确切的 RunAs 规则、软件包是否已安装、生效的 `HOME` 和 npm `userconfig`、项目配置或命令行覆盖设置，以及低权限用户是否控制该名称对应的 registry 或软件包。如果特权应用程序导入新安装的软件包，该软件包的模块代码就可以在应用程序身份下运行。安装时脚本是另一条独立路径，其行为取决于版本和配置；[npm 文档说明了其生命周期和用户处理方式](https://docs.npmjs.com/cli/v6/using-npm/scripts/)。sudo 的 `HOME` 行为取决于已安装策略和发行版，因此特权 npm 进程可能会读取，也可能不会读取用户可写的 `.npmrc`。仅有 `.npmrc` 路径或 `npm install` 行都只是审查线索。被动枚举时检查规则、简短包装器、配置路径和软件包来源，不要安装软件包或启动应用程序。

即使 URL 模式将来源限制为本地服务，且要求使用 `.tar.gz` 后缀，具有 root 权限的 `pip` 或 `pip3 download` 授权如果允许调用者选择不可信源分发包，也属于软件包构建审查线索。`pip download` 接受归档 URL 并解析软件包元数据；准备 sdist 时，可能会调用其构建后端或旧版 `setup.py` 代码，而不只是保存归档。确认确切的 sudo RunAs 和参数规则、调用者是否能发布或替换所选归档，以及该 pip 版本是否确实会准备元数据。固定的可信归档或 wheel 并不能证明这条路径成立。被动枚举时不要获取或构建不可信软件包。参见 pip 的[下载命令](https://pip.pypa.io/en/stable/cli/pip_download/)、[构建系统接口](https://pip.pypa.io/en/stable/reference/build-system/)和[安全安装指南](https://pip.pypa.io/en/stable/topics/secure-installs/)。

允许使用调用者选择的本地项目路径运行 `pip install` 的 sudo 规则，会形成更直接的构建信任边界。[pip 接受本地项目目录](https://pip.pypa.io/en/stable/topics/local-project-installs/)，并会调用其构建系统；[构建后端会运行由项目控制的构建钩子](https://pip.pypa.io/en/stable/reference/build-system/)。在将此规则视为特权代码执行之前，应确认有效的 RunAs 身份、确切的参数限制和拒绝规则、所选项目是否由调用者控制，以及已安装 pip/后端的行为。固定的可信项目或排除调用者所选路径的规则，并不能证明这条路径成立。被动枚举时检查规则和项目元数据，不要安装软件包。

不受限制的 root 权限 `easy_install` 授权也是相关的旧版软件包构建审查线索。[Setuptools 文档](https://setuptools.pypa.io/en/stable/deprecated/easy_install.html)说明，Easy Install 接受本地项目目录并构建源分发包；如果项目由调用者控制，那么在构建过程中，其 `setup.py` 可能会以 sudo 身份执行。确认有效的 RunAs 账户、确切的命令和参数限制（包括后续拒绝规则）、所选项目的控制权，以及已安装工具的行为。固定的可信项目或不允许调用者选择源代码的策略，并不能证明这条路径成立。枚举时检查规则和项目元数据，不要安装软件包。

sudo 允许运行的 Python 包装器如果使用 `setuptools.package_index.PackageIndex.download`，并接受调用者选择的 URL，则与 `pip download` 是不同的审查情形：[setuptools GHSA-5rjg-fvgr-3xxf](https://github.com/pypa/setuptools/security/advisories/GHSA-5rjg-fvgr-3xxf)描述了在 78.1.1 之前的受影响版本中，URL 派生出的文件名可能逃逸预期的下载目录，并以进程权限写入文件。在确认存在任意写入之前，应确认有效的 sudo RunAs 和参数规则、包装器是否将调用者的 URL 传给这个确切 API、已安装版本或供应商回补情况，以及最终路径的解析位置。版本字符串或可写下载目录本身都不能证明存在任意写入。被动枚举时检查简短包装器和软件包元数据，不要获取 URL 或写入文件。

sudo 允许的构建包装器如果将调用者选择的 `.spec` 文件传给 PyInstaller，也需要进行同样的信任边界审查。PyInstaller spec 是在**构建**期间求值的可执行 Python 代码，其 `datas` 条目可以将构建身份可读的文件打包进制品。确认确切的 RunAs 用户、sudo 参数和拒绝规则、包装器的路径与分支处理、调用者对所选 spec 文件的控制权，以及对生成制品的访问权限。仅允许 `.py` 输入或发现已安装 PyInstaller，并不能证明调用者控制了 spec 文件或可执行特权代码。被动审查时只读取范围有限的包装器文件和元数据；不要运行构建。参见[PyInstaller spec 文件文档](https://pyinstaller.org/en/stable/spec-files.html)。

### 通过 sudo 运行的 preset 和插件加载器

接受调用者选择的 preset 或插件目录的 Python 工具，可能会以 sudo 授予的权限导入代码。例如，BBOT 支持通过 `-p` 接受 preset，其[自定义模块文档](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/#load-modules-from-custom-locations)介绍了可通过 `module_dirs` 条目选择其他 Python 模块目录的功能。如果生效的 sudo 规则允许调用者选择 preset，且调用者控制所选目录中的模块，那么即使工具随后拒绝无效模块，导入操作仍可能以特权用户身份执行代码。检查已安装版本、确切的 sudo 运行身份和参数策略，以及 preset 和模块路径的所有权；枚举时不要加载模块。

### 通过 sudo 运行的 Backdrop 命令行工具

[Bee](https://github.com/backdrop-contrib/bee) 是用于 Backdrop CMS 的 PHP 命令行工具。其 `eval` (`php-eval`) 和 `php-script` 命令可以运行调用者提供的 PHP。如果 sudo 规则允许以 root 身份运行 Bee 可执行文件且参数不受限制，那么只要 Bee 能够引导 Backdrop 安装，就可能暴露 root 代码执行。可以从站点目录运行，或使用全局 `--root=<directory>` 选项选择站点；仅发现 Bee 或 Backdrop 的 `settings.php` 文件，并不能证明具备 sudo 权限、存在可用站点或能够成功引导。测试前应审查生效的 sudo 规则、命令排除项、可执行文件的身份，以及对站点的访问权限。被动枚举时检查规则和文件路径，不要调用 Bee。有关 PHP 命令的新增信息，请参见[Bee 命令变更日志](https://github.com/backdrop-contrib/bee/blob/1.x-1.x/CHANGELOG.md)。

### 通过 sudo 运行的终端服务器

`mosh-server` 会以调用者身份启动交互式终端服务器。它会选择一个较高的 UDP 端口和会话密钥，将两者报告给调用者，并通常会在客户端连接时启动该用户的登录 shell。因此，即使服务器命令本身会脱离终端，不受限制的 root 权限 `mosh-server` sudo 授权仍值得作为 shell 候选项审查。检查有效的 RunAs 身份、允许的参数和排除项、已安装的二进制文件、shell、客户端可用性以及 UDP 访问权限。被动枚举时检查 sudo 规则，不要启动服务器或打印任何实时会话密钥。参见[Mosh 服务器手册](https://manpages.debian.org/unstable/mosh/mosh-server.1.en.html)和[上游设计说明](https://github.com/mobile-shell/mosh#how-it-works)。

### 会重写调用者任务文件的特权备份包装器

以 root 身份运行的 shell 包装器可能接受由调用者选择的任务文件，剥除源路径中的 `../`，检查处理后的路径是否以允许目录开头，重写任务文件，然后将其*路径名*传给备份程序。应在完全规范化路径后审查转换结果：单次字符串替换可能会暴露新的目录遍历序列，而词法前缀检查仍可能接受它。还应检查备份程序是读取内存中转换后的数据，还是会重新打开文件。如果它会重新打开文件，那么重写失败后，原始输入可能仍会保留。

在 Linux 上，`fs.protected_regular` 可以阻止对世界可写 sticky 目录中其他用户的普通文件执行带有 `O_CREAT` 的写入操作。这种拒绝具有保护作用，但如果 shell 包装器忽略写入错误，仍可能继续处理原始任务文件。确认该设置、文件所有者和目录，以及包装器是否会在失败时停止。只有当有效的 sudo 规则允许以特权用户身份运行该包装器、调用者控制任务输入和可读的备份目标，且备份工具确实包含受保护源文件时，该路径才只是一个文件泄露候选项。枚举时检查这些条件，不要运行备份。

### 特权网络工具的参数通配符

在 `tcpdump` 的 sudo 规则中，**参数模式**里的 `*` 可以匹配空白和斜杠，因此看似限制路径的模式仍可能允许额外的选项文本。这与命令可执行文件路径中的通配符不同；应检查完整的 RunAs 规则和任何后续拒绝规则。如果可以注入选项，那么是否能利用 `-F`、`-V`、`-r`、`-w` 或 `-Z` 实现有用的读取/写入操作，取决于获准的调用方式和已安装 [`tcpdump` 的选项语义](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)。`-V` 读取的是捕获文件名列表，并非可任意转储文件内容的通用功能。即使 sudo 允许命令，AppArmor 或其他 MAC 策略仍可能阻止文件访问；磁盘上的配置文件并不能证明策略已加载或正在强制执行。下结论前应被动审查授权和策略。[sudoers 手册](https://www.sudo.ws/docs/man/1.9.14/sudoers.man.pdf)介绍了通配符之间的区别。

如果具有 root 权限的 sudo 规则只列出 `tcpdump` 可执行文件而没有限制参数，也值得审查。[tcpdump 手册](https://github.com/the-tcpdump-group/tcpdump/blob/master/tcpdump.1.in)说明，当 `-C` 或 `-G` 轮转已保存的捕获文件时，`-z` 可用于运行轮转后的命令；`-Z` 或编译时默认设置可能会在该命令运行前降权。将该规则视为权限提升路径前，应确认生效的 sudo 规则、已安装的构建版本、降权行为，以及轮转是否能够发生。高亮显示的规则只是候选项，并不证明可以以 root 身份执行命令。

### 通过 sudo 运行的 Nmap 包装器

如果 sudo 允许的 `nmap` 路径是 shell 包装器，应检查确切的允许路径以及它转发的每个选项。阻止常见的 `--script` 拼写并不一定能阻止加载 NSE 代码：Nmap 的 [`--datadir`](https://nmap.org/book/man-misc-options.html) 可以选择数据文件，而启用脚本功能时，NSE 会从选定的数据目录加载 [`nse_main.lua`](https://nmap.org/book/nse-implementation.html)。某些已安装版本也接受其他长选项拼写，因此应将限制规则与该二进制文件实际使用的解析器进行比较。[`--excludefile`](https://nmap.org/book/man-target-specification.html) 是另一个文件读取面；解析器错误可能会泄露文本。被动枚举时应检查生效的 sudo 规则、包装器逻辑、Nmap 版本、目录控制权和 MAC 策略，不要运行扫描。

### 通过 sudo 运行的 Mercurial pull 钩子

即使 `sudo hg pull /fixed/source` 使用固定源，除非命令通过 `-R` 固定目标仓库，否则**接收方**仓库仍由当前工作目录决定。调用者控制的接收仓库可以在 `.hg/hgrc` 中定义钩子，而该钩子可能以 sudo RunAs 用户身份运行。[Mercurial 会忽略由不可信用户或组拥有的仓库配置](https://mercurial-scm.org/help/topics/config)，因此在将其视为代码执行之前，应检查 RunAs 账户的受信任用户/组以及确切的工作目录。被动审查只需读取策略和配置；枚举时不要执行 pull 或调用钩子。

### 通过 sudo 运行的 Git pull 钩子

对于精确的 root 权限 `sudo git pull` 授权，还应检查由工作目录选定的**接收方**仓库。调用者拥有的仓库可以设置可执行的 `post-merge` 钩子；当 pull 成功执行合并时，该钩子会以 Git 进程的身份运行。[Git 文档说明了此钩子](https://git-scm.com/docs/githooks)以及[pull 的合并与 rebase 行为](https://git-scm.com/docs/git-pull)。确认生效的 sudo 规则和 CWD、活动钩子路径及其权限，以及是否可能发生包含新提交的合并。失败、无操作或只执行 rebase 的 pull 并不能证明这条钩子路径成立。检查策略和仓库元数据，不要运行特权 pull。

### 通过 sudo 运行的 rsync 归档副本

对于 `sudo rsync -a ... /writable/source/* /fixed/destination/`，**sudoers 参数模式**中的 `*` 可以匹配空白，并允许在源路径和目标路径之间插入额外选项。这与 shell 对文件名的展开不同。如果调用者可以填充源目录，而特权 rsync 进程可写入目标目录，那么 [`--chown`](https://download.samba.org/pub/rsync/rsync.1) 可以请求特权所有权，同时归档模式保留权限位，可能由此创建归属于特权用户的 SetUID 文件。检查确切的[sudoers 通配符语义](https://man7.org/linux/man-pages/man5/sudoers.5.html)、rsync 版本、后续拒绝规则、文件系统的 `nosuid` 和 MAC 策略。匹配的规则只是审查候选项，并不能证明成功提升权限。

### 通过 sudo 运行的数据包过滤规则导出

如果具有 root 权限的授权同时允许运行 `iptables` 和 `iptables-save`（或对应的 `ip6tables` 组合），则值得审查文件写入风险。`comment` 匹配项接受调用者选择的规则文本，而 `iptables-save -f` 会将序列化后的规则集写入指定路径。<sup>[[20]](#references)[[21]](#references)</sup> 有用的载荷取决于已安装后端如何序列化注释，以及目标文件是否接受导出中的其他行；仅有 `iptables-save` 并不能提供任意内容。检查确切的 sudo RunAs 身份、参数和排除规则、可用的匹配扩展、后端以及目标权限。枚举期间检查授权，不要更改防火墙规则或写入文件。

### 特权 Below 日志目录

[CVE-2025-27591](https://github.com/facebookincubator/below/security/advisories/GHSA-9mc5-7qhg-fp3w) 影响了 0.9.0 之前会创建世界可写 `/var/log/below` 目录的 Below 版本。如果服务或获准的 sudo 命令以 root 身份运行了受影响的构建，那么能够写入并遍历非 sticky 日志目录的用户，可能会在特权进程打开日志条目之前将其替换为符号链接。检查已安装软件包的修复状态、确切的特权执行路径、生效的目录访问权限、sticky bit 和 ACL，以及 `/var/log/below/error_root.log` 的元数据。仅有世界可写路径或 sudo 规则，并不能证明完整利用链成立。sticky 目录或供应商回补会改变评估结果。被动枚举只需检查元数据；无需创建链接或运行特权程序。

### 从可写输入收集特权支持包

sudo 允许运行的支持配置脚本可能会以 root 身份读取固定日志路径，并将内容复制到配置文件归档中。检查脚本的实际文件读取行为，然后确认调用者是否能将源路径或任何父目录条目替换为符号链接。如果特权读取会跟随该链接，且生成的归档可由调用者读取，就可能泄露受保护文件。sudo 授权、可写源路径、特权读取和可读输出必须同时存在；仅有可写日志或配置文件名并不足够。枚举时检查生效的权限和链接元数据，不要替换文件或生成配置文件。[Nagios XI 支持指南](https://support.nagios.com/forum/viewtopic.php?t=62758)记录了其 root 运行的配置脚本和输出归档，说明了为何此类归档必须限制输入和输出访问。

### 以 root 身份运行的 Python 归档恢复脚本

即使 sudo 规则严格限定了 Python 恢复脚本，仍需审查其归档输入。如果调用者可以选择或替换归档，而脚本以 root 身份通过 `tarfile.extractall(filter="data")` 提取内容，则在信任该过滤器之前，应检查解释器是否已安装安全更新。CPython 修复了多个符号链接和硬链接过滤器绕过问题，包括 CVE-2025-4517；修复版本包括 3.9.23、3.10.18、3.11.13、3.12.11 和 3.13.4。发行版回补可能修复更早的版本，因此显示的解释器版本本身并不能证明存在漏洞。<sup>[[16]](#references)[[17]](#references)</sup>

被动审查时，读取确切的 sudo 命令和脚本，追踪哪个参数选择归档，并检查当前用户能否写入归档或其所在目录。分别确认已安装版本的供应商补丁和提取目标位置；`filter="data"` 并不能让所有不可信归档都变得安全。<sup>[[16]](#references)[[17]](#references)</sup>

### 通过 sudo 运行的机器学习模型加载器

如果 sudo 规则允许调用者选择 `.pt`、`.pth` 或 `.ckpt` 文件，而且特权脚本会将该文件传给 [`torch.load`](https://docs.pytorch.org/docs/stable/generated/torch.load.html)、`pickle.load` 或其他基于 pickle 的加载器，则值得审查。检查有效的 RunAs 规则、调用者能否创建或替换所选模型，以及参数如何通过 shell 包装器传给 Python helper。`.pth` 扩展名也用于其他无关的 Python site 配置文件，因此扩展名本身并不能证明正在加载模型。归档扫描或静态 pickle 扫描并不能证明后续加载是安全的；应检查加载器[依赖版本的 `weights_only` 行为](https://docs.pytorch.org/docs/stable/notes/serialization.html)和任何 allowlist。参见[ML pickle 和 Fickling 说明](../../AI/keras-model-deserialization-rce-and-gadget-hunting.md#ml-pickle-import-allowlisting-for-aiml-models-fickling)。被动枚举时绝不要加载或解包模型。

### 通过 sudo 运行的已存储输入表达式解析

通过 sudo 以 root 身份运行的固定 Python 脚本，仍可能对低权限用户可存入应用数据库的文本进行求值。在 TensorFlow 中，调用 `preprocess_input_exprs_arg_string(value, safe=False)` 会选择 `eval` 路径；[TensorFlow 公告](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-75c9-jrh4-79mc)说明了不安全的解析器，以及对其命令行调用方所做的修复。即使命令行调用方已经修复，应用程序显式调用 `safe=False` 仍需单独审查。检查生效的 sudo 规则、谁能修改确切的输入记录、过滤或评分流程是否会让该记录到达此调用，以及已安装函数的行为。TensorFlow 版本、sudo 授权或硬编码的模型文件单独存在，都不能证明完整链路成立。被动检查脚本和数据流；枚举时不要运行特权 helper 或提交测试表达式。

### sudo 允许使用的 needrestart 配置

`needrestart -c` 会加载调用者选择的 Perl 配置文件并求值其内容。如果 `sudo -l` 允许以 root 身份运行 `needrestart`，且参数允许使用 `-c`，同时调用者能在可写位置选择可读配置文件，那么该授权可能导致 root 代码执行。检查确切的 sudo 运行身份和参数规则；只允许固定参数列表的规则可能会阻断这条路径。这与 needrestart 的解释器扫描漏洞不同：更新软件包或禁用 `interpscan`，并不能让不受限制的 root `-c` 授权变得安全。<sup>[[2]](#references)[[18]](#references)[[19]](#references)</sup>

### 通过 sudo 以其他账户身份运行的 Python 导入

固定的 Python 入口点仍可能导入调用者可编辑或替换的模块，即使 sudo 以**非 root**服务用户身份运行脚本也是如此。对于字面量 `from utils import status`，除了检查软件包目录权限外，还要检查本地的 `utils/__init__.py` 和 `utils/status.py`。在将可写文件视为执行路径之前，应确认脚本的导入路径、确切的允许 sudo 参数，以及相关操作是否会到达该导入。枚举期间检查文件和权限，不要导入或运行脚本。<sup>[[2]](#references)[[3]](#references)</sup>

对 `python3 /absolute/script.py` 的精确 sudo 规则只要求脚本可读；文件不需要可执行，也不需要 shebang。也应审查**缺失的**本地模块：如果脚本导入的模块可以在调用者可写的脚本目录中创建同名文件，Python 可能会以 RunAs 身份加载该文件。确认生效的 sudo 规则、解释器实际的[模块搜索路径](https://docs.python.org/3/library/sys_path_init.html)、模块是否为内建或冻结模块，以及是否会执行该导入。直接针对脚本的 sudo 规则，对执行位和 shebang 的要求不同。如果有独立包装器会将调用者提供的标记追加到 `sudo -u account` 之后，也需要审查参数流：这些标记中的另一个 `-u` 只有在被调用的 sudo 策略允许生成的身份时才有影响。仅凭静态字符串并不能证明任一路径成立。

### 通过 sudo 运行并使用调用者控制配置的 Apache

如果 sudo 规则允许使用调用者控制的 `-f` 配置文件调用特权 `apachectl`、`apache2ctl` 或 `httpd`，应审查该文件及其父目录权限。Apache 的 [`LoadModule`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadmodule) 指令接受模块名和**模块文件名**；[`LoadFile`](https://httpd.apache.org/docs/2.4/mod/mod_so.html#loadfile) 也会加载文件。[`Include` 和 `IncludeOptional`](https://httpd.apache.org/docs/2.4/mod/core.html#include) 可以扩展配置，或通过错误暴露文件内容。自定义包装器可能会验证这些路径、降权或限制参数，因此，仅有可写配置文件只是审查候选项，并不证明可以执行代码。下结论前应检查路径规范化、符号链接和指令解析。

### 通过 sudo 运行并使用调用者控制配置的 nginx

不受限制的 root 权限 `nginx` 规则可能允许通过 [`-c` 选择另一份配置](https://nginx.org/en/docs/switches.html)。审查确切的 sudo 参数和排除规则、调用者是否能提供配置，以及由此启动的 master 或 worker 是否仍能访问受保护路径。所选 `root` 配合 `autoindex` 可能通过新的监听器暴露文件；[`dav_methods PUT`](https://nginx.org/en/docs/http/ngx_http_dav_module.html) 可能提供特权文件写入路径，但 DAV 模块默认并非内建，因此必须检查其是否存在、监听器是否可访问、文件权限以及临时文件行为。[`error_log` 指令](https://nginx.org/en/docs/ngx_core_module.html#error_log)也可以指定目标文件；要将日志写入敏感配置文件（例如 `/etc/ld.so.preload`），必须有生效的特权写入权限和可控的日志记录，才会成为权限提升路径。`sudo -l` 中可执行文件的高亮只是审查提示，并不能证明上述任何路径有效。被动枚举时不要启动或重新配置 nginx。

### 特权 Bash 提示符中的模式比较

如果 sudo 允许的 Bash 脚本会读取调用者提供的值，并使用 `[[ "$expected" == $entered ]]` 进行检查，Bash 会将未加引号的右操作数解释为模式。因此，通配符可能在不知道预期值的情况下通过比较。将操作数加引号（`[[ "$expected" == "$entered" ]]`）会让它进行字面字符串比较。审查确切的 sudo 规则、提示符是否可达，以及比较后脚本会执行什么；仅凭语法本身不能证明存在可利用路径。枚举时不要打印预期值。参见[Bash 条件结构参考](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)。

### 通过 sudo 运行用于下载并执行文件的 helper

如果自定义 helper 接受调用者选择的 URL、将响应写入磁盘，然后通过解释器或 shell 调用该文件，那么不受限制的 root 权限 sudo 授权值得进行数据流审查。[Sudoers 允许在命令条目未列出参数时传入任意参数](https://man7.org/linux/man-pages/man5/sudoers.5.html)；固定的可执行文件路径并不能限制参数能选择什么。确认已安装 helper 中的实际 URL 验证、输出路径、成功分支和后续执行过程。仅有 libcurl 导入或可打印字符串并不能证明这条链路成立。

即使输出文件的 basename 固定，只要 helper 在调用者控制的工作目录中使用**相对路径**，该文件仍可能在写入和执行之间被替换。重命名或替换 root 所有文件的权限由目录的写入/搜索权限和任何 sticky bit 限制决定，而不只是文件模式；参见[`rename(2)`](https://man7.org/linux/man-pages/man2/rename.2.html)。检查 helper 后续是重新打开路径还是使用已打开的文件描述符，以及它是否会在写入前切换到可信目录。被动检查 sudo 策略、helper 和目录元数据；枚举时不要调用特权下载或进行竞争攻击。

root-sudo 下载 helper 如果构造类似 `curl <caller input> -o <fixed output>` 的 Bash 命令字符串，也可能暴露**参数**注入。即使过滤器拒绝空白，仍会留下[Bash 花括号展开](https://www.gnu.org/software/bash/manual/html_node/Brace-Expansion.html)问题：未加引号、以逗号分隔的元素可能展开为多个 curl 参数。如果输入在固定的 `-o` 之前到达 curl，那么调用者提供的输出选项可能会以 helper 的身份选择第一个 URL 的目标位置；[curl 会按顺序将输出选项关联到 URL](https://curl.se/docs/manpage.html#-o)。确认确切的 shell、引号处理、输入验证、生效的 sudo 规则、curl 参数顺序和支持的 URL scheme，以及调用者是否控制获取的字节或能读取结果。由 PyInstaller 打包的可执行文件可能包含 Python 应用逻辑，但仅有打包标记或 `curl` 字符串并不能证明这条数据流。获得授权后，离线审查范围有限的副本；常规枚举不应运行 helper 或获取攻击者选择的数据。

以 root-sudo 身份运行的 shell 脚本如果调用 [`mktemp -u` / `--dry-run`](https://www.gnu.org/software/coreutils/manual/html_node/mktemp-invocation.html)，只会选择一个尚未使用的名称；它**不会**创建文件。如果脚本随后在其他用户可以影响的目录中创建该文件，重新打开它，并将其内容追加到 root 的 `authorized_keys` 等受保护目标，就值得审查是否存在临时文件竞争。确认确切的 sudo 规则、目录和文件所有权、创建与重新打开顺序、内核保护措施，以及特权写入是否确实使用了攻击者控制的字节。`mktemp -u` 字符串或可写的 `/tmp` 本身都不能证明存在竞争条件。枚举时检查脚本和路径元数据，不要运行脚本或对临时文件进行竞争。

## 防御说明

- 避免通过 sudo 授权运行解释器或交互式编辑器。<sup>[[1]](#references)</sup>
- 不要使用不受限制的操作数授权 `tee` 等通用文件写入工具。应使用 root 所有的包装器，指定固定目标并拒绝由调用者控制的路径。<sup>[[2]](#references)</sup>
- 优先使用固定的、由 root 所有的包装器，只执行一种范围狭窄的管理操作。<sup>[[1]](#references)[[2]](#references)</sup>
- 如果无法避免使用解释器，应限制确切的脚本路径，并禁止由用户控制的参数、可写导入项、`PYTHONPATH` 和不安全的环境变量保留。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- 如果必须编辑文件，应限制确切的文件路径，并考虑使用 `sudoedit`，同时采用已修补的 sudo 版本和严格的环境处理。<sup>[[1]](#references)[[2]](#references)</sup>
- 审查 `SETENV`、`env_keep`、可写工作目录、可写模块/导入路径、`NOEXEC`、`use_pty` 和日志记录，但不要将它们视为完整沙箱。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

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
- [13] [Vim：usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [重定向 — Bash 参考手册](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
- [16] [Python 3.9.23–3.13.4 安全版本](https://discuss.python.org/t/python-3-13-4-3-12-11-3-11-13-3-10-18-and-3-9-23-are-now-available/94367)
- [17] [tarfile 提取过滤器 — Python 文档](https://docs.python.org/3/library/tarfile.html#extraction-filters)
- [18] [needrestart 配置选项和求值 — 上游源代码](https://github.com/liske/needrestart/blob/master/needrestart)
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
