# Linux 环境变量

{{#include ../../banners/hacktricks-training.md}}

## 全局变量

全局变量**将会**被**子进程**继承。

你可以通过以下方式为当前会话创建全局变量：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
此变量将可被当前会话及其子进程访问。

你可以使用以下命令**删除**变量：
```bash
unset MYGLOBAL
```
## 本地变量

**本地变量**只能由**当前 shell/脚本**进行**访问**。
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
`/proc/*/environ` 的内容以 **NUL 分隔**，因此这些变体通常更易于阅读：
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
如果你正在继承的环境中寻找 **credentials** 或 **interesting service configuration**，也请检查 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)。

## 常见变量

来源：[https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)<sup>[[5]](#references)</sup>

- **DISPLAY** – **X** 使用的显示器。此变量通常设置为 **:0.0**，表示当前计算机上的第一个显示器。
- **EDITOR** – 用户首选的文本编辑器。
- **HISTFILESIZE** – history file 中包含的最大行数。
- **HISTSIZE** – 用户结束会话时添加到 history file 的行数。
- **HOME** – 用户的主目录。
- **HOSTNAME** – 计算机的 hostname。
- **LANG** – 当前语言。
- **MAIL** – 用户 mail spool 的位置。通常为 **/var/spool/mail/USER**。
- **MANPATH** – 用于搜索手册页的目录列表。
- **OSTYPE** – 操作系统类型。
- **PS1** – bash 中的默认提示符。
- **PATH** – 存储所有包含可执行 binary files 的目录路径。只需指定文件名，而不必使用相对路径或绝对路径，即可执行这些文件。
- **PWD** – 当前工作目录。
- **SHELL** – 当前 command shell 的路径（例如 **/bin/bash**）。
- **TERM** – 当前终端类型（例如 **xterm**）。
- **TZ** – 时区。
- **USER** – 当前用户名。

## 用于 hacking 的有趣变量

并非每个变量都同样有用。从 offensive 角度来看，应优先关注会改变 **search paths**、**startup files**、**dynamic linker behavior** 或 **audit/logging** 的变量。

### **HISTFILESIZE**

将此 **variable 的 value 设置为 0**，这样当你 **结束 session** 时，**history file**（\~/.bash_history）将被 **截断为 0 行**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

将此**变量的值改为 0**，这样命令就**不会保存在内存中的历史记录中**，也不会被写回**历史文件**（~/.bash_history）。
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

如果将此变量的**值设置为 `ignorespace` 或 `ignoreboth`**，则任何前面添加了额外空格的命令都不会保存到历史记录中。
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

将**history file**指向**`/dev/null`**，或完全取消设置。通常，这比仅更改 history 大小更可靠。
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

- `all_proxy`：遵循该设置的工具/协议所使用的默认 proxy。
- `no_proxy`：应直接连接的绕过列表（主机/域名/CIDR）。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
根据工具的不同，可能使用小写或大写变体（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

进程将信任 **这些环境变量** 中所指定的证书。这对于让 **`curl`**、**`git`**、Python HTTP 客户端或 package managers 信任由攻击者控制的 CA 很有用（例如，使 interception proxy 看起来合法）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

如果特权 wrapper/script 在执行命令时**未使用绝对路径**，那么 `PATH` 中第一个由 attacker 控制的目录将优先生效。这是许多 **PATH hijacks** 的基础原语，常见于 `sudo`、cron jobs、shell wrappers 和自定义 SUID helpers。请查找 `env_keep+=PATH`、弱 `secure_path`，或按名称调用 `tar`、`service`、`cp`、`python` 等程序的 wrappers。
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
如需查看利用 `PATH` 的完整提权链，请参阅 [Linux Privilege Escalation](linux-privilege-escalation/README.md)。

### **HOME & XDG_CONFIG_HOME**

`HOME` 不仅是目录引用：许多工具会自动从 `$HOME` 或 `$XDG_CONFIG_HOME` 加载 **dotfiles**、**plugins** 和 **per-user configuration**。如果特权工作流保留这些值，**config injection** 可能比二进制劫持更容易实现。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
有趣的目标包括 `.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`，以及 `.terraformrc` 等特定工具的文件。

### **LD_PRELOAD、LD_LIBRARY_PATH & LD_AUDIT**

这些变量会影响 **dynamic linker**：

- `LD_PRELOAD`：强制优先加载额外的 shared objects。
- `LD_LIBRARY_PATH`：将 library 搜索目录置于前面。
- `LD_AUDIT`：加载用于观察 library 加载和 symbol resolution 的 auditor libraries。

如果特权命令保留这些变量，它们对于 **hooking**、**instrumentation** 和 **privilege escalation** 极具价值。在 **secure-execution** 模式下（`AT_SECURE`，例如 setuid/setgid/capabilities），loader 会移除或限制其中许多变量。不过，early loader 阶段的 parser bugs 仍然具有很高的影响，因为它们会在目标程序之前运行。<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` 会改变 glibc 的早期行为（例如 allocator tunables），在 exploit labs 中非常实用。从安全角度来看，它同样十分重要，因为 **dynamic loader 会非常早地对其进行解析**。2023 年的 **Looney Tunables** 漏洞很好地提醒了我们：在 loader 中解析的单个环境变量，可能会针对 SUID 程序变成本地提权原语。<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

如果 **Bash** 以**非交互模式**启动，它会检查 `BASH_ENV`，并在运行目标脚本之前 source 该文件。当 Bash 以 `sh` 身份调用，或处于 POSIX 风格的交互模式时，也可能会检查 `ENV`。如果环境由攻击者控制，这是将 shell wrapper 转化为代码执行的经典方式。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 本身会在 **real/effective IDs 不同** 时禁用这些 startup files，除非使用 `-p`，因此具体行为取决于 wrapper 如何调用 shell。在启动 Bash **之前** 调用 `setuid()`/`setgid()` 的 privileged wrapper 需要特别注意：一旦 IDs 再次匹配，Bash 可能会信任原本会被忽略的 `BASH_ENV`、`ENV` 以及相关 shell 状态。<sup>[[1]](#references)</sup>

### **PYTHONPATH、PYTHONHOME、PYTHONSTARTUP & PYTHONINSPECT**

这些变量会改变 Python 的启动方式：

- `PYTHONPATH`：前置添加 import 搜索路径。
- `PYTHONHOME`：重新定位 standard library tree。
- `PYTHONSTARTUP`：在 interactive prompt 出现前执行一个文件。
- `PYTHONINSPECT=1`：脚本结束后进入 interactive mode。

当 maintenance scripts、debuggers、shells 和 wrappers 使用可控环境调用 Python 时，这些变量很有用。`python -E` 和 `python -I` 会忽略所有 `PYTHON*` 变量。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
最近一个真实世界的例子是 2024 年 Ubuntu/Debian 系统上的 **needrestart** LPE：由 root 拥有的 scanner 从 `/proc/<PID>/environ` 复制了非特权进程的 `PYTHONPATH`，随后执行 Python。公开的 exploit 在攻击者控制的路径中植入了 `importlib/__init__.so`，因此 Python 会在自身初始化期间执行攻击者代码，甚至早于 helper 的硬编码脚本发挥作用。<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl 同样有用的启动变量：

- `PERL5LIB`：在库目录前添加路径。
- `PERL5OPT`：注入开关，就像它们位于每条 `perl` 命令行中一样。

这可以强制执行**自动模块加载**，或在目标脚本执行任何有趣操作之前改变解释器行为。Perl 在 **taint / setuid / setgid** 上下文中会忽略这些变量，但对于普通的 root-run wrapper、CI 作业、installer 和自定义 sudoers 规则，它们仍然非常重要。
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

`NODE_OPTIONS` 会将 **Node.js CLI flags** 添加到所有继承该环境的 `node` 进程之前。因此，它适用于针对 wrappers、CI jobs、Electron helpers 以及最终会调用 Node 的 sudo rules。最有价值的 offensive flags 通常包括：

- `--require <file>`：在目标脚本之前预加载 CommonJS 文件。
- `--import <module>`：在目标脚本之前预加载 ES module。

Node 会拒绝 `NODE_OPTIONS` 中的某些危险 flags，但明确允许 `--require` 和 `--import`，并且会在处理常规命令行参数**之前**处理它们。<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
对于间接设置 `NODE_OPTIONS` 的 remote gadget chains（例如通过 prototype-pollution to RCE），请查看[此页面](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)。

### **RUBYLIB 和 RUBYOPT**

Ruby 提供了同类的启动滥用方式：

- `RUBYLIB`：将目录添加到 Ruby 的加载路径前面。
- `RUBYOPT`：向每次 `ruby` 调用注入命令行选项，例如 `-r`。
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024 年的 **needrestart** vulnerabilities 表明，这并不只是实验室中的技巧：同一个存在 `PYTHONPATH` 滥用漏洞、由 root 所有的 helper，也可以被诱导使用攻击者控制的 `RUBYLIB` 运行 Ruby，从攻击者目录加载 `enc/encdb.so`。<sup>[[3]](#references)</sup>

### **PAGER、MANPAGER、GIT_PAGER、GIT_EDITOR 与 LESSOPEN**

有些工具不仅会从环境中读取路径，还会将该值传递给 **shell**、**editor** 或 **input preprocessor**。因此，当特权 wrapper 运行 `git`、`man`、`less` 或类似的文本查看器时，以下变量尤其值得关注：

- `PAGER`、`MANPAGER`、`GIT_PAGER`：选择 pager 命令。
- `GIT_EDITOR`、`VISUAL`、`EDITOR`：选择 editor 命令，通常也可包含参数。
- `LESSOPEN`、`LESSCLOSE`：定义 pre/post-processors，在 `less` 打开文件时运行。
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
Git 还支持**仅通过环境变量的配置注入**，无需接触磁盘，使用 `GIT_CONFIG_COUNT`、`GIT_CONFIG_KEY_<n>` 和 `GIT_CONFIG_VALUE_<n>`：
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
从 post-exploitation 的角度来看，还要记住，继承的环境通常包含**凭据**、**代理设置**、**服务令牌**或**云密钥**。查看 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)，了解如何检查 `/proc/<PID>/environ` 和 `systemd` 的 `Environment=`。

### PS1

更改提示符的外观。

[**这是一个示例**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

根用户：

![PERL5OPT & PERL5LIB - PS1：这是一个示例](<../images/image (897).png>)

普通用户：

![PERL5OPT & PERL5LIB - PS1：一个、两个和三个后台作业](<../images/image (740).png>)

一个、两个和三个后台作业：

![PERL5OPT & PERL5LIB - PS1：一个、两个和三个后台作业](<../images/image (145).png>)

一个后台作业、一个已停止的作业，并且上一条命令未正确完成：

![PERL5OPT & PERL5LIB - PS1：一个后台作业、一个已停止的作业，并且上一条命令未正确完成](<../images/image (715).png>)

## 参考资料

- [1] [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [Common environment variables - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - Local Privilege Escalation in the glibc's ld.so - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)

{{#include ../../banners/hacktricks-training.md}}
