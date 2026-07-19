# Linux 环境变量

{{#include ../../banners/hacktricks-training.md}}

## 全局变量

全局变量**将被** **子进程**继承。

你可以通过以下方式为当前会话创建全局变量：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
此变量将可被当前 session 及其子进程访问。

你可以通过以下方式**删除**变量：
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
如果你正在继承的环境中寻找 **credentials** 或 **interesting service configuration**，也请查看 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)。

## 常见变量

来源：[https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** 使用的显示器。此变量通常设置为 **:0.0**，表示当前计算机上的第一个显示器。
- **EDITOR** – 用户首选的文本编辑器。
- **HISTFILESIZE** – history file 中包含的最大行数。
- **HISTSIZE** – 用户结束会话时添加到 history file 的行数。
- **HOME** – 用户的 home directory。
- **HOSTNAME** – 计算机的 hostname。
- **LANG** – 当前语言。
- **MAIL** – 用户 mail spool 的位置。通常为 **/var/spool/mail/USER**。
- **MANPATH** – 用于搜索 manual pages 的目录列表。
- **OSTYPE** – 操作系统类型。
- **PS1** – bash 中的默认提示符。
- **PATH** – 存储所有包含可执行 binary files 的目录路径；只需指定文件名，而不必使用相对路径或绝对路径即可执行这些文件。
- **PWD** – 当前 working directory。
- **SHELL** – 当前 command shell 的路径（例如 **/bin/bash**）。
- **TERM** – 当前 terminal 类型（例如 **xterm**）。
- **TZ** – 时区。
- **USER** – 当前 username。

## 用于 hacking 的有趣变量

并非每个变量都同样有用。从 offensive 角度来看，应优先关注会改变 **search paths**、**startup files**、**dynamic linker behavior** 或 **audit/logging** 的变量。

### **HISTFILESIZE**

将 **此变量的值更改为 0**，这样当你 **结束会话** 时，**history file**（\~/.bash_history）就会被 **截断为 0 行**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

将此变量的**值更改为 0**，这样命令就**不会保存在内存中的 history 中**，也不会被写回**history 文件**（\~/.bash_history）。
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

如果**此变量的值设置为 `ignorespace` 或 `ignoreboth`**，任何前面添加了额外空格的命令都不会保存到历史记录中。
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

将 **history file** 指向 **`/dev/null`**，或完全取消设置。相比仅修改 history size，这通常更加可靠。
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

- `all_proxy`：遵循该变量的工具/协议所使用的默认 proxy。
- `no_proxy`：应直接连接的 bypass 列表（主机/域名/CIDR）。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
根据所使用的工具，可能使用小写或大写变体（`http_proxy`/`HTTP_PROXY`、`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

进程将信任 **这些环境变量** 中指定的证书。这对于让 **`curl`**、**`git`**、Python HTTP 客户端或包管理器信任由攻击者控制的 CA 很有用（例如，使拦截代理看起来合法）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

如果特权 wrapper/script 在执行命令时**不使用绝对路径**，那么 `PATH` 中第一个由攻击者控制的目录将优先生效。这是 `sudo`、cron jobs、shell wrappers 和自定义 SUID helpers 中许多 **PATH hijacks** 的基础。查找 `env_keep+=PATH`、弱配置的 `secure_path`，或按名称调用 `tar`、`service`、`cp`、`python` 等程序的 wrappers。
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
如需查看利用 `PATH` 的完整 privilege-escalation chains，请参阅 [Linux Privilege Escalation](linux-privilege-escalation/README.md)。

### **HOME & XDG_CONFIG_HOME**

`HOME` 不仅是目录引用：许多工具会自动从 `$HOME` 或 `$XDG_CONFIG_HOME` 加载 **dotfiles**、**plugins** 和 **per-user configuration**。如果特权工作流保留这些值，**config injection** 可能比 binary hijacking 更容易。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
Interesting targets include `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`，以及特定工具的文件，例如 `.terraformrc`。

### **LD_PRELOAD、LD_LIBRARY_PATH 与 LD_AUDIT**

这些变量会影响 **dynamic linker**：

- `LD_PRELOAD`：强制优先加载额外的 shared objects。
- `LD_LIBRARY_PATH`：在前面添加 library 搜索目录。
- `LD_AUDIT`：加载用于观察 library 加载和 symbol resolution 的 auditor libraries。

如果特权命令会保留这些变量，那么它们对于 **hooking**、**instrumentation** 和 **privilege escalation** 极具价值。在 **secure-execution** 模式下（`AT_SECURE`，例如 setuid/setgid/capabilities），loader 会移除或限制其中许多变量。不过，早期 loader 阶段中的 parser bugs 仍然具有很高的影响，因为它们会在目标程序之前运行。
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` 会改变 glibc 的早期行为（例如 allocator tunables），在 exploit 实验中非常实用。从安全角度来看，它也很重要，因为 **动态加载器会在非常早的阶段解析它**。2023 年的 **Looney Tunables** 漏洞很好地提醒了我们：在加载器中解析的单个环境变量，可能会针对 SUID 程序成为一种**本地权限提升原语**。
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

如果以**非交互模式**启动 **Bash**，它会检查 `BASH_ENV`，并在运行目标脚本之前加载该文件。当 Bash 作为 `sh` 调用，或处于 POSIX 风格的交互模式时，也可能会读取 `ENV`。如果环境变量由攻击者控制，这是将 shell wrapper 转化为代码执行的一种经典方式。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 本身会在 **real/effective IDs 不同** 时禁用这些启动文件，除非使用 `-p`，因此具体行为取决于 wrapper 如何调用 shell。

### **PYTHONPATH、PYTHONHOME、PYTHONSTARTUP 与 PYTHONINSPECT**

这些变量会改变 Python 的启动方式：

- `PYTHONPATH`：在 import 搜索路径前添加路径。
- `PYTHONHOME`：重新定位标准库目录树。
- `PYTHONSTARTUP`：在交互式提示符出现前执行一个文件。
- `PYTHONINSPECT=1`：脚本执行结束后进入交互模式。

当维护脚本、debugger、shell 和 wrapper 使用可控环境调用 Python 时，这些变量很有用。`python -E` 和 `python -I` 会忽略所有 `PYTHON*` 变量。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT 与 PERL5LIB**

Perl 同样有非常实用的启动变量：

- `PERL5LIB`：预置库目录。
- `PERL5OPT`：注入开关，就像它们位于每条 `perl` 命令行中一样。

这可以强制执行**自动模块加载**，或在目标脚本执行任何有意义的操作之前改变解释器行为。Perl 在 **taint / setuid / setgid** 上下文中会忽略这些变量，但对于普通的 root-run wrapper、CI jobs、installers 以及自定义 sudoers 规则，它们仍然非常重要。
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
同样的思路也适用于其他 runtime（`RUBYOPT`、`NODE_OPTIONS` 等）：每当 interpreter 由 privileged wrapper 启动时，都要查找会修改 **module loading** 或 **startup behavior** 的 env vars。

从 post-exploitation 的角度来看，还要记住，继承的 environments 中通常包含 **credentials**、**proxy settings**、**service tokens** 或 **cloud keys**。查看 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)，了解如何检查 `/proc/<PID>/environ` 以及在 `systemd` 中查找 `Environment=`。

### PS1

改变 prompt 的显示方式。

[**这是一个示例**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root：

![PERL5OPT & PERL5LIB - PS1：这是一个示例](<../images/image (897).png>)

普通用户：

![PERL5OPT & PERL5LIB - PS1：一个、两个和三个后台 job](<../images/image (740).png>)

一个、两个和三个后台 job：

![PERL5OPT & PERL5LIB - PS1：一个、两个和三个后台 job](<../images/image (145).png>)

一个后台 job、一个已停止的 job，且上一条命令未正确完成：

![PERL5OPT & PERL5LIB - PS1：一个后台 job、一个已停止的 job，且上一条命令未正确完成](<../images/image (715).png>)

## 参考资料

- [GNU Bash Manual - Bash 启动文件](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
