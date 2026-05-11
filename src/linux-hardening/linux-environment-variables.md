# Linux 环境变量

{{#include ../banners/hacktricks-training.md}}

## 全局变量

全局变量**将会**被**子进程**继承。

你可以通过以下方式为当前会话创建一个全局变量：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
该变量将可被你当前的会话及其子进程访问。

你可以通过以下方式 **移除** 一个变量：
```bash
unset MYGLOBAL
```
## 本地变量

**本地变量** 只能被**当前 shell/script** **访问**。
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
`/proc/*/environ` 的内容是 **NUL-separated**，所以这些变体通常更容易读取：
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
If you are looking for **credentials** or **interesting service configuration** inside inherited environments, also check [Linux Post Exploitation](linux-post-exploitation/README.md).

## 常见变量

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – 由 **X** 使用的显示。这个变量通常设置为 **:0.0**，表示当前计算机上的第一个显示。
- **EDITOR** – 用户偏好的文本编辑器。
- **HISTFILESIZE** – history file 中包含的最大行数。
- **HISTSIZE** – 用户结束会话时添加到 history file 的行数
- **HOME** – 你的 home directory。
- **HOSTNAME** – 计算机的 hostname。
- **LANG** – 你当前的语言。
- **MAIL** – 用户的 mail spool 位置。通常是 **/var/spool/mail/USER**。
- **MANPATH** – 搜索 manual pages 的目录列表。
- **OSTYPE** – operating system 的类型。
- **PS1** – bash 中的默认提示符。
- **PATH** – stores the path of all the directories which holds binary files you want to execute just by specifying the name of the file and not by relative or absolute path.
- **PWD** – 当前 working directory。
- **SHELL** – 当前 command shell 的 path（例如，**/bin/bash**）。
- **TERM** – 当前 terminal type（例如，**xterm**）。
- **TZ** – 你的时区。
- **USER** – 你当前的 username。

## hacking 中有趣的变量

Not every variable is equally useful. From an offensive perspective, prioritize variables that change **search paths**, **startup files**, **dynamic linker behavior**, or **audit/logging**.

### **HISTFILESIZE**

将此变量的 **value** 改为 0，这样当你 **end your session** 时，**history file** (\~/.bash_history) 将被 **truncated to 0 lines**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

将此变量的**值改为 0**，这样命令就**不会保存在内存历史**中，也不会被写回到**history file**（~/.bash_history）。
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

如果 **这个变量的值设置为 `ignorespace` 或 `ignoreboth`**，那么任何在命令前面额外加了一个空格的命令都不会被保存到 history 中。
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

将 **history file** 指向 **`/dev/null`** 或完全取消设置它。通常这比仅仅修改 history size 更可靠。
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

进程将使用此处声明的 **proxy** 通过 **http or https** 连接到互联网。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: 遵循它的工具/协议的默认代理。
- `no_proxy`: 应直接连接的绕过列表（hosts/domains/CIDRs）。
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
根据工具不同，可能会使用小写和大写变体（`http_proxy`/`HTTP_PROXY`，`no_proxy`/`NO_PROXY`）。

### SSL_CERT_FILE & SSL_CERT_DIR

进程会信任 **这些 env variables** 中指定的证书。这对于让 **`curl`**、**`git`**、Python HTTP 客户端或包管理器信任由攻击者控制的 CA 很有用（例如，让 interception proxy 看起来合法）。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

如果一个有特权的 wrapper/script 执行命令时**不使用绝对路径**，那么 `PATH` 中**第一个由攻击者控制的目录**就会生效。这是许多 `sudo`、cron jobs、shell wrappers 和自定义 SUID helpers 中 **PATH hijacks** 的基础。寻找 `env_keep+=PATH`、弱的 `secure_path`，或者那些直接按名称调用 `tar`、`service`、`cp`、`python` 等的 wrapper。
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
For full privilege-escalation chains abusing `PATH`, check [Linux Privilege Escalation](privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` 不只是一个目录引用：许多工具会自动从 `$HOME` 或 `$XDG_CONFIG_HOME` 加载 **dotfiles**、**plugins** 和 **per-user configuration**。如果一个提权流程保留了这些值，**config injection** 可能比 binary hijacking 更容易。
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
有趣的目标包括 `.gitconfig`、`.wgetrc`、`.curlrc`、`.inputrc`、`.pythonrc.py`，以及像 `.terraformrc` 这样的工具特定文件。

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

这些变量会影响 **dynamic linker**：

- `LD_PRELOAD`：强制先加载额外的 shared objects。
- `LD_LIBRARY_PATH`：将 library 搜索目录前置。
- `LD_AUDIT`：加载 auditor libraries，用于观察 library loading 和 symbol resolution。

如果某个特权命令保留了它们，这些变量对 **hooking**、**instrumentation** 和 **privilege escalation** 都非常有价值。在 **secure-execution** 模式（`AT_SECURE`，例如 setuid/setgid/capabilities）下，loader 会移除或限制其中许多变量。不过，早期 loader 阶段的 parser bugs 仍然影响很大，因为它们在目标程序 **before** 运行。
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` 会改变早期的 glibc 行为（例如 allocator tunables），在 exploit labs 里非常有用。从安全角度看，它也很重要，因为 **dynamic loader 会非常早地解析它**。2023 年的 **Looney Tunables** bug 很好地提醒了我们：loader 中解析的一个环境变量，就可能成为针对 SUID 程序的 **local privilege-escalation primitive**。
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

如果 **Bash** 以 **非交互式** 启动，它会检查 `BASH_ENV`，并在运行目标脚本之前 source 该文件。当 Bash 以 `sh` 方式调用，或以 POSIX 风格交互模式运行时，`ENV` 也可能会被读取。这是一种经典方法，可以在环境变量可被攻击者控制时，将 shell wrapper 转化为 code execution。
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 本身在 **real/effective IDs 不同** 时会禁用这些启动文件，除非使用 `-p`，所以具体行为取决于 wrapper 如何调用 shell。

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

这些变量会改变 Python 的启动方式：

- `PYTHONPATH`：在导入搜索路径前添加前缀。
- `PYTHONHOME`：重新定位标准库树。
- `PYTHONSTARTUP`：在交互式提示符前执行一个文件。
- `PYTHONINSPECT=1`：在脚本结束后进入交互模式。

它们对维护脚本、debuggers、shells，以及那些以可控环境调用 Python 的 wrappers 很有用。`python -E` 和 `python -I` 会忽略所有 `PYTHON*` 变量。
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl 也有同样有用的启动变量：

- `PERL5LIB`: 追加 library 目录到前面。
- `PERL5OPT`: 注入 switches，就像它们出现在每一条 `perl` command line 上一样。

这可以强制 **automatic module loading**，或者在目标 script 做任何有趣的事情之前改变 interpreter 行为。Perl 在 **taint / setuid / setgid** 场景下会忽略这些变量，但它们对正常的 root-run wrappers、CI jobs、installers 和自定义 sudoers 规则仍然非常重要。
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
The same idea appears in other runtimes (`RUBYOPT`, `NODE_OPTIONS`, etc.): whenever an interpreter is launched by a privileged wrapper, look for env vars that modify **module loading** or **startup behavior**.

From a post-exploitation perspective, also remember that inherited environments often contain **credentials**, **proxy settings**, **service tokens**, or **cloud keys**. Check [Linux Post Exploitation](linux-post-exploitation/README.md) for `/proc/<PID>/environ` and `systemd` `Environment=` hunting.

### PS1

更改你的提示符外观。

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Regular user:

![](<../images/image (740).png>)

One, two and three backgrounded jobs:

![](<../images/image (145).png>)

One background job, one stopped and last command didn't finish correctly:

![](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../banners/hacktricks-training.md}}
