# Linux Environment Variables

{{#include ../../banners/hacktricks-training.md}}

## Global variables

The global variables **will be** inherited by **child processes**.

You can create a global variable for your current session doing:

```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```

This variable will be accessible by your current sessions and its child processes.

You can **remove** a variable doing:

```bash
unset MYGLOBAL
```

## Local variables

The **local variables** can only be **accessed** by the **current shell/script**.

```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```

## List current variables

```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```

The contents of `/proc/*/environ` are **NUL-separated**, so these variants are usually easier to read:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

If you are looking for **credentials** or **interesting service configuration** inside inherited environments, also check [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – the display used by **X**. This variable is usually set to **:0.0**, which means the first display on the current computer.
- **EDITOR** – the user’s preferred text editor.
- **HISTFILESIZE** – the maximum number of lines contained in the history file.
- **HISTSIZE** – Number of lines added to the history file when the user finish his session
- **HOME** – your home directory.
- **HOSTNAME** – the hostname of the computer.
- **LANG** – your current language.
- **MAIL** – the location of the user’s mail spool. Usually **/var/spool/mail/USER**.
- **MANPATH** – the list of directories to search for manual pages.
- **OSTYPE** – the type of operating system.
- **PS1** – the default prompt in bash.
- **PATH** – stores the path of all the directories which holds binary files you want to execute just by specifying the name of the file and not by relative or absolute path.
- **PWD** – the current working directory.
- **SHELL** – the path to the current command shell (for example, **/bin/bash**).
- **TERM** – the current terminal type (for example, **xterm**).
- **TZ** – your time zone.
- **USER** – your current username.

## Interesting variables for hacking

Not every variable is equally useful. From an offensive perspective, prioritize variables that change **search paths**, **startup files**, **dynamic linker behavior**, or **audit/logging**.

### **HISTFILESIZE**

Change the **value of this variable to 0**, so when you **end your session** the **history file** (\~/.bash_history) will be **truncated to 0 lines**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

Change the **value of this variable to 0**, so commands are **not kept in the in-memory history** and won't be written back to the **history file** (\~/.bash_history).

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

If the **value of this variable is set to `ignorespace` or `ignoreboth`**, any command prepended with an extra space will not be saved in the history.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

Point the **history file** to **`/dev/null`** or unset it completely. This is usually more reliable than only changing the history size.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

The processes will use the **proxy** declared here to connect to internet through **http or https**.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: default proxy for tools/protocols that honor it.
- `no_proxy`: bypass list (hosts/domains/CIDRs) that should connect directly.

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

Both lowercase and uppercase variants may be used depending on the tool (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

The processes will trust the certificates indicated in **these env variables**. This is useful to make tools such as **`curl`**, **`git`**, Python HTTP clients, or package managers trust a CA controlled by the attacker (for example, to make an interception proxy look legitimate).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

If a privileged wrapper/script executes commands **without absolute paths**, the **first attacker-controlled directory** in `PATH` wins. This is the primitive behind many **PATH hijacks** in `sudo`, cron jobs, shell wrappers, and custom SUID helpers. Look for `env_keep+=PATH`, weak `secure_path`, or wrappers that call `tar`, `service`, `cp`, `python`, etc. by name.

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

For full privilege-escalation chains abusing `PATH`, check [Linux Privilege Escalation](linux-privilege-escalation/README.md).

### **HOME & XDG_CONFIG_HOME**

`HOME` is not only a directory reference: many tools automatically load **dotfiles**, **plugins**, and **per-user configuration** from `$HOME` or `$XDG_CONFIG_HOME`. If a privileged workflow preserves these values, **config injection** may be easier than binary hijacking.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Interesting targets include `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, and tool-specific files such as `.terraformrc`.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

These variables influence the **dynamic linker**:

- `LD_PRELOAD`: force extra shared objects to be loaded first.
- `LD_LIBRARY_PATH`: prepend library search directories.
- `LD_AUDIT`: load auditor libraries that observe library loading and symbol resolution.

They are extremely valuable for **hooking**, **instrumentation**, and **privilege escalation** if a privileged command preserves them. In **secure-execution** mode (`AT_SECURE`, e.g. setuid/setgid/capabilities), the loader strips or restricts many of these variables. However, parser bugs in that early loader stage are still high-impact because they run **before** the target program.

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES` changes early glibc behavior (for example, allocator tunables) and is very handy in exploit labs. It also matters from a security perspective because the **dynamic loader parses it very early**. The 2023 **Looney Tunables** bug was a good reminder that a single environment variable parsed in the loader can become a **local privilege-escalation primitive** against SUID programs.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

If **Bash** is started **non-interactively**, it checks `BASH_ENV` and sources that file before running the target script. When Bash is invoked as `sh`, or in POSIX-style interactive mode, `ENV` may also be consulted. This is a classic way to turn a shell wrapper into code execution if the environment is attacker-controlled.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash itself disables these startup files when the **real/effective IDs differ** unless `-p` is used, so the exact behavior depends on how the wrapper invokes the shell. Be careful with privileged wrappers that call `setuid()`/`setgid()` **before** launching Bash: once the IDs match again, Bash may trust `BASH_ENV`, `ENV`, and related shell state that would otherwise be ignored.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

These variables change how Python starts:

- `PYTHONPATH`: prepend import search paths.
- `PYTHONHOME`: relocate the standard library tree.
- `PYTHONSTARTUP`: execute a file before the interactive prompt.
- `PYTHONINSPECT=1`: drop into interactive mode after a script finishes.

They are useful against maintenance scripts, debuggers, shells, and wrappers that call Python with a controllable environment. `python -E` and `python -I` ignore all `PYTHON*` variables.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```

A recent real-world example was the 2024 **needrestart** LPE on Ubuntu/Debian systems: the root-owned scanner copied an unprivileged process's `PYTHONPATH` from `/proc/<PID>/environ` and then executed Python. The published exploit planted `importlib/__init__.so` in the attacker-controlled path so Python executed attacker code during its own initialization, before the helper's hard-coded script even mattered.

### **PERL5OPT & PERL5LIB**

Perl has equally useful startup variables:

- `PERL5LIB`: prepend library directories.
- `PERL5OPT`: inject switches as if they were on every `perl` command line.

This can force **automatic module loading** or change interpreter behavior before the target script does anything interesting. Perl ignores these variables in **taint / setuid / setgid** contexts, but they still matter a lot for normal root-run wrappers, CI jobs, installers, and custom sudoers rules.

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

`NODE_OPTIONS` prepends **Node.js CLI flags** to every `node` process that inherits the environment. This makes it useful against wrappers, CI jobs, Electron helpers, and sudo rules that eventually invoke Node. The most interesting flags offensively are usually:

- `--require <file>`: preload a CommonJS file before the target script.
- `--import <module>`: preload an ES module before the target script.

Node rejects some dangerous flags in `NODE_OPTIONS`, but `--require` and `--import` are explicitly allowed and are processed **before** the regular command-line arguments.

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

For remote gadget chains that set `NODE_OPTIONS` indirectly (for example, prototype-pollution to RCE), check [this other page](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md).

### **RUBYLIB & RUBYOPT**

Ruby offers the same class of startup abuse:

- `RUBYLIB`: prepend directories to Ruby's load path.
- `RUBYOPT`: inject command-line options such as `-r` into every `ruby` invocation.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

The 2024 **needrestart** vulnerabilities showed that this is not just a lab trick: the same root-owned helper that was vulnerable to `PYTHONPATH` abuse could also be coerced into running Ruby with an attacker-controlled `RUBYLIB`, loading `enc/encdb.so` from an attacker directory.

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

Some tools do not just read a path from the environment; they pass the value to a **shell**, an **editor**, or an **input preprocessor**. This makes the following variables especially interesting when a privileged wrapper runs `git`, `man`, `less`, or similar text viewers:

- `PAGER`, `MANPAGER`, `GIT_PAGER`: choose the pager command.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: choose the editor command, often with arguments.
- `LESSOPEN`, `LESSCLOSE`: define pre/post-processors that run when `less` opens a file.

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

Git also supports **env-only config injection** without touching disk via `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, and `GIT_CONFIG_VALUE_<n>`:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

From a post-exploitation perspective, also remember that inherited environments often contain **credentials**, **proxy settings**, **service tokens**, or **cloud keys**. Check [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md) for `/proc/<PID>/environ` and `systemd` `Environment=` hunting.

### PS1

Change how your prompt looks.

[**This is an example**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: This is an example](<../images/image (897).png>)

Regular user:

![PERL5OPT & PERL5LIB - PS1: One, two and three backgrounded jobs](<../images/image (740).png>)

One, two and three backgrounded jobs:

![PERL5OPT & PERL5LIB - PS1: One, two and three backgrounded jobs](<../images/image (145).png>)

One background job, one stopped and last command didn't finish correctly:

![PERL5OPT & PERL5LIB - PS1: One background job, one stopped and last command didn't finish correctly](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
