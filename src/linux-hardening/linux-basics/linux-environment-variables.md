# Linux 환경 변수

{{#include ../../banners/hacktricks-training.md}}

## 전역 변수

전역 변수는 **자식 프로세스에** 상속됩니다.

현재 세션에 전역 변수를 생성하려면 다음을 실행합니다:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
이 변수는 현재 세션과 해당 세션의 자식 프로세스에서 사용할 수 있습니다.

다음과 같이 변수를 **제거**할 수 있습니다:
```bash
unset MYGLOBAL
```
## 로컬 변수

**로컬 변수**는 **현재 shell/script**에서만 **액세스**할 수 있습니다.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 현재 변수 목록
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
`/proc/*/environ`의 내용은 **NUL로 구분**되어 있으므로, 다음 변형을 사용하면 일반적으로 더 쉽게 읽을 수 있습니다:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
상속된 환경 내부에서 **credentials** 또는 **interesting service configuration**을 찾고 있다면 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)도 확인하세요.

## 일반적인 변수

출처: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X**에서 사용하는 display입니다. 이 변수는 일반적으로 **:0.0**으로 설정되며, 현재 컴퓨터의 첫 번째 display를 의미합니다.
- **EDITOR** – 사용자가 선호하는 text editor입니다.
- **HISTFILESIZE** – history file에 포함되는 최대 줄 수입니다.
- **HISTSIZE** – 사용자가 session을 종료할 때 history file에 추가되는 줄 수입니다.
- **HOME** – 사용자의 home directory입니다.
- **HOSTNAME** – 컴퓨터의 hostname입니다.
- **LANG** – 현재 language입니다.
- **MAIL** – 사용자의 mail spool 위치입니다. 일반적으로 **/var/spool/mail/USER**입니다.
- **MANPATH** – manual page를 검색할 directory 목록입니다.
- **OSTYPE** – operating system의 유형입니다.
- **PS1** – bash의 default prompt입니다.
- **PATH** – 파일 이름만 지정하여 실행할 수 있도록, 실행하려는 binary file이 포함된 모든 directory의 path를 저장합니다. relative path 또는 absolute path를 지정할 필요가 없습니다.
- **PWD** – 현재 working directory입니다.
- **SHELL** – 현재 command shell의 path입니다(예: **/bin/bash**).
- **TERM** – 현재 terminal 유형입니다(예: **xterm**).
- **TZ** – time zone입니다.
- **USER** – 현재 username입니다.

## hacking에 유용한 변수

모든 변수가 동일하게 유용한 것은 아닙니다. offensive 관점에서는 **search path**, **startup file**, **dynamic linker behavior** 또는 **audit/logging**을 변경하는 변수의 우선순위를 높이세요.

### **HISTFILESIZE**

**이 변수의 값을 0으로 변경**하면 **session을 종료할 때** **history file**(\~/.bash_history)이 **0줄로 잘립니다**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**이 변수의 값을 0으로 변경**하면 명령어가 **메모리 내 history에 보관되지 않으며**, **history file**(\~/.bash_history)에 기록되지 않습니다.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

**이 변수의 값이 `ignorespace` 또는 `ignoreboth`로 설정된 경우**, 앞에 추가 공백이 붙은 command는 history에 저장되지 않습니다.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file**을 **`/dev/null`**로 지정하거나 완전히 unset합니다. 이는 history size만 변경하는 것보다 일반적으로 더 안정적입니다.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

프로세스는 **http 또는 https**를 통해 인터넷에 연결할 때 여기에 선언된 **proxy**를 사용합니다.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: 이를 따르는 도구/프로토콜의 기본 프록시.
- `no_proxy`: 직접 연결해야 하는 호스트/도메인/CIDR의 우회 목록.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
도구에 따라 소문자 및 대문자 변형을 사용할 수 있습니다 (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

프로세스는 **이러한 env variables**에 지정된 인증서를 신뢰합니다. 이는 **`curl`**, **`git`**, Python HTTP clients 또는 package managers와 같은 도구가 공격자가 제어하는 CA를 신뢰하도록 만드는 데 유용합니다(예를 들어 interception proxy가 정상적인 것으로 보이게 만들 수 있습니다).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

권한이 있는 wrapper/script가 **절대 경로 없이** 명령을 실행하면, `PATH`에서 **공격자가 제어하는 첫 번째 directory**가 우선 사용됩니다. 이는 `sudo`, cron jobs, shell wrappers 및 custom SUID helpers에서 발생하는 많은 **PATH hijacks**의 기반이 되는 primitive입니다. `env_keep+=PATH`, 취약한 `secure_path`, 또는 `tar`, `service`, `cp`, `python` 등을 이름만으로 호출하는 wrappers를 찾아보세요.
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
`PATH`를 악용하는 전체 privilege-escalation chain은 [Linux Privilege Escalation](linux-privilege-escalation/README.md)을 확인하세요.

### **HOME & XDG_CONFIG_HOME**

`HOME`은 단순한 디렉터리 참조가 아닙니다. 많은 도구가 `$HOME` 또는 `$XDG_CONFIG_HOME`에서 **dotfiles**, **plugins**, **per-user configuration**을 자동으로 로드합니다. 권한이 있는 workflow가 이러한 값을 유지한다면, **config injection**이 binary hijacking보다 쉬울 수 있습니다.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
흥미로운 대상에는 `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, 그리고 `.terraformrc`와 같은 tool-specific 파일이 포함됩니다.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

이 변수들은 **dynamic linker**에 영향을 줍니다:

- `LD_PRELOAD`: 추가 shared object가 먼저 로드되도록 강제합니다.
- `LD_LIBRARY_PATH`: library 검색 디렉터리를 앞에 추가합니다.
- `LD_AUDIT`: library 로딩 및 symbol resolution을 관찰하는 auditor library를 로드합니다.

권한이 있는 command가 이러한 변수를 유지한다면 **hooking**, **instrumentation**, **privilege escalation**에 매우 유용합니다. **secure-execution** 모드(`AT_SECURE`, 예: setuid/setgid/capabilities)에서는 loader가 이러한 변수 대부분을 제거하거나 제한합니다. 그러나 초기 loader 단계에서 발생하는 parser bug는 여전히 큰 영향을 미칩니다. 해당 단계가 target program보다 **먼저** 실행되기 때문입니다.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`는 초기 glibc 동작(예: allocator tunables)을 변경하며 exploit lab에서 매우 유용합니다. 또한 **dynamic loader가 이를 매우 이른 단계에서 파싱**하기 때문에 보안 관점에서도 중요합니다. 2023년 **Looney Tunables** 버그는 loader에서 파싱되는 단일 환경 변수가 SUID 프로그램에 대한 **로컬 권한 상승 primitive**가 될 수 있다는 점을 다시 한번 보여주는 좋은 사례였습니다.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash**가 **비대화형**으로 시작되면 대상 스크립트를 실행하기 전에 `BASH_ENV`를 확인하고 해당 파일을 source합니다. Bash가 `sh`로 호출되거나 POSIX 스타일 대화형 모드에서 실행되는 경우에는 `ENV`도 확인할 수 있습니다. 이는 환경이 공격자의 제어하에 있을 때 shell wrapper를 code execution으로 바꾸는 고전적인 방법입니다.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 자체는 `-p`가 사용되지 않는 한 **real/effective IDs가 서로 다를 때** 이러한 startup files를 비활성화하므로, 정확한 동작은 wrapper가 shell을 호출하는 방식에 따라 달라집니다.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

이러한 변수는 Python의 시작 방식을 변경합니다.

- `PYTHONPATH`: import search paths 앞에 경로를 추가합니다.
- `PYTHONHOME`: standard library tree의 위치를 변경합니다.
- `PYTHONSTARTUP`: interactive prompt 전에 파일을 실행합니다.
- `PYTHONINSPECT=1`: script가 종료된 후 interactive mode로 진입합니다.

이 변수들은 제어 가능한 environment로 Python을 호출하는 maintenance scripts, debuggers, shells 및 wrappers를 대상으로 유용합니다. `python -E` 및 `python -I`는 모든 `PYTHON*` 변수를 무시합니다.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl에는 이와 마찬가지로 유용한 startup variables가 있습니다:

- `PERL5LIB`: library directories를 prepend합니다.
- `PERL5OPT`: 모든 `perl` command line에 있는 것처럼 switches를 inject합니다.

이를 통해 대상 script가 중요한 작업을 수행하기 전에 **automatic module loading**을 강제하거나 interpreter behavior를 변경할 수 있습니다. Perl은 **taint / setuid / setgid** contexts에서는 이러한 variables를 무시하지만, 일반적인 root-run wrappers, CI jobs, installers 및 custom sudoers rules에서는 여전히 매우 중요합니다.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
동일한 아이디어는 다른 runtime (`RUBYOPT`, `NODE_OPTIONS` 등)에도 적용됩니다. privileged wrapper가 interpreter를 실행할 때마다 **module loading** 또는 **startup behavior**를 수정하는 env vars를 확인하세요.

post-exploitation 관점에서는 상속된 환경에 **credentials**, **proxy settings**, **service tokens** 또는 **cloud keys**가 포함되는 경우가 많다는 점도 기억하세요. `/proc/<PID>/environ` 및 `systemd` `Environment=` hunting에 대해서는 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)을 확인하세요.

### PS1

prompt가 표시되는 방식을 변경합니다.

[**예시입니다**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: 예시입니다](<../images/image (897).png>)

일반 사용자:

![PERL5OPT & PERL5LIB - PS1: 백그라운드에서 실행된 작업 하나, 둘, 세 개](<../images/image (740).png>)

백그라운드에서 실행된 작업 하나, 둘, 세 개:

![PERL5OPT & PERL5LIB - PS1: 백그라운드에서 실행된 작업 하나, 둘, 세 개](<../images/image (145).png>)

백그라운드 작업 하나, 중지된 작업 하나, 마지막 명령이 올바르게 완료되지 않음:

![PERL5OPT & PERL5LIB - PS1: 백그라운드 작업 하나, 중지된 작업 하나, 마지막 명령이 올바르게 완료되지 않음](<../images/image (715).png>)

## References

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)

{{#include ../../banners/hacktricks-training.md}}
