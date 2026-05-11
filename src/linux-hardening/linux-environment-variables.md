# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## 전역 변수

전역 변수는 **자식 프로세스**에 의해 **상속됩니다**.

다음과 같이 현재 세션에 대한 전역 변수를 만들 수 있습니다:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
이 변수는 현재 세션과 해당 자식 프로세스에서 접근할 수 있습니다.

다음과 같이 변수를 **제거**할 수 있습니다:
```bash
unset MYGLOBAL
```
## 로컬 변수

**로컬 변수**는 **현재 shell/script**에서만 **accessed**할 수 있다.
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
`/proc/*/environ`의 내용은 **NUL로 구분**되므로, 이러한 변형이 보통 더 읽기 쉽습니다:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
If you are looking for **credentials** or **interesting service configuration** inside inherited environments, also check [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X**가 사용하는 디스플레이. 이 변수는 보통 **:0.0**으로 설정되며, 이는 현재 컴퓨터의 첫 번째 디스플레이를 의미합니다.
- **EDITOR** – 사용자가 선호하는 텍스트 편집기.
- **HISTFILESIZE** – history file에 포함되는 최대 줄 수.
- **HISTSIZE** – 사용자가 세션을 끝낼 때 history file에 추가되는 줄 수
- **HOME** – 홈 디렉터리.
- **HOSTNAME** – 컴퓨터의 hostname.
- **LANG** – 현재 언어.
- **MAIL** – 사용자의 mail spool 위치. 보통 **/var/spool/mail/USER**.
- **MANPATH** – manual pages를 검색할 디렉터리 목록.
- **OSTYPE** – operating system의 유형.
- **PS1** – bash의 기본 prompt.
- **PATH** – 실행할 binary files가 들어 있는 모든 디렉터리의 path를 저장합니다. 파일의 이름만 지정해서 실행할 수 있고, 상대 경로나 절대 경로를 직접 지정할 필요가 없습니다.
- **PWD** – 현재 작업 디렉터리.
- **SHELL** – 현재 command shell의 path (예: **/bin/bash**).
- **TERM** – 현재 terminal 유형 (예: **xterm**).
- **TZ** – 시간대.
- **USER** – 현재 username.

## Interesting variables for hacking

모든 변수의 유용성이 같은 것은 아닙니다. offensive 관점에서는 **search paths**, **startup files**, **dynamic linker behavior**, 또는 **audit/logging**을 바꾸는 변수들을 우선적으로 보세요.

### **HISTFILESIZE**

이 변수의 **value를 0으로 변경**하면, **세션을 종료할 때** **history file**(\~/.bash_history)이 **0 lines로 잘려** 저장됩니다.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

**이 변수의 값을 0으로 변경**하면, 명령이 **메모리 내 히스토리에 저장되지 않으며** **history 파일** (\~/.bash_history)로 다시 기록되지 않습니다.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

**이 변수의 값이 `ignorespace` 또는 `ignoreboth`로 설정되면**, 앞에 추가 공백이 붙은 모든 명령은 history에 저장되지 않습니다.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file**를 **`/dev/null`**로 지정하거나 완전히 unset하세요. 이것은 보통 history size만 변경하는 것보다 더 신뢰할 수 있습니다.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

프로세스는 인터넷에 연결하기 위해 여기서 선언된 **proxy**를 **http or https**를 통해 사용합니다.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: 이를 인식하는 tools/protocols를 위한 기본 proxy.
- `no_proxy`: 직접 연결해야 하는 우회 목록(hosts/domains/CIDRs).
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
도구에 따라 소문자와 대문자 변형이 모두 사용될 수 있습니다 (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

프로세스는 **이 env variables**에 지정된 certificates를 신뢰합니다. 이는 **`curl`**, **`git`**, Python HTTP clients, 또는 package managers 같은 도구가 공격자가 제어하는 CA를 신뢰하도록 만드는 데 유용합니다(예: interception proxy를 합법적으로 보이게 하기 위해).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

권한 있는 wrapper/script가 **절대 경로 없이** 명령을 실행하면, `PATH`에서 **가장 먼저 잡히는 공격자 제어 디렉터리**가 우선됩니다. 이것은 `sudo`, cron jobs, shell wrappers, 그리고 custom SUID helpers에서의 많은 **PATH hijacks**의 핵심 원리입니다. `env_keep+=PATH`, 약한 `secure_path`, 또는 `tar`, `service`, `cp`, `python` 등을 이름만으로 호출하는 wrapper를 찾아보세요.
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

`HOME`는 단순한 디렉터리 참조가 아닙니다: 많은 도구가 `$HOME` 또는 `$XDG_CONFIG_HOME`에서 **dotfiles**, **plugins**, 그리고 **per-user configuration**을 자동으로 불러옵니다. 권한이 높은 workflow가 이 값들을 유지한다면, **config injection**은 binary hijacking보다 더 쉬울 수 있습니다.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
흥미로운 타깃에는 `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, 그리고 `.terraformrc` 같은 도구별 파일이 포함된다.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

이 변수들은 **dynamic linker**에 영향을 준다:

- `LD_PRELOAD`: 추가 shared objects를 먼저 로드하도록 강제한다.
- `LD_LIBRARY_PATH`: library search directories를 앞에 추가한다.
- `LD_AUDIT`: library loading과 symbol resolution을 관찰하는 auditor libraries를 로드한다.

이 변수들은 **hooking**, **instrumentation**, 그리고 privileged command가 이를 보존할 때 **privilege escalation**에 매우 유용하다. **secure-execution** mode(`AT_SECURE`, 예: setuid/setgid/capabilities)에서는 loader가 이러한 변수들 중 많은 부분을 제거하거나 제한한다. 하지만 그 초기 loader 단계의 parser bugs는 여전히 영향력이 큰데, 이는 대상 program **이전**에 실행되기 때문이다.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`는 초기 glibc 동작(예: allocator tunables)을 변경하며, exploit lab에서 매우 유용합니다. 보안 관점에서도 중요한데, **dynamic loader가 이를 매우 일찍 파싱하기 때문**입니다. 2023년 **Looney Tunables** bug는 loader에서 파싱되는 하나의 environment variable이 SUID 프로그램에 대한 **local privilege-escalation primitive**가 될 수 있다는 점을 잘 보여준 사례였습니다.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash**가 **non-interactively** 시작되면 `BASH_ENV`를 확인하고, 대상 스크립트를 실행하기 전에 해당 파일을 source합니다. Bash가 `sh`로 호출되거나 POSIX-style interactive mode에서 실행될 때는 `ENV`도 참고될 수 있습니다. 이는 environment가 attacker-controlled일 때 shell wrapper를 code execution으로 바꾸는 고전적인 방법입니다.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 자체는 **실제/유효 ID가 다를 때** `-p`가 사용되지 않으면 이러한 시작 파일들을 비활성화하므로, 정확한 동작은 wrapper가 shell을 호출하는 방식에 따라 달라집니다.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

이 변수들은 Python이 시작되는 방식을 바꿉니다:

- `PYTHONPATH`: import 검색 경로를 앞에 추가합니다.
- `PYTHONHOME`: 표준 라이브러리 트리를 다른 위치로 옮깁니다.
- `PYTHONSTARTUP`: interactive prompt 전에 파일을 실행합니다.
- `PYTHONINSPECT=1`: script가 끝난 뒤 interactive mode로 들어갑니다.

이들은 maintenance scripts, debuggers, shells, 그리고 제어 가능한 environment로 Python을 호출하는 wrappers에 대해 유용합니다. `python -E`와 `python -I`는 모든 `PYTHON*` 변수를 무시합니다.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl에는 마찬가지로 유용한 startup variables가 있습니다:

- `PERL5LIB`: library directories를 앞에 추가합니다.
- `PERL5OPT`: 마치 모든 `perl` command line에 들어간 것처럼 switches를 주입합니다.

이것은 target script가 어떤 흥미로운 작업을 하기 전에 **automatic module loading**을 강제하거나 interpreter behavior를 변경할 수 있습니다. Perl은 **taint / setuid / setgid** contexts에서는 이러한 variables를 무시하지만, normal root-run wrappers, CI jobs, installers, 그리고 custom sudoers rules에서는 여전히 매우 중요합니다.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
같은 아이디어는 다른 runtime(`RUBYOPT`, `NODE_OPTIONS` 등)에서도 나타난다: interpreter가 privileged wrapper에 의해 실행될 때마다, **module loading** 또는 **startup behavior**를 수정하는 env vars를 찾아라.

post-exploitation 관점에서는, 상속된 environment에 종종 **credentials**, **proxy settings**, **service tokens**, 또는 **cloud keys**가 들어 있다는 점도 기억하자. `/proc/<PID>/environ`과 `systemd` `Environment=` 탐색은 [Linux Post Exploitation](linux-post-exploitation/README.md)를 확인하라.

### PS1

prompt의 표시 방식을 바꾼다.

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
