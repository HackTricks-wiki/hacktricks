# Linux Environment Variables

{{#include ../banners/hacktricks-training.md}}

## Global variables

전역 변수는 **자식 프로세스**가 **상속합니다**.

현재 세션에 대해 전역 변수를 만들려면 다음을 수행할 수 있습니다:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
이 변수는 현재 세션과 그 자식 프로세스에서 접근할 수 있습니다.

다음과 같이 변수를 **제거**할 수 있습니다:
```bash
unset MYGLOBAL
```
## 로컬 변수

**로컬 변수**는 **현재 shell/script**에서만 **접근**할 수 있습니다.
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
`/proc/*/environ`의 내용은 **NUL로 구분**되므로, 보통 다음 변형들이 더 읽기 쉽습니다:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
If you are looking for **credentials** or **interesting service configuration** inside inherited environments, also check [Linux Post Exploitation](linux-post-exploitation/README.md).

## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X**가 사용하는 디스플레이. 이 변수는 보통 **:0.0**으로 설정되며, 현재 컴퓨터의 첫 번째 디스플레이를 의미한다.
- **EDITOR** – 사용자가 선호하는 텍스트 에디터.
- **HISTFILESIZE** – history file에 포함되는 최대 줄 수.
- **HISTSIZE** – 사용자가 세션을 끝낼 때 history file에 추가되는 줄 수.
- **HOME** – 홈 디렉터리.
- **HOSTNAME** – 컴퓨터의 hostname.
- **LANG** – 현재 언어.
- **MAIL** – 사용자의 mail spool 위치. 보통 **/var/spool/mail/USER**.
- **MANPATH** – manual pages를 찾기 위한 디렉터리 목록.
- **OSTYPE** – operating system의 type.
- **PS1** – bash의 기본 prompt.
- **PATH** – 실행하려는 binary file의 이름만 지정해도 실행되도록 해주는, binary files가 들어 있는 모든 디렉터리의 path를 저장한다. 상대 경로나 절대 경로는 필요 없다.
- **PWD** – 현재 working directory.
- **SHELL** – 현재 command shell의 path (예: **/bin/bash**).
- **TERM** – 현재 terminal type (예: **xterm**).
- **TZ** – time zone.
- **USER** – 현재 username.

## Interesting variables for hacking

Not every variable is equally useful. From an offensive perspective, prioritize variables that change **search paths**, **startup files**, **dynamic linker behavior**, or **audit/logging**.

### **HISTFILESIZE**

이 변수의 **값을 0으로 변경**하면, **세션을 종료할 때** **history file** (\~/.bash_history)이 **0줄로 잘린다**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

이 변수의 **값을 0으로 변경**하면, 명령이 **메모리 내 history에 저장되지 않으며** **history file** (\~/.bash_history)로 다시 기록되지 않습니다.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

**이 변수의 값이 `ignorespace` 또는 `ignoreboth`로 설정되면**, 앞에 공백이 하나 더 붙은 모든 명령은 history에 저장되지 않습니다.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file**를 **`/dev/null`**로 지정하거나 완전히 unset하세요. 이는 보통 **history size**만 변경하는 것보다 더 신뢰할 수 있습니다.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

프로세스는 **http 또는 https**를 통해 인터넷에 연결하기 위해 여기 선언된 **proxy**를 사용합니다.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: 이를 지원하는 tools/protocols의 기본 proxy.
- `no_proxy`: 직접 연결해야 하는 우회 목록(hosts/domains/CIDRs).
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
도구에 따라 소문자와 대문자 변형이 모두 사용될 수 있습니다 (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

프로세스는 **이 env 변수들**에 지정된 인증서를 신뢰합니다. 이는 **`curl`**, **`git`**, Python HTTP client, 또는 package manager가 공격자가 제어하는 CA를 신뢰하게 만드는 데 유용합니다(예를 들어, interception proxy를 합법적으로 보이게 하기 위해).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

권한이 있는 wrapper/script가 **절대 경로 없이** 명령을 실행하면, `PATH`에서 **가장 먼저 있는 공격자가 제어하는 디렉터리**가 이깁니다. 이것은 `sudo`, cron jobs, shell wrappers, 커스텀 SUID helpers에서의 많은 **PATH hijacks**의 기반이 되는 primitive입니다. `env_keep+=PATH`, 약한 `secure_path`, 또는 `tar`, `service`, `cp`, `python` 등을 이름만으로 호출하는 wrappers를 찾아보세요.
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
`PATH`를 악용한 전체 privilege-escalation 체인은 [Linux Privilege Escalation](privilege-escalation/README.md)를 확인하세요.

### **HOME & XDG_CONFIG_HOME**

`HOME`은 단순한 디렉터리 참조가 아닙니다: 많은 도구가 `$HOME` 또는 `$XDG_CONFIG_HOME`에서 **dotfiles**, **plugins**, 그리고 **per-user configuration**을 자동으로 로드합니다. 권한 있는 workflow가 이 값들을 유지한다면, **config injection**은 binary hijacking보다 더 쉬울 수 있습니다.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
흥미로운 대상에는 `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, 그리고 `.terraformrc` 같은 도구별 파일이 포함된다.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

이 변수들은 **dynamic linker**에 영향을 준다:

- `LD_PRELOAD`: 추가 shared objects를 먼저 로드하도록 강제한다.
- `LD_LIBRARY_PATH`: library 검색 디렉터리를 앞에 추가한다.
- `LD_AUDIT`: library 로딩과 symbol resolution을 관찰하는 auditor libraries를 로드한다.

이들은 **hooking**, **instrumentation**, 그리고 권한 있는 command가 이를 유지할 경우 **privilege escalation**에 매우 유용하다. **secure-execution** 모드(`AT_SECURE`, 예: setuid/setgid/capabilities)에서는 loader가 이러한 변수들 중 다수를 제거하거나 제한한다. 하지만 초기 loader 단계의 parser bugs는 대상 program **before**에 실행되므로 여전히 영향력이 매우 크다.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`는 초기 glibc 동작(예: allocator tunables)을 변경하며 exploit lab에서 매우 유용합니다. 보안 관점에서도 중요한데, **dynamic loader가 이를 매우 일찍 파싱**하기 때문입니다. 2023년 **Looney Tunables** bug는 loader에서 파싱되는 단일 environment variable이 SUID programs를 상대로 한 **local privilege-escalation primitive**가 될 수 있음을 잘 보여준 사례였습니다.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash**가 **비대화형**으로 시작되면 `BASH_ENV`를 확인하고, 대상 스크립트를 실행하기 전에 그 파일을 source 합니다. Bash가 `sh`로 호출되거나 POSIX 스타일 대화형 모드로 실행되면 `ENV`도 참조될 수 있습니다. 이는 환경이 공격자에 의해 제어될 때 shell wrapper를 code execution으로 전환하는 고전적인 방법입니다.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 자체는 **실제/유효 ID가 다를 때** `-p`가 사용되지 않으면 이러한 startup files를 비활성화하므로, 정확한 동작은 wrapper가 shell을 어떻게 호출하는지에 따라 달라집니다.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

이 변수들은 Python의 시작 방식을 바꿉니다:

- `PYTHONPATH`: import 검색 경로를 앞에 추가합니다.
- `PYTHONHOME`: standard library tree를 다른 위치로 옮깁니다.
- `PYTHONSTARTUP`: interactive prompt 전에 파일을 실행합니다.
- `PYTHONINSPECT=1`: script가 끝난 뒤 interactive mode로 들어갑니다.

이 변수들은 maintenance scripts, debuggers, shells, 그리고 제어 가능한 environment로 Python을 호출하는 wrappers에 대해 유용합니다. `python -E`와 `python -I`는 모든 `PYTHON*` 변수들을 무시합니다.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
### **PERL5OPT & PERL5LIB**

Perl에는 똑같이 유용한 startup variables가 있습니다:

- `PERL5LIB`: library directories를 앞에 추가합니다.
- `PERL5OPT`: 모든 `perl` command line에 있는 것처럼 switches를 주입합니다.

이것은 대상 script가 의미 있는 작업을 하기 전에 **automatic module loading**을 강제하거나 interpreter behavior를 변경할 수 있습니다. Perl은 **taint / setuid / setgid** contexts에서 이 variables를 무시하지만, normal root-run wrappers, CI jobs, installers, custom sudoers rules에서는 여전히 매우 중요합니다.
```bash
mkdir -p /tmp/perllib
cat > /tmp/perllib/HT.pm <<'EOF'
package HT;
BEGIN { print "PERL5OPT_TRIGGERED\n" }
1;
EOF
PERL5LIB=/tmp/perllib PERL5OPT=-MHT perl -e 'print "target\n"'
```
같은 아이디어는 다른 runtime(`RUBYOPT`, `NODE_OPTIONS`, etc.)에도 나타납니다: privileged wrapper에 의해 interpreter가 실행될 때마다, **module loading** 또는 **startup behavior**를 수정하는 env vars를 찾아보세요.

post-exploitation 관점에서도, 상속된 environments에는 종종 **credentials**, **proxy settings**, **service tokens**, 또는 **cloud keys**가 포함된다는 점을 기억하세요. `/proc/<PID>/environ`과 `systemd` `Environment=` 탐색은 [Linux Post Exploitation](linux-post-exploitation/README.md)를 확인하세요.

### PS1

prompt가 어떻게 보이는지 변경합니다.

[**이것은 예시입니다**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

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
