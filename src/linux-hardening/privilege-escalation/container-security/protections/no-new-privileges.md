# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs`는 `execve()`를 통해 프로세스가 더 높은 권한을 얻는 것을 방지하는 커널 하드닝 기능이다. 실무적으로 말하면, 이 플래그가 설정되면 setuid 바이너리, setgid 바이너리, 또는 Linux file capabilities를 가진 파일을 실행해도 프로세스가 이미 가지고 있던 권한을 넘어선 추가 권한을 얻지 못한다. 컨테이너화된 환경에서는 이미지 내부에서 실행 시 권한이 변경되는 실행 파일을 찾아 권한 상승 체인을 만드는 경우가 많기 때문에 이 기능이 중요하다.

방어 관점에서, `no_new_privs`는 namespaces, seccomp, 또는 capability dropping을 대체하지 않는다. 이는 보강 레이어이다. 코드 실행이 이미 이루어진 이후에 발생할 수 있는 특정 종류의 후속 권한 상승을 차단한다. 이로 인해 이미지에 helper binaries, package-manager artifacts, 또는 legacy tools가 포함되어 있어 부분적 침해와 결합될 때 위험해질 수 있는 환경에서 특히 유용하다.

## 동작

이 동작의 배후에 있는 커널 플래그는 `PR_SET_NO_NEW_PRIVS`이다. 한 번 프로세스에 설정되면 이후의 `execve()` 호출로 권한을 높일 수 없다. 중요한 점은 프로세스가 여전히 바이너리를 실행할 수 있다는 것이며, 단지 그 바이너리를 사용해 커널이 본래 인정했을 권한 경계를 넘을 수 없다는 것이다.

Kubernetes 지향 환경에서는 `allowPrivilegeEscalation: false`가 컨테이너 프로세스에 대해 이 동작과 대응된다. Docker 및 Podman 스타일 런타임에서는 동등한 설정이 보통 보안 옵션을 통해 명시적으로 활성화된다.

## Lab

현재 프로세스 상태를 확인하라:
```bash
grep NoNewPrivs /proc/self/status
```
런타임이 해당 플래그를 활성화한 컨테이너와 비교해 보자:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
On a hardened workload, the result should show `NoNewPrivs: 1`.

## 보안 영향

If `no_new_privs` is absent, a foothold inside the container may still be upgraded through setuid helpers or binaries with file capabilities. If it is present, those post-exec privilege changes are cut off. The effect is especially relevant in broad base images that ship many utilities the application never needed in the first place.

## 잘못된 구성

The most common problem is simply not enabling the control in environments where it would be compatible. In Kubernetes, leaving `allowPrivilegeEscalation` enabled is often the default operational mistake. In Docker and Podman, omitting the relevant security option has the same effect. Another recurring failure mode is assuming that because a container is "not privileged", exec-time privilege transitions are automatically irrelevant.

## 악용

If `no_new_privs` is not set, the first question is whether the image contains binaries that can still raise privilege:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
흥미로운 결과는 다음과 같습니다:

- `NoNewPrivs: 0`
- setuid helpers such as `su`, `mount`, `passwd`, or distribution-specific admin tools
- file capabilities를 통해 네트워크 또는 파일시스템 권한을 부여하는 바이너리

실제 평가에서는 이러한 발견만으로 작동하는 escalation을 증명하지는 못하지만, 다음으로 테스트할 가치가 있는 바이너리를 정확히 식별합니다.

### 전체 예: In-Container Privilege Escalation Through setuid

이 컨트롤은 일반적으로 호스트 이스케이프를 직접적으로 막기보다는 **in-container privilege escalation**을 방지합니다. `NoNewPrivs`가 `0`이고 setuid helper가 존재하면, 이를 명시적으로 테스트하세요:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
알려진 setuid 바이너리가 존재하고 정상적으로 작동한다면, 권한 전환을 유지하는 방식으로 실행해 보세요:
```bash
/bin/su -c id 2>/dev/null
```
이것 자체만으로는 container를 탈출하지 못하지만, container 내부의 low-privilege foothold를 container-root로 전환할 수 있으며, 이는 종종 이후 mounts, runtime sockets, 또는 kernel-facing interfaces를 통한 host escape의 전제조건이 된다.

## 검사

이러한 검사의 목적은 exec-time privilege gain이 차단되었는지, 그리고 차단되지 않았을 경우 영향을 미칠 수 있는 helpers가 image에 여전히 포함되어 있는지를 확인하는 것이다.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
What is interesting here:

- `NoNewPrivs: 1`은 보통 더 안전한 결과입니다.
- `NoNewPrivs: 0`은 setuid 및 file-cap 기반 권한 상승 경로가 여전히 유효함을 의미합니다.
- setuid/file-cap 바이너리가 거의 없거나 없는 최소 이미지는 `no_new_privs`가 없어도 공격자의 post-exploitation 옵션을 줄여줍니다.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화되어 있지 않음 | 명시적으로 `--security-opt no-new-privileges=true`로 활성화됨 | 플래그를 생략하거나 `--privileged` 사용 |
| Podman | 기본적으로 활성화되어 있지 않음 | 명시적으로 `--security-opt no-new-privileges` 또는 동등한 보안 설정으로 활성화됨 | 옵션을 생략하거나 `--privileged` 사용 |
| Kubernetes | 워크로드 정책에 의해 제어됨 | `allowPrivilegeEscalation: false`가 이 효과를 활성화함; 많은 워크로드는 여전히 이를 활성화된 상태로 둠 | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes 워크로드 설정을 따름 | 보통 Pod security context에서 상속됨 | Kubernetes 행과 동일 |

이 보호 기능은 런타임이 이를 지원하지 않기 때문이 아니라 단순히 아무도 활성화하지 않았기 때문에 종종 적용되어 있지 않습니다.
{{#include ../../../../banners/hacktricks-training.md}}
