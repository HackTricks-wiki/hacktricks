# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs`는 프로세스가 `execve()`를 통해 더 높은 권한을 얻지 못하도록 하는 커널 하드닝 기능입니다. 실무적으로는 이 플래그가 설정되면 setuid 바이너리, setgid 바이너리, 또는 Linux file capabilities가 설정된 파일을 실행하더라도 프로세스가 이미 가지고 있던 권한을 초과하는 추가 권한을 부여받지 못합니다. 컨테이너화된 환경에서는 이미지 내부에서 실행 시 권한을 변경하는 실행파일을 찾아내는 것에 의존하는 많은 privilege-escalation 체인 때문에 이것이 중요합니다.

방어적인 관점에서 `no_new_privs`는 namespaces, seccomp, 또는 capability dropping을 대신할 수 없습니다. 이는 보강 계층으로 작동합니다. 이미 code execution이 확보된 이후 발생하는 특정 범주의 후속 권한 상승을 차단합니다. 따라서 이미지에 helper binaries, package-manager artifacts, 또는 부분적인 침해와 결합되었을 때 위험할 수 있는 레거시 도구들이 포함된 환경에서 특히 유용합니다.

## 동작

이 동작의 배후에 있는 커널 플래그는 `PR_SET_NO_NEW_PRIVS`입니다. 이 플래그가 프로세스에 설정되면 이후의 `execve()` 호출은 권한을 증가시킬 수 없습니다. 중요한 점은 프로세스가 여전히 바이너리를 실행할 수는 있지만, 그 바이너리들을 사용하여 커널이 통상적으로 인정할 권한 경계를 넘을 수는 없다는 것입니다.

Kubernetes 기반 환경에서는 컨테이너 프로세스에 대해 `allowPrivilegeEscalation: false`가 이 동작에 대응합니다. Docker 및 Podman 스타일 런타임에서는 동등한 설정이 일반적으로 보안 옵션을 통해 명시적으로 활성화됩니다.

## 실습

현재 프로세스 상태를 검사하세요:
```bash
grep NoNewPrivs /proc/self/status
```
런타임이 플래그를 활성화하는 컨테이너와 비교해 보자:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
하드닝된 워크로드에서는 결과에 `NoNewPrivs: 1`가 표시되어야 합니다.

## 보안 영향

만약 `no_new_privs`가 없으면, 컨테이너 내부의 발판은 setuid 헬퍼나 binaries with file capabilities를 통해 여전히 권한 상승될 수 있습니다. `no_new_privs`가 설정되어 있으면, 그런 post-exec 권한 변경은 차단됩니다. 이 효과는 애플리케이션이 처음부터 필요하지 않았던 많은 유틸리티를 포함한 광범위한 베이스 이미지에서 특히 관련이 깊습니다.

## 잘못된 구성

가장 흔한 문제는 해당 환경에서 호환되는데도 이 제어를 단순히 활성화하지 않는 것입니다. Kubernetes에서는 `allowPrivilegeEscalation`을 활성화한 채로 두는 것이 자주 발생하는 기본 운영 오류입니다. Docker와 Podman에서는 관련 보안 옵션을 생략하는 것이 동일한 결과를 낳습니다. 또 다른 반복되는 실패 모드는 컨테이너가 "not privileged"이기 때문에 exec 시점의 권한 전환은 자동으로 무관하다고 가정하는 것입니다.

## 악용

만약 `no_new_privs`가 설정되어 있지 않다면, 첫 번째 질문은 이미지에 여전히 권한을 상승시킬 수 있는 바이너리가 포함되어 있는지 여부입니다:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
흥미로운 결과로는 다음이 포함됩니다:

- `NoNewPrivs: 0`
- `su`, `mount`, `passwd` 같은 setuid 헬퍼 또는 배포판별 admin 도구
- file capabilities가 네트워크 또는 파일시스템 권한을 부여하는 바이너리

실제 평가에서는 이러한 발견만으로 작동하는 escalation이 증명되지는 않지만, 다음에 테스트할 가치가 있는 바이너리를 정확히 식별해 줍니다.

### 전체 예제: In-Container Privilege Escalation Through setuid

이 컨트롤은 일반적으로 호스트 탈출(host escape)보다는 **in-container privilege escalation**을 방지합니다. 만약 `NoNewPrivs`가 `0`이고 setuid 헬퍼가 존재한다면, 이를 명시적으로 테스트하세요:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
알려진 setuid 바이너리가 존재하고 정상 동작한다면, privilege transition을 보존하는 방식으로 실행해 보세요:
```bash
/bin/su -c id 2>/dev/null
```
이것만으로는 컨테이너를 탈출하지는 못하지만, 컨테이너 내부의 낮은 권한 발판을 컨테이너 루트로 전환할 수 있으며, 이는 종종 마운트, 런타임 소켓 또는 커널 연동 인터페이스를 통해 이후 호스트 탈출의 전제 조건이 된다.

## Checks

이 검사들의 목적은 실행 시 권한 상승이 차단되어 있는지, 그리고 차단되어 있지 않을 경우 이미지에 여전히 영향을 줄 수 있는 헬퍼가 포함되어 있는지를 확인하는 것이다.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
What is interesting here:

- `NoNewPrivs: 1` is usually the safer result.
- `NoNewPrivs: 0` means setuid and file-cap based escalation paths remain relevant.
- A minimal image with few or no setuid/file-cap binaries gives an attacker fewer post-exploitation options even when `no_new_privs` is missing.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화되어 있지 않음 | 명시적으로 `--security-opt no-new-privileges=true`로 활성화됨 | 플래그를 생략하거나 `--privileged` |
| Podman | 기본적으로 활성화되어 있지 않음 | 명시적으로 `--security-opt no-new-privileges` 또는 동등한 보안 설정으로 활성화됨 | 옵션을 생략하거나 `--privileged` |
| Kubernetes | 워크로드 정책으로 제어됨 | `allowPrivilegeEscalation: false`가 이 효과를 활성화함; 많은 워크로드는 여전히 이를 활성화된 상태로 둠 | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes 워크로드 설정을 따름 | 보통 Pod 보안 컨텍스트에서 상속됨 | Kubernetes 행과 동일 |

이 보호 기능은 런타임이 지원하지 않아서가 아니라 단순히 아무도 활성화하지 않았기 때문에 종종 적용되어 있지 않습니다.
