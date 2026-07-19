# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security에서 가장 큰 혼란의 원인 중 하나는 서로 완전히 다른 여러 구성 요소가 흔히 하나의 단어로 뭉뚱그려진다는 점입니다. "Docker"는 image format, CLI, daemon, build system, runtime stack 또는 단순히 containers라는 개념 전반을 의미할 수 있습니다. Security 작업에서 이러한 모호성은 문제가 됩니다. 서로 다른 계층이 서로 다른 보호 기능을 담당하기 때문입니다. 잘못된 bind mount로 발생한 breakout은 low-level runtime bug로 발생한 breakout과 다르며, 둘 다 Kubernetes의 cluster policy 실수와는 다릅니다.

이 페이지에서는 ecosystem을 역할별로 구분하여, 이 섹션의 나머지 부분에서 특정 protection이나 weakness가 실제로 어느 위치에 존재하는지 정확히 설명할 수 있도록 합니다.

## OCI As The Common Language

Modern Linux container stack은 일련의 OCI specification을 사용하기 때문에 서로 연동되는 경우가 많습니다. **OCI Image Specification**은 image와 layer가 표현되는 방식을 설명합니다. **OCI Runtime Specification**은 namespace, mount, cgroup, security setting을 포함하여 runtime이 process를 실행해야 하는 방식을 설명합니다. **OCI Distribution Specification**은 registry가 content를 제공하는 방식을 표준화합니다.

이는 한 tool로 build한 container image를 다른 tool로 실행할 수 있는 경우가 많은 이유와, 여러 engine이 동일한 low-level runtime을 공유할 수 있는 이유를 설명합니다. 또한 서로 다른 product에서 security 동작이 비슷하게 보일 수 있는 이유도 설명합니다. 많은 product가 동일한 OCI runtime configuration을 구성한 뒤, 이를 동일한 소수의 runtime에 전달하기 때문입니다.

## Low-Level OCI Runtimes

Low-level runtime은 kernel boundary에 가장 가까운 구성 요소입니다. 실제로 namespace를 생성하고, cgroup 설정을 기록하고, capability와 seccomp filter를 적용한 다음, 마지막으로 container process에 `execve()`를 수행하는 부분입니다. 사람들이 "container isolation"을 mechanical level에서 논의할 때는 명시적으로 말하지 않더라도 대개 이 계층을 가리킵니다.

### `runc`

`runc`는 reference OCI runtime이며 여전히 가장 잘 알려진 implementation입니다. Docker, containerd 및 다양한 Kubernetes deployment에서 광범위하게 사용됩니다. 많은 public research와 exploitation material이 `runc`-style environment를 대상으로 하는 이유는 이러한 환경이 흔하고, `runc`가 많은 사람이 Linux container를 떠올릴 때 생각하는 baseline을 정의하기 때문입니다. 따라서 `runc`를 이해하면 classic container isolation에 대한 강력한 mental model을 얻을 수 있습니다.

### `crun`

`crun`은 C로 작성된 또 다른 OCI runtime으로, modern Podman environment에서 널리 사용됩니다. 뛰어난 cgroup v2 지원, 강력한 rootless 사용성, 낮은 overhead로 자주 좋은 평가를 받습니다. Security 관점에서 중요한 점은 다른 language로 작성되었다는 것이 아니라, 동일한 역할을 수행한다는 것입니다. 즉, OCI configuration을 kernel 아래에서 실행되는 process tree로 변환하는 구성 요소입니다. Rootless Podman workflow가 더 안전하게 느껴지는 경우가 많은 이유는 `crun`이 모든 문제를 마법처럼 해결하기 때문이 아니라, 이를 둘러싼 전체 stack이 user namespace와 least privilege를 더 강하게 지향하는 경향이 있기 때문입니다.

### `runsc` From gVisor

`runsc`는 gVisor에서 사용하는 runtime입니다. 여기서는 boundary의 의미가 크게 달라집니다. 일반적인 방식으로 대부분의 syscall을 host kernel에 직접 전달하는 대신, gVisor는 Linux interface의 상당 부분을 emulate하거나 mediate하는 userspace kernel layer를 삽입합니다. 그 결과는 몇 가지 flag가 추가된 일반적인 `runc` container가 아니라, host-kernel attack surface를 줄이는 것을 목적으로 하는 다른 sandbox design입니다. Compatibility와 performance tradeoff도 이러한 design의 일부이므로, `runsc`를 사용하는 environment는 일반적인 OCI runtime environment와 다르게 문서화해야 합니다.

### `kata-runtime`

Kata Containers는 workload를 lightweight virtual machine 내부에서 실행하여 boundary를 더욱 확장합니다. 관리 측면에서는 여전히 container deployment처럼 보일 수 있고 orchestration layer도 여전히 이를 그렇게 취급할 수 있지만, 실제 isolation boundary는 classic host-kernel-shared container보다는 virtualization에 가깝습니다. 따라서 Kata는 container 중심 workflow를 포기하지 않고 더 강력한 tenant isolation을 원할 때 유용합니다.

## Engines And Container Managers

Low-level runtime이 kernel과 직접 통신하는 구성 요소라면, engine 또는 manager는 일반적으로 사용자와 operator가 상호작용하는 구성 요소입니다. Image pull, metadata, log, network, volume, lifecycle operation 및 API exposure를 처리합니다. 이 계층은 매우 중요합니다. 실제 compromise의 상당수가 여기서 발생하기 때문입니다. Low-level runtime 자체가 완전히 정상이어도 runtime socket이나 daemon API에 대한 접근은 host compromise와 동등할 수 있습니다.

### Docker Engine

Docker Engine은 개발자에게 가장 잘 알려진 container platform이며, container vocabulary가 Docker 중심으로 형성된 이유 중 하나입니다. 일반적인 경로는 `docker` CLI에서 `dockerd`로 이어지고, `dockerd`는 다시 `containerd` 및 OCI runtime과 같은 lower-level component를 조정합니다. 역사적으로 Docker deployment는 **rootful**인 경우가 많았으며, 따라서 Docker socket에 대한 접근은 매우 강력한 primitive였습니다. 이것이 많은 실전 privilege-escalation material이 `docker.sock`에 집중하는 이유입니다. Process가 `dockerd`에 privileged container를 생성하거나, host path를 mount하거나, host namespace에 join하도록 요청할 수 있다면 kernel exploit이 전혀 필요하지 않을 수 있습니다.

### Podman

Podman은 보다 daemonless한 model을 중심으로 설계되었습니다. 운영 측면에서 이는 container가 하나의 장시간 실행되는 privileged daemon이 아니라 standard Linux mechanism을 통해 관리되는 process일 뿐이라는 개념을 강화합니다. 또한 Podman은 많은 사람이 처음 배운 classic Docker deployment보다 훨씬 강력한 **rootless** story를 제공합니다. 그렇다고 Podman이 자동으로 안전해지는 것은 아니지만, 특히 user namespace, SELinux 및 `crun`과 결합될 때 기본 risk profile이 크게 달라집니다.

### containerd

containerd는 많은 modern stack에서 핵심 runtime management component입니다. Docker에서 사용되며, 주요 Kubernetes runtime backend 중 하나이기도 합니다. Powerful API를 노출하고, image와 snapshot을 관리하며, 최종 process 생성을 low-level runtime에 위임합니다. containerd에 관한 security 논의에서는 containerd socket 또는 `ctr`/`nerdctl` functionality에 대한 접근이 Docker API에 대한 접근만큼 위험할 수 있다는 점을 강조해야 합니다. Interface와 workflow가 덜 "developer friendly"하게 느껴지더라도 마찬가지입니다.

### CRI-O

CRI-O는 Docker Engine보다 범위가 좁습니다. General-purpose developer platform이 아니라 Kubernetes Container Runtime Interface를 깔끔하게 구현하는 것을 중심으로 제작되었습니다. 따라서 Kubernetes distribution과 OpenShift 같은 SELinux 중심 ecosystem에서 특히 흔합니다. Security 관점에서 이러한 좁은 범위는 개념적 혼란을 줄여주므로 유용합니다. CRI-O는 여러 기능을 포함한 platform이라기보다 "Kubernetes용으로 container를 실행하는" 계층의 구성 요소에 가깝습니다.

### Incus, LXD, And LXC

Incus/LXD/LXC system은 **system container**로 자주 사용되므로 Docker-style application container와 구분할 필요가 있습니다. System container는 일반적으로 더 완전한 userspace, 장시간 실행되는 service, 풍부한 device exposure 및 더욱 광범위한 host integration을 갖춘 lightweight machine처럼 동작할 것으로 기대됩니다. Isolation mechanism은 여전히 kernel primitive이지만 운영상의 기대가 다릅니다. 따라서 이 환경의 misconfiguration은 흔히 "잘못된 app-container default"라기보다 lightweight virtualization 또는 host delegation의 실수에 가깝습니다.

### systemd-nspawn

systemd-nspawn은 systemd-native이며 testing, debugging 및 OS와 유사한 environment 실행에 매우 유용하기 때문에 흥미로운 위치를 차지합니다. Cloud-native production runtime으로 가장 많이 사용되지는 않지만, lab과 distro 중심 environment에서 충분히 자주 등장하므로 언급할 가치가 있습니다. Security analysis 관점에서 이는 "container"라는 개념이 여러 ecosystem과 운영 방식에 걸쳐 있다는 또 하나의 예시입니다.

### Apptainer / Singularity

Apptainer(구 Singularity)는 research 및 HPC environment에서 흔히 사용됩니다. 이들의 trust assumption, user workflow 및 execution model은 Docker/Kubernetes 중심 stack과 중요한 차이가 있습니다. 특히 이러한 environment에서는 사용자에게 광범위한 privileged container-management power를 부여하지 않고도 packaged workload를 실행하게 하는 것이 매우 중요할 수 있습니다. 모든 container environment가 기본적으로 "server에서 실행되는 Docker"라고 가정하는 reviewer는 이러한 deployment를 크게 잘못 이해하게 됩니다.

## Build-Time Tooling

많은 security 논의가 run time만 다루지만, build-time tooling도 중요합니다. 이것이 image content, build secret exposure 및 최종 artifact에 얼마나 많은 trusted context가 포함되는지를 결정하기 때문입니다.

**BuildKit**과 `docker buildx`는 caching, secret mounting, SSH forwarding 및 multi-platform build와 같은 기능을 지원하는 modern build backend입니다. 이러한 기능은 유용하지만, security 관점에서는 secret이 image layer로 leak되거나 지나치게 광범위한 build context가 포함되어서는 안 되는 file을 노출할 수 있는 지점도 만듭니다. **Buildah**는 OCI-native ecosystem, 특히 Podman 주변에서 유사한 역할을 수행하며, **Kaniko**는 build pipeline에 privileged Docker daemon을 부여하지 않으려는 CI environment에서 자주 사용됩니다.

핵심 교훈은 image creation과 image execution이 서로 다른 phase라는 점입니다. 하지만 취약한 build pipeline은 container가 실행되기 훨씬 전부터 취약한 runtime posture를 만들 수 있습니다.

## Orchestration Is Another Layer, Not The Runtime

Kubernetes를 runtime 자체와 동일하게 생각해서는 안 됩니다. Kubernetes는 orchestrator입니다. Pod를 schedule하고, desired state를 저장하며, workload configuration을 통해 security policy를 표현합니다. 이후 kubelet은 containerd 또는 CRI-O 같은 CRI implementation과 통신하고, 해당 implementation은 다시 `runc`, `crun`, `runsc` 또는 `kata-runtime` 같은 low-level runtime을 호출합니다.

이러한 분리는 중요합니다. 많은 사람이 실제로는 node runtime이 적용한 protection을 "Kubernetes"의 기능으로 잘못 생각하거나, Pod spec에서 비롯된 동작을 "containerd default"의 문제로 오해하기 때문입니다. 실제 최종 security posture는 여러 요소의 조합입니다. Orchestrator가 무언가를 요청하고, runtime stack이 이를 변환하며, 마지막으로 kernel이 이를 enforce합니다.

## Why Runtime Identification Matters During Assessment

Engine과 runtime을 초기에 식별하면 이후의 여러 관찰을 더 쉽게 해석할 수 있습니다. Rootless Podman container라면 user namespace가 관련되어 있을 가능성이 높습니다. Workload에 Docker socket이 mount되어 있다면 API-driven privilege escalation이 현실적인 경로일 수 있습니다. CRI-O/OpenShift node라면 즉시 SELinux label과 restricted workload policy를 고려해야 합니다. gVisor 또는 Kata environment라면 classic `runc` breakout PoC가 동일하게 동작할 것이라고 가정하는 데 더 신중해야 합니다.

따라서 container assessment의 첫 단계 중 하나는 항상 다음 두 가지 간단한 질문에 답하는 것이어야 합니다. **어떤 component가 container를 관리하는가**, 그리고 **어떤 runtime이 실제로 process를 실행했는가**. 이 답이 명확해지면 나머지 environment도 일반적으로 훨씬 쉽게 분석할 수 있습니다.

## Runtime Vulnerabilities

모든 container escape가 operator misconfiguration에서 발생하는 것은 아닙니다. 때로는 runtime 자체가 vulnerable component입니다. 이는 신중하게 구성된 것처럼 보이는 configuration으로 workload를 실행하더라도 low-level runtime flaw를 통해 노출될 수 있다는 의미입니다.

대표적인 예는 `runc`의 **CVE-2019-5736**입니다. 악성 container가 host의 `runc` binary를 overwrite한 뒤, 이후의 `docker exec` 또는 이와 유사한 runtime invocation이 attacker-controlled code를 실행하도록 유도할 수 있었습니다. 이 exploit path는 단순한 bind-mount 또는 capability 실수와 매우 다릅니다. exec handling 과정에서 runtime이 container process space에 재진입하는 방식을 악용하기 때문입니다.

Red-team 관점에서 minimal reproduction workflow는 다음과 같습니다:
```bash
go build main.go
./main
```
그런 다음, host에서:
```bash
docker exec -it <container-name> /bin/sh
```
핵심 교훈은 정확한 과거 exploit 구현이 아니라 assessment에 대한 시사점입니다. runtime 버전이 취약하다면, 눈에 보이는 컨테이너 설정이 명백하게 취약해 보이지 않더라도 일반적인 컨테이너 내부 code execution만으로 host를 compromise하기에 충분할 수 있습니다.

`runc`의 `CVE-2024-21626`, BuildKit mount race, containerd parsing bug와 같은 최근 runtime CVE는 같은 점을 다시 강조합니다. runtime 버전과 patch level은 단순한 유지 관리 정보가 아니라 security boundary의 일부입니다.
{{#include ../../../banners/hacktricks-training.md}}
