# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

실용적으로 컨테이너를 정의하면 다음과 같습니다: 컨테이너는 특정 OCI-style 설정 하에서 시작되어 제어된 파일시스템, 제한된 커널 자원 집합, 그리고 제한된 권한 모델을 보도록 구성된 일반적인 Linux 프로세스 트리입니다. 프로세스는 자신이 PID 1이라고 믿을 수 있고, 자체 네트워크 스택이 있다고 믿을 수 있으며, 자신의 호스트명과 IPC 자원을 소유한다고 생각할 수 있고, 심지어 자신의 user namespace 안에서 root로 실행될 수도 있습니다. 그러나 내부적으로는 여전히 커널이 다른 프로세스들처럼 스케줄하는 호스트 프로세스입니다.

이것이 컨테이너 보안이 실질적으로 그 환상이 어떻게 구성되는지 그리고 그것이 어떻게 깨지는지를 연구하는 이유입니다. mount namespace가 약하면 프로세스는 호스트 파일시스템을 볼 수 있습니다. user namespace가 없거나 비활성화되어 있으면 컨테이너 내부의 root가 호스트의 root와 너무 가깝게 매핑될 수 있습니다. seccomp가 제한되지 않았고 capability 집합이 너무 넓으면 프로세스는 도달하면 안 될 syscall과 권한 있는 커널 기능에 접근할 수 있습니다. runtime socket이 컨테이너 안에 마운트되어 있다면 컨테이너는 커널 탈출 없이도 runtime에게 더 강력한 sibling 컨테이너를 실행시키거나 호스트 루트 파일시스템을 직접 마운트하도록 요청할 수 있습니다.

## How Containers Differ From Virtual Machines

VM은 보통 자체 커널과 하드웨어 추상 경계를 가집니다. 이는 게스트 커널이 크래시, 패닉, 혹은 익스플로잇 되더라도 자동으로 호스트 커널에 대한 직접적인 제어를 의미하지 않는다는 뜻입니다. 컨테이너에서는 워크로드가 별도의 커널을 얻지 않습니다. 대신 동일한 호스트 커널에 대해 신중하게 필터링되고 namespaced된 뷰를 받습니다. 결과적으로 컨테이너는 보통 더 가볍고, 시작이 빠르며, 한 머신에 더 밀집해서 배포하기 쉬우며, 단명하는 애플리케이션 배포에 더 적합합니다. 대가는 격리 경계가 호스트와 runtime 설정의 정확성에 훨씬 더 직접적으로 의존한다는 점입니다.

이것이 컨테이너가 "취약하다"거나 VM이 "안전하다"는 의미는 아닙니다. 보안 모델이 다르다는 의미입니다. rootless 실행, user namespaces, 기본 seccomp, 엄격한 capability 집합, 호스트 namespace 비공유, 강한 SELinux 또는 AppArmor 강제 적용 등으로 잘 구성된 컨테이너 스택은 매우 견고할 수 있습니다. 반대로 `--privileged`로 시작된 컨테이너, 호스트 PID/네트워크 공유, Docker socket이 내부에 마운트된 경우, 그리고 `/`의 쓰기 가능한 bind mount를 가진 컨테이너는 안전하게 격리된 애플리케이션 샌드박스라기보다 호스트 root 접근에 기능적으로 훨씬 가깝습니다. 차이는 어떤 레이어가 활성화되었는지 또는 비활성화되었는지에서 옵니다.

현실 환경에서는 중간 형태도 점점 더 자주 등장하므로 독자가 이를 이해하는 것이 중요합니다. **Sandboxed container runtimes**인 **gVisor**와 **Kata Containers**는 고의적으로 고전적인 `runc` 컨테이너를 넘어서 경계를 강화합니다. gVisor는 워크로드와 많은 호스트 커널 인터페이스 사이에 userspace 커널 레이어를 배치하고, Kata는 워크로드를 경량 VM 안에서 실행합니다. 이들은 여전히 컨테이너 생태계와 오케스트레이션 워크플로를 통해 사용되지만, 보안 속성은 평범한 OCI 런타임과 다르며 모든 것이 동일하게 동작하는 "일반 Docker containers"와 정신적으로 동일시해서는 안 됩니다.

## The Container Stack: Several Layers, Not One

누군가가 "이 컨테이너는 취약하다"고 말할 때, 유용한 후속 질문은: **어떤 레이어가 그것을 취약하게 만들었는가?** 입니다. 컨테이너화된 워크로드는 보통 여러 구성 요소가 함께 작동한 결과입니다.

상단에는 BuildKit, Buildah, 또는 Kaniko와 같은 **image build layer**가 있어 OCI 이미지와 메타데이터를 생성하는 경우가 많습니다. 저수준 runtime 위에는 Docker Engine, Podman, containerd, CRI-O, Incus, 또는 systemd-nspawn과 같은 **engine or manager**가 있을 수 있습니다. 클러스터 환경에서는 Kubernetes와 같은 **orchestrator**가 워크로드 구성으로 요청된 보안 자세를 결정할 수도 있습니다. 마지막으로 **kernel**은 실제로 namespaces, cgroups, seccomp, 그리고 MAC 정책을 시행하는 주체입니다.

이 레이어드 모델은 기본값을 이해하는 데 중요합니다. 제한은 Kubernetes에서 요청될 수 있고, containerd나 CRI-O를 통해 CRI로 변환되며, runtime wrapper에 의해 OCI spec으로 변환되고, 그 다음에 `runc`, `crun`, `runsc` 또는 다른 런타임에 의해 커널에 대해 적용될 수 있습니다. 환경 간 기본값이 다를 때는 보통 이 레이어들 중 하나가 최종 구성을 변경했기 때문입니다. 동일한 메커니즘은 따라서 Docker나 Podman에서는 CLI 플래그로, Kubernetes에서는 Pod 또는 `securityContext` 필드로, 그리고 저수준 런타임 스택에서는 워크로드를 위해 생성된 OCI 구성으로 나타날 수 있습니다. 그러므로 이 섹션의 CLI 예제들은 모든 도구에서 보편적으로 지원되는 플래그가 아니라 일반적인 컨테이너 개념에 대한 **runtime-specific syntax**로 읽어야 합니다.

## The Real Container Security Boundary

실무에서 컨테이너 보안은 하나의 완벽한 통제에서 나오지 않고 **중첩된 제어들(overlapping controls)** 에서 나옵니다. Namespaces는 가시성을 격리합니다. cgroups는 자원 사용을 관리하고 제한합니다. Capabilities는 권한처럼 보이는 프로세스가 실제로 무엇을 할 수 있는지를 줄입니다. seccomp는 위험한 syscalls가 커널에 도달하기 전에 차단합니다. AppArmor와 SELinux는 일반 DAC 검사 위에 Mandatory Access Control을 추가합니다. `no_new_privs`, masked procfs paths, 그리고 read-only system paths는 일반적인 권한 상승과 proc/sys 남용 체인을 더 어렵게 만듭니다. runtime 자체도 중요합니다. runtime은 어떻게 마운트, 소켓, 라벨, namespace 조인이 생성되는지를 결정합니다.

이것이 많은 컨테이너 보안 문서가 반복적으로 보이는 이유입니다. 동일한 탈출 체인은 종종 여러 메커니즘에 동시에 의존합니다. 예를 들어, 쓰기 가능한 호스트 bind mount는 나쁘지만, 컨테이너가 호스트의 실제 root로 실행되고 `CAP_SYS_ADMIN`을 가지며 seccomp에 의해 제한되지 않고 SELinux나 AppArmor로 제한되지 않는다면 훨씬 더 위험해집니다. 마찬가지로 호스트 PID 공유는 심각한 노출이지만, 그것이 공격자에게 엄청나게 유용해지는 것은 `CAP_SYS_PTRACE`, 약한 procfs 보호, 또는 `nsenter` 같은 namespace-entry 도구와 결합될 때입니다. 따라서 이 주제를 문서화하는 올바른 방법은 동일한 공격을 모든 페이지에서 반복하는 것이 아니라 각 레이어가 최종 경계에 무엇을 기여하는지 설명하는 것입니다.

## How To Read This Section

이 섹션은 가장 일반적인 개념에서 가장 구체적인 것으로 조직되어 있습니다.

먼저 runtime 및 생태계 개요부터 시작하십시오:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

그런 다음 공격자가 실제로 kernel escape를 시도해야 하는지 여부를 자주 결정하는 제어 평면과 공급망 표면을 검토하십시오:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

그다음 보호 모델로 이동하십시오:

{{#ref}}
protections/
{{#endref}}

namespace 페이지들은 커널 격리 원시(primitives)를 개별적으로 설명합니다:

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths, 그리고 read-only system paths에 관한 페이지들은 보통 namespace 위에 레이어로 적용되는 메커니즘을 설명합니다:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## A Good First Enumeration Mindset

컨테이너화된 대상 평가 시, 유명한 escape PoC로 바로 뛰어들기보다 작은 집합의 정확한 기술적 질문들을 던지는 것이 훨씬 유용합니다. 먼저 **stack**을 식별하세요: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer 또는 더 특화된 무언가인지. 그런 다음 **runtime**을 식별하세요: `runc`, `crun`, `runsc`, `kata-runtime` 또는 다른 OCI-compatible 구현인지. 그 다음 환경이 **rootful 또는 rootless**인지, **user namespaces**가 활성화되어 있는지, 어떤 **host namespaces**가 공유되는지, 어떤 **capabilities**가 남아 있는지, **seccomp**가 활성화되어 있는지, 실제로 **MAC 정책**이 강제되는지, **위험한 마운트나 소켓**이 존재하는지, 그리고 프로세스가 컨테이너 runtime API와 상호작용할 수 있는지를 확인하세요.

이 답변들이 실제 보안 자세에 대해 베이스 이미지 이름보다 훨씬 더 많은 것을 알려줍니다. 많은 평가에서 최종 컨테이너 구성을 이해하는 것만으로도 단 한 개의 애플리케이션 파일을 읽기 전에 어떤 breakout 계열이 가능할지 예측할 수 있습니다.

## Coverage

이 섹션은 컨테이너 지향 조직 하에 있는 오래된 Docker 중심 자료를 다룹니다: runtime 및 daemon 노출, authorization plugins, 이미지 신뢰 및 빌드 시크릿, 민감한 호스트 마운트, distroless 워크로드, privileged containers, 그리고 컨테이너 실행 주위에 일반적으로 레이어되는 커널 보호들.
{{#include ../../../banners/hacktricks-training.md}}
