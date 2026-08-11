# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## 실제 Container란 무엇인가

Container를 실용적으로 정의하면 다음과 같습니다. Container는 특정 OCI 스타일 configuration으로 시작되어 제어된 filesystem, 제어된 kernel resource 집합, 제한된 privilege model을 보게 되는 **일반적인 Linux process tree**입니다. 해당 process는 자신이 PID 1이라고 생각할 수 있고, 자체 network stack을 가지고 있다고 생각할 수 있으며, 자체 hostname과 IPC resource를 소유한다고 생각할 수 있습니다. 심지어 자체 user namespace 안에서 root로 실행될 수도 있습니다. 하지만 내부적으로는 여전히 kernel이 다른 process와 동일한 방식으로 schedule하는 host process입니다.

이것이 바로 container security가 실제로는 이러한 illusion이 어떻게 구성되고 어떻게 실패하는지를 연구하는 분야인 이유입니다. mount namespace가 취약하면 process가 host filesystem을 볼 수 있습니다. user namespace가 없거나 비활성화되어 있으면 container 내부의 root가 host의 root에 지나치게 가깝게 매핑될 수 있습니다. seccomp가 unconfined 상태이고 capability set이 너무 광범위하면 process가 접근해서는 안 되는 syscall과 privileged kernel feature에 접근할 수 있습니다. runtime socket이 container 내부에 mount되어 있으면 container는 kernel breakout이 전혀 필요하지 않을 수 있습니다. runtime에 더 강력한 sibling container를 실행하도록 요청하거나 host root filesystem을 직접 mount할 수 있기 때문입니다.

## Container와 Virtual Machine의 차이

VM은 일반적으로 자체 kernel과 hardware abstraction boundary를 가집니다. 따라서 guest kernel이 crash, panic되거나 exploit되더라도 host kernel을 직접 제어할 수 있다는 의미로 자동 연결되지는 않습니다. Container에서는 workload가 별도의 kernel을 제공받지 않습니다. 대신 host가 사용하는 동일한 kernel에 대해 신중하게 filtering되고 namespaced된 view를 제공받습니다. 그 결과 container는 일반적으로 더 가볍고, 더 빠르게 시작되며, 한 machine에 더 밀도 높게 배치하기 쉽고, 단기 application deployment에 더 적합합니다. 그 대가는 isolation boundary가 올바른 host 및 runtime configuration에 훨씬 더 직접적으로 의존한다는 것입니다.

이는 container가 "insecure"하고 VM이 "secure"하다는 의미가 아닙니다. security model이 다르다는 의미입니다. rootless execution, user namespace, default seccomp, strict capability set, host namespace sharing 비활성화, 강력한 SELinux 또는 AppArmor enforcement를 사용하는 잘 구성된 container stack은 매우 견고할 수 있습니다. 반대로 `--privileged`, host PID/network sharing, 내부에 mount된 Docker socket, `/`에 대한 writable bind mount로 시작된 container는 안전하게 격리된 application sandbox라기보다 host root access에 기능적으로 훨씬 가깝습니다. 차이는 활성화되거나 비활성화된 layer에서 발생합니다.

또한 독자가 이해해야 할 중간 지점도 있습니다. 실제 environment에서 점점 더 자주 등장하기 때문입니다. **Sandboxed container runtime**인 **gVisor**와 **Kata Containers**는 classic `runc` container보다 boundary를 의도적으로 강화합니다. gVisor는 workload와 여러 host kernel interface 사이에 userspace kernel layer를 배치하고, Kata는 workload를 lightweight virtual machine 내부에서 실행합니다. 이들은 여전히 container ecosystem과 orchestration workflow를 통해 사용되지만, security property는 일반 OCI runtime과 다르며 모든 것이 동일하게 동작하는 것처럼 "normal Docker container"와 정신적으로 같은 그룹으로 묶어서는 안 됩니다.

## Container Stack: 하나가 아닌 여러 Layer

누군가 "이 container는 insecure하다"고 말했을 때 유용한 후속 질문은 다음과 같습니다. **어떤 layer가 이를 insecure하게 만들었는가?** Containerized workload는 일반적으로 여러 component가 함께 동작한 결과입니다.

상위에는 OCI image와 metadata를 생성하는 BuildKit, Buildah 또는 Kaniko와 같은 **image build layer**가 있는 경우가 많습니다. Low-level runtime 위에는 Docker Engine, Podman, containerd, CRI-O, Incus 또는 systemd-nspawn과 같은 **engine 또는 manager**가 있을 수 있습니다. Cluster environment에는 workload configuration을 통해 요청된 security posture를 결정하는 Kubernetes와 같은 **orchestrator**도 있을 수 있습니다. 마지막으로 **kernel**이 실제로 namespace, cgroup, seccomp 및 MAC policy를 enforce합니다.

이 layered model은 default를 이해하는 데 중요합니다. Kubernetes가 restriction을 요청하고, containerd 또는 CRI-O가 이를 CRI를 통해 변환하며, runtime wrapper가 이를 OCI spec으로 변환한 다음, `runc`, `crun`, `runsc` 또는 다른 runtime이 kernel에 대해 workload에 적용할 수 있습니다. Environment마다 default가 다른 경우, 이는 이러한 layer 중 하나가 최종 configuration을 변경했기 때문인 경우가 많습니다. 따라서 동일한 mechanism이 Docker 또는 Podman에서는 CLI flag로, Kubernetes에서는 Pod 또는 `securityContext` field로, lower-level runtime stack에서는 workload를 위해 생성된 OCI configuration으로 나타날 수 있습니다. 이러한 이유로 이 section의 CLI example은 모든 tool이 지원하는 universal flag가 아니라 **일반적인 container concept를 위한 runtime-specific syntax**로 읽어야 합니다.

## 실제 Container Security Boundary

실제로 container security는 하나의 완벽한 control이 아니라 **서로 겹치는 control**에서 비롯됩니다. Namespace는 visibility를 격리합니다. cgroup은 resource usage를 관리하고 제한합니다. Capability는 privileged-looking process가 실제로 수행할 수 있는 작업을 줄입니다. seccomp는 위험한 syscall이 kernel에 도달하기 전에 차단합니다. AppArmor와 SELinux는 일반적인 DAC check 위에 Mandatory Access Control을 추가합니다. `no_new_privs`, masked procfs path 및 read-only system path는 일반적인 privilege 및 proc/sys abuse chain을 더 어렵게 만듭니다. Mount, socket, label 및 namespace join이 생성되는 방식을 결정하므로 runtime 자체도 중요합니다.

이것이 많은 container security documentation이 반복적으로 보이는 이유입니다. 동일한 escape chain이 여러 mechanism에 동시에 의존하는 경우가 많습니다. 예를 들어 writable host bind mount도 위험하지만, container가 host에서 실제 root로 실행되고 `CAP_SYS_ADMIN`을 보유하며 seccomp가 unconfined이고 SELinux 또는 AppArmor의 제한도 받지 않으면 훨씬 더 위험해집니다. 마찬가지로 host PID sharing은 심각한 exposure이지만, `CAP_SYS_PTRACE`, 취약한 procfs protection 또는 `nsenter`와 같은 namespace-entry tool과 결합되면 attacker에게 훨씬 더 유용해집니다. 따라서 이 주제를 document하는 올바른 방법은 모든 page에서 동일한 attack을 반복하는 것이 아니라, 각 layer가 최종 boundary에 무엇을 기여하는지 설명하는 것입니다.

## 이 Section을 읽는 방법

이 section은 가장 일반적인 concept에서 가장 구체적인 concept 순서로 구성되어 있습니다.

Runtime 및 ecosystem overview부터 시작합니다.

{{#ref}}
runtimes-and-engines.md
{{#endref}}

그런 다음 attacker가 kernel escape를 필요로 하는지 여부를 결정하는 경우가 많은 control plane과 supply-chain surface를 검토합니다.

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

그런 다음 protection model로 이동합니다.

{{#ref}}
protections/
{{#endref}}

Namespace page는 kernel isolation primitive를 개별적으로 설명합니다.

{{#ref}}
protections/namespaces/
{{#endref}}

cgroup, capability, seccomp, AppArmor, SELinux, `no_new_privs`, masked path 및 read-only system path에 대한 page는 일반적으로 namespace 위에 layer로 적용되는 mechanism을 설명합니다.

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

## 좋은 초기 Enumeration 관점

Containerized target을 assess할 때는 유명한 escape PoC로 바로 넘어가기보다 소수의 정확한 technical question을 묻는 것이 훨씬 유용합니다. 먼저 **stack**을 식별합니다. Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer 또는 더 specialized된 무언가일 수 있습니다. 그런 다음 **runtime**을 식별합니다. `runc`, `crun`, `runsc`, `kata-runtime` 또는 다른 OCI-compatible implementation일 수 있습니다. 이후 environment가 **rootful인지 rootless인지**, **user namespace**가 활성화되어 있는지, **host namespace**가 shared되어 있는지, 어떤 **capability**가 남아 있는지, **seccomp**가 활성화되어 있는지, **MAC policy**가 실제로 enforcing 중인지, **dangerous mount 또는 socket**이 존재하는지, process가 container runtime API와 상호작용할 수 있는지를 확인합니다.

이러한 답변은 base image name보다 실제 security posture에 대해 훨씬 더 많은 정보를 제공합니다. 많은 assessment에서는 단 하나의 application file을 읽기 전에도 최종 container configuration을 이해하는 것만으로 발생 가능성이 높은 breakout family를 예측할 수 있습니다.

## Coverage

이 section은 container 중심의 organization 아래에 있는 기존 Docker-focused material을 다룹니다. Runtime 및 daemon exposure, authorization plugin, image trust와 build secret, sensitive host mount, distroless workload, privileged container, 그리고 일반적으로 container execution 주변에 layer로 적용되는 kernel protection을 포함합니다.

{{#include ../../../banners/hacktricks-training.md}}
