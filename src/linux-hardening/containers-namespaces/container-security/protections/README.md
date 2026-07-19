# Container Protections 개요

{{#include ../../../../banners/hacktricks-training.md}}

Container hardening에서 가장 중요한 점은 "container security"라는 단일 control이 존재하지 않는다는 것입니다. 사람들이 container isolation이라고 부르는 것은 실제로 여러 Linux security 및 resource-management 메커니즘이 함께 작동한 결과입니다. 문서에서 그중 하나만 설명하면 독자는 그 강도를 과대평가하기 쉽습니다. 반대로 모든 메커니즘을 나열하기만 하고 서로 어떻게 상호작용하는지 설명하지 않으면, 독자는 이름 목록만 얻게 되고 실제 모델은 이해하지 못합니다. 이 섹션은 이 두 가지 실수를 모두 피하려고 합니다.

이 모델의 중심에는 **namespaces**가 있으며, 이는 workload가 볼 수 있는 것을 격리합니다. namespaces는 process에 filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths 및 일부 clocks에 대한 전용 또는 부분적으로 전용된 관점을 제공합니다. 하지만 namespaces만으로 process가 무엇을 할 수 있는지가 결정되지는 않습니다. 다음 layer가 필요한 이유가 바로 여기에 있습니다.

**cgroups**는 resource usage를 관리합니다. cgroups는 mount 또는 PID namespaces와 동일한 의미의 주요 isolation boundary는 아니지만, memory, CPU, PIDs, I/O 및 device access를 제한하므로 운영 측면에서 매우 중요합니다. 또한 과거의 breakout techniques가 writable cgroup features를 악용했기 때문에 security 측면에서도 중요하며, 특히 cgroup v1 environments에서 그러했습니다.

**Capabilities**는 과거의 전능한 root model을 더 작은 privilege units로 분할합니다. 이는 많은 workload가 여전히 container 내부에서 UID 0으로 실행되기 때문에 containers에 근본적으로 중요합니다. 따라서 질문은 단순히 "process가 root인가?"가 아니라, "어떤 capabilities가 유지되었으며, 어떤 namespaces 내부에서, 어떤 seccomp 및 MAC restrictions 아래에 있는가?"입니다. 이것이 한 container의 root process는 비교적 제한될 수 있지만, 다른 container의 root process는 실제로 host root와 거의 구분되지 않을 수 있는 이유입니다.

**seccomp**는 syscalls를 filtering하여 workload가 노출되는 kernel attack surface를 줄입니다. 이는 `unshare`, `mount`, `keyctl` 또는 breakout chains에서 사용되는 기타 syscalls와 같이 명백히 위험한 calls를 차단하는 mechanism인 경우가 많습니다. process가 작업을 수행할 수 있도록 허용하는 capability를 가지고 있더라도, seccomp는 kernel이 이를 완전히 처리하기 전에 syscall path를 차단할 수 있습니다.

**AppArmor**와 **SELinux**는 일반적인 filesystem 및 privilege checks 위에 Mandatory Access Control을 추가합니다. 이는 container가 필요 이상으로 많은 capabilities를 가지고 있는 경우에도 계속 적용되므로 특히 중요합니다. workload가 어떤 action을 시도할 이론적 privilege를 보유하고 있더라도, 해당 label 또는 profile이 관련 path, object 또는 operation에 대한 access를 금지하면 실제로 수행하지 못할 수 있습니다.

마지막으로 실제 attacks에서 정기적으로 중요하지만 상대적으로 덜 주목받는 추가 hardening layers가 있습니다. 여기에는 `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems 및 신중한 runtime defaults가 포함됩니다. 이러한 mechanisms는 특히 attacker가 code execution을 더 넓은 privilege gain으로 전환하려 할 때 compromise의 "last mile"을 차단하는 경우가 많습니다.

이 폴더의 나머지 부분에서는 이러한 각 mechanisms를 더 자세히 설명합니다. 여기에는 kernel primitive가 실제로 수행하는 작업, 이를 locally observe하는 방법, 일반적인 runtimes가 이를 사용하는 방식 및 operators가 실수로 이를 약화시키는 방법이 포함됩니다.

## 다음에 읽을 내용

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

실제 escapes의 상당수는 workload에 어떤 host content가 mount되었는지에도 좌우되므로, 핵심 protections를 읽은 후에는 다음 내용으로 계속 진행하는 것이 유용합니다.

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
