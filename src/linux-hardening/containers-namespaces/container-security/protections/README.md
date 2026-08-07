# Container 보호 기능 개요

{{#include ../../../../banners/hacktricks-training.md}}

Container hardening에서 가장 중요한 점은 "container security"라는 단일 control이 존재하지 않는다는 것입니다. 사람들이 container isolation이라고 부르는 것은 실제로 여러 Linux security 및 resource-management mechanism이 함께 작동한 결과입니다. 문서에서 이 중 하나만 설명하면 독자는 그 강도를 과대평가하기 쉽습니다. 반대로 모든 mechanism을 나열하기만 하고 서로 어떻게 상호작용하는지 설명하지 않으면 이름 목록만 남고 실제 모델은 이해하기 어렵습니다. 이 섹션은 이 두 가지 실수를 모두 피하려고 합니다.

이 모델의 중심에는 workload가 볼 수 있는 것을 격리하는 **namespaces**가 있습니다. namespaces는 process에 filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths 및 일부 clocks에 대한 private 또는 partially private view를 제공합니다. 하지만 namespaces만으로 process가 무엇을 할 수 있는지가 결정되지는 않습니다. 다음 layers가 필요한 이유가 여기에 있습니다.

**cgroups**는 resource usage를 관리합니다. cgroups는 mount 또는 PID namespaces와 동일한 의미의 주요 isolation boundary는 아니지만, memory, CPU, PIDs, I/O 및 device access를 제한하므로 운영 측면에서 매우 중요합니다. 또한 과거의 breakout technique이 writable cgroup feature를 악용했기 때문에 security 측면에서도 중요합니다. 특히 cgroup v1 환경에서 그러했습니다.

**Capabilities**는 기존의 모든 권한을 가진 root model을 더 작은 privilege unit으로 나눕니다. 많은 workload가 여전히 container 내부에서 UID 0으로 실행되기 때문에 이는 container에서 fundamental한 요소입니다. 따라서 질문은 단순히 "process가 root인가?"가 아니라 "어떤 capabilities가 유지되었고, 어떤 namespaces 내부에서, 어떤 seccomp 및 MAC restriction 아래에 있는가?"입니다. 그렇기 때문에 한 container의 root process는 상대적으로 제한될 수 있는 반면, 다른 container의 root process는 실제로 host root와 거의 구별되지 않을 수 있습니다.

**seccomp**는 syscall을 filter하여 workload에 노출되는 kernel attack surface를 줄입니다. 이는 `unshare`, `mount`, `keyctl` 또는 breakout chain에서 사용되는 기타 syscall과 같이 명백히 위험한 call을 차단하는 mechanism인 경우가 많습니다. process에 원래라면 특정 operation을 허용했을 capability가 있더라도, seccomp는 kernel이 해당 operation을 완전히 처리하기 전에 syscall path를 차단할 수 있습니다.

**AppArmor**와 **SELinux**는 일반적인 filesystem 및 privilege check 위에 Mandatory Access Control을 추가합니다. 이는 container에 필요 이상으로 많은 capabilities가 있는 경우에도 계속 적용되므로 특히 중요합니다. workload가 특정 action을 시도할 이론적 privilege를 가지고 있더라도, label 또는 profile이 관련 path, object 또는 operation에 대한 access를 금지하면 해당 action을 수행하지 못할 수 있습니다.

마지막으로 실제 attack에서 정기적으로 중요한 추가 hardening layer가 있습니다. `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems 및 신중하게 설정된 runtime defaults가 이에 해당하지만, 상대적으로 덜 주목받습니다. 이러한 mechanism은 특히 attacker가 code execution을 더 광범위한 privilege gain으로 전환하려 할 때 compromise의 "last mile"을 차단하는 경우가 많습니다.

이 폴더의 나머지 부분에서는 각 mechanism을 더 자세히 설명합니다. 여기에는 kernel primitive가 실제로 수행하는 작업, 이를 로컬에서 관찰하는 방법, 일반적인 runtime이 이를 사용하는 방식 및 operator가 실수로 이를 약화시키는 방법이 포함됩니다.

## 다음 읽을 내용

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

실제 escape 중 상당수는 workload에 mount된 host content에 따라서도 달라집니다. 따라서 core protection을 읽은 후에는 다음 내용을 계속 살펴보는 것이 좋습니다.

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
