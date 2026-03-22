# Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

컨테이너 하드닝에서 가장 중요한 개념은 "container security"라는 단일 통제가 존재하지 않는다는 점입니다. 사람들이 말하는 컨테이너 격리는 실제로 여러 Linux 보안 및 리소스 관리 메커니즘이 함께 작동한 결과입니다. 문서가 그들 중 하나만 설명하면 독자들은 그 힘을 과대평가하는 경향이 있습니다. 반대로 상호작용 방식을 설명하지 않고 모두 나열하면 이름 목록만 얻을 뿐 실질적인 모델은 얻지 못합니다. 이 섹션은 두 가지 실수를 모두 피하려고 합니다.

모델의 중심에는 워크로드가 볼 수 있는 것을 격리하는 **namespaces**가 있습니다. namespaces는 프로세스에 파일시스템 마운트, PIDs, 네트워킹, IPC 객체, 호스트이름, 사용자/그룹 매핑, cgroup 경로 및 일부 시계에 대한 전용 또는 부분 전용 뷰를 제공합니다. 그러나 namespaces만으로 프로세스가 무엇을 할 수 있는지가 결정되지는 않습니다. 다음 레이어들이 그 역할을 합니다.

**cgroups**는 리소스 사용을 관리합니다. mount나 PID namespace와 같은 의미의 격리 경계라기보다는 메모리, CPU, PID, I/O 및 장치 접근을 제약하기 때문에 운영상 중요합니다. 또한 역사적인 탈출 기법들이 특히 cgroup v1 환경에서 쓰기 가능한 cgroup 기능을 악용했기 때문에 보안적 관련성도 있습니다.

**Capabilities**는 예전의 모든 권한을 가진 root 모델을 더 작은 권한 단위로 분할합니다. 이는 많은 워크로드가 여전히 컨테이너 내부에서 UID 0으로 실행되기 때문에 컨테이너에서 근본적입니다. 따라서 질문은 단순히 "프로세스가 root인가?"가 아니라 "어떤 namespaces 내에서, 어떤 seccomp 및 MAC 제한 아래에서 어떤 capabilities가 남아있는가?"가 됩니다. 그래서 한 컨테이너의 root 프로세스는 비교적 제약될 수 있는 반면, 다른 컨테이너의 root 프로세스는 실제로 호스트 root와 거의 구별되지 않을 수 있습니다.

**seccomp**는 syscall을 필터링하여 워크로드에 노출되는 커널 공격 표면을 줄입니다. 이는 종종 `unshare`, `mount`, `keyctl` 또는 탈출 체인에서 사용되는 다른 syscall과 같은 명백히 위험한 호출을 차단하는 메커니즘입니다. 프로세스가 원래라면 어떤 작업을 허용하는 capability를 가지고 있더라도, seccomp는 커널이 그것을 완전히 처리하기 전에 syscall 경로를 차단할 수 있습니다.

**AppArmor**와 **SELinux**는 일반 파일시스템 및 권한 검사 위에 Mandatory Access Control을 추가합니다. 이는 컨테이너가 있어서는 안 될 추가 capabilities를 가졌을 때도 계속 중요합니다. 워크로드가 이론적으로 어떤 동작을 시도할 권한을 가질 수 있지만, 레이블이나 프로필이 관련 경로, 객체 또는 작업에 대한 접근을 금지하면 실제로 수행하지 못할 수 있습니다.

마지막으로, 덜 주목받지만 실제 공격에서 정기적으로 중요한 추가 하드닝 레이어들이 있습니다: `no_new_privs`, masked procfs paths, 읽기 전용 시스템 경로, 읽기 전용 루트 파일시스템, 그리고 신중한 런타임 기본값들. 이 메커니즘들은 특히 공격자가 코드 실행을 더 넓은 권한 획득으로 바꾸려 할 때 타협의 "마지막 단계"를 종종 막습니다.

이 폴더의 나머지 내용은 각 메커니즘이 실제로 어떤 커널 프리미티브를 수행하는지, 로컬에서 어떻게 관찰하는지, 일반 런타임이 어떻게 사용하는지, 운영자가 실수로 어떻게 약화시키는지를 더 자세히 설명합니다.

## Read Next

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

많은 실제 탈출은 또한 호스트에서 어떤 콘텐츠가 워크로드로 마운트되었는지에 달려 있으므로, 핵심 보호 장치를 읽은 후에는 다음을 계속 읽는 것이 유용합니다:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
