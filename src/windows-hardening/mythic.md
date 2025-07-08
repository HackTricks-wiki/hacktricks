# Mythic

{{#include ../banners/hacktricks-training.md}}

## What is Mythic?

Mythic은 레드 팀을 위해 설계된 오픈 소스 모듈형 명령 및 제어(C2) 프레임워크입니다. 보안 전문가가 Windows, Linux 및 macOS를 포함한 다양한 운영 체제에서 여러 에이전트(페이로드)를 관리하고 배포할 수 있도록 합니다. Mythic은 에이전트를 관리하고, 명령을 실행하며, 결과를 수집하기 위한 사용자 친화적인 웹 인터페이스를 제공하여 통제된 환경에서 실제 공격을 시뮬레이션하는 강력한 도구입니다.

### Installation

To install Mythic, follow the instructions on the official **[Mythic repo](https://github.com/its-a-feature/Mythic)**.

### Agents

Mythic은 **손상된 시스템에서 작업을 수행하는 페이로드**인 여러 에이전트를 지원합니다. 각 에이전트는 특정 요구 사항에 맞게 조정할 수 있으며, 다양한 운영 체제에서 실행될 수 있습니다.

기본적으로 Mythic에는 설치된 에이전트가 없습니다. 그러나 [**https://github.com/MythicAgents**](https://github.com/MythicAgents)에서 일부 오픈 소스 에이전트를 제공합니다.

To install an agent from that repo you just need to run:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/apfell
```
새로운 에이전트를 이전 명령으로 추가할 수 있으며, Mythic이 이미 실행 중인 경우에도 가능합니다.

### C2 프로필

Mythic의 C2 프로필은 **에이전트가 Mythic 서버와 통신하는 방법**을 정의합니다. 이들은 통신 프로토콜, 암호화 방법 및 기타 설정을 지정합니다. Mythic 웹 인터페이스를 통해 C2 프로필을 생성하고 관리할 수 있습니다.

기본적으로 Mythic은 프로필 없이 설치되지만, 다음 명령을 실행하여 리포에서 일부 프로필을 다운로드할 수 있습니다: [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles)
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo는 SpecterOps 교육 제공을 위해 설계된 4.0 .NET Framework를 사용하여 C#로 작성된 Windows 에이전트입니다.

설치하려면:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
이 에이전트는 Cobalt Strike의 Beacon과 매우 유사한 많은 명령어를 가지고 있으며 몇 가지 추가 기능이 있습니다. 그 중에서 지원하는 기능은 다음과 같습니다:

### 일반 작업

- `cat`: 파일의 내용을 출력합니다.
- `cd`: 현재 작업 디렉토리를 변경합니다.
- `cp`: 한 위치에서 다른 위치로 파일을 복사합니다.
- `ls`: 현재 디렉토리 또는 지정된 경로의 파일 및 디렉토리를 나열합니다.
- `pwd`: 현재 작업 디렉토리를 출력합니다.
- `ps`: 대상 시스템에서 실행 중인 프로세스를 나열합니다 (추가 정보 포함).
- `download`: 대상 시스템에서 로컬 머신으로 파일을 다운로드합니다.
- `upload`: 로컬 머신에서 대상 시스템으로 파일을 업로드합니다.
- `reg_query`: 대상 시스템의 레지스트리 키 및 값을 쿼리합니다.
- `reg_write_value`: 지정된 레지스트리 키에 새 값을 씁니다.
- `sleep`: 에이전트의 수면 간격을 변경하여 Mythic 서버와 얼마나 자주 체크인하는지를 결정합니다.
- 기타 여러 가지, 전체 명령어 목록을 보려면 `help`를 사용하세요.

### 권한 상승

- `getprivs`: 현재 스레드 토큰에서 가능한 많은 권한을 활성화합니다.
- `getsystem`: winlogon에 핸들을 열고 토큰을 복제하여 효과적으로 SYSTEM 수준으로 권한을 상승시킵니다.
- `make_token`: 새로운 로그온 세션을 생성하고 이를 에이전트에 적용하여 다른 사용자를 가장할 수 있게 합니다.
- `steal_token`: 다른 프로세스에서 기본 토큰을 훔쳐 에이전트가 해당 프로세스의 사용자를 가장할 수 있게 합니다.
- `pth`: Pass-the-Hash 공격으로, 에이전트가 평문 비밀번호 없이 NTLM 해시를 사용하여 사용자로 인증할 수 있게 합니다.
- `mimikatz`: Mimikatz 명령을 실행하여 메모리 또는 SAM 데이터베이스에서 자격 증명, 해시 및 기타 민감한 정보를 추출합니다.
- `rev2self`: 에이전트의 토큰을 기본 토큰으로 되돌려 원래 수준으로 권한을 낮춥니다.
- `ppid`: 새로운 부모 프로세스 ID를 지정하여 포스트 익스플로잇 작업의 부모 프로세스를 변경하여 작업 실행 컨텍스트에 대한 더 나은 제어를 가능하게 합니다.
- `printspoofer`: PrintSpoofer 명령을 실행하여 인쇄 스풀러 보안 조치를 우회하여 권한 상승 또는 코드 실행을 가능하게 합니다.
- `dcsync`: 사용자의 Kerberos 키를 로컬 머신으로 동기화하여 오프라인 비밀번호 크래킹 또는 추가 공격을 가능하게 합니다.
- `ticket_cache_add`: 현재 로그온 세션 또는 지정된 세션에 Kerberos 티켓을 추가하여 티켓 재사용 또는 가장을 가능하게 합니다.

### 프로세스 실행

- `assembly_inject`: 원격 프로세스에 .NET 어셈블리 로더를 주입할 수 있습니다.
- `execute_assembly`: 에이전트의 컨텍스트에서 .NET 어셈블리를 실행합니다.
- `execute_coff`: 메모리에서 COFF 파일을 실행하여 컴파일된 코드를 메모리에서 실행할 수 있게 합니다.
- `execute_pe`: 비관리 실행 파일(PE)을 실행합니다.
- `inline_assembly`: 일회용 AppDomain에서 .NET 어셈블리를 실행하여 에이전트의 주요 프로세스에 영향을 주지 않고 코드를 임시로 실행할 수 있게 합니다.
- `run`: 대상 시스템에서 이진 파일을 실행하며, 시스템의 PATH를 사용하여 실행 파일을 찾습니다.
- `shinject`: 원격 프로세스에 셸코드를 주입하여 임의의 코드를 메모리에서 실행할 수 있게 합니다.
- `inject`: 에이전트 셸코드를 원격 프로세스에 주입하여 에이전트의 코드를 메모리에서 실행할 수 있게 합니다.
- `spawn`: 지정된 실행 파일에서 새로운 에이전트 세션을 생성하여 새로운 프로세스에서 셸코드를 실행할 수 있게 합니다.
- `spawnto_x64` 및 `spawnto_x86`: 포스트 익스플로잇 작업에서 기본 이진 파일을 지정된 경로로 변경하여 매개변수 없이 `rundll32.exe`를 사용하는 대신 소음이 적게 합니다.

### Mithic Forge

이 기능은 Mythic Forge에서 **COFF/BOF** 파일을 로드할 수 있게 하며, 이는 대상 시스템에서 실행할 수 있는 미리 컴파일된 페이로드 및 도구의 저장소입니다. 로드할 수 있는 모든 명령어로 인해 현재 에이전트 프로세스에서 BOF로 실행하여 일반 작업을 수행할 수 있게 됩니다 (보통 더 은밀하게). 

설치를 시작하려면:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
그런 다음 `forge_collections`를 사용하여 Mythic Forge의 COFF/BOF 모듈을 표시하여 에이전트의 메모리에 선택하고 로드할 수 있도록 합니다. 기본적으로 Apollo에 다음 2개의 컬렉션이 추가됩니다:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

모듈이 하나 로드되면 `forge_bof_sa-whoami` 또는 `forge_bof_sa-netuser`와 같은 다른 명령으로 목록에 나타납니다.

### Powershell & 스크립트 실행

- `powershell_import`: 새로운 PowerShell 스크립트(.ps1)를 에이전트 캐시에 가져와 나중에 실행할 수 있도록 합니다.
- `powershell`: 에이전트의 컨텍스트에서 PowerShell 명령을 실행하여 고급 스크립팅 및 자동화를 가능하게 합니다.
- `powerpick`: 희생 프로세스에 PowerShell 로더 어셈블리를 주입하고 PowerShell 명령을 실행합니다(파워셸 로깅 없이).
- `psinject`: 지정된 프로세스에서 PowerShell을 실행하여 다른 프로세스의 컨텍스트에서 스크립트를 타겟팅하여 실행할 수 있습니다.
- `shell`: 에이전트의 컨텍스트에서 셸 명령을 실행하며, cmd.exe에서 명령을 실행하는 것과 유사합니다.

### 측면 이동

- `jump_psexec`: PsExec 기술을 사용하여 Apollo 에이전트 실행 파일(apollo.exe)을 먼저 복사하고 실행하여 새로운 호스트로 측면 이동합니다.
- `jump_wmi`: WMI 기술을 사용하여 Apollo 에이전트 실행 파일(apollo.exe)을 먼저 복사하고 실행하여 새로운 호스트로 측면 이동합니다.
- `wmiexecute`: WMI를 사용하여 로컬 또는 지정된 원격 시스템에서 명령을 실행하며, 임시 사용을 위한 선택적 자격 증명을 제공합니다.
- `net_dclist`: 지정된 도메인에 대한 도메인 컨트롤러 목록을 검색하여 측면 이동을 위한 잠재적 대상을 식별하는 데 유용합니다.
- `net_localgroup`: 지정된 컴퓨터의 로컬 그룹을 나열하며, 컴퓨터가 지정되지 않은 경우 기본적으로 localhost로 설정됩니다.
- `net_localgroup_member`: 로컬 또는 원격 컴퓨터에서 지정된 그룹의 로컬 그룹 멤버십을 검색하여 특정 그룹의 사용자 열거를 가능하게 합니다.
- `net_shares`: 지정된 컴퓨터에서 원격 공유 및 접근 가능성을 나열하여 측면 이동을 위한 잠재적 대상을 식별하는 데 유용합니다.
- `socks`: 대상 네트워크에서 SOCKS 5 호환 프록시를 활성화하여 손상된 호스트를 통해 트래픽을 터널링할 수 있도록 합니다. proxychains와 같은 도구와 호환됩니다.
- `rpfwd`: 대상 호스트의 지정된 포트에서 수신 대기하고 Mythic을 통해 원격 IP 및 포트로 트래픽을 전달하여 대상 네트워크의 서비스에 원격으로 접근할 수 있도록 합니다.
- `listpipes`: 로컬 시스템의 모든 명명된 파이프를 나열하며, IPC 메커니즘과 상호작용하여 측면 이동 또는 권한 상승에 유용할 수 있습니다.

### 기타 명령
- `help`: 특정 명령에 대한 자세한 정보 또는 에이전트에서 사용할 수 있는 모든 명령에 대한 일반 정보를 표시합니다.
- `clear`: 작업을 '지워짐'으로 표시하여 에이전트가 선택할 수 없도록 합니다. `all`을 지정하여 모든 작업을 지우거나 특정 작업을 지우기 위해 `task Num`을 지정할 수 있습니다.


## [Poseidon Agent](https://github.com/MythicAgents/Poseidon)

Poseidon은 **Linux 및 macOS** 실행 파일로 컴파일되는 Golang 에이전트입니다.
```bash
./mythic-cli install github https://github.com/MythicAgents/Poseidon.git
```
사용자가 리눅스에서 사용할 수 있는 몇 가지 흥미로운 명령어가 있습니다:

### 일반 작업

- `cat`: 파일의 내용을 출력합니다.
- `cd`: 현재 작업 디렉토리를 변경합니다.
- `chmod`: 파일의 권한을 변경합니다.
- `config`: 현재 구성 및 호스트 정보를 봅니다.
- `cp`: 한 위치에서 다른 위치로 파일을 복사합니다.
- `curl`: 선택적 헤더와 메서드로 단일 웹 요청을 실행합니다.
- `upload`: 파일을 대상에 업로드합니다.
- `download`: 대상 시스템에서 로컬 머신으로 파일을 다운로드합니다.
- 그리고 더 많은 것들

### 민감한 정보 검색

- `triagedirectory`: 호스트의 디렉토리 내에서 민감한 파일이나 자격 증명과 같은 흥미로운 파일을 찾습니다.
- `getenv`: 현재 모든 환경 변수를 가져옵니다.

### 수평 이동

- `ssh`: 지정된 자격 증명을 사용하여 호스트에 SSH로 접속하고 ssh를 생성하지 않고 PTY를 엽니다.
- `sshauth`: 지정된 자격 증명을 사용하여 지정된 호스트에 SSH로 접속합니다. 이를 통해 원격 호스트에서 특정 명령을 실행하거나 파일을 SCP하는 데 사용할 수 있습니다.
- `link_tcp`: TCP를 통해 다른 에이전트에 연결하여 에이전트 간의 직접 통신을 가능하게 합니다.
- `link_webshell`: 웹셸 P2P 프로필을 사용하여 에이전트에 연결하여 에이전트의 웹 인터페이스에 원격으로 접근할 수 있게 합니다.
- `rpfwd`: 리버스 포트 포워드를 시작하거나 중지하여 대상 네트워크의 서비스에 원격으로 접근할 수 있게 합니다.
- `socks`: 대상 네트워크에서 SOCKS5 프록시를 시작하거나 중지하여 손상된 호스트를 통해 트래픽을 터널링할 수 있게 합니다. proxychains와 같은 도구와 호환됩니다.
- `portscan`: 호스트에서 열린 포트를 스캔하여 수평 이동이나 추가 공격을 위한 잠재적 대상을 식별하는 데 유용합니다.

### 프로세스 실행

- `shell`: /bin/sh를 통해 단일 셸 명령을 실행하여 대상 시스템에서 명령을 직접 실행할 수 있게 합니다.
- `run`: 인수와 함께 디스크에서 명령을 실행하여 대상 시스템에서 바이너리 또는 스크립트를 실행할 수 있게 합니다.
- `pty`: 상호작용하는 PTY를 열어 대상 시스템의 셸과 직접 상호작용할 수 있게 합니다.


{{#include ../banners/hacktricks-training.md}}
