# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic이란?

Mythic은 red teaming을 위해 설계된 오픈 소스 modular collaborative command and control (C2) framework입니다. 이를 통해 operators는 Windows, Linux, macOS를 포함한 다양한 운영 체제에서 agents (payloads)를 관리하고 deploy할 수 있습니다. Mythic은 multi-operator tasking, file handling, SOCKS/rpfwd management, payload generation을 위한 browser UI를 제공합니다.

Monolithic frameworks와 달리 Mythic repository 자체에는 **payload types나 C2 profiles가 포함되어 있지 않습니다**. Agents, wrappers, C2 profiles는 일반적으로 external components로 설치되며 Mythic core와 독립적으로 업데이트할 수 있습니다.

### Installation

Mythic을 설치하려면 공식 **[Mythic repo](https://github.com/its-a-feature/Mythic)**의 instructions를 따르세요. Mythic directory에서 일반적으로 사용하는 bootstrap은 다음과 같습니다:
```bash
sudo make
sudo ./mythic-cli start
```
Mythic이 이미 실행 중인 경우 일반적으로 `./mythic-cli install github ...`을 사용해 새 agent 또는 profile을 추가한 다음, Mythic을 재시작하거나 새 component만 직접 시작하면 됩니다.

### Agents

Mythic은 여러 agent를 지원하며, 이들은 **침해된 시스템에서 작업을 수행하는 payload**입니다. 각 agent는 특정 요구 사항에 맞게 구성할 수 있으며 서로 다른 운영 체제에서 실행할 수 있습니다.

기본적으로 Mythic에는 설치된 agent가 없습니다. 오픈 소스 커뮤니티 agent는 [**https://github.com/MythicAgents**](https://github.com/MythicAgents)에 있으며, [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html)를 사용하면 지원되는 운영 체제, payload 형식, wrapper 및 C2 profile을 빠르게 확인할 수 있습니다.

해당 org에서 agent를 설치하려면 다음을 실행합니다:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` 형식은 non-root 환경에서 설치할 때 유용합니다. Mythic이 이미 실행 중인 경우에도 이전 명령을 사용하여 새 agent를 추가할 수 있습니다.

### C2 Profiles

Mythic의 C2 Profiles는 **agent가 Mythic server와 통신하는 방식**을 정의합니다. 통신 프로토콜, encryption methods 및 기타 설정을 지정합니다. Mythic web interface를 통해 C2 Profiles를 생성하고 관리할 수 있습니다.

기본적으로 Mythic은 profiles 없이 설치되지만, 다음을 실행하여 repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles)에서 일부 profiles를 다운로드할 수 있습니다:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): 기본 비동기 GET/POST traffic.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): 여러 callback domains, fail-over/round-robin rotation, custom headers/query parameters, 그리고 cookies, headers, query parameters 또는 body에 배치되는 message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`)를 지원하는 더욱 유연한 HTTP traffic.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): static `http` profile이 너무 식별하기 쉬울 때 JSON/TOML 기반 HTTP message shaping을 제공합니다.

### Current platform notes

- 현재 많은 public agents와 profiles는 pre-built remote container images를 사용해 설치됩니다.
component를 fork하거나 로컬에서 patch했는데 Mythic이 계속 이전 동작을
사용한다면, 생성된 `.env` 항목에서 `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, `*_USE_VOLUME`을 확인하세요. 일반적으로
`*_USE_BUILD_CONTEXT="true"`를 활성화해야 Mythic이 원격 image를
조용히 재사용하지 않고 로컬 Docker context에서 다시 build합니다.
- Browser scripts는 operators를 위한 Mythic의 가장 유용한 quality-of-life 기능 중
하나입니다. 이를 통해 raw command output을 tables, screenshot
viewers, download links, search links 및 UI에서 직접 후속 tasking을
실행하는 buttons로 변환할 수 있습니다. 현재 Mythic builds에서는 각 operator가
자신의 scripts를 유지하고, 이를 전체적으로 또는 task별로 toggle할 수 있으며,
agents가 plaintext 대신 structured JSON을 반환할 때 가장 좋은 결과를
얻습니다. 이는 반복적인 `ls`, `ps`, triage 및 file-browser workflows에
특히 유용합니다.
- 최신 Mythic builds는 interactive tasking과 Push C2 patterns도 지원하므로
PTY/SOCKS/rpfwd 중심 operations에서 `sleep 0` polling의 필요성이 줄어듭니다.
agent/profile이 이를 지원한다면, interactive channel을 유지하기 위해
constant check-ins로 server를 계속 두드리는 것보다 일반적으로 overhead가
낮습니다.
- 현재 3.4-era Mythic builders는 이전 writeups에서 설명한 것보다 context-aware합니다.
이제 build parameters를 선택한 OS 또는 다른 build options에 따라
group하거나 숨길 수 있고, payload types는 하나의 build에서 multiple C2
profiles 또는 동일한 C2의 multiple instances를 지원하는지 선언할 수 있으며,
C2 parameter deviations를 통해 agent가 실제로 구현하지 않은 fields를
숨길 수 있습니다. 이는 `http`, `httpx`, `smb`, `tcp`, `websocket` 사이를
전환할 때 중요합니다. safe/valid build surface가 더 이상 평면적인 static form이
아니기 때문입니다.
- custom agent/profile pair를 build하면서 Mythic의 JSON message format이나
default crypto를 wire에서 사용하고 싶지 않다면
`translation_container`를 사용하세요. Mythic은 UUID를 제거하고, encrypted blob과
key material을 gRPC를 통해 translator에 전달한 뒤 agent-native bytes를
반환받습니다. 이는 전체 server를 다시 작성하지 않고 binary protocols,
custom framing 또는 agent-side encryption을 지원하는 깔끔한 방법입니다.
- linked/P2P callbacks는 단순히 tasking만 전달하지 않는다는 점을 기억하세요.
Mythic의 `get_tasking` flow는 responses와 함께 `delegates`, `socks`,
`rpfwd`, `interactive` data도 전달할 수 있습니다. 실제로 하나의 egress
callback이 동일한 polling loop에서 inner callbacks와 pivot channels를
서비스할 수 있습니다. child agents가 자체적인 periodic check-ins을
수행한다면 `get_delegate_tasks=false`를 사용해 parent가 inner callback의
queued jobs를 실수로 소비하지 않도록 하세요.

### Wrapper payloads

Wrapper payloads를 사용하면 동일한 agent logic을 유지하면서 전달되거나 persist되는 on-disk representation을 변경할 수 있습니다.

- `service_wrapper`: 다른 payload를 Windows service executable로 변환하며, execution path에 유효한 service binary가 필요한 경우 유용합니다.
- `scarecrow_wrapper`: 호환되는 shellcode를 ScareCrow loader로 wrapping하여 EXE/DLL/CPL과 같은 loader-backed outputs를 생성합니다.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo는 SpecterOps training offerings에서 사용하도록 설계된 4.0 .NET Framework 기반의 C#으로 작성된 Windows agent입니다.

다음 명령으로 설치합니다:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### 현재 build/profile 참고 사항

- Apollo는 현재 `WinExe`, `Shellcode`, `Service`, `Source` payload를 생성할 수 있습니다.
- 일반적으로 사용되는 Apollo profile은 `http`, `httpx`, `smb`, `tcp`, `websocket`입니다.
- `httpx`는 이전의 정적 `http` profile보다 domain rotation, proxy 지원, custom message placement 및 message transforms가 필요할 때 일반적으로 더 유연한 옵션입니다.
- Apollo는 기능이 완성도 높은 community agent 중 하나이며, 현재 browser scripts, file/process browser views, screenshots, keylogging, SOCKS, rpfwd, Push C2 및 P2P routing과 같은 Mythic-side integrations를 제공합니다.
- Apollo는 `service_wrapper` 및 `scarecrow_wrapper`와 같은 wrapper payload를 지원합니다.
- Apollo는 dynamic command loading을 지원하므로, 초기 payload를 간결하게 유지하고 모든 post-ex 기능을 첫 build에 포함하는 대신 나중에 추가 commands 또는 Forge modules를 로드할 수 있습니다.
- shellcode output을 생성할 때 Apollo의 현재 builder는 Donut format 선택 항목(`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`)과 Donut bypass 동작(`None`, `Abort on fail`, `Continue on fail`)도 제공합니다. 이는 최종적으로 shellcode를 `service_wrapper`, `scarecrow_wrapper` 또는 custom loader로 다시 wrapping하려는 경우 유용합니다.
- `register_file` 및 `register_assembly`는 `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import` 및 `powerpick`을 위한 staging primitive입니다. 현재 Apollo build에서 이러한 staged artifact는 client-side에 DPAPI로 보호된 AES256 blob으로 caching됩니다.
- `ls` 및 `ps` 결과는 Mythic의 browser scripts와 file/process browser에 특히 잘 통합되므로 collaborative operation에서 operator triage가 눈에 띄게 빨라집니다.
- Apollo의 fork-and-run job은 `spawnto_x86` / `spawnto_x64`에서 sacrificial process 설정을 상속하고, `ppid`에서 parent selection을 상속한 다음 현재 선택된 injection primitive를 사용합니다. 실제로 이는 한 command에 대한 OPSEC tuning이 동시에 `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe` 및 `spawn`에 영향을 줄 수 있음을 의미합니다.
- 현재 문서화된 Apollo injection backend에는 syscalls를 통한 `CreateRemoteThread`, `QueueUserAPC` (early-bird style) 및 `NtCreateThreadEx`가 포함됩니다. noisy post-exploitation 전에 `get_injection_techniques`를 사용하고, target 또는 실행하려는 command와 충돌하는 primitive에서 변경해야 한다면 `set_injection_technique`를 사용하십시오.
- `blockdlls`는 post-exploitation job을 위해 생성된 sacrificial process에만 영향을 줍니다. 기본값인 bare `rundll32.exe`보다 덜 의심스러운 `spawnto_x64` target과 함께 사용하면 assembly/PowerShell 중심 tasking을 실행하기 전에 적용하기 가장 쉬운 Apollo-side 변경 사항 중 하나입니다.

이 agent에는 Cobalt Strike의 Beacon과 매우 유사하면서 일부 추가 기능을 제공하는 많은 commands가 있습니다. 주요 지원 항목은 다음과 같습니다.

### 일반 작업

- `cat`: 파일의 내용을 출력
- `cd`: 현재 working directory 변경
- `cp`: 한 위치에서 다른 위치로 파일 복사
- `ls`: 현재 directory 또는 지정된 path의 파일 및 directory 목록 표시
- `ifconfig`: network adapter 및 interface 확인
- `netstat`: TCP 및 UDP connection 정보 확인
- `pwd`: 현재 working directory 출력
- `ps`: target system에서 실행 중인 process 목록 표시 (추가 정보 포함)
- `jobs`: long-running tasking과 연결된 모든 실행 중인 job 목록 표시
- `download`: target system에서 local machine으로 파일 다운로드
- `upload`: local machine에서 target system으로 파일 업로드
- `reg_query`: target system의 registry key 및 value 조회
- `reg_write_value`: 지정된 registry key에 새 value 기록
- `sleep`: agent의 sleep interval 변경. 이 값은 agent가 Mythic server에 check-in하는 빈도를 결정합니다.
- 그 외에도 많은 command가 있으며, 전체 사용 가능한 목록은 `help`로 확인할 수 있습니다.

### 권한 상승

- `getprivs`: 현재 thread token에서 가능한 많은 privilege 활성화
- `getsystem`: winlogon에 대한 handle을 열고 token을 duplicate하여 사실상 SYSTEM level로 권한 상승
- `make_token`: 새 logon session을 생성하고 agent에 적용하여 다른 user를 impersonate
- `steal_token`: 다른 process에서 primary token을 훔쳐 agent가 해당 process의 user를 impersonate
- `pth`: Pass-the-Hash attack. plaintext password 없이 NTLM hash를 사용하여 user로 authenticate
- `mimikatz`: Mimikatz commands를 실행하여 memory 또는 SAM database에서 credential, hash 및 기타 민감한 정보 추출
- `rev2self`: agent의 token을 primary token으로 되돌려 privilege를 원래 level로 복원
- `ppid`: 새 parent process ID를 지정하여 post-exploitation job의 parent process 변경. 이를 통해 job execution context를 더 세밀하게 제어
- `printspoofer`: PrintSpoofer commands를 실행하여 print spooler security measure를 우회하고 privilege escalation 또는 code execution 수행
- `dcsync`: user의 Kerberos key를 local machine으로 sync하여 offline password cracking 또는 추가 attack 수행
- `ticket_cache_add`: 현재 logon session 또는 지정된 session에 Kerberos ticket을 추가하여 ticket 재사용 또는 impersonation 수행

### Process execution

- `assembly_inject`: remote process에 .NET assembly loader 주입
- `blockdlls`: post-exploitation job에 Microsoft 서명이 없는 DLL이 로드되지 않도록 차단
- `execute_assembly`: agent context에서 .NET assembly 실행
- `execute_coff`: COFF file을 memory에서 실행하여 compiled code의 in-memory execution 수행
- `execute_pe`: unmanaged executable (PE) 실행
- `keylog_inject`: 다른 process에 keylogger를 주입하고 keystroke를 Mythic의 keylog view로 stream
- `screenshot` / `screenshot_inject`: 현재 desktop을 직접 capture하거나 target process/session에 screenshot assembly를 주입하여 capture
- `get_injection_techniques`: 사용 가능한 injection technique 및 현재 선택된 technique 표시
- `inline_assembly`: disposable AppDomain에서 .NET assembly를 실행하여 agent의 main process에 영향을 주지 않고 일시적으로 code 실행
- `register_assembly`: 나중에 실행할 .NET assembly 등록
- `register_file`: 나중의 `execute_*` 또는 PowerShell tasking을 위해 agent cache에 file 등록
- `run`: system의 PATH를 사용하여 executable을 찾은 뒤 target system에서 binary 실행
- `set_injection_technique`: post-exploitation job에서 사용하는 injection primitive 변경
- `shinject`: remote process에 shellcode를 주입하여 arbitrary code의 in-memory execution 수행
- `inject`: remote process에 agent shellcode를 주입하여 agent code의 in-memory execution 수행
- `spawn`: 지정된 executable에서 새 agent session을 생성하여 새 process에서 shellcode 실행
- `spawnto_x64` 및 `spawnto_x86`: post-exploitation job에서 사용하는 기본 binary를 지정된 path로 변경. 매개변수 없이 `rundll32.exe`를 사용하는 것보다 훨씬 덜 noisy합니다.

### Mythic Forge

이는 pre-compiled payload 및 tool을 저장하는 repository인 Mythic Forge에서 **COFF/BOF** file을 로드할 수 있도록 합니다. 로드할 수 있는 모든 command를 사용하면 현재 agent process에서 BOF로 실행하여 일반적인 작업을 수행할 수 있습니다 (일반적으로 별도의 process를 spawn하는 것보다 더 나은 OPSEC를 제공).

다음 명령으로 설치를 시작합니다:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
그런 다음 `forge_collections`를 사용하여 Mythic Forge의 COFF/BOF modules를 표시하고, 이를 선택하여 agent의 memory에 로드한 후 실행할 수 있습니다. 기본적으로 Apollo에는 다음 2개의 collections가 추가됩니다:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

하나의 module이 로드되면 `forge_bof_sa-whoami` 또는 `forge_bof_sa-netuser`와 같은 또 다른 command로 목록에 표시됩니다.

BOF의 경우 Forge는 단순히 하나의 flat argument string을 Apollo에 전달하지 않는다는 점을 기억하세요. BOF parameters를 Mythic의 typed-array format으로 매핑한 다음 Apollo의 `execute_coff` flow로 전달합니다. Forge로 로드된 BOF가 이상하게 동작한다면 입력한 command line만 확인하지 말고, 예상되는 BOF argument types / entrypoint를 확인하세요. 또한 Apollo의 최신 BOF loader는 훨씬 이전의 2.3.1-era builds와 비교하여 argument handling이 변경되었으므로, marshaling expectations가 변경된 것만으로도 오래된 BOF 또는 old collections가 실패할 수 있습니다.

### PowerShell 및 scripting execution

- `powershell_import`: 나중에 실행할 수 있도록 새 PowerShell script (.ps1)를 agent cache로 import합니다.
- `powershell`: agent의 context에서 PowerShell command를 실행하여 고급 scripting 및 automation을 수행할 수 있습니다.
- `powerpick`: PowerShell loader assembly를 sacrificial process에 inject하고 PowerShell command를 실행합니다(powerShell logging 없이).
- `psinject`: 지정된 process에서 PowerShell을 실행하여 다른 process의 context에서 scripts를 targeted execution할 수 있습니다.
- `shell`: agent의 context에서 shell command를 실행하며, cmd.exe에서 command를 실행하는 것과 유사합니다.

### Lateral Movement

- `jump_psexec`: 먼저 Apollo agent executable (apollo.exe)을 복사하고 실행하여 PsExec technique을 사용해 새 host로 lateral movement를 수행합니다.
- `jump_wmi`: 먼저 Apollo agent executable (apollo.exe)을 복사하고 실행하여 WMI technique을 사용해 새 host로 lateral movement를 수행합니다.
- `link` 및 `unlink`: callbacks 간에 P2P links(예: SMB/TCP를 통한 links)를 생성하고 해제합니다.
- `wmiexecute`: impersonation을 위한 optional credentials를 사용하여 WMI로 local 또는 지정된 remote system에서 command를 실행합니다.
- `net_dclist`: 지정된 domain의 domain controllers 목록을 가져오며, lateral movement의 potential targets를 식별하는 데 유용합니다.
- `net_localgroup`: 지정된 computer의 local groups를 나열합니다. computer가 지정되지 않으면 기본값은 localhost입니다.
- `net_localgroup_member`: local 또는 remote computer에서 지정된 group의 local group membership을 가져와 특정 groups의 users를 열거할 수 있습니다.
- `net_shares`: 지정된 computer의 remote shares와 해당 accessibility를 나열하여 lateral movement의 potential targets를 식별하는 데 유용합니다.
- `socks`: target network에서 SOCKS 5 compliant proxy를 활성화하여 compromised host를 통해 traffic을 tunneling할 수 있습니다. proxychains와 같은 tools와 호환됩니다.
- `rpfwd`: target host의 지정된 port에서 listening을 시작하고 Mythic을 통해 traffic을 remote IP 및 port로 forward하여 target network의 services에 remote access할 수 있습니다.
- `listpipes`: local system의 모든 named pipes를 나열합니다. IPC mechanisms와 상호작용하여 lateral movement 또는 privilege escalation을 수행하는 데 유용할 수 있습니다.

`jump_wmi` 또는 `wmiexecute`에서 내부적으로 사용되는 lower-level WMI execution primitives는 [WmiExec](lateral-movement/wmiexec.md)를 확인하세요. 더 광범위한 pivoting patterns는 [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md)을 확인하세요.

### Miscellaneous Commands
- `help`: 특정 commands에 대한 자세한 정보 또는 agent에서 사용 가능한 모든 commands에 대한 일반 정보를 표시합니다.
- `clear`: tasks를 'cleared'로 표시하여 agents가 해당 tasks를 가져갈 수 없도록 합니다. `all`을 지정하면 모든 tasks를 clear하고, `task Num`을 지정하면 특정 task를 clear할 수 있습니다.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon은 **Linux 및 macOS** executables로 compile되는 Golang agent입니다.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### 현재 build/profile 참고 사항

- 현재 Poseidon builds는 `x86_64` 및 `arm64`에서 Linux와 macOS를 대상으로 합니다.
- 지원되는 output format에는 native executable과 `dylib`, `so` 같은 shared-library 스타일 output이 포함됩니다.
- Poseidon은 `http`, `websocket`, `tcp`, `dynamichttp`를 지원하며, 현재 builders는 `egress_order` 및 failover threshold 같은 multi-egress 설정을 제공합니다.
- Poseidon의 현재 capability metadata에는 browser scripts, file/process browser integration, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd, P2P도 포함되어 있으므로 단순한 remote shell이 아니라 실제 Linux/macOS pivot node로 사용할 수 있습니다.
- 더 깔끔한 network behavior나 추가적인 Go binary obfuscation이 필요하다면 `proxy_bypass` 및 `garble` 같은 build-time option을 확인할 가치가 있습니다.
- `pty`는 Linux/macOS operations에서 가장 유용한 최신 quality-of-life command 중 하나입니다. interactive PTY를 열고 Mythic 측 port를 노출하여, 기존의 `sleep 0` + SOCKS workaround 없이 더 완전한 terminal interaction을 제공할 수 있습니다.
- Poseidon의 현재 docs는 macOS 중심 tradecraft에 특히 흥미롭습니다. `jxa`는 JavaScript for Automation을 in-memory로 실행하고, `screencapture`는 로그인된 desktop을 캡처하며, `clipboard_monitor`는 pasteboard 변경 사항을 stream하고, `execute_library`는 local dylib를 load한 뒤 그 안의 function을 호출하며, `libinject`는 remote process가 disk에 있는 dylib를 load하도록 강제합니다.
- 장시간 실행되는 job에서는 Poseidon이 post-exploitation 작업을 cooperative 방식으로 동작하며 hard-kill할 수 없는 goroutines/threads에서 실행한다는 점을 기억해야 합니다. 또한 docs에는 현재 built-in agent obfuscation이 없다고 명시되어 있으므로, 고도로 obfuscated된 commercial implant보다 build/profile 수준의 tradecraft가 더 중요합니다.

Mythic 기반 operations에서 macOS-specific tradecraft, JAMF abuse 또는 MDM-as-C2 아이디어를 다루려면 [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md)을 확인하세요.

Linux 또는 macOS에서 사용할 경우 다음과 같은 흥미로운 commands가 있습니다.

### 일반적인 작업

- `cat`: 파일의 내용을 출력
- `cd`: 현재 working directory 변경
- `chmod`: 파일의 permissions 변경
- `config`: 현재 config 및 host 정보 확인
- `cp`: 한 위치에서 다른 위치로 파일 복사
- `curl`: 선택적인 headers 및 method를 사용하여 단일 web request 실행
- `upload`: target에 파일 upload
- `download`: target system에서 local machine으로 파일 download
- 그 외에도 많은 기능

### 민감한 정보 검색

- `triagedirectory`: 민감한 파일이나 credentials 등 host의 directory 내에서 흥미로운 파일 검색
- `getenv`: 현재 모든 environment variables 가져오기

### macOS-specific tradecraft

- `jxa`: `OSAScript`를 통해 JavaScript for Automation을 in-memory로 실행합니다. 별도의 script file을 남기지 않고 native macOS post-exploitation을 수행할 때 유용합니다.
- `clipboard_monitor`: pasteboard를 polling하고 변경 사항을 Mythic에 보고합니다. copy/paste에 의존하는 credential/token theft workflow에 유용합니다.
- `screencapture`: macOS에서 사용자의 desktop 캡처
- `execute_library`: disk에서 dylib를 load하고 특정 exported function 호출
- `libinject`: 다른 macOS process가 disk에서 dylib를 load하도록 강제하는 shellcode stub inject
- `persist_launchd`: agent에서 직접 LaunchAgent / LaunchDaemon persistence 생성

### Laterally 이동

- `ssh`: 지정된 credentials를 사용하여 host에 SSH하고 ssh를 spawn하지 않은 채 PTY 열기
- `sshauth`: 지정된 credentials를 사용하여 지정된 host(s)에 SSH합니다. 이를 사용하여 SSH를 통해 remote hosts에서 특정 command를 실행하거나 SCP files를 사용할 수도 있습니다.
- `link_tcp`: TCP를 통해 다른 agent에 link하여 agents 간 direct communication 허용
- `link_webshell`: webshell P2P profile을 사용하여 agent에 link하고 agent의 web interface에 remote access 허용
- `rpfwd`: Reverse Port Forward 시작 또는 중지. target network의 services에 remote access 허용
- `socks`: target network에서 SOCKS5 proxy 시작 또는 중지. compromised host를 통한 traffic tunneling 허용. proxychains 같은 tools와 호환
- `portscan`: host(s)의 open ports scan. lateral movement 또는 추가 attacks를 위한 potential targets 식별에 유용

### Process execution

- `shell`: `/bin/sh`를 통해 단일 shell command 실행하여 target system에서 commands를 직접 실행
- `run`: arguments와 함께 disk에서 command 실행하여 target system에서 binaries 또는 scripts 실행
- `pty`: interactive PTY를 열어 target system의 shell과 직접 interaction 허용






## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [Mythic 3.3->3.4 Updates](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [Transforming Red Team Ops with Mythic’s Hidden Gems: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
{{#include ../banners/hacktricks-training.md}}
