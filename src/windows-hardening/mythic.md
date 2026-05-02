# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic이란?

Mythic은 red teaming을 위해 설계된 오픈소스의 모듈형 협업 command and control (C2) framework입니다. 이를 통해 운영자는 Windows, Linux, macOS를 포함한 다양한 운영체제에서 agents(payloads)를 관리하고 배포할 수 있습니다. Mythic은 multi-operator tasking, file handling, SOCKS/rpfwd management, payload generation을 위한 browser UI를 제공합니다.

단일 구조의 framework와 달리, Mythic repository 자체는 payload types나 C2 profiles를 **포함하지 않습니다**. Agents, wrappers, 그리고 C2 profiles는 일반적으로 외부 component로 설치되며 Mythic core와 독립적으로 업데이트할 수 있습니다.

### Installation

Mythic을 설치하려면 공식 **[Mythic repo](https://github.com/its-a-feature/Mythic)**의 지침을 따르세요. Mythic directory에서의 일반적인 bootstrap은 다음과 같습니다:
```bash
sudo make
sudo ./mythic-cli start
```
Mythic이 이미 실행 중이라면, 보통 `./mythic-cli install github ...`로 새 agent나 profile을 추가한 다음, Mythic을 재시작하거나 새 component를 직접 시작하면 됩니다.

### Agents

Mythic은 여러 agent를 지원하며, 이들은 **침해된 시스템에서 task를 수행하는 payloads**입니다. 각 agent는 특정 요구 사항에 맞게 조정할 수 있으며, 다른 운영체제에서 실행될 수 있습니다.

기본적으로 Mythic에는 설치된 agent가 없습니다. 오픈소스 community agent는 [**https://github.com/MythicAgents**](https://github.com/MythicAgents)에 있으며, [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html)는 지원되는 운영체제, payload formats, wrappers, 그리고 C2 profiles를 빠르게 확인하는 데 유용합니다.

그 org에서 agent를 설치하려면 다음을 실행할 수 있습니다:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` 형식은 non-root 환경에서 설치할 때 유용합니다. Mythic이 이미 실행 중이더라도 이전 명령으로 새로운 agent를 추가할 수 있습니다.

### C2 Profiles

Mythic의 C2 profiles는 **agent가 Mythic server와 어떻게 통신하는지**를 정의합니다. 여기에는 통신 protocol, encryption methods, 그리고 기타 설정이 지정됩니다. Mythic web interface를 통해 C2 profiles를 생성하고 관리할 수 있습니다.

기본적으로 Mythic은 profiles 없이 설치되지만, repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles)에서 일부 profiles를 다운로드할 수 있습니다. 실행:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): 기본 비동기 GET/POST 트래픽.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): 여러 callback domains, fail-over/round-robin rotation, custom headers/query parameters, 그리고 메시지 transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`)를 cookies, headers, query parameters, 또는 body에 배치하는 더 유연한 HTTP 트래픽.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): static `http` profile이 너무 눈에 띌 때 사용하는 JSON/TOML 기반 HTTP message shaping.

### Wrapper payloads

Wrapper payloads는 동일한 agent logic을 유지하면서도, 전달되거나 지속되는 on-disk representation을 바꿀 수 있게 해줍니다.

- `service_wrapper`: 다른 payload를 Windows service executable로 바꾸며, execution path에 유효한 service binary가 필요할 때 유용합니다.
- `scarecrow_wrapper`: 호환되는 shellcode를 ScareCrow loader로 감싸 EXE/DLL/CPL 같은 loader-backed outputs를 생성합니다.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo는 SpecterOps training offerings에서 사용하도록 설계된, 4.0 .NET Framework를 사용하는 C#으로 작성된 Windows agent입니다.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo는 현재 `WinExe`, `Shellcode`, `Service`, 그리고 `Source` payloads를 emit할 수 있다.
- 일반적으로 많이 쓰는 Apollo profiles는 `http`, `httpx`, `smb`, `tcp`, 그리고 `websocket`이다.
- `httpx`는 domain rotation, proxy support, custom message placement, message transforms가 필요할 때, 예전의 정적인 `http` profile보다 보통 더 유연한 옵션이다.
- Apollo는 `service_wrapper`와 `scarecrow_wrapper` 같은 wrapper payloads를 지원한다.
- `register_file`과 `register_assembly`는 `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, 그리고 `powerpick`의 staging primitives이다. 현재 Apollo builds에서는 이런 staged artifacts가 client-side에 DPAPI-protected AES256 blobs로 캐시된다.
- `ls`와 `ps` 결과는 Mythic의 browser scripts와 file/process browser와 특히 잘 통합되며, 협업 작업에서 operator triage를 눈에 띄게 빠르게 만든다.

This agent has a lot of commands that makes it very similar to Cobalt Strike's Beacon with some extras. Among them, it supports:

### Common actions

- `cat`: 파일 내용을 출력한다
- `cd`: 현재 working directory를 변경한다
- `cp`: 한 위치에서 다른 위치로 파일을 복사한다
- `ls`: 현재 directory 또는 지정한 path의 파일과 directory를 나열한다
- `ifconfig`: network adapters와 interfaces를 가져온다
- `netstat`: TCP와 UDP connection 정보를 가져온다
- `pwd`: 현재 working directory를 출력한다
- `ps`: 대상 시스템에서 실행 중인 processes를 나열한다(추가 정보 포함)
- `jobs`: 장기 실행 tasking과 연결된 모든 running jobs를 나열한다
- `download`: 대상 시스템에서 local machine으로 파일을 다운로드한다
- `upload`: local machine에서 대상 시스템으로 파일을 업로드한다
- `reg_query`: 대상 시스템의 registry keys와 values를 조회한다
- `reg_write_value`: 지정한 registry key에 새 value를 쓴다
- `sleep`: agent의 sleep interval을 변경한다. 이는 Mythic server와 얼마나 자주 check in할지를 결정한다
- 그 외에도 많으며, 사용 가능한 전체 commands 목록은 `help`를 사용해 확인한다.

### Privilege escalation

- `getprivs`: 현재 thread token에서 가능한 한 많은 privileges를 활성화한다
- `getsystem`: winlogon에 handle을 열고 token을 duplicate하여, 사실상 privileges를 SYSTEM level로 올린다
- `make_token`: 새 logon session을 만들고 이를 agent에 적용하여 다른 user의 impersonation을 가능하게 한다
- `steal_token`: 다른 process에서 primary token을 훔쳐와 agent가 그 process의 user를 impersonate할 수 있게 한다
- `pth`: Pass-the-Hash attack으로, plaintext password 없이 NTLM hash를 사용해 user로 인증할 수 있게 한다
- `mimikatz`: Mimikatz commands를 실행해 memory나 SAM database에서 credentials, hashes, 그리고 기타 민감한 정보를 추출한다
- `rev2self`: agent의 token을 primary token으로 되돌려, privileges를 원래 수준으로 떨어뜨린다
- `ppid`: 새 parent process ID를 지정해 post-exploitation jobs의 parent process를 바꾸며, job execution context를 더 잘 제어할 수 있게 한다
- `printspoofer`: PrintSpoofer commands를 실행해 print spooler security measures를 우회하고, privilege escalation 또는 code execution을 가능하게 한다
- `dcsync`: 사용자의 Kerberos keys를 local machine과 동기화하여, offline password cracking 또는 추가 공격을 가능하게 한다
- `ticket_cache_add`: 현재 logon session 또는 지정한 session에 Kerberos ticket을 추가하여, ticket reuse 또는 impersonation을 가능하게 한다

### Process execution

- `assembly_inject`: 원격 process에 .NET assembly loader를 inject할 수 있게 한다
- `blockdlls`: Microsoft 서명이 아닌 DLL이 post-exploitation jobs에 로드되는 것을 차단한다
- `execute_assembly`: agent context에서 .NET assembly를 실행한다
- `execute_coff`: 메모리에서 COFF file을 실행하여 compiled code를 in-memory execution할 수 있게 한다
- `execute_pe`: unmanaged executable (PE)을 실행한다
- `get_injection_techniques`: 사용 가능한 injection techniques와 현재 선택된 technique을 보여준다
- `inline_assembly`: disposable AppDomain에서 .NET assembly를 실행하여, agent의 main process에 영향을 주지 않고 code를 임시로 실행할 수 있게 한다
- `register_assembly`: 나중에 실행할 .NET assembly를 등록한다
- `register_file`: 나중의 `execute_*` 또는 PowerShell tasking을 위해 agent cache에 file을 등록한다
- `run`: system의 PATH를 사용해 executable을 찾아 대상 시스템에서 binary를 실행한다
- `set_injection_technique`: post-exploitation jobs에서 사용하는 injection primitive를 변경한다
- `shinject`: 원격 process에 shellcode를 inject하여 arbitrary code를 in-memory execution할 수 있게 한다
- `inject`: agent shellcode를 원격 process에 inject하여 agent code를 in-memory execution할 수 있게 한다
- `spawn`: 지정한 executable에서 새 agent session을 생성하여, 새 process에서 shellcode 실행을 가능하게 한다
- `spawnto_x64` and `spawnto_x86`: 매우 시끄러운 `rundll32.exe`를 params 없이 쓰는 대신, post-exploitation jobs에서 기본 binary로 사용할 path를 지정한 것으로 변경한다.

### Mythic Forge

This allows to **load COFF/BOF** files from the Mythic Forge, which is a repository of pre-compiled payloads and tools that can be executed on the target system. With all the commands that can be loaded it'll be possible to perform common actions executing them in the current agent process as BOFs (usually with better OPSEC than spawning a separate process).

Start installing them with:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, `forge_collections`를 사용해 Mythic Forge의 COFF/BOF 모듈을 표시하여 에이전트의 메모리에 선택해서 로드하고 실행할 수 있게 합니다. 기본적으로 Apollo에는 다음 2개 컬렉션이 추가됩니다:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

모듈이 하나 로드되면 `forge_bof_sa-whoami` 또는 `forge_bof_sa-netuser` 같은 다른 명령으로 목록에 나타납니다.

### PowerShell & scripting execution

- `powershell_import`: 나중에 실행할 수 있도록 새 PowerShell 스크립트(.ps1)를 에이전트 캐시에 가져옵니다
- `powershell`: 에이전트 컨텍스트에서 PowerShell 명령을 실행하며, 고급 스크립팅과 자동화를 허용합니다
- `powerpick`: PowerShell 로더 어셈블리를 sacrificial process에 주입하고 PowerShell 명령을 실행합니다 (powershell logging 없이).
- `psinject`: 지정된 프로세스에서 PowerShell을 실행하여, 다른 프로세스 컨텍스트에서 스크립트를 대상으로 실행할 수 있게 합니다
- `shell`: cmd.exe에서 실행하는 것과 유사하게, 에이전트 컨텍스트에서 shell 명령을 실행합니다

### Lateral Movement

- `jump_psexec`: PsExec technique를 사용해 Apollo agent executable(apollo.exe)을 먼저 복사한 뒤 실행하여 새 호스트로 lateral movement를 수행합니다
- `jump_wmi`: WMI technique를 사용해 Apollo agent executable(apollo.exe)을 먼저 복사한 뒤 실행하여 새 호스트로 lateral movement를 수행합니다
- `link` and `unlink`: callbacks 사이에 P2P 링크를 생성하고 제거합니다(예: SMB/TCP를 통해)
- `wmiexecute`: impersonation을 위한 선택적 credentials와 함께 WMI를 사용해 local 또는 지정된 remote system에서 명령을 실행합니다
- `net_dclist`: 지정된 domain의 domain controllers 목록을 가져오며, lateral movement의 잠재적 target을 식별하는 데 유용합니다
- `net_localgroup`: 지정된 computer의 local groups를 나열하며, computer가 지정되지 않으면 localhost를 기본값으로 합니다
- `net_localgroup_member`: local 또는 remote computer에서 지정된 group의 local group membership을 가져와 특정 group의 users를 열거할 수 있게 합니다
- `net_shares`: 지정된 computer의 remote shares와 접근 가능 여부를 나열하며, lateral movement의 잠재적 target을 식별하는 데 유용합니다
- `socks`: 대상 network에서 SOCKS 5 호환 proxy를 활성화하여 compromised host를 통해 traffic을 터널링할 수 있게 합니다. proxychains 같은 tools와 호환됩니다
- `rpfwd`: 대상 host의 지정된 port에서 수신을 시작하고 traffic을 Mythic을 통해 remote IP와 port로 전달하여, 대상 network의 services에 remote access할 수 있게 합니다
- `listpipes`: local system의 모든 named pipes를 나열하며, IPC mechanisms와 상호작용하여 lateral movement나 privilege escalation에 유용할 수 있습니다

`jump_wmi` 또는 `wmiexecute` 아래에서 사용되는 더 낮은 수준의 WMI execution primitives는 [WmiExec](lateral-movement/wmiexec.md)를 확인하세요. 더 넓은 pivoting patterns는 [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md)를 확인하세요.

### Miscellaneous Commands
- `help`: agent에서 사용 가능한 특정 명령이나 전체 명령에 대한 자세한 정보를 표시합니다
- `clear`: 작업을 'cleared'로 표시하여 agents가 가져갈 수 없게 합니다. 모든 작업을 지우려면 `all`을, 특정 작업을 지우려면 `task Num`을 지정할 수 있습니다


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon은 **Linux and macOS** 실행 파일로 컴파일되는 Golang agent입니다.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- 현재 Poseidon 빌드는 `x86_64`와 `arm64` 모두에서 Linux와 macOS를 대상으로 한다.
- 지원되는 출력 형식에는 네이티브 실행 파일과 `dylib`, `so` 같은 shared-library 스타일 출력이 포함된다.
- Poseidon은 `http`, `websocket`, `tcp`, `dynamichttp`를 지원하며, 현재 빌더는 `egress_order`와 failover thresholds 같은 multi-egress 설정을 노출한다.
- `proxy_bypass`와 `garble` 같은 build-time 옵션은 더 깔끔한 네트워크 동작이나 추가적인 Go binary obfuscation이 필요할 때 확인할 가치가 있다.

Mythic-backed operations, JAMF abuse, 또는 MDM-as-C2 아이디어에 대한 macOS-specific tradecraft는 [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md)를 확인하라.

Linux나 macOS에서 사용할 때 흥미로운 명령들이 있다:

### Common actions

- `cat`: 파일의 내용을 출력
- `cd`: 현재 작업 디렉터리 변경
- `chmod`: 파일의 권한 변경
- `config`: 현재 config와 호스트 정보 보기
- `cp`: 한 위치에서 다른 위치로 파일 복사
- `curl`: 선택적 헤더와 method를 사용해 단일 웹 요청 실행
- `upload`: 대상에 파일 업로드
- `download`: 대상 시스템에서 로컬 머신으로 파일 다운로드
- 그리고 더 많다

### Search Sensitive Information

- `triagedirectory`: 호스트의 디렉터리에서 민감한 파일이나 credentials 같은 흥미로운 파일 찾기.
- `getenv`: 현재 모든 environment variables 가져오기.

### Move laterally

- `ssh`: 지정된 credentials를 사용해 host에 SSH로 접속하고, ssh를 새로 띄우지 않은 채 PTY 열기.
- `sshauth`: 지정된 credentials를 사용해 특정 host들에 SSH로 접속. 원격 host에서 특정 command를 실행하거나 파일을 SCP로 전송하는 데도 사용할 수 있다.
- `link_tcp`: TCP를 통해 다른 agent에 연결하여 agent 간 직접 communication을 허용.
- `link_webshell`: webshell P2P profile을 사용해 agent에 연결하여 agent의 web interface에 remote access 제공.
- `rpfwd`: Reverse Port Forward를 시작하거나 중지하여 대상 network의 services에 remote access 제공.
- `socks`: 대상 network에서 SOCKS5 proxy를 시작하거나 중지하여 compromised host를 통한 traffic tunneling 허용. proxychains 같은 도구와 호환.
- `portscan`: host(s)의 open ports를 스캔하여 lateral movement 또는 추가 공격의 잠재적 target을 식별하는 데 유용.

### Process execution

- `shell`: /bin/sh를 통해 단일 shell command 실행하여 대상 시스템에서 command를 직접 실행.
- `run`: arguments와 함께 disk의 command를 실행하여 대상 시스템에서 binaries나 scripts 실행.
- `pty`: interactive PTY를 열어 대상 시스템의 shell과 직접 상호작용 가능.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
{{#include ../banners/hacktricks-training.md}}
