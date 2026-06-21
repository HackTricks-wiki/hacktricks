# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic이란?

Mythic은 red teaming을 위해 설계된 오픈소스의 모듈형 협업 command and control (C2) framework입니다. 운영자가 Windows, Linux, macOS를 포함한 다양한 운영 체제에서 agent(payloads)를 관리하고 배포할 수 있게 해줍니다. Mythic은 다중 운영자 tasking, file handling, SOCKS/rpfwd management, payload generation을 위한 browser UI를 제공합니다.

단일 덩어리형 framework와 달리, Mythic repository 자체에는 payload types나 C2 profiles가 포함되어 있지 않습니다. Agent, wrapper, C2 profile은 일반적으로 외부 component로 설치되며 Mythic core와 독립적으로 업데이트할 수 있습니다.

### 설치

Mythic을 설치하려면 공식 **[Mythic repo](https://github.com/its-a-feature/Mythic)**의 안내를 따르세요. Mythic directory에서의 일반적인 bootstrap은 다음과 같습니다:
```bash
sudo make
sudo ./mythic-cli start
```
Mythic이 이미 실행 중이라면, 보통 `./mythic-cli install github ...`로 새 agent나 profile을 추가한 다음, Mythic을 다시 시작하거나 새 component를 바로 시작하면 됩니다.

### Agents

Mythic은 여러 agent를 지원하며, 이는 **침해된 시스템에서 task를 수행하는 payloads**입니다. 각 agent는 특정 요구에 맞게 조정할 수 있고, 서로 다른 operating system에서 실행될 수 있습니다.

기본적으로 Mythic에는 설치된 agent가 없습니다. open-source community agents는 [**https://github.com/MythicAgents**](https://github.com/MythicAgents)에 있고, [**community feature matrix**](https://mythicmeta.github.io/overview/agent_matrix.html)는 지원되는 operating system, payload format, wrapper, C2 profile을 빠르게 확인하는 데 유용합니다.

그 org에서 agent를 설치하려면 다음을 실행하면 됩니다:
```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
`sudo -E` 형식은 non-root 환경에서 설치할 때 유용합니다. Mythic이 이미 실행 중이더라도 이전 명령으로 새 agent를 추가할 수 있습니다.

### C2 Profiles

Mythic의 C2 profiles는 **agent가 Mythic server와 통신하는 방식**을 정의합니다. 이들은 communication protocol, encryption methods, 그리고 기타 설정을 지정합니다. Mythic web interface를 통해 C2 profiles를 생성하고 관리할 수 있습니다.

기본적으로 Mythic은 profiles 없이 설치되지만, repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles)에서 일부 profiles를 다운로드할 수 있습니다. 실행:
```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
Current operator-relevant profiles to keep in mind:

- [`http`](https://github.com/MythicC2Profiles/http): 기본 비동기 GET/POST 트래픽.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): 여러 callback domain, fail-over/round-robin rotation, custom headers/query parameters, 그리고 cookie, headers, query parameters, 또는 body에 배치되는 message transforms (`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`)을 지원하는 더 유연한 HTTP 트래픽.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): static `http` profile이 너무 눈에 띌 때 사용하는 JSON/TOML 기반 HTTP message shaping.

### Current platform notes

- 많은 public agent와 profiles는 이제 pre-built remote container images와 함께 설치된다.
If you fork a component or patch it locally and Mythic keeps using the old
behavior, inspect the generated `.env` entries for `*_REMOTE_IMAGE`,
`*_USE_BUILD_CONTEXT`, and `*_USE_VOLUME`; enabling
`*_USE_BUILD_CONTEXT="true"` is usually what makes Mythic rebuild from your
local Docker context instead of silently reusing the remote image.
- Browser scripts are one of Mythic's highest-value quality-of-life features
for operators: they can turn raw command output into tables, screenshot
viewers, download links, and buttons that issue follow-on tasking directly
from the UI. This is especially useful for repetitive `ls`, `ps`, triage,
and file-browser workflows.
- Newer Mythic builds also support interactive tasking and Push C2 patterns
that reduce the need for `sleep 0` polling during PTY/SOCKS/rpfwd-heavy
operations. When an agent/profile supports it, this is usually lower-overhead
than hammering the server with constant check-ins just to keep an interactive
channel usable.

### Wrapper payloads

Wrapper payloads let you keep the same agent logic while changing the on-disk representation that gets delivered or persisted.

- `service_wrapper`: turns another payload into a Windows service executable, which is useful when the execution path requires a valid service binary.
- `scarecrow_wrapper`: wraps compatible shellcode with the ScareCrow loader to generate loader-backed outputs such as EXE/DLL/CPL.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo is a Windows agent written in C# using the 4.0 .NET Framework designed to be used in SpecterOps training offerings.

Install it with:
```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```
### Current build/profile notes

- Apollo는 현재 `WinExe`, `Shellcode`, `Service`, `Source` payloads를 emit할 수 있습니다.
- 일반적으로 사용되는 Apollo profiles는 `http`, `httpx`, `smb`, `tcp`, `websocket`입니다.
- `httpx`는 domain rotation, proxy support, custom message placement, message transforms가 필요할 때, 기존의 정적 `http` profile보다 보통 더 유연한 옵션입니다.
- Apollo는 `service_wrapper`, `scarecrow_wrapper` 같은 wrapper payloads를 지원합니다.
- `register_file`과 `register_assembly`는 `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, `powerpick`의 staging primitives입니다. 현재 Apollo builds에서는 이런 staged artifacts가 client-side에서 DPAPI-protected AES256 blobs로 캐시됩니다.
- `ls`와 `ps` 결과는 Mythic의 browser scripts 및 file/process browser와 특히 잘 통합되며, 이로 인해 collaborative operations에서 operator triage가 눈에 띄게 빨라집니다.
- Apollo의 fork-and-run jobs는 sacrificial process settings를 `spawnto_x86` / `spawnto_x64`에서 상속하고, parent selection은 `ppid`에서 상속한 뒤, 현재 선택된 injection primitive를 사용합니다. 실제로는, 한 command에 대한 OPSEC tuning이 `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, `spawn` 모두에 동시에 영향을 줄 수 있다는 뜻입니다.
- 현재 문서화된 Apollo injection backends에는 `CreateRemoteThread`, `QueueUserAPC` (early-bird style), `NtCreateThreadEx` via syscalls가 포함됩니다. 시끄러운 post-exploitation 전에 `get_injection_techniques`를 사용하고, 대상이나 실행하려는 command와 충돌하는 primitive에서 벗어나야 할 때는 `set_injection_technique`를 사용하세요.
- `blockdlls`는 post-exploitation jobs를 위해 생성된 sacrificial processes에만 영향을 줍니다. 기본 bare `rundll32.exe`보다 덜 수상한 `spawnto_x64` target과 함께 사용하면, assembly/PowerShell-heavy tasking을 실행하기 전에 Apollo 측에서 가장 쉽게 적용할 수 있는 변경 중 하나입니다.

이 agent는 Cobalt Strike의 Beacon과 매우 비슷하면서도 몇 가지 extras가 있는 많은 commands를 제공합니다. 그중 다음을 지원합니다:

### Common actions

- `cat`: 파일의 내용을 출력
- `cd`: 현재 working directory 변경
- `cp`: 한 위치에서 다른 위치로 파일 복사
- `ls`: 현재 directory 또는 지정한 path의 파일과 directory 나열
- `ifconfig`: network adapters와 interfaces 확인
- `netstat`: TCP 및 UDP connection information 확인
- `pwd`: 현재 working directory 출력
- `ps`: 대상 system에서 실행 중인 process 나열(추가 정보 포함)
- `jobs`: long-running tasking과 연결된 모든 running job 나열
- `download`: 대상 system에서 local machine으로 file 다운로드
- `upload`: local machine에서 대상 system으로 file 업로드
- `reg_query`: 대상 system의 registry keys와 values 조회
- `reg_write_value`: 지정한 registry key에 새 value 기록
- `sleep`: agent의 sleep interval 변경, Mythic server를 얼마나 자주 check in할지 결정
- 그 외에도 많으며, 전체 available commands 목록은 `help`를 사용하세요.

### Privilege escalation

- `getprivs`: 현재 thread token에서 가능한 한 많은 privileges 활성화
- `getsystem`: winlogon에 handle을 열고 token을 duplicate하여, 사실상 privileges를 SYSTEM level로 상승
- `make_token`: 새 logon session을 만들고 agent에 적용하여 다른 user를 impersonation할 수 있게 함
- `steal_token`: 다른 process에서 primary token을 훔쳐, agent가 그 process의 user를 impersonation할 수 있게 함
- `pth`: Pass-the-Hash attack, 평문 password 없이 NTLM hash를 사용해 user로 authentication할 수 있게 함
- `mimikatz`: Mimikatz commands를 실행하여 memory 또는 SAM database에서 credentials, hashes, 기타 민감 정보를 추출
- `rev2self`: agent의 token을 primary token으로 되돌려, privileges를 원래 수준으로 사실상 복구
- `ppid`: 새 parent process ID를 지정하여 post-exploitation jobs의 parent process를 변경, job execution context를 더 잘 제어할 수 있게 함
- `printspoofer`: PrintSpoofer commands를 실행하여 print spooler security measures를 우회, privilege escalation 또는 code execution 가능
- `dcsync`: 사용자의 Kerberos keys를 local machine으로 sync하여 offline password cracking 또는 추가 attack을 가능하게 함
- `ticket_cache_add`: 현재 logon session 또는 지정한 session에 Kerberos ticket을 추가하여 ticket reuse 또는 impersonation 가능

### Process execution

- `assembly_inject`: 원격 process에 .NET assembly loader를 inject할 수 있게 함
- `blockdlls`: post-exploitation jobs에서 Microsoft 서명되지 않은 DLL이 로드되는 것을 차단
- `execute_assembly`: agent context에서 .NET assembly 실행
- `execute_coff`: 메모리에서 COFF file을 실행하여 compiled code를 in-memory로 실행 가능
- `execute_pe`: unmanaged executable (PE) 실행
- `keylog_inject`: 다른 process에 keylogger를 inject하고 keystrokes를 Mythic의 keylog view로 스트리밍
- `screenshot` / `screenshot_inject`: 현재 desktop을 직접 캡처하거나 target process/session에 screenshot assembly를 inject하여 캡처
- `get_injection_techniques`: 사용 가능한 injection techniques와 현재 선택된 technique 표시
- `inline_assembly`: disposable AppDomain에서 .NET assembly를 실행하여 agent의 main process에 영향을 주지 않고 일시적으로 code 실행 가능
- `register_assembly`: 나중에 실행할 .NET assembly 등록
- `register_file`: 나중의 `execute_*` 또는 PowerShell tasking을 위해 agent cache에 file 등록
- `run`: system의 PATH를 사용해 executable을 찾아 target system에서 binary 실행
- `set_injection_technique`: post-exploitation jobs가 사용하는 injection primitive 변경
- `shinject`: 원격 process에 shellcode를 inject하여 arbitrary code를 in-memory로 실행 가능
- `inject`: agent shellcode를 원격 process에 inject하여 agent code를 in-memory로 실행 가능
- `spawn`: 지정한 executable에서 새 agent session을 생성하여 새 process에서 shellcode 실행 가능
- `spawnto_x64` 및 `spawnto_x86`: 매개변수 없이 `rundll32.exe`를 사용하는 대신, post-exploitation jobs의 기본 binary를 지정한 path로 변경. 이는 매우 시끄럽습니다.

### Mythic Forge

이것은 Mythic Forge에서 **COFF/BOF를 load**할 수 있게 해줍니다. Mythic Forge는 target system에서 실행할 수 있는 사전 컴파일된 payloads와 tools의 repository입니다. load할 수 있는 모든 commands를 사용하면, 현재 agent process에서 BOFs로 실행하여 일반적인 actions를 수행할 수 있습니다(보통 별도의 process를 생성하는 것보다 OPSEC이 더 좋음).

다음으로 설치를 시작하세요:
```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```
Then, `forge_collections`를 사용해 Mythic Forge의 COFF/BOF 모듈을 보여 주어 에이전트 메모리에 로드해서 실행할 수 있게 합니다. 기본적으로 Apollo에는 다음 2개 컬렉션이 추가됩니다:

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

한 모듈이 로드되면, `forge_bof_sa-whoami` 또는 `forge_bof_sa-netuser` 같은 또 다른 command로 목록에 표시됩니다.

BOF의 경우, Forge가 Apollo로 단순히 하나의 평평한 argument string만 넘기는 것이 아니라는 점을 기억하세요. BOF parameters를 Mythic의 typed-array format으로 매핑한 뒤, Apollo의 `execute_coff` flow로 전달합니다. Forge-loaded BOF가 이상하게 동작하면, 입력한 command line만 보지 말고 기대되는 BOF argument types / entrypoint를 확인하세요.

### PowerShell & scripting execution

- `powershell_import`: 나중에 실행하기 위해 새로운 PowerShell script (.ps1)를 agent cache에 import합니다
- `powershell`: agent context에서 PowerShell command를 실행하여, 고급 scripting과 automation을 가능하게 합니다
- `powerpick`: PowerShell loader assembly를 sacrificial process에 inject하고 PowerShell command를 실행합니다 (powershell logging 없이).
- `psinject`: 지정한 process에서 PowerShell을 실행하여, 다른 process context에서 scripts를 targeted execution할 수 있게 합니다
- `shell`: cmd.exe에서 실행하는 것처럼 agent context에서 shell command를 실행합니다

### Lateral Movement

- `jump_psexec`: PsExec technique를 사용해 먼저 Apollo agent executable (apollo.exe)을 복사한 뒤 실행하여 새로운 host로 lateral movement를 합니다.
- `jump_wmi`: WMI technique를 사용해 먼저 Apollo agent executable (apollo.exe)을 복사한 뒤 실행하여 새로운 host로 lateral movement를 합니다.
- `link` and `unlink`: callbacks 간에 P2P links를 만들고 해제합니다(예: SMB/TCP를 통해).
- `wmiexecute`: optional credentials for impersonation을 사용해 local 또는 지정한 remote system에서 WMI로 command를 실행합니다.
- `net_dclist`: 지정한 domain의 domain controllers 목록을 가져옵니다. lateral movement의 potential targets를 식별하는 데 유용합니다.
- `net_localgroup`: 지정한 computer의 local groups를 나열하며, computer를 지정하지 않으면 localhost를 기본으로 합니다.
- `net_localgroup_member`: local 또는 remote computer의 지정한 group에 대한 local group membership을 가져와, 특정 group의 users를 enumerate할 수 있게 합니다.
- `net_shares`: 지정한 computer의 remote shares와 접근 가능 여부를 나열하며, lateral movement의 potential targets를 식별하는 데 유용합니다.
- `socks`: target network에서 SOCKS 5 호환 proxy를 활성화하여 compromised host를 통해 traffic tunneling을 가능하게 합니다. proxychains 같은 tools와 호환됩니다.
- `rpfwd`: target host의 지정한 port에서 listening을 시작하고 Mythic을 통해 traffic을 remote IP와 port로 forward하여, target network의 services에 remote access할 수 있게 합니다.
- `listpipes`: local system의 모든 named pipes를 나열하며, IPC mechanisms와 상호작용해 lateral movement 또는 privilege escalation에 유용할 수 있습니다.

`jump_wmi` 또는 `wmiexecute` 아래에서 사용되는 lower-level WMI execution primitives는 [WmiExec](lateral-movement/wmiexec.md)를 확인하세요. 더 넓은 pivoting patterns는 [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md)를 확인하세요.

### Miscellaneous Commands
- `help`: agent에서 사용할 수 있는 특정 commands 또는 모든 commands에 대한 general information을 자세히 표시합니다.
- `clear`: task를 'cleared'로 표시하여 agents가 가져갈 수 없게 합니다. `all`을 지정해 모든 task를 지우거나 `task Num`을 지정해 특정 task를 지울 수 있습니다.


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon은 **Linux and macOS** executables로 컴파일되는 Golang agent입니다.
```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```
### Current build/profile notes

- 현재 Poseidon 빌드는 `x86_64`와 `arm64` 모두에서 Linux와 macOS를 대상으로 합니다.
- 지원되는 출력 형식에는 네이티브 실행 파일과 함께 `dylib` 및 `so` 같은 shared-library 스타일 출력이 포함됩니다.
- Poseidon은 `http`, `websocket`, `tcp`, `dynamichttp`를 지원하며, 현재 빌더는 `egress_order`와 failover thresholds 같은 multi-egress 설정을 제공합니다.
- `proxy_bypass`와 `garble` 같은 build-time 옵션은 더 깔끔한 네트워크 동작이나 추가 Go binary obfuscation이 필요할 때 확인할 가치가 있습니다.
- `pty`는 Linux/macOS operations에서 가장 유용한 newer-quality-of-life commands 중 하나입니다. interactive PTY를 열고, 더 오래된 `sleep 0` + SOCKS workaround를 쓰지 않고도 더 완전한 terminal interaction을 위해 Mythic-side port를 노출할 수 있기 때문입니다.
- Poseidon의 현재 docs는 특히 macOS-heavy tradecraft에서 흥미롭습니다: `jxa`는 JavaScript for Automation을 in-memory로 실행하고, `screencapture`는 로그인한 desktop을 캡처하며, `clipboard_monitor`는 pasteboard 변경을 스트리밍하고, `execute_library`는 로컬 dylib를 로드해 그 안의 function을 호출하며, `libinject`는 원격 process가 on-disk dylib를 로드하도록 강제합니다.
- 오래 실행되는 jobs의 경우, Poseidon은 post-exploitation work를 hard-killable이 아니라 cooperative한 goroutines/threads에서 실행한다는 점을 기억하세요. docs는 현재 built-in agent obfuscation이 없다는 점도 명시하므로, build/profile-level tradecraft가 강하게 난독화된 commercial implants보다 더 중요합니다.

Mythic-backed operations, JAMF abuse, 또는 MDM-as-C2 ideas와 관련된 macOS-specific tradecraft는 [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md)을 확인하세요.

Linux나 macOS에서 사용하면 흥미로운 commands가 있습니다:

### Common actions

- `cat`: 파일의 내용을 출력
- `cd`: 현재 working directory 변경
- `chmod`: 파일의 permissions 변경
- `config`: 현재 config와 host 정보 보기
- `cp`: 한 위치에서 다른 위치로 파일 복사
- `curl`: 선택적 headers와 method를 사용해 단일 web request 실행
- `upload`: 대상에 파일 업로드
- `download`: 대상 시스템에서 로컬 머신으로 파일 다운로드
- 그리고 더 많은 것들

### Search Sensitive Information

- `triagedirectory`: host의 directory 안에서 sensitive files나 credentials 같은 흥미로운 파일 찾기.
- `getenv`: 현재 모든 environment variables 가져오기.

### macOS-specific tradecraft

- `jxa`: `OSAScript`를 통해 JavaScript for Automation을 in-memory로 실행하며, 별도 script files를 떨어뜨리지 않고 native macOS post-exploitation에 유용합니다.
- `clipboard_monitor`: pasteboard를 폴링하고 변경 사항을 Mythic으로 보고하며, copy/paste에 의존하는 credential/token theft workflows에 편리합니다.
- `screencapture`: macOS에서 사용자의 desktop을 캡처합니다.
- `execute_library`: disk에서 dylib를 로드하고 특정 exported function을 호출합니다.
- `libinject`: shellcode stub를 주입해 다른 macOS process가 disk의 dylib를 로드하도록 강제합니다.
- `persist_launchd`: agent에서 직접 LaunchAgent / LaunchDaemon persistence를 생성합니다.

### Move laterally

- `ssh`: 지정된 credentials를 사용해 host에 SSH로 접속하고, ssh를 spawning하지 않고 PTY를 엽니다.
- `sshauth`: 지정된 credentials를 사용해 지정된 host(s)에 SSH로 접속합니다. SSH를 통해 원격 host에서 특정 command를 실행하거나 파일을 SCP로 전송하는 데에도 사용할 수 있습니다.
- `link_tcp`: TCP를 통해 다른 agent에 링크하여 agent 간 직접 통신을 가능하게 합니다.
- `link_webshell`: webshell P2P profile을 사용해 agent에 링크하여 agent의 web interface에 원격으로 접근할 수 있게 합니다.
- `rpfwd`: Reverse Port Forward를 시작하거나 중지하여 대상 network의 services에 원격으로 접근할 수 있게 합니다.
- `socks`: 대상 network에서 SOCKS5 proxy를 시작하거나 중지하여 compromised host를 통해 traffic을 터널링할 수 있게 합니다. `proxychains` 같은 tools와 호환됩니다.
- `portscan`: host(s)의 open ports를 스캔하며, lateral movement나 추가 공격의 잠재적 대상을 식별하는 데 유용합니다.

### Process execution

- `shell`: `/bin/sh`를 통해 단일 shell command를 실행하여 대상 시스템에서 명령을 직접 실행할 수 있게 합니다.
- `run`: arguments와 함께 disk의 command를 실행하여 대상 시스템에서 binaries나 scripts를 실행할 수 있게 합니다.
- `pty`: interactive PTY를 열어 대상 시스템의 shell과 직접 상호작용할 수 있게 합니다.




## References

- [Mythic Community Agent Feature Matrix](https://mythicmeta.github.io/overview/agent_matrix.html)
- [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [Mythic v3.2 Highlights: Interactive Tasking, Push C2, and Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [Browser Scripts - Mythic Documentation](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
{{#include ../banners/hacktricks-training.md}}
