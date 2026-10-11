# Mythic

{{#include ../banners/hacktricks-training.md}}

## Mythic이란?

Mythic은 red teaming을 위해 설계된 오픈소스 모듈형 협업 command and control (C2) 프레임워크입니다. 운영자는 Mythic을 통해 Windows, Linux, macOS 등 다양한 운영 체제에서 agents (payloads)를 관리하고 배포할 수 있습니다. Mythic은 여러 운영자의 작업 지시, 파일 처리, SOCKS/rpfwd 관리, payload 생성 기능을 제공하는 브라우저 UI를 지원합니다.

모놀리식 프레임워크와 달리 Mythic 저장소 자체에는 **payload 유형이나 C2 프로필이 포함되어 있지 않습니다**. 일반적으로 agent, wrapper, C2 프로필은 외부 구성 요소로 설치되며 Mythic 코어와 독립적으로 업데이트할 수 있습니다.

### 설치

Mythic을 설치하려면 공식 **[Mythic repo](https://github.com/its-a-feature/Mythic)**의 안내를 따르세요. Mythic 디렉터리에서 일반적으로 사용하는 bootstrap 명령은 다음과 같습니다.

```bash
sudo make
sudo ./mythic-cli start
```

Mythic이 이미 실행 중이라면 일반적으로 `./mythic-cli install github ...`을 사용해 새 agent나 profile을 추가한 다음, Mythic을 재시작하거나 새 component를 직접 시작하면 됩니다.

### Agents

Mythic은 여러 agent를 지원합니다. agent는 **침해된 시스템에서 작업을 수행하는 payload**입니다. 각 agent는 특정 요구 사항에 맞게 조정할 수 있으며, 다양한 운영 체제에서 실행할 수 있습니다.

기본적으로 Mythic에는 설치된 agent가 없습니다. 오픈 소스 커뮤니티 agent는 [**https://github.com/MythicAgents**](https://github.com/MythicAgents)에 있으며, [**커뮤니티 기능 매트릭스**](https://mythicmeta.github.io/overview/agent_matrix.html)를 통해 지원되는 운영 체제, payload 형식, wrapper, C2 profile을 빠르게 확인할 수 있습니다.<sup>[[1]](#references)</sup>

해당 조직의 agent를 설치하려면 다음을 실행하면 됩니다:

```bash
sudo ./mythic-cli install github https://github.com/MythicAgents/<agent-name>
sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

`sudo -E` 형식은 root가 아닌 환경에서 설치할 때 유용합니다. Mythic이 이미 실행 중이어도 이전 명령어로 새 agent를 추가할 수 있습니다.

### C2 Profiles

Mythic의 C2 profiles는 **agent가 Mythic 서버와 통신하는 방식**을 정의합니다. 통신 프로토콜, 암호화 방법 및 기타 설정을 지정합니다. Mythic 웹 인터페이스를 통해 C2 profiles를 생성하고 관리할 수 있습니다.

기본적으로 Mythic은 profiles 없이 설치되지만, 다음을 실행해 repo [**https://github.com/MythicC2Profiles**](https://github.com/MythicC2Profiles)에서 일부 profiles를 다운로드할 수 있습니다:

```bash
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/<c2-profile>
sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

현재 operator에게 유용한 프로필:

- [`http`](https://github.com/MythicC2Profiles/http): 기본 비동기 GET/POST 트래픽.
- [`httpx`](https://github.com/MythicC2Profiles/httpx): 여러 callback 도메인, fail-over/round-robin 순환, 사용자 지정 헤더/query 매개변수, 그리고 쿠키·헤더·query 매개변수 또는 본문에 배치되는 메시지 변환(`base64`, `base64url`, `xor`, `netbios`, `prepend`, `append`)을 지원하는 더욱 유연한 HTTP 트래픽.
- [`dynamichttp`](https://github.com/MythicC2Profiles/dynamichttp): 정적 `http` 프로필이 너무 쉽게 식별될 때 사용하는 JSON/TOML 기반 HTTP 메시지 구성.

### 현재 플랫폼 참고 사항

- 이제 여러 공개 agent와 프로필은 사전 빌드된 원격 컨테이너 이미지와 함께 설치됩니다.
  component를 fork하거나 로컬에서 patch했는데도 Mythic이 이전 동작을 계속 사용한다면, 생성된 `.env` 항목에서 `*_REMOTE_IMAGE`, `*_USE_BUILD_CONTEXT`, `*_USE_VOLUME`을 확인하세요. `*_USE_BUILD_CONTEXT="true"`를 활성화하면 Mythic이 원격 이미지를 조용히 재사용하는 대신 로컬 Docker context에서 다시 빌드하는 경우가 많습니다.
- 브라우저 스크립트는 Mythic에서 operator의 편의성을 가장 크게 높여 주는 기능 중 하나입니다. 원시 명령 출력을 표, 스크린샷 뷰어, 다운로드 링크, 검색 링크, 그리고 UI에서 후속 tasking을 실행하는 버튼으로 바꿀 수 있습니다. 최신 Mythic 빌드에서는 각 operator가 자체 스크립트를 유지하고 전역 또는 task별로 활성화할 수 있으며, agent가 일반 텍스트 대신 구조화된 JSON을 반환할 때 가장 효과적입니다. 반복적인 `ls`, `ps`, triage, 파일 브라우저 작업에 특히 유용합니다.<sup>[[4]](#references)[[6]](#references)</sup>
- 최신 Mythic 빌드는 PTY/SOCKS/rpfwd 작업이 많은 환경에서 `sleep 0` polling의 필요성을 줄여 주는 interactive tasking과 Push C2 패턴도 지원합니다. agent/profile이 이를 지원한다면, interactive 채널을 유지하기 위해 계속해서 서버에 check-in을 요청하는 것보다 일반적으로 overhead가 적습니다.<sup>[[3]](#references)</sup>
- 최신 3.4-era Mythic builder는 이전 문서에서 설명한 것보다 더 많은 context를 고려합니다. 이제 선택한 OS나 다른 build 옵션에 따라 build 매개변수를 그룹화하거나 숨길 수 있고, payload type은 하나의 build에서 여러 C2 profile 또는 동일한 C2의 여러 instance를 지원하는지 선언할 수 있으며, C2 매개변수 편차를 통해 agent가 실제로 구현하지 않은 필드를 숨길 수도 있습니다. `http`, `httpx`, `smb`, `tcp`, `websocket` 사이를 전환할 때 안전하고 유효한 build 옵션이 더 이상 고정된 단일 양식이 아니라는 점에서 중요합니다.<sup>[[5]](#references)</sup>
- 사용자 지정 agent/profile 조합을 만들면서 Mythic의 JSON 메시지 형식이나 기본 암호화를 wire 상에서 사용하지 않으려면 `translation_container`를 사용하세요. Mythic은 UUID를 제거하고, 암호화된 blob과 key material을 gRPC를 통해 translator에 전달한 다음, agent 고유 형식의 bytes를 돌려받습니다. 이는 서버 전체를 다시 작성하지 않고 binary protocol, 사용자 지정 framing 또는 agent 측 암호화를 지원하는 깔끔한 방법입니다.
- linked/P2P callback은 tasking만 전달하는 것이 아닙니다. Mythic의 `get_tasking` 흐름에는 응답과 `delegates`, `socks`, `rpfwd`, `interactive` 데이터도 포함될 수 있습니다. 실제로는 하나의 egress callback이 동일한 polling loop에서 내부 callback과 pivot 채널을 처리할 수 있습니다. 하위 agent가 자체적으로 주기적 check-in을 수행한다면, `get_delegate_tasks=false`를 설정해 parent가 내부 callback의 대기 중인 작업을 실수로 가져가지 않도록 하세요.

### Wrapper payload

Wrapper payload를 사용하면 동일한 agent 로직을 유지하면서 전달되거나 저장되는 디스크상의 표현을 바꿀 수 있습니다.

- `service_wrapper`: 다른 payload를 Windows service 실행 파일로 변환합니다. 실행 경로에 유효한 service binary가 필요한 경우 유용합니다.
- `scarecrow_wrapper`: 호환되는 shellcode를 ScareCrow loader로 감싸 loader 기반 EXE/DLL/CPL 등의 결과물을 생성합니다.

## [Apollo Agent](https://github.com/MythicAgents/Apollo)

Apollo는 SpecterOps 교육 과정에서 사용하도록 설계된, 4.0 .NET Framework 기반의 C#으로 작성된 Windows agent입니다.<sup>[[2]](#references)</sup>

다음 명령으로 설치하세요:

```bash
./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### 현재 빌드/프로필 참고 사항

- Apollo는 현재 `WinExe`, `Shellcode`, `Service`, `Source` payload를 생성할 수 있습니다.
- Apollo에서 흔히 사용하는 프로필은 `http`, `httpx`, `smb`, `tcp`, `websocket`입니다.
- 도메인 로테이션, 프록시 지원, 사용자 지정 메시지 배치, 메시지 변환이 필요한 경우에는 기존의 정적 `http` 프로필보다 `httpx`가 대체로 더 유연한 선택입니다.
- Apollo는 기능이 비교적 완전한 커뮤니티 에이전트 중 하나이며, 현재 Mythic 측에서 브라우저 스크립트, 파일/프로세스 브라우저 보기, 스크린샷, keylogging, SOCKS, rpfwd, Push C2, P2P 라우팅 등의 통합 기능을 제공합니다.
- Apollo는 `service_wrapper` 및 `scarecrow_wrapper` 같은 wrapper payload를 지원합니다.
- Apollo는 동적 명령 로드를 지원하므로, 초기 payload를 가볍게 유지하고 모든 post-ex 기능을 첫 빌드에 컴파일하는 대신 나중에 추가 명령이나 Forge 모듈을 로드할 수 있습니다.
- Shellcode 출력을 생성할 때 Apollo의 현재 builder는 Donut 형식 옵션(`Binary`, `Base64`, `C`, `Ruby`, `Python`, `Powershell`, `C#`, `Hex`)과 Donut 우회 동작(`None`, `Abort on fail`, `Continue on fail`)도 제공합니다. 이는 최종적으로 `service_wrapper`, `scarecrow_wrapper` 또는 사용자 지정 loader로 shellcode를 다시 감싸려는 경우 유용합니다.
- `register_file` 및 `register_assembly`는 `execute_assembly`, `execute_pe`, `inline_assembly`, `execute_coff`, `powershell_import`, `powerpick`에 사용되는 staging 기본 요소입니다. 현재 Apollo 빌드에서는 staging된 아티팩트가 DPAPI로 보호된 AES256 blob으로 클라이언트 측에 캐시됩니다.
- `ls` 및 `ps` 결과는 Mythic의 브라우저 스크립트 및 파일/프로세스 브라우저와 특히 잘 통합되어, 협업 작업에서 operator의 triage 속도를 눈에 띄게 높여 줍니다.
- Apollo의 fork-and-run 작업은 `spawnto_x86` / `spawnto_x64`에서 sacrificial process 설정을 상속하고, `ppid`에서 부모 프로세스 선택을 상속한 다음 현재 선택된 injection primitive를 사용합니다. 실제로 이는 한 명령에 대한 OPSEC 조정이 `execute_assembly`, `powerpick`, `mimikatz`, `pth`, `dcsync`, `execute_pe`, `spawn`에 동시에 영향을 주는 경우가 많다는 의미입니다.
- 현재 문서화된 Apollo injection backend에는 syscall을 통한 `CreateRemoteThread`, `QueueUserAPC`(early-bird 방식), `NtCreateThreadEx`가 포함됩니다. 시끄러운 post-exploitation 작업을 수행하기 전에 `get_injection_techniques`를 사용하고, 대상이나 실행하려는 명령과 충돌하는 primitive를 바꿔야 한다면 `set_injection_technique`를 사용하세요.
- `blockdlls`는 post-exploitation 작업용으로 생성된 sacrificial process에만 영향을 줍니다. 기본값인 일반 `rundll32.exe`보다 덜 의심스러운 `spawnto_x64` 대상을 함께 사용하면, assembly/PowerShell 비중이 높은 작업을 실행하기 전에 적용하기 쉬운 Apollo 측 변경 사항 중 하나입니다.

### 탐지 고려 .NET agent 빌드 파이프라인

탐지를 고려한 Apollo fork는 마지막 단계의 **`obfuscate.exe` 실행이 아니라 전체 빌드 시스템 문제**로 다뤄야 합니다. 이 사례 연구는 일반적인 [AV evasion methodology](av-bypass.md) 및 [.NET inspection tools](../reversing/reversing-tools-basic-methods/README.md)를 보완합니다. wire identifier, IL metadata, dependency 패키징, reflection, 동적으로 컴파일되는 task의 변경은 하나의 호환성 경계를 형성합니다.<sup>[[8]](#references)</sup>

#### YARA를 고려한 프로토콜 변경

코드를 변경하기 전에 공개된 파일/메모리 규칙을 점검하세요. 예를 들어 Elastic의 `Multi_Trojan_Mythic_4beb7e17`은 `task_id`, `post_response`, `c2_profile`, `get_tasking`, `get_delegate_tasks`를 포함한 11개의 Mythic JSON/action 문자열 중 **7개 이상**이 존재할 때 매칭됩니다. 충분한 수의 필드 이름을 바꾸면 이 임계값을 피할 수 있지만, 이는 외형만 다른 심볼이 아니라 프로토콜 값입니다. 따라서 agent와 해당 server/profile 구현을 함께 변경해야 합니다.<sup>[[7]](#references)[[8]](#references)</sup>

이렇게 해도 정적 특징 집합 하나만 제거됩니다. 체크인 주기, 메시지 형태, task/response 흐름, 런타임 문자열 재구성은 여전히 동작 기반 또는 메모리 지표로 남을 수 있습니다. 따라서 문자열 검사 결과가 깨끗한 것을 성공으로 간주하지 말고, 빌드된 아티팩트와 실제 callback을 모두 검증하세요.<sup>[[8]](#references)</sup>

#### 전역 변환을 적용하기 전에 병합

Costura 같은 도구로 리소스를 삽입하면 종속 어셈블리가 압축된 리소스로 남습니다. 바깥쪽 모듈만 처리하는 obfuscator는 해당 어셈블리의 형식 이름과 metadata를 놓치며, 각 DLL을 개별적으로 obfuscate하면 어셈블리 간 계약에 서로 호환되지 않는 이름이 지정될 수 있습니다. 먼저 빌드 출력을 IL 수준에서 병합한 다음(예: [ILRepack](https://github.com/gluck/il-repack)), 결과 모듈에 단일 rename map을 적용하세요.<sup>[[8]](#references)</sup>

```text
agent.exe + dependency DLLs
          -> ILRepack -> merged.exe
          -> dnlib IL/metadata transforms
          -> AsmResolver PE/resource patching
          -> final payload
```

커스텀 pass는 managed IL/metadata 변환에 [dnlib](https://github.com/0xd4d/dnlib)을, write 후 PE/resource 패치에 [AsmResolver](https://github.com/Washi1337/AsmResolver)를 사용할 수 있습니다. 사례 연구에서는 대상 `ldstr` 명령어가 새로 생성한 16바이트 rolling-XOR 키를 사용하는 integer-token/decryptor 호출로 바뀌었으며, 심볼과 namespace는 짧고 순차적인 식별자 대신 그럴듯한 엔터프라이즈 스타일 이름으로 매핑되었습니다. 다른 pass에서는 선택된 compiler/debugger 속성을 제거하고, merger/embedding 참조를 지우고, 리소스 이름을 바꾸고, 버전 정보를 패치했습니다. 서로 독립적인 빌드마다 이름, dead code, 암호화 재료를 다시 생성하세요. 암호문을 바꾸면 안정적으로 반복되는 바이트는 사라지지만, 안정적인 decryptor나 식별 가능한 변환 패턴 자체가 signature가 됩니다.<sup>[[8]](#references)</sup>

#### 동적 task를 payload와 동기화하기

Apollo는 서버 측에서 task 소스를 컴파일하고, DLL 바이트를 전송한 다음 `Assembly.Load()`로 로드할 수 있습니다. 기본 agent의 public 타입 이름을 바꾸고 나면, 원래 API에 맞춰 컴파일된 이후 task는 더 이상 해당 타입을 확인할 수 없습니다. 내보낸 rename map을 payload별 ABI 산출물로 취급하세요.<sup>[[8]](#references)</sup>

1. map과 타입 컨텍스트를 정확한 payload/build 식별자에 연결합니다.
2. 각 task 빌드에서 해당 map을 가져와 임시 소스 트리를 다시 작성합니다.
3. 확인된 namespace, 타입, 중첩/제네릭 타입, 필드, 속성 참조만 다시 작성한 다음 난독화된 병합 어셈블리를 기준으로 컴파일합니다.
4. task를 전달하기 전에 map이 없거나 일치하지 않으면 거부하고, 컴파일 후 초기화 테스트를 실행합니다.

식별자는 문자열, 지역 선언, 멤버 접근, framework 타입 또는 관련 없는 namespace에도 나타날 수 있으므로, 무분별한 전역 치환은 안전하지 않습니다. 텍스트/정규식 rewriter를 계속 사용한다면 해당 컨텍스트를 명시적으로 보호하고 map 스키마나 rename pass가 바뀔 때마다 회귀 테스트를 수행하세요.<sup>[[8]](#references)</sup>

#### Reflection 계약을 namespace에 종속되지 않게 만들기

`t.FullName.StartsWith("Tasks.")`를 확인하는 discovery 코드는 namespace를 필수 조건으로 만들기 때문에 namespace remapping 이후 실패합니다. 대신 안정적인 타입 관계를 기준으로 검색하되, dispatch가 여전히 `t.Name`을 사용한다면 command 클래스 이름은 유지하세요.<sup>[[8]](#references)</sup>

```csharp
foreach (Type t in _tasksAsm.GetExportedTypes())
{
    if (t.IsSubclassOf(typeof(Tasking)) && !t.IsAbstract)
        _loadedTaskTypes[t.Name] = t;
}
```

Reflection에서 확인할 수 있는 이름, serializer 필드, 진입점, 어셈블리 간 API 중 이름을 변경하면 안 되는 항목의 명시적인 allowlist를 유지하세요. 마지막으로 ILSpy/dnSpy로 결과를 디컴파일하고, 파일 및 메모리 표현을 모두 검사한 뒤, EDR 실험 환경에서 모든 command/loader 경로를 실행해 보세요. 빌드가 성공적으로 시작되더라도 이름 변경으로 인해 작업이 손상되거나 실행 후에만 탐지되는 동작이 포함될 수 있습니다.<sup>[[8]](#references)</sup>

이 에이전트에는 Cobalt Strike의 Beacon과 매우 유사한 여러 command와 몇 가지 추가 기능이 있습니다. 그중에는 다음 기능이 포함됩니다.

### 일반 작업

- `cat`: 파일 내용 출력
- `cd`: 현재 작업 디렉터리 변경
- `cp`: 파일을 한 위치에서 다른 위치로 복사
- `ls`: 현재 디렉터리나 지정한 경로의 파일 및 디렉터리 목록 표시
- `ifconfig`: 네트워크 어댑터 및 인터페이스 정보 확인
- `netstat`: TCP 및 UDP 연결 정보 확인
- `pwd`: 현재 작업 디렉터리 출력
- `ps`: 대상 시스템에서 실행 중인 프로세스 목록 표시(추가 정보 포함)
- `jobs`: 장시간 실행되는 tasking과 관련된 모든 실행 중인 job 목록 표시
- `download`: 대상 시스템에서 로컬 머신으로 파일 다운로드
- `upload`: 로컬 머신에서 대상 시스템으로 파일 업로드
- `reg_query`: 대상 시스템의 registry 키 및 값 조회
- `reg_write_value`: 지정한 registry 키에 새 값 쓰기
- `sleep`: Mythic 서버에 체크인하는 빈도를 결정하는 에이전트의 sleep 간격 변경
- 기타 여러 command가 있습니다. 사용 가능한 전체 command 목록은 `help`를 사용해 확인하세요.

### 권한 상승

- `getprivs`: 현재 thread token에서 가능한 한 많은 privilege 활성화
- `getsystem`: winlogon의 handle을 열고 token을 복제하여 효과적으로 SYSTEM 수준으로 권한 상승
- `make_token`: 새 logon session을 만들고 에이전트에 적용하여 다른 사용자의 impersonation 허용
- `steal_token`: 다른 프로세스에서 primary token을 훔쳐 에이전트가 해당 프로세스 사용자를 impersonation하도록 허용
- `pth`: Pass-the-Hash 공격으로, 평문 password 없이 NTLM hash를 사용해 사용자로 인증
- `mimikatz`: Mimikatz command를 실행해 메모리나 SAM database에서 credential, hash 및 기타 민감한 정보 추출
- `rev2self`: 에이전트의 token을 primary token으로 되돌려 원래 수준으로 권한을 낮춤
- `ppid`: 새 parent process ID를 지정해 post-exploitation job의 parent process를 변경하고, job 실행 context를 더 효과적으로 제어
- `printspoofer`: PrintSpoofer command를 실행해 print spooler 보안 조치를 우회하고 권한 상승 또는 code 실행 수행
- `dcsync`: 사용자의 Kerberos key를 로컬 머신에 동기화해 오프라인 password cracking 또는 추가 공격 수행
- `ticket_cache_add`: 현재 logon session이나 지정한 session에 Kerberos ticket을 추가해 ticket 재사용 또는 impersonation 수행

### 프로세스 실행

- `assembly_inject`: .NET assembly loader를 원격 프로세스에 inject
- `blockdlls`: post-exploitation job에서 Microsoft 서명이 없는 DLL의 로드를 차단
- `execute_assembly`: 에이전트 context에서 .NET assembly 실행
- `execute_coff`: COFF 파일을 메모리에서 실행해 컴파일된 code를 메모리 내에서 실행
- `execute_pe`: unmanaged executable(PE) 실행
- `keylog_inject`: keylogger를 다른 프로세스에 inject하고 keystroke를 Mythic의 keylog view로 전송
- `screenshot` / `screenshot_inject`: 현재 desktop을 직접 캡처하거나 대상 프로세스/session에 screenshot assembly를 inject하여 캡처
- `get_injection_techniques`: 사용 가능한 injection technique과 현재 선택된 technique 표시
- `inline_assembly`: .NET assembly를 disposable AppDomain에서 실행해 에이전트의 메인 프로세스에 영향을 주지 않고 임시로 code 실행
- `register_assembly`: 나중에 실행할 .NET assembly 등록
- `register_file`: 이후 `execute_*` 또는 PowerShell tasking에서 사용하도록 에이전트 cache에 파일 등록
- `run`: 시스템의 PATH를 사용해 실행 파일을 찾아 대상 시스템에서 실행
- `set_injection_technique`: post-exploitation job에서 사용하는 injection primitive 변경
- `shinject`: shellcode를 원격 프로세스에 inject해 임의의 code를 메모리에서 실행
- `inject`: 에이전트 shellcode를 원격 프로세스에 inject해 에이전트 code를 메모리에서 실행
- `spawn`: 지정한 executable에서 새 에이전트 session을 실행해 새 프로세스에서 shellcode 실행
- `spawnto_x64` 및 `spawnto_x86`: post-exploitation job에서 사용하는 기본 binary를 지정한 경로로 변경. 인자 없이 `rundll32.exe`를 사용하는 방식은 매우 시끄럽습니다.

### Mythic Forge

이를 통해 Mythic Forge에서 **COFF/BOF** 파일을 로드할 수 있습니다. Mythic Forge는 대상 시스템에서 실행할 수 있는 사전 컴파일된 payload와 tool의 repository입니다. 로드 가능한 모든 command를 사용하면 현재 에이전트 프로세스에서 BOF로 실행하여 일반적인 작업을 수행할 수 있습니다(별도의 프로세스를 생성하는 것보다 보통 OPSEC 측면에서 더 유리함).

다음 명령으로 설치를 시작하세요:

```bash
./mythic-cli install github https://github.com/MythicAgents/forge.git
```

그런 다음 `forge_collections`를 사용해 Mythic Forge의 COFF/BOF 모듈을 표시하면, 모듈을 선택해 agent 메모리에 로드하고 실행할 수 있습니다. 기본적으로 Apollo에는 다음 두 컬렉션이 추가됩니다.

- `forge_collections {"collectionName":"SharpCollection"}`
- `forge_collections {"collectionName":"SliverArmory"}`

모듈을 로드하면 `forge_bof_sa-whoami` 또는 `forge_bof_sa-netuser` 같은 명령으로 목록에 표시됩니다.

BOF의 경우 Forge가 하나의 평평한 인자 문자열만 Apollo에 전달하는 것은 아니라는 점을 기억하세요. BOF 매개변수를 Mythic의 typed-array 형식으로 매핑한 다음 Apollo의 `execute_coff` 흐름으로 전달합니다. Forge로 로드한 BOF가 예상과 다르게 동작하면 입력한 명령줄만 확인하지 말고, 예상되는 BOF 인자 형식과 entrypoint도 확인하세요. 또한 Apollo의 최신 BOF loader는 훨씬 이전의 2.3.1-era 빌드와 비교해 인자 처리가 변경되었습니다. 따라서 오래된 BOF나 컬렉션은 marshaling 요구 사항이 변경된 것만으로도 실패할 수 있습니다.

### PowerShell 및 스크립트 실행

- `powershell_import`: 나중에 실행할 수 있도록 새 PowerShell 스크립트(.ps1)를 agent 캐시에 가져옵니다.
- `powershell`: agent 컨텍스트에서 PowerShell 명령을 실행하여 고급 스크립팅 및 자동화를 지원합니다.
- `powerpick`: PowerShell loader 어셈블리를 sacrificial process에 주입한 다음, PowerShell 명령을 실행합니다(PowerShell 로깅 없이).
- `psinject`: 지정된 프로세스에서 PowerShell을 실행하여 다른 프로세스의 컨텍스트에서 스크립트를 대상으로 실행할 수 있습니다.
- `shell`: agent 컨텍스트에서 shell 명령을 실행하며, cmd.exe에서 명령을 실행하는 것과 유사합니다.

### 측면 이동

- `jump_psexec`: 먼저 Apollo agent 실행 파일(apollo.exe)을 복사한 뒤 실행하는 PsExec 기법으로 새 호스트에 측면 이동합니다.
- `jump_wmi`: 먼저 Apollo agent 실행 파일(apollo.exe)을 복사한 뒤 실행하는 WMI 기법으로 새 호스트에 측면 이동합니다.
- `link` 및 `unlink`: callback 간 P2P 링크(예: SMB/TCP)를 생성하고 해제합니다.
- `wmiexecute`: 가장을 위한 자격 증명을 선택적으로 사용해 WMI로 로컬 또는 지정된 원격 시스템에서 명령을 실행합니다.
- `net_dclist`: 지정된 도메인의 도메인 컨트롤러 목록을 가져오며, 측면 이동의 잠재적 대상을 식별하는 데 유용합니다.
- `net_localgroup`: 지정된 컴퓨터의 로컬 그룹을 나열합니다. 컴퓨터를 지정하지 않으면 localhost를 기본값으로 사용합니다.
- `net_localgroup_member`: 로컬 또는 원격 컴퓨터에서 지정된 그룹의 로컬 그룹 구성원 정보를 가져와 특정 그룹의 사용자를 열거할 수 있습니다.
- `net_shares`: 지정된 컴퓨터의 원격 공유 및 접근 가능 여부를 나열하며, 측면 이동의 잠재적 대상을 식별하는 데 유용합니다.
- `socks`: 대상 네트워크에서 SOCKS 5 호환 프록시를 활성화하여 침해된 호스트를 통해 트래픽을 터널링할 수 있습니다. proxychains 같은 도구와 호환됩니다.
- `rpfwd`: 대상 호스트의 지정된 포트에서 수신을 시작하고 Mythic을 통해 원격 IP 및 포트로 트래픽을 전달하여 대상 네트워크의 서비스에 원격으로 접근할 수 있습니다.
- `listpipes`: 로컬 시스템의 모든 named pipe를 나열합니다. IPC 메커니즘을 이용한 측면 이동이나 권한 상승에 유용할 수 있습니다.

`jump_wmi` 또는 `wmiexecute`에서 내부적으로 사용하는 저수준 WMI 실행 기본 요소는 [WmiExec](lateral-movement/wmiexec.md)를 확인하세요. 더 폭넓은 pivoting 패턴은 [Tunneling and Port Forwarding](../generic-hacking/tunneling-and-port-forwarding.md)을 확인하세요.

### 기타 명령
- `help`: 특정 명령에 대한 자세한 정보나 agent에서 사용할 수 있는 모든 명령에 대한 일반 정보를 표시합니다.
- `clear`: 작업을 'cleared'로 표시해 agent가 가져가지 못하게 합니다. `all`을 지정하면 모든 작업을 지우고, `task Num`을 지정하면 특정 작업을 지울 수 있습니다.  


## [Poseidon Agent](https://github.com/MythicAgents/poseidon)

Poseidon은 **Linux 및 macOS** 실행 파일로 컴파일되는 Golang agent입니다.

```bash
./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### 현재 빌드/프로필 참고 사항

- 현재 Poseidon 빌드는 `x86_64` 및 `arm64` 아키텍처에서 Linux와 macOS를 대상으로 합니다.
- 지원되는 출력 형식에는 네이티브 실행 파일과 `dylib`, `so` 같은 공유 라이브러리 형식의 출력이 포함됩니다.
- Poseidon은 `http`, `websocket`, `tcp`, `dynamichttp`를 지원하며, 현재 빌더는 `egress_order` 및 장애 조치 임계값 같은 다중 egress 설정을 제공합니다.
- Poseidon의 현재 capability metadata에는 browser scripts, file/process browser 통합, interactive tasking, keylogging, screenshots, Push C2, SOCKS, rpfwd, P2P도 포함되어 있으므로 단순한 원격 shell이 아니라 실제 Linux/macOS pivot node로 사용할 수 있습니다.
- 더 깔끔한 네트워크 동작이나 Go binary obfuscation을 강화해야 한다면 `proxy_bypass`, `garble` 같은 빌드 시점 옵션을 확인해 볼 만합니다.
- `pty`는 Linux/macOS 작업에 유용한 최신 편의 기능 명령 중 하나입니다. interactive PTY를 열고 Mythic 측 포트를 노출해, 기존의 `sleep 0` + SOCKS 우회 방법 없이도 더 완전한 터미널 상호작용을 지원할 수 있습니다.
- Poseidon의 최신 문서는 macOS 중심 tradecraft에 특히 유용합니다. `jxa`는 JavaScript for Automation을 메모리에서 실행하고, `screencapture`는 로그인된 데스크톱을 캡처하며, `clipboard_monitor`는 pasteboard 변경 사항을 스트리밍합니다. `execute_library`는 로컬 dylib를 로드하고 해당 함수 하나를 호출하며, `libinject`는 원격 프로세스가 디스크에 있는 dylib를 로드하도록 강제합니다.
- 장시간 실행되는 작업의 경우, Poseidon이 goroutines/threads에서 post-exploitation 작업을 실행하며, 이들은 강제로 종료할 수 없고 cooperative 방식으로 동작한다는 점을 기억하세요. 문서에는 현재 내장된 agent obfuscation이 없다고도 명시되어 있으므로, obfuscation이 강력한 상용 implant보다 빌드/프로필 수준의 tradecraft가 더 중요합니다.

Mythic 기반 작업의 macOS 특화 tradecraft, JAMF 악용 또는 MDM-as-C2 아이디어는 [macOS Red Teaming](../macos-hardening/macos-red-teaming/README.md)을 참조하세요.

Linux 또는 macOS에서 사용할 때 유용한 명령이 몇 가지 있습니다.

### 일반적인 작업

- `cat`: 파일 내용 출력
- `cd`: 현재 작업 디렉터리 변경
- `chmod`: 파일 권한 변경
- `config`: 현재 설정 및 호스트 정보 보기
- `cp`: 파일을 한 위치에서 다른 위치로 복사
- `curl`: 선택적 헤더 및 method를 사용해 단일 웹 요청 실행
- `upload`: 파일을 타깃에 업로드
- `download`: 타깃 시스템에서 로컬 머신으로 파일 다운로드
- 기타 다수

### 민감 정보 검색

- `triagedirectory`: 호스트의 디렉터리에서 민감한 파일이나 자격 증명 등 흥미로운 파일 검색
- `getenv`: 현재 환경 변수 모두 가져오기

### macOS 특화 tradecraft

- `jxa`: `OSAScript`를 통해 JavaScript for Automation을 메모리에서 실행합니다. 별도의 script 파일을 저장하지 않고 macOS 네이티브 post-exploitation을 수행하는 데 유용합니다.
- `clipboard_monitor`: pasteboard를 확인하고 변경 사항을 Mythic에 보고합니다. 복사/붙여넣기에 의존하는 자격 증명/token 탈취 작업에 유용합니다.
- `screencapture`: macOS에서 사용자의 데스크톱을 캡처합니다.
- `execute_library`: 디스크에서 dylib를 로드하고 특정 exported function을 호출합니다.
- `libinject`: 다른 macOS 프로세스가 디스크에서 dylib를 로드하도록 강제하는 shellcode stub을 주입합니다.
- `persist_launchd`: agent에서 직접 LaunchAgent / LaunchDaemon persistence를 생성합니다.

### 측면 이동

- `ssh`: 지정된 자격 증명을 사용해 호스트에 SSH로 접속하고, ssh를 실행하지 않고 PTY를 엽니다.
- `sshauth`: 지정된 자격 증명을 사용해 지정된 호스트에 SSH로 접속합니다. 이를 사용해 SSH로 원격 호스트에서 특정 명령을 실행하거나 파일을 SCP로 전송할 수도 있습니다.
- `link_tcp`: TCP를 통해 다른 agent에 연결하여 agent 간 직접 통신을 허용합니다.
- `link_webshell`: webshell P2P profile을 사용해 agent에 연결하여 agent의 웹 인터페이스에 원격으로 접근할 수 있습니다.
- `rpfwd`: Reverse Port Forward를 시작하거나 중지하여 타깃 네트워크의 서비스에 원격으로 접근할 수 있습니다.
- `socks`: 타깃 네트워크에서 SOCKS5 proxy를 시작하거나 중지하여 침해된 호스트를 통해 트래픽을 터널링할 수 있습니다. proxychains 같은 도구와 호환됩니다.
- `portscan`: 호스트의 열린 포트를 스캔하여 측면 이동 또는 추가 공격의 잠재적 타깃을 찾습니다.

### 프로세스 실행

- `shell`: `/bin/sh`를 통해 단일 shell 명령을 실행하여 타깃 시스템에서 직접 명령을 실행할 수 있습니다.
- `run`: 디스크에서 인수를 지정해 명령을 실행하여 타깃 시스템에서 binary 또는 script를 실행할 수 있습니다.
- `pty`: interactive PTY를 열어 타깃 시스템의 shell과 직접 상호작용할 수 있습니다.

## References

- [1] [Mythic Community Agent 기능 매트릭스](https://mythicmeta.github.io/overview/agent_matrix.html)
- [2] [Apollo README](https://github.com/MythicAgents/Apollo/blob/master/README.md)
- [3] [Mythic v3.2 주요 내용: Interactive Tasking, Push C2 및 Dynamic File Browser](https://posts.specterops.io/mythic-v3-2-highlights-interactive-tasking-push-c2-and-dynamic-file-browser-7035065e2b3d)
- [4] [Browser Scripts - Mythic 문서](https://docs.mythic-c2.net/operational-pieces/browser-scripts)
- [5] [Mythic 3.3->3.4 업데이트](https://docs.mythic-c2.net/updating/mythic-3.3-greater-than-3.4-updates)
- [6] [Mythic의 숨겨진 보석으로 Red Team Ops 혁신하기: Browser Scripting](https://specterops.io/blog/2025/08/21/transforming-red-team-ops-with-mythics-hidden-gems-browser-scripting/)
- [7] [Elastic protections-artifacts: Multi_Trojan_Mythic YARA rules](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Multi_Trojan_Mythic.yar)
- [8] [Fork에서 Framework까지: Apollo 수정으로 Agent Invasion에 관해 배운 것](https://bishopfox.com/blog/from-fork-to-framework-what-modifying-apollo-taught-us-about-agent-invasion)
{{#include ../banners/hacktricks-training.md}}
