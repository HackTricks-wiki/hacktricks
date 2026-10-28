# Eskalacija privilegija pomoću Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** se može koristiti za pokretanje programa pri **pokretanju sistema**. Pogledajte koji su binarni fajlovi podešeni da se pokreću pri pokretanju sistema pomoću:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Zakazani zadaci

**Zadaci** mogu biti zakazani da se pokreću **određenom učestalošću**. Koristite sledeće komande da biste videli koji su binaries zakazani za pokretanje:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

Zadatak kreiran pomoću `/sc ONLOGON /rl HIGHEST` zahteva najviši nivo izvršavanja **dostupan identitetu pod kojim je registrovan**; sama ova opcija ne menja taj identitet niti zaobilazi UAC. Proces sa niskim privilegijama ne može da registruje zadatak sa najvišim nivoom izvršavanja niti da izabere SYSTEM kao identitet zadatka. Tretirajte gornji primer kao radnju koju izvršava već povišen proces, a ne kao put od standardnog korisnika do SYSTEM.<sup>[[8]](#references)</sup>

Omogućen zadatak koji se izvršava kao SYSTEM treba proveriti čak i kada su njegova definicija i datoteka radnje zaštićene. [Planer zadataka zahteva dozvolu za izvršavanje zadatka da bi ga pokrenuo na zahtev](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). Ako korisnik sa niskim privilegijama ima tu dozvolu, pregledajte tačnu radnju, naročito PowerShell skripte koje menjaju ACL-ove u Active Directory-ju ili resetuju postavke zaštite naloga. Proverite postavku `AllowDemandStart` zadatka i utvrdite šta skripta radi i kako obrađuje ulazne podatke; sama dozvola za pokretanje fiksnog zadatka ne podrazumeva izvršavanje proizvoljnog koda.

## Fascikle

Sve binarne datoteke smeštene u **fasciklama za pokretanje izvršavaju se pri pokretanju**. Uobičajene fascikle za pokretanje navedene su u nastavku, ali je putanja fascikle za pokretanje navedena u registru. [Pročitajte ovo da biste saznali gde.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

Unos u Startup folderu korisnika sa višim privilegijama može da pokrene zaštićenu skriptu koja više puta otvara datoteke iz direktorijuma u koji drugi korisnik može da upisuje. Pre nego što taj direktorijum smatrate putem za eskalaciju privilegija, proverite **stvarni identitet za prijavljivanje**, ulazni direktorijum skripte i njegove ACL-ove, kao i tačnu radnju. Konkretno, [`hh.exe` otvara kompajlirane HTML Help (`.chm`) datoteke](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); skripta koja mu prosleđuje datoteke koje je dostavio pozivalac prelazi granicu poverenja u sadržaj, čak i ako proverava naziv datoteke ili njene prve bajtove. [HTML Help smernice mogu da ograniče izvršne prečice](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), zato proverite instaliranu smernicu i ponašanje dostupnog sadržaja. Samo `.chm` ekstenzija ili magični bajtovi ne dokazuju izvršavanje koda sa višim privilegijama. Pregledajte autorun, komandnu liniju procesa i dozvole za putanju, bez otvaranja nepouzdane datoteke tokom enumeracije.

Ista granica poverenja u sadržaj postoji kada osoba sa višim privilegijama **ručno otvori** `.chm` iz fascikle sa dokumentacijom koju drugi korisnik može da zameni. Proverite tačnu datoteku i dozvole za upis u nadređeni direktorijum, stvarni identitet pregledača i događaj otvaranja, kao i efektivnu HTML Help smernicu. Fascikla u koju može da se upisuje ili zahtev za pregled dokumentacije ne dokazuju da je korisnik sa višim privilegijama otvorio sadržaj koji je kontrolisao napadač.

> **NAPOMENA**: Ranjivosti *path traversal* pri raspakivanju arhiva (kao što je ona iskorišćena u WinRAR-u pre verzije 7.13 – CVE-2025-8088) mogu da se iskoriste za **postavljanje payloads direktno u ove Startup fascikle tokom raspakivanja**, što dovodi do izvršavanja koda pri sledećem prijavljivanju korisnika. Za detaljan pregled ove tehnike pogledajte:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registar

> [!TIP]
> [Napomena odavde](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Unos registra **Wow6432Node** ukazuje na to da koristite 64-bitnu verziju sistema Windows. Operativni sistem koristi ovaj ključ da bi prikazao zaseban prikaz ključa HKEY_LOCAL_MACHINE\SOFTWARE za 32-bitne aplikacije koje rade na 64-bitnim verzijama sistema Windows.

### Pokretanja

**Uobičajeno poznati** AutoRun unosi u registru:

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Wow6432Npde\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce`
- `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx`

Ključevi registra poznati kao **Run** i **RunOnce** namenjeni su automatskom pokretanju programa svaki put kada se korisnik prijavi u sistem. Komandna linija dodeljena kao vrednost podataka ključa ograničena je na najviše 260 znakova.<sup>[[2]](#references)</sup>

**Pokretanja servisa** (mogu da kontrolišu automatsko pokretanje servisa tokom podizanja sistema):

- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce`
- `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`
- `HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices`

**RunOnceEx:**

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx`
- `HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx`

U sistemu Windows Vista i novijim verzijama, ključevi registra **Run** i **RunOnce** ne kreiraju se automatski. Unosi u ovim ključevima mogu direktno da pokreću programe ili da ih navedu kao zavisnosti. Na primer, za učitavanje DLL datoteke pri prijavljivanju, može se koristiti ključ registra **RunOnceEx** zajedno sa ključem „Depend“. To se može demonstrirati dodavanjem unosa u registar koji izvršava „C:\temp\evil.dll“ tokom pokretanja sistema:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: Ako možete da pišete u bilo koji od pomenutih registara unutar **HKLM**, možete eskalirati privilegije kada se drugi korisnik prijavi.

> [!TIP]
> **Exploit 2**: Ako možete da zamenite bilo koju binarnu datoteku navedenu u nekom od registara unutar **HKLM**, možete da izmenite tu binarnu datoteku tako da sadrži backdoor kada se drugi korisnik prijavi i eskalirate privilegije.

```bash
#CMD
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE

reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices
reg query HKCU\Software\Wow5432Node\Microsoft\Windows\CurrentVersion\RunServices

reg query HKLM\Software\Microsoft\Windows\RunOnceEx
reg query HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Microsoft\Windows\RunOnceEx
reg query HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx

#PowerShell
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunE'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices'

Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKLM\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\RunOnceEx'
Get-ItemProperty -Path 'Registry::HKCU\Software\Wow6432Node\Microsoft\Windows\RunOnceEx'
```

### Putanja za pokretanje

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Prečice smeštene u fasciklu **Startup** automatski će pokrenuti servise ili aplikacije prilikom prijavljivanja korisnika ili ponovnog pokretanja sistema. Lokacija fascikle **Startup** definisana je u registru za opsege **Local Machine** i **Current User**. To znači da će svaka prečica dodata na navedene lokacije fascikle **Startup** obezbediti pokretanje povezanog servisa ili programa nakon prijavljivanja ili ponovnog pokretanja, što predstavlja jednostavan način za automatsko pokretanje programa.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Ako možete da zamenite bilo koju fasciklu [User] Shell pod **HKLM**, moći ćete da je usmerite na fasciklu kojom vi upravljate i postavite backdoor koji će se izvršavati svaki put kada se korisnik prijavi na sistem, čime se povećavaju privilegije.

```bash
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders" /v "Common Startup"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" /v "Common Startup"

Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' -Name "Common Startup"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name "Common Startup"
```

### UserInitMprLogonScript

- `HKCU\Environment\UserInitMprLogonScript`

Ova korisnička vrednost registra može da upućuje na skriptu ili komandu koja se izvršava kada se taj korisnik prijavi. Uglavnom služi kao primitive za **persistence**, jer se izvršava samo u kontekstu pogođenog korisnika, ali je ipak vredi proveriti tokom post-exploitation provera i pregleda autorun stavki.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Ako možete da upisujete ovu vrednost za trenutnog korisnika, možete ponovo da pokrenete izvršavanje pri sledećoj interaktivnoj prijavi, bez potrebe za administratorskim pravima. Ako možete da je upišete u hive registra drugog korisnika, možete dobiti izvršavanje koda kada se taj korisnik prijavi.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Napomene:

- Prednost dajte punim putanjama do `.bat`, `.cmd`, `.ps1` ili drugih launcher datoteka koje su već čitljive ciljnom korisniku.
- Ovo ostaje aktivno nakon odjave ili ponovnog pokretanja dok se vrednost ne ukloni.
- Za razliku od `HKLM\...\Run`, ovo samo po sebi ne dodeljuje povišene privilegije; reč je o per-user persistence.

### Winlogon ključevi

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Ključ **Userinit** je obično podešen na **userinit.exe**. Međutim, ako se ovaj ključ izmeni, navedeni izvršni fajl će takođe pokrenuti **Winlogon** prilikom prijave korisnika. Slično tome, očekuje se da ključ **Shell** pokazuje na **explorer.exe**, koji je podrazumevani shell za Windows.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> Ako možete da prepišete vrednost registra ili binarni fajl, moći ćete da povećate privilegije.

### Podešavanja smernica

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Proverite ključ **Run**.

```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```

### AlternateShell

### Menjanje komandnog prompta u bezbednom režimu

U Windows registru, pod `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, postoji vrednost **`AlternateShell`** koja je podrazumevano postavljena na `cmd.exe`. To znači da se pri izboru opcije „Safe Mode with Command Prompt“ tokom pokretanja (pritiskom na F8) koristi `cmd.exe`. Međutim, moguće je podesiti računar tako da se automatski pokrene u ovom režimu, bez potrebe za pritiskom na F8 i ručnim izborom opcije.

Koraci za kreiranje opcije pokretanja koja automatski pokreće „Safe Mode with Command Prompt“:<sup>[[5]](#references)</sup>

1. Promenite atribute datoteke `boot.ini` da biste uklonili oznake samo za čitanje, sistemske i skrivene datoteke: `attrib c:\boot.ini -r -s -h`
2. Otvorite `boot.ini` za uređivanje.
3. Ubacite red poput ovog: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Sačuvajte izmene u `boot.ini`.
5. Vratite prvobitne atribute datoteke: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Promena ključa registra **AlternateShell** omogućava podešavanje prilagođene komandne ljuske, što može dovesti do neovlašćenog pristupa.
- **Exploit 2 (PATH dozvole za pisanje):** Dozvole za pisanje u bilo kom delu sistemske promenljive **PATH**, naročito pre `C:\Windows\system32`, omogućavaju izvršavanje prilagođenog `cmd.exe`, koji bi mogao da posluži kao backdoor ako se sistem pokrene u bezbednom režimu.
- **Exploit 3 (PATH i boot.ini dozvole za pisanje):** Pristup za pisanje u `boot.ini` omogućava automatsko pokretanje u bezbednom režimu, što olakšava neovlašćen pristup pri sledećem ponovnom pokretanju.

Da biste proverili trenutnu postavku **AlternateShell**, koristite ove komande:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Instalirana komponenta

Active Setup je funkcija u Windowsu koja **pokreće proces pre nego što se okruženje radne površine u potpunosti učita**. Ona daje prioritet izvršavanju određenih komandi, koje moraju da se završe pre nego što se nastavi prijavljivanje korisnika. Ovaj proces se odvija čak i pre aktiviranja drugih stavki pri pokretanju, kao što su one u odeljcima Run ili RunOnce registra.

Active Setup se upravlja pomoću sledećih ključeva registra:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

U okviru ovih ključeva postoje različiti potključevi, od kojih svaki odgovara određenoj komponenti. Vrednosti ključeva od posebnog značaja obuhvataju:

- **IsInstalled:**
  - `0` označava da se komanda komponente neće izvršiti.
  - `1` znači da će se komanda izvršiti jednom za svakog korisnika; to je podrazumevano ponašanje ako vrednost `IsInstalled` nedostaje.
- **StubPath:** Definiše komandu koju će izvršiti Active Setup. To može biti bilo koja važeća komandna linija, poput pokretanja programa `notepad`.

**Bezbednosni uvidi:**

- Izmena ili upisivanje u ključ u kom je **`IsInstalled`** postavljen na `"1"` i definisan određeni **`StubPath`** može dovesti do neovlašćenog izvršavanja komandi, što potencijalno omogućava eskalaciju privilegija.
- Izmena binarne datoteke na koju upućuje bilo koja vrednost **`StubPath`** takođe može omogućiti eskalaciju privilegija, uz odgovarajuće dozvole.

Za pregled konfiguracija **`StubPath`** u Active Setup komponentama mogu se koristiti sledeće komande:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Pregled Browser Helper Objects (BHO)

Browser Helper Objects (BHO) su DLL moduli koji dodaju dodatne funkcije Microsoft Internet Explorer-u. Učitavaju se u Internet Explorer i Windows Explorer pri svakom pokretanju. Međutim, njihovo izvršavanje može da se blokira postavljanjem ključa **NoExplorer** na 1, čime se sprečava njihovo učitavanje u instancama Windows Explorer-a.<sup>[[1]](#references)</sup>

BHO su kompatibilni sa Windows 10 preko Internet Explorer 11, ali nisu podržani u Microsoft Edge-u, podrazumevanom pregledaču u novijim verzijama Windows-a.

Da biste pregledali BHO registrovane na sistemu, možete da proverite sledeće registry ključeve:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Svaki BHO je u registry-ju predstavljen svojim **CLSID**-om, koji služi kao jedinstveni identifikator. Detaljne informacije o svakom CLSID-u mogu se pronaći pod `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Za upite o BHO u registry-ju mogu se koristiti sledeće komande:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer ekstenzije

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Imajte na umu da će registar sadržati po jedan novi ključ za svaku dll datoteku, a on će biti predstavljen pomoću **CLSID**. Informacije o CLSID-u možete pronaći u `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Drajveri fontova

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Komanda za otvaranje

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### COM rukovaoci kontekstnog menija

Explorer rukovaoci kontekstnog menija su shell extensions registrovani pod ključevima kao što su `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` i `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. Podrazumevana vrednost rukovaoca, a ponekad i naziv njegovog ključa, jeste CLSID. Pratite taj CLSID do `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; njegova podrazumevana vrednost navodi DLL koji se učitava kada se rukovalac pozove.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Proverite i 32-bitni i 64-bitni prikaz registra. `HKCR` objedinjuje registracije klasa za korisnika i za ceo računar, zato proverite koji će osnovni ključ proces koristiti. Identitet sa niskim privilegijama koji može da promeni vrednost `InprocServer32` za ceo računar može da preusmeri proces sa većim privilegijama na drugu DLL datoteku, ali za eskalaciju je potrebno da taj proces pozove rukovalac. Putanja do DLL datoteke u koju može da se upisuje može predstavljati sličan rizik čak i kada je sama vrednost registra zaštićena.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Imajte na umu da su sva mesta na kojima možete pronaći autoruns **već pretražena pomoću**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Međutim, za **sveobuhvatniji spisak datoteka koje se automatski izvršavaju** možete koristiti [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) iz systinternals:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Više

**Pronađite još registara sličnih Autoruns-u na** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Uobičajeni mehanizmi održavanja postojanosti malvera](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Automatsko pokretanje pri podizanju sistema ili prijavljivanju: ključevi Run u registru / fascikla Startup](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Skripte za inicijalizaciju pri podizanju sistema ili prijavljivanju: skripta za prijavljivanje (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Kategorije automatskog pokretanja (Rešavanje problema pomoću alata Windows Sysinternals, 2. izdanje)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Kako mogu da dodam opciju pokretanja koja pokreće alternativnu ljusku?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit – pregled 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – Bezbednosni konteksti za zadatke](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
