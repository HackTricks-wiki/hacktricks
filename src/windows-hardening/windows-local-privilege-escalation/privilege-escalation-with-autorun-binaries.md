# Voorregte-eskalasie met Autoruns

{{#include ../../banners/hacktricks-training.md}}



## WMIC

**Wmic** kan gebruik word om programme tydens **opstart** uit te voer. Kyk met die volgende opdrag watter binêre lêers geprogrammeer is om tydens opstart te loop:

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

#Requires an elevated caller to register a task as SYSTEM
#You can also write that content on a bat file that is being executed by a scheduled task
schtasks /Create /RU "SYSTEM" /SC ONLOGON /TN "SchedPE" /TR "cmd /c net localgroup administrators user /add"
```

'n Taak wat met `/sc ONLOGON /rl HIGHEST` geskep is, versoek die hoogste loopvlak **wat vir sy geregistreerde principal beskikbaar is**; die skakelaar alleen verander nie daardie principal nie en omseil ook nie UAC nie. 'n Proses met lae voorregte kan nie 'n taak met die hoogste loopvlak registreer of SYSTEM as die taakidentiteit kies nie. Beskou die voorbeeld hierbo as 'n aksie vir 'n oproeper wat reeds verhoogde voorregte het, nie as 'n pad van 'n standaardgebruiker na SYSTEM nie.<sup>[[8]](#references)</sup>

'n Geaktiveerde taak wat as SYSTEM loop, verdien ondersoek, selfs wanneer sy taakdefinisie en aksielêer beskerm is. [Task Scheduler vereis uitvoertoestemming op die taak om dit op aanvraag te laat loop](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks). As 'n gebruiker met lae voorregte daardie toestemming het, ondersoek die presiese aksie, veral PowerShell-skripte wat Active Directory ACLs wysig of rekeningbeskermingsinstellings terugstel. Gaan die taak se `AllowDemandStart`-instelling na en verifieer die skrip se insette en uitwerkings; toestemming om 'n vaste taak te begin, impliseer nie op sigself arbitrêre kode-uitvoering nie.

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

'n Opstartinskrywing van 'n gebruiker met hoër voorregte kan 'n beskermde script begin wat herhaaldelik lêers oopmaak vanuit 'n gids waarin 'n ander gebruiker kan skryf. Gaan die inskrywing se **werklike aanmeldidentiteit**, die script se invoergids en ACL's, en die presiese aksie na voordat jy daardie gids as 'n eskalasiepad beskou. In die besonder: [`hh.exe` maak saamgestelde HTML Help (`.chm`)-lêers oop](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/about-the-html-help-executable-program); 'n script wat lêers wat deur die oproeper verskaf word daaraan deurgee, kruis 'n inhoudsvertrouensgrens, selfs al kontroleer dit die lêernaam of eerste grepe. [HTML Help-beleide kan uitvoerbare kortpaaie beperk](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/htmlhelp/system-policies-for-shortcut-and-winhelp-commands), dus bevestig die geïnstalleerde beleid en hoe toeganklike inhoud optree. 'n `.chm`-uitbreiding of magic bytes alleen bewys nie dat kode met hoër voorregte uitgevoer word nie. Ondersoek die autorun, prosesopdragreël en padtoestemmings sonder om die onbetroubare lêer tydens die inventarisering oop te maak.

Dieselfde inhoudsgrens bestaan wanneer iemand met hoër voorregte 'n `.chm` **handmatig oopmaak** vanuit 'n dokumentasiegids wat 'n ander gebruiker kan vervang. Bevestig die presiese lêer en skryftoestemmings op die ouergids, die werklike kykeridentiteit en die openingsgebeurtenis, en die effektiewe HTML Help-beleid. 'n Skryfbare gids of 'n versoek om dokumentasie na te gaan, bewys nie dat die identiteit met hoër voorregte aanvallerbeheerde inhoud oopgemaak het nie.

> **TER INLIGTING**: Archive extraction *path traversal*-kwesbaarhede (soos die een wat in WinRAR voor 7.13 misbruik is – CVE-2025-8088) kan benut word om **payloads direk binne hierdie Startup-gidse neer te sit tydens dekompressie**, wat kode-uitvoering by die volgende gebruiker se aanmelding tot gevolg het.  Vir 'n diepgaande bespreking van hierdie tegniek, sien:


{{#ref}}
../../generic-hacking/archive-extraction-path-traversal.md
{{#endref}}



## Register

> [!TIP]
> [Nota van hier af](https://answers.microsoft.com/en-us/windows/forum/all/delete-registry-key/d425ae37-9dcc-4867-b49c-723dcd15147f): Die **Wow6432Node**-registerinskrywing dui aan dat jy 'n 64-bis Windows-weergawe gebruik. Die bedryfstelsel gebruik hierdie sleutel om 'n aparte aansig van HKEY_LOCAL_MACHINE\SOFTWARE te vertoon vir 32-bis-toepassings wat op 64-bis Windows-weergawes loop.

### Runs

**Algemeen bekende** AutoRun-registerinskrywings:

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

Registersleutels bekend as **Run** en **RunOnce** is ontwerp om programme outomaties uit te voer elke keer wanneer 'n gebruiker by die stelsel aanmeld. Die opdragreël wat as 'n sleutel se dat waarde toegewys is, is beperk tot 260 karakters of minder.<sup>[[2]](#references)</sup>

**Diens-runs** (kan die outomatiese opstart van dienste tydens selflaai beheer):

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

In Windows Vista en latere weergawes word die **Run**- en **RunOnce**-registersleutels nie outomaties geskep nie. Inskrywings in hierdie sleutels kan programme direk begin of hulle as afhanklikhede spesifiseer. Om byvoorbeeld 'n DLL-lêer tydens aanmelding te laai, kan 'n mens die **RunOnceEx**-registersleutel saam met 'n "Depend"-sleutel gebruik. Dit word gedemonstreer deur 'n registerinskrywing by te voeg om "C:\temp\evil.dll" tydens stelselopstart uit te voer:<sup>[[2]](#references)</sup>

```
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend /v 1 /d "C:\\temp\\evil.dll"
```

> [!TIP]
> **Exploit 1**: As jy binne enige van die genoemde registersleutels in **HKLM** kan skryf, kan jy voorregte eskaleer wanneer ’n ander gebruiker aanmeld.

> [!TIP]
> **Exploit 2**: As jy enige van die binaries wat in enige van die registersleutels in **HKLM** aangedui word, kan oorskryf, kan jy daardie binary met ’n backdoor wysig wanneer ’n ander gebruiker aanmeld en voorregte eskaleer.

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

Kortpaaie wat in die **Startup**-lêergids geplaas word, sal dienste of toepassings outomaties laat begin wanneer ’n gebruiker aanmeld of die stelsel herlaai word. Die ligging van die **Startup**-lêergids word in die register vir beide die **Local Machine**- en **Current User**-omvang gedefinieer. Dit beteken dat enige kortpad wat by hierdie gespesifiseerde **Startup**-liggings gevoeg word, verseker dat die gekoppelde diens of program ná die aanmeld- of herlaaiproses begin, wat dit ’n eenvoudige manier maak om programme te skeduleer om outomaties te loop.<sup>[[1]](#references)[[2]](#references)</sup>

> [!TIP]
> As jy enige \[User] Shell Folder onder **HKLM** kan oorskryf, sal jy dit na ’n lêergids onder jou beheer kan laat wys en ’n backdoor daarin kan plaas wat uitgevoer word wanneer enige gebruiker by die stelsel aanmeld, en sodoende voorregte eskaleer.

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

Hierdie per-gebruiker-registerwaarde kan verwys na ’n script of opdrag wat uitgevoer word wanneer daardie gebruiker aanmeld. Dit is hoofsaaklik ’n **persistence**-primitief omdat dit slegs in die konteks van die betrokke gebruiker uitgevoer word, maar dit is steeds die moeite werd om dit tydens post-exploitation- en autoruns-oorsigte na te gaan.<sup>[[3]](#references)[[6]](#references)[[7]](#references)</sup>

> [!TIP]
> As jy hierdie waarde vir die huidige gebruiker kan skryf, kan jy die uitvoering by die volgende interaktiewe aanmelding weer aktiveer sonder dat jy adminregte nodig het. As jy dit vir ’n ander gebruiker se hive kan skryf, kan jy kode-uitvoering verkry wanneer daardie gebruiker aanmeld.

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
- Dit bly van krag ná afmelding/herlaai totdat die waarde verwyder word.
- Anders as `HKLM\...\Run`, verleen dit nie op sigself verhoogde regte nie; dit is volharding op gebruikersvlak.

### Winlogon-sleutels

`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

Tipies is die **Userinit**-sleutel op **userinit.exe** gestel. As hierdie sleutel egter gewysig word, sal **Winlogon** die gespesifiseerde uitvoerbare lêer ook begin wanneer die gebruiker aanmeld. Net so is die **Shell**-sleutel bedoel om na **explorer.exe** te verwys, wat die verstekdop vir Windows is.<sup>[[1]](#references)</sup>

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

### Verander die opdragprompt in Veilige modus

In die Windows-register onder `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot` is daar ’n **`AlternateShell`**-waarde wat by verstek op `cmd.exe` gestel is. Dit beteken dat `cmd.exe` gebruik word wanneer jy tydens die opstartproses “Veilige modus met opdragprompt” kies (deur F8 te druk). Dit is egter moontlik om jou rekenaar so op te stel dat dit outomaties in hierdie modus begin, sonder dat jy F8 hoef te druk en dit handmatig te kies.

Stappe om ’n opstartopsie te skep wat outomaties in “Veilige modus met opdragprompt” begin:<sup>[[5]](#references)</sup>

1. Verander die eienskappe van die `boot.ini`-lêer om die leesalleen-, stelsel- en versteekte vlae te verwyder: `attrib c:\boot.ini -r -s -h`
2. Maak `boot.ini` oop om dit te wysig.
3. Voeg ’n reël soos hierdie in: `multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Microsoft Windows XP Professional" /fastdetect /SAFEBOOT:MINIMAL(ALTERNATESHELL)`
4. Stoor die veranderinge aan `boot.ini`.
5. Herstel die oorspronklike lêereienskappe: `attrib c:\boot.ini +r +s +h`

- **Exploit 1:** Deur die **AlternateShell**-registersleutel te verander, kan ’n pasgemaakte opdragdop opgestel word, wat moontlik ongemagtigde toegang kan bied.
- **Exploit 2 (PATH-skryftoestemmings):** As jy skryftoestemmings het vir enige deel van die stelsel se **PATH**-veranderlike, veral voor `C:\Windows\system32`, kan jy ’n pasgemaakte `cmd.exe` uitvoer. Dit kan ’n agterdeur wees as die stelsel in Veilige modus begin.
- **Exploit 3 (PATH- en boot.ini-skryftoestemmings):** Skryftoegang tot `boot.ini` maak outomatiese opstart in Veilige modus moontlik, wat ongemagtigde toegang tydens die volgende herbegin kan vergemaklik.

Gebruik hierdie opdragte om die huidige **AlternateShell**-instelling na te gaan:

```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot /v AlternateShell
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SafeBoot' -Name 'AlternateShell'
```

### Geïnstalleerde komponent

Active Setup is ’n Windows-funksie wat **begin voordat die werkskermomgewing volledig gelaai is**. Dit gee voorkeur aan die uitvoering van sekere opdragte, wat voltooi moet word voordat die gebruikersaanmelding voortgaan. Hierdie proses vind plaas nog voordat ander opstartinskrywings, soos dié in die Run- of RunOnce-registerafdelings, geaktiveer word.

Active Setup word deur die volgende registersleutels bestuur:

- `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components`
- `HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components`

Binne hierdie sleutels bestaan daar verskeie subsleutels, elk wat met ’n spesifieke komponent ooreenstem. Sleutelwaardes van besondere belang sluit in:

- **IsInstalled:**
  - `0` dui aan dat die komponent se opdrag nie uitgevoer sal word nie.
  - `1` beteken dat die opdrag een keer vir elke gebruiker uitgevoer sal word. Dit is die verstekgedrag as die `IsInstalled`-waarde ontbreek.
- **StubPath:** Definieer die opdrag wat deur Active Setup uitgevoer moet word. Dit kan enige geldige opdragreël wees, soos om `notepad` te begin.

**Sekuriteitsinsigte:**

- Die wysiging van of skryf na ’n sleutel waar **`IsInstalled`** op `"1"` gestel is, met ’n spesifieke **`StubPath`**, kan tot ongemagtigde opdraguitvoering lei, moontlik vir privilege escalation.
- Die wysiging van die binêre lêer waarna enige **`StubPath`**-waarde verwys, kan ook privilege escalation moontlik maak, mits daar voldoende toestemmings is.

Om die **`StubPath`**-konfigurasies oor Active Setup-komponente te inspekteer, kan hierdie opdragte gebruik word:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v StubPath
```

### Browser Helper Objects

### Oorsig van Browser Helper Objects (BHOs)

Browser Helper Objects (BHOs) is DLL-modules wat ekstra kenmerke by Microsoft Internet Explorer voeg. Hulle laai met elke begin in Internet Explorer en Windows Explorer. Hulle uitvoering kan egter geblokkeer word deur die **NoExplorer**-sleutel op 1 te stel, wat verhoed dat hulle saam met Windows Explorer-instansies laai.<sup>[[1]](#references)</sup>

BHO's is versoenbaar met Windows 10 via Internet Explorer 11, maar word nie in Microsoft Edge ondersteun nie; dit is die verstekblaaier in nuwer weergawes van Windows.

Om BHO's wat op ’n stelsel geregistreer is te ondersoek, kan jy die volgende registersleutels nagaan:

- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`
- `HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

Elke BHO word in die register deur sy **CLSID** verteenwoordig, wat as ’n unieke identifiseerder dien. Gedetailleerde inligting oor elke CLSID kan gevind word onder `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`.

Hierdie opdragte kan gebruik word om BHO's in die register op te soek:

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" /s
```

### Internet Explorer-uitbreidings

- `HKLM\Software\Microsoft\Internet Explorer\Extensions`
- `HKLM\Software\Wow6432Node\Microsoft\Internet Explorer\Extensions`

Let daarop dat die register een nuwe registerinskrywing vir elke DLL sal bevat, wat deur die **CLSID** voorgestel word. Jy kan die CLSID-inligting vind by `HKLM\SOFTWARE\Classes\CLSID\{<CLSID>}`

### Lettertipebestuurders

- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`
- `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers`

```bash
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers"
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers"
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers'
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Font Drivers'
```

### Maak-opdrag

- `HKLM\SOFTWARE\Classes\htmlfile\shell\open\command`
- `HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command`

```bash
reg query "HKLM\SOFTWARE\Classes\htmlfile\shell\open\command" /v ""
reg query "HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command" /v ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Classes\htmlfile\shell\open\command' -Name ""
Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Classes\htmlfile\shell\open\command' -Name ""
```

### COM-hanteerders vir context menu

Explorer se context menu-handlers is shell extensions wat geregistreer is onder sleutels soos `HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers` en `HKLM\SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers`. ’n Handler se verstekwaarde, of soms sy sleutelnaam, is ’n CLSID. Volg daardie CLSID na `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32`; die verstekwaarde daarvan gee die naam van die DLL wat gelaai word wanneer die handler aangeroep word.

```powershell
reg query "HKLM\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers" /s
reg query "HKLM\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32" /ve
Get-Acl 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{CLSID}\InprocServer32' |
  Select-Object -ExpandProperty Access
```

Kontroleer beide 32-bis- en 64-bis-registeraansigte. `HKCR` voeg gebruiker- en masjienwye klasregistrasies saam, dus moet jy verifieer watter onderliggende sleutel ’n proses sal gebruik. ’n Identiteit met lae voorregte wat ’n masjienwye `InprocServer32`-waarde kan verander, kan ’n proses met hoër voorregte na ’n ander DLL herlei, maar vir die eskalasie moet daardie proses die handler aanroep. ’n Skryfbare DLL-pad kan ’n soortgelyke risiko inhou, selfs wanneer die registerwaarde self beskerm word.

### Image File Execution Options

```
HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options
HKLM\Software\Microsoft\Wow6432Node\Windows NT\CurrentVersion\Image File Execution Options
```

## SysInternals

Let daarop dat al die plekke waar jy autoruns kan vind reeds deur [**winpeas.exe**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS/winPEASexe) deursoek word. Vir ’n **meer omvattende lys van lêers wat outomaties uitgevoer word**, kan jy egter [autoruns ](https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns) van systinternals gebruik:

```
autorunsc.exe -m -nobanner -a * -ct /accepteula
```

## Meer

**Vind meer Autoruns soos registers by** [**https://www.microsoftpressstore.com/articles/article.aspx?p=2762082\&seqNum=2**](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)<sup>[[4]](#references)</sup>

## References

- [1] [Algemene volhardingsmeganismes van wanware](https://resources.infosecinstitute.com/common-malware-persistence-mechanisms/#gref)
- [2] [MITRE ATT&CK T1547.001 – Outomatiese opstartuitvoering tydens boot of aanmelding: Registeruitvoersleutels / Opstartgids](https://attack.mitre.org/techniques/T1547/001/)
- [3] [MITRE ATT&CK T1037.001 – Initialiseringskripte tydens boot of aanmelding: Aanmeldingskrip (Windows)](https://attack.mitre.org/techniques/T1037/001/)
- [4] [Autoruns – Outomatiese opstartkategorieë (Probleemoplossing met die Windows Sysinternals-gereedskap, 2de uitgawe)](https://www.microsoftpressstore.com/articles/article.aspx?p=2762082&seqNum=2)
- [5] [Hoe kan ek ’n opstartopsie byvoeg wat ’n alternatiewe shell begin?](https://www.itprotoday.com/cloud-computing/how-can-i-add-boot-option-starts-alternate-shell)
- [6] [Metasploit-opsomming 04/03/2026](https://www.rapid7.com/blog/post/pt-metasploit-wrap-up-04-03-2026)
- [7] [Metasploit PR #21032 – windows/persistence/userinit_mpr_logon_script](https://github.com/rapid7/metasploit-framework/pull/21032)
- [8] [Microsoft Learn – Sekuriteitskontekste vir take](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks)
{{#include ../../banners/hacktricks-training.md}}
