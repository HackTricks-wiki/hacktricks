# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Windows Vista और उसके बाद के versions में, securable objects में **integrity level** label हो सकता है। अधिकांश objects को medium integrity माना जाता है, जबकि low-integrity applications के लिए निर्धारित विशेष locations को low label किया जा सकता है। Standard users द्वारा शुरू किए गए processes सामान्यतः medium integrity पर चलते हैं, elevated applications high integrity पर चलती हैं, और कई services system integrity पर चलती हैं।<sup>[[1]](#references)</sup>

एक महत्वपूर्ण नियम यह है कि किसी object के level से कम integrity level वाले processes उस object को modify नहीं कर सकते। Windows object की discretionary access control list (DACL) का मूल्यांकन करने से पहले यह Mandatory Integrity Control (MIC) check लागू करता है। आमतौर पर मिलने वाले levels ये हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: सबसे निचला level, जिसे `SECURITY_MANDATORY_UNTRUSTED_RID` द्वारा दर्शाया जाता है।
- **Low**: मुख्य रूप से internet interactions के लिए, विशेषकर Internet Explorer के Protected Mode में, जो संबंधित files और processes तथा **Temporary Internet Folder** जैसे कुछ folders को प्रभावित करता है। Low integrity processes पर महत्वपूर्ण restrictions होती हैं, जिनमें registry write access न होना और user profile में सीमित write access शामिल है।
- **Medium**: अधिकांश activities के लिए default level, जो standard users और specific integrity levels के बिना objects को assign किया जाता है। Administrators group के members भी default रूप से इसी level पर operate करते हैं।
- **High**: administrators के लिए reserved, जिससे वे lower integrity levels वाले objects को modify कर सकते हैं, जिनमें स्वयं high level वाले objects भी शामिल हैं।
- **System**: Windows kernel और core services के लिए सबसे उच्च operational level, जो administrators की पहुंच से भी बाहर होता है और vital system functions की सुरक्षा सुनिश्चित करता है।

Windows System से ऊपर एक protected-process integrity value भी define करता है। हालांकि, **TrustedInstaller** एक अलग MIC level के बजाय Windows service identity है; protected operating-system resources को modify करने की इसकी ability उस identity को दी गई permissions से आती है।

आप **Sysinternals** के **Process Explorer** का उपयोग करके किसी process का integrity level प्राप्त कर सकते हैं। इसके लिए process properties खोलें और **Security** tab देखें:<sup>[[3]](#references)</sup>

![Integrity Levels - Integrity Levels: आप Sysinternals के Process Explorer का उपयोग करके process का integrity level प्राप्त कर सकते हैं, process की properties खोलकर और "...](<../../images/image (824).png>)

आप `whoami /groups` का उपयोग करके अपना **current integrity level** भी प्राप्त कर सकते हैं:

![Integrity Levels - Integrity Levels: आप whoami /groups का उपयोग करके अपना current integrity level भी प्राप्त कर सकते हैं](<../../images/image (325).png>)

### File System में Integrity Levels

File system में किसी object के पास **minimum integrity-level requirement** हो सकती है। उस level से नीचे का process object की mandatory policy के अधीन होता है, भले ही उसकी DACL अन्यथा access grant करती हो। उदाहरण के लिए, standard-user console से एक regular file बनाएं और उसकी permissions inspect करें:<sup>[[1]](#references)[[4]](#references)</sup>
```
echo asd >asd.txt
icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
```
अब फ़ाइल के लिए **High** का न्यूनतम integrity level निर्धारित करें। यह कार्य **administrator** के रूप में चल रहे **console** से ही किया जाना **अनिवार्य** है, क्योंकि एक सामान्य console Medium integrity पर चलता है और किसी object को High integrity असाइन करने की अनुमति **नहीं दी जाएगी**:
```
icacls asd.txt /setintegritylevel(oi)(ci) High
processed file: asd.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Public>icacls asd.txt
asd.txt BUILTIN\Administrators:(I)(F)
DESKTOP-IDJHTKP\user:(I)(F)
NT AUTHORITY\SYSTEM:(I)(F)
NT AUTHORITY\INTERACTIVE:(I)(M,DC)
NT AUTHORITY\SERVICE:(I)(M,DC)
NT AUTHORITY\BATCH:(I)(M,DC)
Mandatory Label\High Mandatory Level:(NW)
```
यूज़र `DESKTOP-IDJHTKP\user` के पास फ़ाइल पर **FULL privileges** हैं क्योंकि उस यूज़र ने इसे बनाया है। हालांकि, mandatory label यूज़र को फ़ाइल में संशोधन करने से रोकता है, जब तक कि process High integrity पर न चल रहा हो। यूज़र इसे अभी भी पढ़ सकता है क्योंकि प्रदर्शित mandatory policy `(NW)` या no-write-up है:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **इसलिए, जब किसी file का minimum integrity level निर्धारित होता है, तो उसे modify करने के लिए आपको कम-से-कम उसी integrity level पर run करना आवश्यक है।**

### Binaries में Integrity Levels

निम्नलिखित उदाहरण `cmd.exe` की `C:\Windows\System32\cmd-low.exe` पर स्थित एक copy का उपयोग करता है और उसे **administrator console से Low integrity level assign करता है**:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
अब, जब मैं `cmd-low.exe` चलाता हूँ, तो यह Medium के बजाय **Low-integrity level पर चलेगा**:

![File-system में Integrity Levels - Binaries में Integrity Levels: अब, जब मैं cmd-low.exe चलाता हूँ, तो यह Medium के बजाय Low-integrity level पर चलेगा](<../../images/image (313).png>)

किसी binary को High integrity label देना (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) उसे अपने-आप High integrity पर नहीं चलाता। यदि उसे किसी Medium-integrity process से invoke किया जाता है, तो वह Medium integrity पर चलता है, क्योंकि नया process executable file और caller के integrity levels में से जो कम हो, उसे प्राप्त करता है।<sup>[[1]](#references)</sup>

### Processes में Integrity Levels

सभी files और folders में स्पष्ट minimum integrity label नहीं होता, **लेकिन प्रत्येक process किसी न किसी integrity level पर चलता है**। File-system objects की तरह, **किसी अन्य process तक write access चाहने वाले process का integrity level कम-से-कम उतना ही होना चाहिए**। इसलिए, Low-integrity process किसी Medium-integrity process को full access के साथ open नहीं कर सकता।<sup>[[1]](#references)</sup>

इन restrictions के कारण, सबसे सुरक्षित तरीका यह है कि **प्रत्येक process को उस सबसे निम्न integrity level पर चलाया जाए, जो उसे अपना निर्धारित कार्य करने की अनुमति देता हो**।

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
{{#include ../../banners/hacktricks-training.md}}
