# इंटेग्रिटी लेवल

{{#include ../../banners/hacktricks-training.md}}

## इंटेग्रिटी लेवल

Windows Vista और बाद के versions में, securable objects पर **integrity level** label हो सकता है। अधिकांश objects को medium integrity माना जाता है, जबकि low-integrity applications के लिए निर्धारित locations को low के रूप में label किया जा सकता है। Standard users द्वारा शुरू किए गए processes सामान्यतः medium integrity पर चलते हैं, elevated applications high integrity पर चलती हैं, और कई services system integrity पर चलती हैं।<sup>[[1]](#references)</sup>

एक महत्वपूर्ण नियम यह है कि किसी object के level से कम integrity level वाले processes उस object को modify नहीं कर सकते। Windows object की discretionary access control list (DACL) का मूल्यांकन करने से पहले यह Mandatory Integrity Control (MIC) check लागू करता है। आमतौर पर मिलने वाले levels हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: सबसे निचला level, जिसे `SECURITY_MANDATORY_UNTRUSTED_RID` द्वारा दर्शाया जाता है। वास्तविक उदाहरण के रूप में, Chromium का Windows sandbox शुरुआत में sandboxed targets को Low integrity देता है और startup के बाद renderer targets को Untrusted integrity पर ले आता है।<sup>[[5]](#references)</sup>
- **Low**: मुख्य रूप से internet interactions के लिए, खासकर Internet Explorer के Protected Mode में, जो संबंधित files और processes तथा **Temporary Internet Folder** जैसे कुछ folders को प्रभावित करता है। Low integrity processes पर महत्वपूर्ण restrictions होती हैं, जिनमें registry write access न होना और user profile में सीमित write access शामिल हैं।
- **Medium**: अधिकांश activities के लिए default level, जो standard users और specific integrity levels के बिना objects को दिया जाता है। Administrators group के members भी default रूप से इसी level पर operate करते हैं।
- **High**: administrators के लिए reserved, जिससे वे lower integrity levels वाले objects, जिनमें स्वयं high level वाले objects भी शामिल हैं, को modify कर सकते हैं।
- **System**: Windows kernel और core services के लिए सबसे ऊंचा operational level, जो administrators की पहुंच से भी बाहर होता है और vital system functions की protection सुनिश्चित करता है।

Windows System से ऊपर एक protected-process integrity value भी define करता है। हालांकि, **TrustedInstaller** एक अलग MIC level नहीं, बल्कि Windows service identity है; protected operating-system resources को modify करने की इसकी ability उस identity को दी गई permissions से आती है।

आप **Sysinternals** के **Process Explorer** का उपयोग करके किसी process का integrity level प्राप्त कर सकते हैं। इसके लिए process properties खोलें और **Security** tab देखें:<sup>[[3]](#references)</sup>

![इंटेग्रिटी लेवल - इंटेग्रिटी लेवल: आप Sysinternals के Process Explorer का उपयोग करके process का integrity level प्राप्त कर सकते हैं, process की properties खोलकर और "...](<../../images/image (824).png>)

आप `whoami /groups` का उपयोग करके अपना **current integrity level** भी प्राप्त कर सकते हैं:

![इंटेग्रिटी लेवल - इंटेग्रिटी लेवल: आप whoami /groups का उपयोग करके अपना current integrity level भी प्राप्त कर सकते हैं](<../../images/image (325).png>)

### File System में इंटेग्रिटी लेवल

File system में किसी object के लिए **minimum integrity-level requirement** हो सकती है। उस level से नीचे का process object की mandatory policy के अधीन रहता है, भले ही उसकी DACL अन्यथा access की अनुमति देती हो। उदाहरण के लिए, standard-user console से एक regular file बनाएं और उसकी permissions का निरीक्षण करें:<sup>[[1]](#references)[[4]](#references)</sup>
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
अब, फ़ाइल को **High** का न्यूनतम integrity level असाइन करें। यह कार्य **administrator** के रूप में चल रहे **console** से ही किया जाना **अनिवार्य** है, क्योंकि एक सामान्य console **Medium** integrity पर चलता है और किसी object को High integrity असाइन करने की अनुमति **नहीं दी जाएगी**:
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
यूज़र `DESKTOP-IDJHTKP\user` के पास फ़ाइल पर **FULL privileges** हैं क्योंकि उस यूज़र ने इसे बनाया है। हालांकि, mandatory label यूज़र को फ़ाइल में बदलाव करने से रोकता है, जब तक कि process High integrity पर न चल रहा हो। यूज़र इसे फिर भी पढ़ सकता है क्योंकि प्रदर्शित mandatory policy `(NW)` या no-write-up है:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **इसलिए, जब किसी file का minimum integrity level हो, तो उसे modify करने के लिए आपको कम-से-कम उसी integrity level पर चलना आवश्यक है।**

### Binaries में Integrity Levels

निम्न उदाहरण `cmd.exe` की एक copy को `C:\Windows\System32\cmd-low.exe` पर उपयोग करता है और उसे **administrator console से Low integrity level** assign करता है:
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

![Integrity Levels in File-system - Integrity Levels in Binaries: अब, जब मैं cmd-low.exe चलाता हूँ, तो यह Medium के बजाय Low-integrity level पर चलेगा](<../../images/image (313).png>)

किसी binary को High integrity label (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) देने से वह अपने-आप High integrity पर नहीं चलती। यदि उसे किसी Medium-integrity process से invoke किया जाता है, तो वह Medium integrity पर चलती है, क्योंकि नया process executable file और caller के integrity levels में से जो कम हो, उसे प्राप्त करता है।<sup>[[1]](#references)</sup>

### Processes में Integrity Levels

सभी files और folders में स्पष्ट minimum integrity label नहीं होता, **लेकिन हर process किसी न किसी integrity level पर चलता है**। File-system objects की तरह, **किसी अन्य process को write access देने की इच्छा रखने वाले process के पास कम-से-कम समान integrity level होना चाहिए**। इसलिए, Low-integrity process किसी Medium-integrity process को full access के साथ open नहीं कर सकता।<sup>[[1]](#references)</sup>

इन restrictions के कारण, सबसे सुरक्षित तरीका यह है कि **हर process को उस सबसे निचले integrity level पर चलाया जाए, जो उसे अपना निर्धारित कार्य करने की अनुमति देता हो**।

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – Default Windows sandbox integrity policy](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
{{#include ../../banners/hacktricks-training.md}}
