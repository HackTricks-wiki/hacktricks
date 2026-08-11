# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Windows Vista और उसके बाद के versions में, securable objects पर **integrity level** label हो सकता है। अधिकांश objects को medium integrity माना जाता है, जबकि low-integrity applications के लिए निर्धारित specific locations को low label किया जा सकता है। Standard users द्वारा शुरू किए गए processes सामान्यतः medium integrity पर चलते हैं, elevated applications high integrity पर चलते हैं, और कई services system integrity पर चलती हैं।<sup>[[1]](#references)</sup>

एक महत्वपूर्ण नियम यह है कि objects को उस object के level से lower integrity level वाले processes द्वारा modify नहीं किया जा सकता। Windows object की discretionary access control list (DACL) का मूल्यांकन करने से पहले यह Mandatory Integrity Control (MIC) check लागू करता है। आमतौर पर पाए जाने वाले levels हैं:<sup>[[1]](#references)[[2]](#references)</sup>

- **Untrusted**: सबसे निम्न level, जिसे `SECURITY_MANDATORY_UNTRUSTED_RID` (`S-1-16-0`) द्वारा दर्शाया जाता है। इस integrity label को **Anonymous Logon** identity (`S-1-5-7`) के साथ भ्रमित न करें; authentication identities और MIC labels अलग-अलग SID namespaces हैं। वास्तविक उदाहरण के रूप में, Chromium का Windows sandbox शुरुआत में sandboxed targets को Low integrity देता है और startup के बाद renderer targets को Untrusted integrity तक lower कर देता है।<sup>[[5]](#references)[[6]](#references)</sup>
- **Low**: मुख्यतः internet interactions के लिए, विशेष रूप से Internet Explorer के Protected Mode में, जिससे संबंधित files और processes तथा **Temporary Internet Folder** जैसे कुछ folders प्रभावित होते हैं। Low integrity processes को महत्वपूर्ण restrictions का सामना करना पड़ता है, जिनमें registry write access न होना और user profile में सीमित write access शामिल हैं।
- **Medium**: अधिकांश activities के लिए default level, जो standard users और specific integrity levels के बिना objects को दिया जाता है। Administrators group के members भी default रूप से इसी level पर operate करते हैं।
- **High**: administrators के लिए reserved, जिससे वे lower integrity levels वाले objects, जिनमें स्वयं high level वाले objects भी शामिल हैं, को modify कर सकते हैं।
- **System**: Windows kernel और core services के लिए सबसे उच्च operational level, जो administrators की पहुंच से भी बाहर होता है और vital system functions की protection सुनिश्चित करता है।

Windows System से ऊपर एक protected-process integrity value भी define करता है। हालांकि, **TrustedInstaller** एक अलग MIC level नहीं, बल्कि Windows service identity है; protected operating-system resources को modify करने की इसकी ability उस identity को दी गई permissions से आती है।

यह assume न करें कि system drive के root जैसी location पर हमेशा fixed High integrity label होता है। `icacls` का उपयोग करके effective DACL और किसी explicit mandatory label का निरीक्षण करें; बिना label वाला object MIC के लिए Medium माना जाता है, जबकि उसका DACL और ownership अभी भी independently access को restrict कर सकते हैं।<sup>[[1]](#references)[[4]](#references)</sup>

आप **Sysinternals** के **Process Explorer** का उपयोग करके process का integrity level प्राप्त कर सकते हैं। इसके लिए process properties खोलें और **Security** tab देखें:<sup>[[3]](#references)</sup>

![Integrity Levels - Integrity Levels: आप Sysinternals के Process Explorer का उपयोग करके process का integrity level प्राप्त कर सकते हैं, process की properties खोलकर और "...](<../../images/image (824).png>)

आप `whoami /groups` का उपयोग करके अपना **current integrity level** भी प्राप्त कर सकते हैं:

![Integrity Levels - Integrity Levels: आप whoami /groups का उपयोग करके अपना current integrity level भी प्राप्त कर सकते हैं](<../../images/image (325).png>)

### Integrity Levels in the File System

File system में किसी object के पास **minimum integrity-level requirement** हो सकती है। उस level से नीचे का process object की mandatory policy के अधीन होता है, भले ही उसका DACL अन्यथा access grant करता हो। उदाहरण के लिए, standard-user console से एक regular file बनाएं और उसकी permissions का निरीक्षण करें:<sup>[[1]](#references)[[4]](#references)</sup>
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
अब फ़ाइल को **High** का न्यूनतम integrity level असाइन करें। यह कार्य **administrator** के रूप में चल रहे **console** से ही किया जाना **अनिवार्य** है, क्योंकि सामान्य console Medium integrity पर चलता है और किसी object को High integrity असाइन करने की अनुमति **नहीं दी जाएगी**:
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
उपयोगकर्ता `DESKTOP-IDJHTKP\user` के पास फ़ाइल पर **FULL privileges** हैं, क्योंकि उस उपयोगकर्ता ने इसे बनाया है। हालांकि, mandatory label उपयोगकर्ता को फ़ाइल में बदलाव करने से रोकता है, जब तक कि process High integrity पर न चल रहा हो। उपयोगकर्ता इसे अभी भी पढ़ सकता है, क्योंकि प्रदर्शित mandatory policy `(NW)` है, यानी no-write-up:
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **इसलिए, जब किसी file में minimum integrity level होता है, तो उसे modify करने के लिए आपको कम से कम उसी integrity level पर चलना आवश्यक है।**

### Binaries में Integrity Levels

निम्नलिखित example में `C:\Windows\System32\cmd-low.exe` पर `cmd.exe` की एक copy का उपयोग किया गया है और उसे **administrator console से Low integrity level** assign किया गया है:
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
अब, जब मैं `cmd-low.exe` चलाता हूँ, तो यह Medium integrity level के बजाय **Low integrity level पर चलेगा**:

![File-system में Integrity Levels - Binaries में Integrity Levels: अब, जब मैं cmd-low.exe चलाता हूँ, तो यह Medium integrity level के बजाय Low integrity level पर चलेगा](<../../images/image (313).png>)

किसी binary को High integrity label (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`) देने से वह अपने-आप High integrity पर नहीं चलता। यदि उसे Medium-integrity process से invoke किया जाता है, तो वह Medium integrity पर चलता है, क्योंकि नया process executable file और caller के integrity levels में से कम वाला integrity level प्राप्त करता है।<sup>[[1]](#references)</sup>

### Processes में Integrity Levels

सभी files और folders में स्पष्ट minimum integrity label नहीं होता, **लेकिन हर process किसी न किसी integrity level पर चलता है**। File-system objects की तरह, **किसी दूसरे process को write access की आवश्यकता रखने वाले process के पास कम-से-कम वही integrity level होना चाहिए**। इसलिए, Low-integrity process किसी Medium-integrity process को full access के साथ open नहीं कर सकता।<sup>[[1]](#references)</sup>

इन restrictions के कारण, सबसे सुरक्षित तरीका यह है कि **हर process को उस सबसे कम integrity level पर चलाया जाए, जो उसे अपना intended work करने की अनुमति देता हो**।

## References

- [1] [Microsoft Learn – Mandatory Integrity Control](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control)
- [2] [Microsoft Learn – MANDATORY_LEVEL enumeration](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-mandatory_level)
- [3] [Microsoft Sysinternals – Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)
- [4] [Microsoft Learn – icacls](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)
- [5] [Chromium source – Default Windows sandbox integrity policy](https://github.com/chromium/chromium/blob/main/sandbox/policy/win/sandbox_win.cc#L212-L216)
- [6] [Microsoft Learn – Well-known SIDs](https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids)
{{#include ../../banners/hacktricks-training.md}}
