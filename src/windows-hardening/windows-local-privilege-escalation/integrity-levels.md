# Integrity Levels

{{#include ../../banners/hacktricks-training.md}}

## Integrity Levels

Windows Vista और उसके बाद के versions में, सभी protected items के साथ एक **integrity level** tag जुड़ा होता है। यह setup आमतौर पर files और registry keys को "medium" integrity level देता है, सिवाय कुछ folders और files के, जिन्हें Internet Explorer 7 low integrity level पर write कर सकता है। Default behavior के अनुसार standard users द्वारा शुरू किए गए processes का integrity level medium होता है, जबकि services आमतौर पर system integrity level पर operate करती हैं। High-integrity label root directory की सुरक्षा करता है।

एक महत्वपूर्ण नियम यह है कि objects को ऐसे processes द्वारा modify नहीं किया जा सकता जिनका integrity level उस object के level से कम हो। Integrity levels इस प्रकार हैं:

- **Untrusted**: यह level anonymous logins वाले processes के लिए होता है। Example: Chrome
- **Low**: मुख्य रूप से internet interactions के लिए, खासकर Internet Explorer के Protected Mode में, जिससे संबंधित files और processes, तथा **Temporary Internet Folder** जैसे कुछ folders प्रभावित होते हैं। Low integrity processes पर महत्वपूर्ण restrictions होती हैं, जिनमें registry write access न होना और user profile में सीमित write access शामिल है।
- **Medium**: अधिकांश activities के लिए default level, जो standard users और specific integrity levels के बिना objects को दिया जाता है। Administrators group के members भी default रूप से इसी level पर operate करते हैं।
- **High**: administrators के लिए reserved, जिससे वे lower integrity levels वाले objects को modify कर सकते हैं, जिनमें स्वयं high level वाले objects भी शामिल हैं।
- **System**: Windows kernel और core services के लिए highest operational level, जो administrators की पहुंच से भी बाहर होता है और vital system functions की सुरक्षा सुनिश्चित करता है।
- **Installer**: एक unique level जो बाकी सभी levels से ऊपर होता है और इस level के objects को किसी भी अन्य object को uninstall करने की अनुमति देता है।

आप **Sysinternals** के **Process Explorer** का उपयोग करके किसी process का integrity level प्राप्त कर सकते हैं। इसके लिए process की **properties** खोलें और "**Security**" tab देखें:

![Integrity Levels - Integrity Levels: आप Sysinternals के Process Explorer का उपयोग करके process का integrity level प्राप्त कर सकते हैं, process की properties खोलकर और "...](<../../images/image (824).png>)

आप `whoami /groups` का उपयोग करके अपना **current integrity level** भी प्राप्त कर सकते हैं।

![Integrity Levels - Integrity Levels: आप whoami /groups का उपयोग करके अपना current integrity level भी प्राप्त कर सकते हैं](<../../images/image (325).png>)

### File-system में Integrity Levels

File-system के अंदर किसी object के लिए **minimum integrity level requirement** हो सकती है और यदि किसी process के पास यह integrity level नहीं है, तो वह उसके साथ interact नहीं कर पाएगा।\
उदाहरण के लिए, **एक regular user console से एक regular file create करें और permissions check करें**:
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
अब, file को **High** का minimum integrity level assign करते हैं। यह कार्य **administrator** के रूप में चल रहे **console** से ही **करना होगा**, क्योंकि एक **regular console** Medium Integrity level में चलेगा और किसी object को High Integrity level assign करने की **अनुमति नहीं होगी**:
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
यहीं से चीज़ें दिलचस्प होती हैं। आप देख सकते हैं कि user `DESKTOP-IDJHTKP\user` के पास file पर **FULL privileges** हैं (वास्तव में, इसी user ने file बनाई थी), हालांकि, लागू किए गए minimum integrity level के कारण वह अब file को modify नहीं कर पाएगा, जब तक कि वह High Integrity Level के अंदर run न कर रहा हो (ध्यान दें कि वह इसे read कर पाएगा):
```
echo 1234 > asd.txt
Access is denied.

del asd.txt
C:\Users\Public\asd.txt
Access is denied.
```
> [!TIP]
> **इसलिए, जब किसी file में minimum integrity level होता है, तो उसे modify करने के लिए आपको कम से कम उसी integrity level पर run करना आवश्यक है।**

### Binaries में Integrity Levels

मैंने `cmd.exe` की एक copy `C:\Windows\System32\cmd-low.exe` में बनाई और उसे **administrator console से low का integrity level दिया:**
```
icacls C:\Windows\System32\cmd-low.exe
C:\Windows\System32\cmd-low.exe NT AUTHORITY\SYSTEM:(I)(F)
BUILTIN\Administrators:(I)(F)
BUILTIN\Users:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APP PACKAGES:(I)(RX)
Mandatory Label\Low Mandatory Level:(NW)
```
अब, जब मैं `cmd-low.exe` चलाता हूं, तो यह medium के बजाय **low-integrity level के अंतर्गत चलेगा**:

![File-system में Integrity Levels - Binaries में Integrity Levels: अब, जब मैं cmd-low.exe चलाता हूं, तो यह medium के बजाय low-integrity level के अंतर्गत चलेगा](<../../images/image (313).png>)

जिज्ञासु लोगों के लिए, यदि आप किसी binary को high integrity level प्रदान करते हैं (`icacls C:\Windows\System32\cmd-high.exe /setintegritylevel high`), तो यह अपने-आप high integrity level के साथ नहीं चलेगा (यदि आप इसे medium integrity level से invoke करते हैं --by default-- तो यह medium integrity level के अंतर्गत चलेगा)।

### Processes में Integrity Levels

सभी files और folders में minimum integrity level नहीं होता, **लेकिन सभी processes किसी न किसी integrity level के अंतर्गत चल रहे होते हैं**। और file-system में जो हुआ, उसके समान ही, **यदि कोई process किसी अन्य process के अंदर write करना चाहता है, तो उसके पास कम-से-कम समान integrity level होना चाहिए**। इसका अर्थ है कि low integrity level वाला process, medium integrity level वाले process के लिए full access वाला handle open नहीं कर सकता।

इस section और पिछली section में बताई गई restrictions के कारण, security के दृष्टिकोण से, किसी process को हमेशा **संभव सबसे निचले integrity level पर चलाने की recommendation दी जाती है**।

{{#include ../../banners/hacktricks-training.md}}
