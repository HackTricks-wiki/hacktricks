# Access Tokens

{{#include ../../banners/hacktricks-training.md}}

## Access Tokens

प्रत्येक **उपयोगकर्ता जो** सिस्टम पर **लॉग इन है, उसके पास उस लॉगिन सत्र के लिए सुरक्षा जानकारी के साथ एक एक्सेस टोकन होता है**। जब उपयोगकर्ता लॉग इन करता है, तो सिस्टम एक एक्सेस टोकन बनाता है। **प्रत्येक प्रक्रिया जो** उपयोगकर्ता की ओर से **निष्पादित होती है, उसके पास एक्सेस टोकन की एक प्रति होती है**। टोकन उपयोगकर्ता, उपयोगकर्ता के समूहों और उपयोगकर्ता के विशेषाधिकारों की पहचान करता है। एक टोकन में एक लॉगिन SID (सुरक्षा पहचानकर्ता) भी होता है जो वर्तमान लॉगिन सत्र की पहचान करता है।

आप इस जानकारी को `whoami /all` चलाकर देख सकते हैं।
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
या _Process Explorer_ का उपयोग करके Sysinternals से (प्रक्रिया का चयन करें और "सुरक्षा" टैब तक पहुँचें):

![](<../../images/image (772).png>)

### स्थानीय व्यवस्थापक

जब एक स्थानीय व्यवस्थापक लॉगिन करता है, **दो एक्सेस टोकन बनाए जाते हैं**: एक व्यवस्थापक अधिकारों के साथ और दूसरा सामान्य अधिकारों के साथ। **डिफ़ॉल्ट रूप से**, जब यह उपयोगकर्ता एक प्रक्रिया निष्पादित करता है, तो **सामान्य** (गैर-व्यवस्थापक) **अधिकारों वाला** टोकन उपयोग किया जाता है। जब यह उपयोगकर्ता **व्यवस्थापक के रूप में** कुछ **निष्पादित** करने की कोशिश करता है ("व्यवस्थापक के रूप में चलाएँ" उदाहरण के लिए) तो **UAC** अनुमति मांगने के लिए उपयोग किया जाएगा।\
यदि आप [**UAC के बारे में अधिक जानना चाहते हैं, तो इस पृष्ठ को पढ़ें**](../authentication-credentials-uac-and-efs/#uac)**.**

### क्रेडेंशियल्स उपयोगकर्ता अनुकरण

यदि आपके पास **किसी अन्य उपयोगकर्ता के वैध क्रेडेंशियल्स** हैं, तो आप उन क्रेडेंशियल्स के साथ **एक नया लॉगिन सत्र** **बना सकते हैं**:
```
runas /user:domain\username cmd.exe
```
**एक्सेस टोकन** में **LSASS** के अंदर लॉगिन सत्रों का भी **संदर्भ** होता है, यह उपयोगी है यदि प्रक्रिया को नेटवर्क के कुछ ऑब्जेक्ट्स तक पहुंचने की आवश्यकता है।\
आप एक प्रक्रिया लॉन्च कर सकते हैं जो **नेटवर्क सेवाओं तक पहुंचने के लिए विभिन्न क्रेडेंशियल्स का उपयोग करती है**:
```
runas /user:domain\username /netonly cmd.exe
```
यह उपयोगी है यदि आपके पास नेटवर्क में वस्तुओं तक पहुँचने के लिए उपयोगी क्रेडेंशियल्स हैं लेकिन वे क्रेडेंशियल्स वर्तमान होस्ट के अंदर मान्य नहीं हैं क्योंकि वे केवल नेटवर्क में उपयोग किए जाने वाले हैं (वर्तमान होस्ट में आपके वर्तमान उपयोगकर्ता विशेषाधिकारों का उपयोग किया जाएगा)।

### टोकन के प्रकार

दो प्रकार के टोकन उपलब्ध हैं:

- **प्राथमिक टोकन**: यह एक प्रक्रिया के सुरक्षा क्रेडेंशियल्स का प्रतिनिधित्व करता है। प्रक्रियाओं के साथ प्राथमिक टोकनों का निर्माण और संघनन ऐसे कार्य हैं जो उच्च विशेषाधिकार की आवश्यकता होती है, जो विशेषाधिकार विभाजन के सिद्धांत को उजागर करता है। आमतौर पर, टोकन निर्माण के लिए एक प्रमाणीकरण सेवा जिम्मेदार होती है, जबकि एक लॉगिन सेवा इसे उपयोगकर्ता के ऑपरेटिंग सिस्टम शेल के साथ संघनित करती है। यह ध्यान देने योग्य है कि प्रक्रियाएँ अपने माता-पिता की प्रक्रिया का प्राथमिक टोकन निर्माण के समय विरासत में लेती हैं।
- **प्रतिनिधित्व टोकन**: एक सर्वर एप्लिकेशन को सुरक्षित वस्तुओं तक पहुँचने के लिए ग्राहक की पहचान को अस्थायी रूप से अपनाने की शक्ति देता है। यह तंत्र चार स्तरों में विभाजित है:
- **गुमनाम**: एक अज्ञात उपयोगकर्ता के समान सर्वर पहुँच प्रदान करता है।
- **पहचान**: सर्वर को ग्राहक की पहचान की पुष्टि करने की अनुमति देता है बिना इसे वस्तु पहुँच के लिए उपयोग किए।
- **प्रतिनिधित्व**: सर्वर को ग्राहक की पहचान के तहत कार्य करने में सक्षम बनाता है।
- **प्रतिनिधित्व**: प्रतिनिधित्व के समान लेकिन इसमें इस पहचान को दूरस्थ प्रणालियों तक विस्तारित करने की क्षमता शामिल है जिनके साथ सर्वर बातचीत करता है, जिससे क्रेडेंशियल संरक्षण सुनिश्चित होता है।

#### प्रतिनिधित्व टोकन

यदि आपके पास पर्याप्त विशेषाधिकार हैं तो आप _**incognito**_ मॉड्यूल का उपयोग करके अन्य **टोकनों** को आसानी से **सूचीबद्ध** और **प्रतिनिधित्व** कर सकते हैं। यह **अन्य उपयोगकर्ता के रूप में कार्य करने** के लिए उपयोगी हो सकता है। आप इस तकनीक के साथ **विशेषाधिकार बढ़ा** भी सकते हैं।

### टोकन विशेषाधिकार

जानें कि कौन से **टोकन विशेषाधिकारों का दुरुपयोग करके विशेषाधिकार बढ़ाए जा सकते हैं:**

{{#ref}}
privilege-escalation-abusing-tokens.md
{{#endref}}

[**सभी संभावित टोकन विशेषाधिकारों और कुछ परिभाषाओं के लिए इस बाहरी पृष्ठ पर नज़र डालें**](https://github.com/gtworek/Priv2Admin)।

## संदर्भ

इन ट्यूटोरियल में टोकनों के बारे में अधिक जानें: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) और [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

{{#include ../../banners/hacktricks-training.md}}
