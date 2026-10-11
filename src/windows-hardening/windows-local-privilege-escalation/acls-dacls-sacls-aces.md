# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL), Access Control Entries (ACEs) का एक क्रमबद्ध समूह होता है, जो किसी ऑब्जेक्ट और उसकी प्रॉपर्टीज़ की सुरक्षा निर्धारित करता है। मूल रूप से, ACL यह तय करता है कि कौन-से security principals (users या groups) किसी ऑब्जेक्ट पर कौन-सी कार्रवाइयाँ कर सकते हैं या नहीं कर सकते।

ACLs दो प्रकार के होते हैं:

- **Discretionary Access Control List (DACL):** यह तय करता है कि किन users और groups को किसी ऑब्जेक्ट का access है या नहीं है।
- **System Access Control List (SACL):** यह किसी ऑब्जेक्ट पर access attempts की auditing को नियंत्रित करता है।

किसी file को access करते समय, system यह तय करने के लिए ऑब्जेक्ट के security descriptor की तुलना user के access token से करता है कि access दिया जाना चाहिए या नहीं, और ACEs के आधार पर access का स्तर क्या होना चाहिए।<sup>[[1]](#references)</sup>

जब parent directory Full Control देती है, लेकिन child file पढ़ने से रोकती है, तो **child file** के effective DACL, owner और inheritance को अलग-अलग जाँचें। उस file का DACL बदलने के लिए file पर `WRITE_DAC` या लागू owner right की आवश्यकता होती है; [Microsoft `WRITE_DAC` को परिभाषित करता है](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) और [owner के implicit access का दस्तावेज़ देता है](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object)। केवल parent directory की permissions से यह साबित नहीं होता कि child file पढ़ी जा सकती है या उसका DACL बदला जा सकता है।

### **Key Components**

- **DACL:** इसमें ACEs होते हैं, जो किसी ऑब्जेक्ट के लिए users और groups को access permissions देते या रोकते हैं। मूल रूप से, यह मुख्य ACL है जो access rights निर्धारित करता है।
- **SACL:** इसका उपयोग ऑब्जेक्ट्स के access की auditing के लिए होता है। इसमें ACEs उन access के प्रकार तय करते हैं जिन्हें Security Event Log में दर्ज किया जाना है। अनधिकृत access attempts का पता लगाने या access की समस्याओं का निवारण करने में यह उपयोगी हो सकता है।<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

हर user session एक access token से जुड़ा होता है, जिसमें उस session से जुड़ी security जानकारी होती है, जैसे user और group identities तथा privileges। इस token में एक logon SID भी होता है, जो session की विशिष्ट पहचान करता है।

Local Security Authority (LSASS) किसी ऑब्जेक्ट पर access requests को process करते समय DACL में ऐसे ACEs खोजता है जो access का प्रयास कर रहे security principal से मेल खाते हों। यदि कोई संबंधित ACE नहीं मिलता, तो access तुरंत दे दिया जाता है। अन्यथा, LSASS access token में मौजूद security principal के SID के साथ ACEs की तुलना करके तय करता है कि access दिया जा सकता है या नहीं।<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** DACLs के ज़रिए access permissions और SACLs के ज़रिए audit rules तय करते हैं।
- **Access Token:** इसमें session के user, group और privilege की जानकारी होती है।
- **Access Decision:** DACL ACEs की तुलना access token से करके लिया जाता है; SACLs का उपयोग auditing के लिए होता है।<sup>[[1]](#references)</sup>

### ACEs

Access Control Entries (ACEs) के **तीन मुख्य प्रकार** हैं:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: यह ACE किसी DACL में बताए गए users या groups को किसी ऑब्जेक्ट का access स्पष्ट रूप से रोकता है।
- **Access Allowed ACE**: यह ACE किसी DACL में बताए गए users या groups को किसी ऑब्जेक्ट का access स्पष्ट रूप से देता है।
- **System Audit ACE**: System Access Control List (SACL) में मौजूद यह ACE, users या groups द्वारा किसी ऑब्जेक्ट को access करने के प्रयास पर audit logs बनाता है। यह दर्ज करता है कि access दिया गया या रोका गया, और access का प्रकार क्या था।

हर ACE के **चार महत्वपूर्ण घटक** होते हैं:<sup>[[1]](#references)</sup>

1. User या group का **Security Identifier (SID)** (या graphical representation में उनका principal name)।
2. एक **flag**, जो ACE का प्रकार बताता है (access denied, allowed या system audit)।
3. **Inheritance flags**, जो तय करते हैं कि child objects अपने parent से ACE inherit कर सकते हैं या नहीं।
4. एक [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), जो 32-bit value है और ऑब्जेक्ट को दिए गए rights बताती है।

Access का निर्णय हर ACE को क्रम से जाँचकर तब तक किया जाता है, जब तक:<sup>[[1]](#references)</sup>

- कोई **Access-Denied ACE**, access token में पहचाने गए trustee के अनुरोधित rights को स्पष्ट रूप से रोक न दे।
- **Access-Allowed ACE(s)**, access token में मौजूद trustee को सभी अनुरोधित rights स्पष्ट रूप से न दे दें।
- सभी ACEs की जाँच के बाद, यदि कोई अनुरोधित right **स्पष्ट रूप से allow नहीं किया गया है**, तो access को अप्रत्यक्ष रूप से **deny** कर दिया जाता है।

### Order of ACEs

**ACEs** (वे rules जो बताते हैं कि कौन किसी चीज़ को access कर सकता है या नहीं) को **DACL** नाम की list में किस क्रम में रखा गया है, यह बहुत महत्वपूर्ण है। ऐसा इसलिए है क्योंकि system इन rules के आधार पर access देने या रोकने के बाद बाकी rules को जाँचना बंद कर देता है।<sup>[[1]](#references)</sup>

इन ACEs को व्यवस्थित करने का एक बेहतर तरीका है, जिसे **"canonical order"** कहते हैं। इससे यह सुनिश्चित करने में मदद मिलती है कि सब कुछ सुचारू और निष्पक्ष रूप से काम करे। **Windows 2000** और **Windows Server 2003** जैसे systems में यह क्रम इस तरह है:

- पहले उन सभी rules को रखें जो **खास तौर पर इसी item के लिए** बनाए गए हैं। इसके बाद parent folder जैसी दूसरी जगह से inherited rules रखें।
- इन specific rules में, **"नहीं" (deny)** कहने वाले rules को **"हाँ" (allow)** कहने वाले rules से पहले रखें।
- दूसरी जगह से inherited rules में, **सबसे नज़दीकी source**—जैसे parent—के rules पहले रखें, फिर उससे दूर के sources के rules। यहाँ भी **"नहीं"** कहने वाले rules को **"हाँ"** कहने वाले rules से पहले रखें।

इस व्यवस्था के दो बड़े फायदे हैं:

- यह सुनिश्चित करती है कि कोई specific **"नहीं"** लागू हो, चाहे दूसरे **"हाँ"** वाले rules कुछ भी कहते हों।
- इससे item का owner, parent folders या अन्य sources के rules लागू होने से पहले, यह तय कर सकता है कि किसे access मिले।

इस तरह, किसी file या folder का owner यह बारीकी से तय कर सकता है कि किसे access मिले, ताकि सही लोग अंदर आ सकें और बाकी नहीं।

![NTFS access control entry क्रम का diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

इसलिए, **"canonical order"** का उद्देश्य यह है कि access rules स्पष्ट और प्रभावी रहें—specific rules को पहले रखा जाए और बाकी को सही क्रम में व्यवस्थित किया जाए।

### GUI Example

[**Example from here**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

यह किसी folder का classic security tab है, जिसमें ACL, DACL और ACEs दिखाए गए हैं:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

अगर हम **Advanced button** पर click करें, तो inheritance जैसे और options दिखाई देंगे:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

और अगर आप कोई Security Principal जोड़ें या edit करें:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

अंत में, Auditing tab में SACL होता है:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Access Control को सरल तरीके से समझना

Folder जैसे resources का access नियंत्रित करने के लिए, हम Access Control Lists (ACLs) और Access Control Entries (ACEs) नाम की lists और rules का उपयोग करते हैं। ये तय करते हैं कि कौन किसी खास data को access कर सकता है या नहीं।<sup>[[1]](#references)</sup>

#### किसी खास Group का Access रोकना

मान लें कि आपके पास Cost नाम का एक folder है और आप चाहते हैं कि marketing team को छोड़कर बाकी सभी लोग इसे access कर सकें। Rules को सही तरीके से सेट करके, हम यह सुनिश्चित कर सकते हैं कि बाकी सभी को access देने से पहले marketing team का access स्पष्ट रूप से रोका जाए। इसके लिए marketing team का access रोकने वाला rule, सभी को access देने वाले rule से पहले रखा जाता है।

#### Denied Group के किसी खास Member को Access देना

मान लें कि marketing director Bob को Cost folder का access चाहिए, जबकि marketing team को आम तौर पर access नहीं मिलना चाहिए। हम Bob के लिए एक specific rule (ACE) जोड़ सकते हैं, जो उसे access देता है, और उसे marketing team का access रोकने वाले rule से पहले रख सकते हैं। इस तरह, अपनी team पर लागू सामान्य रोक के बावजूद Bob को access मिल जाता है।

#### Access Control Entries को समझना

ACEs, ACL में मौजूद अलग-अलग rules होते हैं। ये users या groups की पहचान करते हैं, बताते हैं कि कौन-सा access दिया या रोका गया है, और तय करते हैं कि ये rules sub-items पर कैसे लागू होंगे (inheritance)। ACEs के दो मुख्य प्रकार हैं:

- **Generic ACEs**: ये व्यापक रूप से लागू होते हैं—या तो सभी प्रकार के objects पर, या सिर्फ containers (जैसे folders) और non-containers (जैसे files) के बीच अंतर करके। उदाहरण के लिए, कोई rule users को folder की contents देखने दे सकता है, लेकिन उसके अंदर की files access करने की अनुमति नहीं देता।
- **Object-Specific ACEs**: ये अधिक सटीक नियंत्रण देते हैं। इनके ज़रिए खास प्रकार के objects या किसी object की अलग-अलग properties के लिए rules सेट किए जा सकते हैं। उदाहरण के लिए, users की directory में कोई rule user को अपना phone number update करने दे सकता है, लेकिन login hours बदलने की अनुमति नहीं देता।

हर ACE में महत्वपूर्ण जानकारी होती है, जैसे कि rule किस पर लागू होता है (Security Identifier या SID से), rule क्या allow या deny करता है (access mask से), और दूसरे objects इसे कैसे inherit करते हैं।

#### ACE Types के बीच मुख्य अंतर

- **Generic ACEs** सरल access control scenarios के लिए उपयुक्त हैं, जहाँ एक ही rule किसी object के सभी पहलुओं या container के सभी objects पर लागू होता है।
- **Object-Specific ACEs** अधिक जटिल scenarios के लिए इस्तेमाल होते हैं—खासकर Active Directory जैसे environments में, जहाँ किसी object की विशिष्ट properties का access अलग-अलग नियंत्रित करना पड़ सकता है।

संक्षेप में, ACLs और ACEs सटीक access controls तय करने में मदद करते हैं। इससे यह सुनिश्चित होता है कि केवल सही व्यक्तियों या groups को संवेदनशील जानकारी या resources का access मिले। साथ ही, access rights को individual properties या object types के स्तर तक तय किया जा सकता है।

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | ACE का प्रकार बताने वाला flag। Windows 2000 और Windows Server 2003, ACE के छह प्रकारों को support करते हैं: तीन generic ACE types, जो सभी securable objects से जुड़े होते हैं; और तीन object-specific ACE types, जो Active Directory objects के लिए हो सकते हैं।                                                                                                                                                                                                                                                            |
| Flags       | Bit flags का ऐसा समूह जो inheritance और auditing को नियंत्रित करता है।                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | ACE के लिए allocate की गई memory के bytes की संख्या।                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | 32-bit value, जिसके bits ऑब्जेक्ट के access rights से जुड़े होते हैं। Bits को on या off किया जा सकता है, लेकिन setting का अर्थ ACE के प्रकार पर निर्भर करता है। उदाहरण के लिए, यदि permissions पढ़ने के right से जुड़ा bit on है और ACE का प्रकार Deny है, तो ACE ऑब्जेक्ट की permissions पढ़ने का right रोकता है। यदि वही bit on हो और ACE का प्रकार Allow हो, तो ACE ऑब्जेक्ट की permissions पढ़ने का right देता है। Access mask की अधिक जानकारी अगली table में है। |
| SID         | उस user या group की पहचान करता है, जिसका access इस ACE द्वारा नियंत्रित या monitor किया जाता है।                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | Data पढ़ना, Execute, Data जोड़ना           |
| 16 - 22     | Standard Access Rights             | Delete, Write ACL, Write Owner            |
| 23          | Security ACL को access कर सकता है  |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | नीचे दी गई सभी चीज़ें                      |
| 29          | Generic Execute                    | Program execute करने के लिए आवश्यक सभी चीज़ें |
| 30          | Generic Write                      | File में लिखने के लिए आवश्यक सभी चीज़ें   |
| 31          | Generic Read                       | File पढ़ने के लिए आवश्यक सभी चीज़ें       |

## References

- [1] [System ACLs का उपयोग कैसे करता है - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL और ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}
