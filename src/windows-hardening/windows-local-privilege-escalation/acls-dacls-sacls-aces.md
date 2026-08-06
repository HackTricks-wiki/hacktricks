# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL), Access Control Entries (ACEs) का एक क्रमबद्ध समूह होता है, जो किसी object और उसकी properties के लिए protections निर्धारित करता है। मूल रूप से, ACL यह निर्धारित करता है कि दिए गए object पर कौन-सी actions, किन security principals (users या groups) द्वारा अनुमत या अस्वीकृत हैं।

ACLs दो प्रकार के होते हैं:

- **Discretionary Access Control List (DACL):** यह निर्दिष्ट करता है कि किन users और groups को किसी object तक access प्राप्त है या नहीं है।
- **System Access Control List (SACL):** यह किसी object तक access attempts की auditing को नियंत्रित करता है।

किसी file तक access करने की प्रक्रिया में system, object के security descriptor को user के access token के विरुद्ध जांचता है ताकि यह निर्धारित किया जा सके कि access दिया जाना चाहिए या नहीं और उस access की सीमा क्या होगी। यह निर्णय ACEs के आधार पर किया जाता है।<sup>[[1]](#references)</sup>

### **Key Components**

- **DACL:** इसमें किसी object के लिए users और groups को access permissions देने या अस्वीकार करने वाले ACEs होते हैं। मूल रूप से, यह मुख्य ACL है जो access rights निर्धारित करता है।
- **SACL:** इसका उपयोग objects तक access की auditing के लिए किया जाता है, जिसमें ACEs यह निर्धारित करते हैं कि Security Event Log में किस प्रकार के access को log किया जाएगा। यह unauthorized access attempts का पता लगाने या access issues की troubleshooting में अत्यंत उपयोगी हो सकता है।<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

प्रत्येक user session एक access token से जुड़ा होता है, जिसमें उस session से संबंधित security information शामिल होती है, जैसे user और group identities तथा privileges। इस token में एक logon SID भी शामिल होता है, जो session की विशिष्ट पहचान करता है।

Local Security Authority (LSASS), objects के access requests को process करते समय DACL में ऐसे ACEs खोजता है जो access का प्रयास करने वाले security principal से match करते हों। यदि कोई relevant ACE नहीं मिलता, तो access तुरंत grant कर दिया जाता है। अन्यथा, LSASS access token में मौजूद security principal के SID के विरुद्ध ACEs की तुलना करके यह निर्धारित करता है कि access दिया जा सकता है या नहीं।<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** DACLs के माध्यम से access permissions और SACLs के माध्यम से audit rules निर्धारित करते हैं।
- **Access Token:** इसमें किसी session के लिए user, group और privilege information होती है।
- **Access Decision:** यह DACL ACEs की access token के साथ तुलना करके लिया जाता है; SACLs का उपयोग auditing के लिए किया जाता है।<sup>[[1]](#references)</sup>

### ACEs

Access Control Entries (ACEs) के **तीन मुख्य प्रकार** होते हैं:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: यह ACE किसी object के लिए निर्दिष्ट users या groups को access स्पष्ट रूप से अस्वीकार करता है (DACL में)।
- **Access Allowed ACE**: यह ACE किसी object के लिए निर्दिष्ट users या groups को access स्पष्ट रूप से grant करता है (DACL में)।
- **System Audit ACE**: System Access Control List (SACL) में स्थित यह ACE, users या groups द्वारा किसी object तक access attempts के दौरान audit logs generate करने के लिए जिम्मेदार होता है। यह record करता है कि access allowed था या denied और access का प्रकार क्या था।

प्रत्येक ACE के **चार महत्वपूर्ण components** होते हैं:<sup>[[1]](#references)</sup>

1. User या group का **Security Identifier (SID)** (या graphical representation में उनका principal name)।
2. एक **flag**, जो ACE के type (access denied, allowed या system audit) की पहचान करता है।
3. **Inheritance flags**, जो यह निर्धारित करते हैं कि child objects अपने parent से ACE inherit कर सकते हैं या नहीं।
4. एक [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), जो 32-bit value होती है और object के granted rights को निर्दिष्ट करती है।

Access determination प्रत्येक ACE की क्रमिक जांच करके तब तक की जाती है जब तक:<sup>[[1]](#references)</sup>

- कोई **Access-Denied ACE**, access token में पहचाने गए trustee को requested rights स्पष्ट रूप से deny न कर दे।
- कोई **Access-Allowed ACE(s)** access token में मौजूद trustee को सभी requested rights स्पष्ट रूप से grant न कर दे।
- सभी ACEs की जांच के बाद, यदि किसी requested right को स्पष्ट रूप से allow नहीं किया गया है, तो access implicitly **denied** होता है।

### Order of ACEs

**ACEs** (वे rules जो बताते हैं कि कौन किसी चीज तक access कर सकता है या नहीं) को **DACL** नामक list में किस क्रम में रखा जाता है, यह बहुत महत्वपूर्ण है। ऐसा इसलिए है क्योंकि system इन rules के आधार पर access grant या deny करने के बाद बाकी rules की जांच करना बंद कर देता है।<sup>[[1]](#references)</sup>

इन ACEs को व्यवस्थित करने का एक सर्वोत्तम तरीका है, जिसे **"canonical order"** कहा जाता है। यह method सुनिश्चित करता है कि सब कुछ सुचारु और उचित तरीके से काम करे। **Windows 2000** और **Windows Server 2003** जैसे systems में इसका क्रम इस प्रकार है:

- सबसे पहले, इस item के लिए **specifically** बनाए गए सभी rules को उन rules से पहले रखें जो किसी अन्य स्थान, जैसे parent folder, से आए हैं।
- इन specific rules में, **"no" (deny)** कहने वाले rules को **"yes" (allow)** कहने वाले rules से पहले रखें।
- किसी अन्य स्थान से आए rules में, सबसे **closest source**, जैसे parent, से आए rules को पहले रखें और फिर क्रमशः पीछे के sources पर जाएं। यहां भी **"no"** को **"yes"** से पहले रखें।

यह setup दो महत्वपूर्ण तरीकों से सहायता करता है:

- यह सुनिश्चित करता है कि यदि कोई specific **"no"** मौजूद है, तो अन्य **"yes"** rules होने पर भी उसका पालन किया जाए।
- यह item के owner को यह तय करने का **अंतिम अधिकार** देता है कि किसे access मिले, इससे पहले कि parent folders या उससे पीछे के rules लागू हों।

इस तरीके से, किसी file या folder का owner यह सटीक रूप से निर्धारित कर सकता है कि किसे access मिलेगा, ताकि सही लोग access कर सकें और गलत लोग नहीं।

![NTFS access control entry ordering diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

इसलिए, यह **"canonical order"** यह सुनिश्चित करने के बारे में है कि access rules स्पष्ट और प्रभावी हों, specific rules को पहले रखकर और बाकी सभी rules को एक सुव्यवस्थित तरीके से व्यवस्थित करके।

### GUI Example

[**Example from here**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

यह किसी folder का classic security tab है, जिसमें ACL, DACL और ACEs दिखाए गए हैं:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

यदि हम **Advanced button** पर click करते हैं, तो हमें inheritance जैसे अधिक options मिलेंगे:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

और यदि आप कोई Security Principal add या edit करते हैं:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

अंत में, Auditing tab में SACL मौजूद होता है:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

जब हम किसी folder जैसे resource तक access manage करते हैं, तो हम Access Control Lists (ACLs) और Access Control Entries (ACEs) नामक lists और rules का उपयोग करते हैं। ये निर्धारित करते हैं कि कौन-सा user किसी data तक access कर सकता है और कौन नहीं।<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

मान लीजिए आपके पास Cost नाम का एक folder है और आप marketing team को छोड़कर सभी को उसका access देना चाहते हैं। Rules को सही तरीके से set up करके हम यह सुनिश्चित कर सकते हैं कि marketing team को access स्पष्ट रूप से deny किया जाए और उसके बाद बाकी सभी को access allow किया जाए। इसके लिए marketing team को access deny करने वाले rule को सभी को access allow करने वाले rule से पहले रखना होगा।

#### Allowing Access to a Specific Member of a Denied Group

मान लीजिए Bob, जो marketing director है, को Cost folder का access चाहिए, जबकि सामान्य रूप से marketing team को access नहीं मिलना चाहिए। हम Bob के लिए एक specific rule (ACE) add कर सकते हैं, जो उसे access grant करे, और इसे marketing team को access deny करने वाले rule से पहले रख सकते हैं। इस तरह, अपनी team पर लागू सामान्य restriction के बावजूद Bob को access मिल जाएगा।

#### Understanding Access Control Entries

ACEs, ACL में मौजूद individual rules होते हैं। ये users या groups की पहचान करते हैं, यह निर्दिष्ट करते हैं कि कौन-सा access allowed या denied है, और यह निर्धारित करते हैं कि ये rules sub-items पर किस प्रकार लागू होंगे (inheritance)। ACEs के दो मुख्य प्रकार होते हैं:

- **Generic ACEs**: ये व्यापक रूप से लागू होते हैं और या तो सभी प्रकार के objects को प्रभावित करते हैं या केवल containers (जैसे folders) और non-containers (जैसे files) के बीच अंतर करते हैं। उदाहरण के लिए, ऐसा rule जो users को folder के contents देखने की अनुमति देता है, लेकिन उसके अंदर मौजूद files तक access की अनुमति नहीं देता।
- **Object-Specific ACEs**: ये अधिक सटीक control प्रदान करते हैं और specific types of objects या object के अंदर individual properties के लिए rules set करने की अनुमति देते हैं। उदाहरण के लिए, users की directory में कोई rule किसी user को अपना phone number update करने की अनुमति दे सकता है, लेकिन login hours को नहीं।

प्रत्येक ACE में महत्वपूर्ण information होती है, जैसे rule किस पर लागू होता है (Security Identifier या SID का उपयोग करके), rule क्या allow या deny करता है (access mask का उपयोग करके), और यह अन्य objects द्वारा किस प्रकार inherit किया जाएगा।

#### Key Differences Between ACE Types

- **Generic ACEs** सरल access control scenarios के लिए उपयुक्त होते हैं, जहां एक ही rule किसी object के सभी aspects या किसी container के अंदर मौजूद सभी objects पर लागू होता है।
- **Object-Specific ACEs** अधिक complex scenarios के लिए उपयोग किए जाते हैं, विशेष रूप से Active Directory जैसे environments में, जहां किसी object की specific properties के लिए अलग-अलग access control की आवश्यकता हो सकती है।

संक्षेप में, ACLs और ACEs सटीक access controls निर्धारित करने में सहायता करते हैं, जिससे यह सुनिश्चित होता है कि केवल सही individuals या groups को sensitive information या resources तक access मिले। साथ ही, access rights को individual properties या object types के स्तर तक customize किया जा सकता है।

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | ACE के type को दर्शाने वाला flag। Windows 2000 और Windows Server 2003 छह प्रकार के ACE support करते हैं: तीन generic ACE types, जो सभी securable objects से जुड़े होते हैं। तीन object-specific ACE types, जो Active Directory objects के लिए मौजूद हो सकते हैं।                                                                                                                                                                                                                                                            |
| Flags       | Bit flags का set, जो inheritance और auditing को control करता है।                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | ACE के लिए allocate की गई memory के bytes की संख्या।                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | 32-bit value, जिसके bits object के access rights से संबंधित होते हैं। Bits को on या off set किया जा सकता है, लेकिन setting का अर्थ ACE type पर निर्भर करता है। उदाहरण के लिए, यदि read permissions right से संबंधित bit on है और ACE type Deny है, तो ACE object की permissions पढ़ने के अधिकार को deny करता है। यदि वही bit set है लेकिन ACE type Allow है, तो ACE object की permissions पढ़ने का अधिकार grant करता है। Access mask की अधिक details अगली table में दी गई हैं। |
| SID         | उस user या group की पहचान करता है, जिसका access इस ACE द्वारा controlled या monitored किया जाता है।                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | Data read करना, Execute करना, Data append करना |
| 16 - 22     | Standard Access Rights             | Delete, Write ACL, Write Owner            |
| 23          | Can access security ACL            |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | नीचे दिए गए सभी rights                   |
| 29          | Generic Execute                    | किसी program को execute करने के लिए आवश्यक सभी actions |
| 30          | Generic Write                      | किसी file में write करने के लिए आवश्यक सभी actions   |
| 31          | Generic Read                       | किसी file को read करने के लिए आवश्यक सभी actions       |

## References

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}
