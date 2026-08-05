# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**अधिक जानकारी के लिए original post देखें:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). यह एक summary है:

## Mach Messages Basic Info

यदि आप नहीं जानते कि Mach Messages क्या हैं, तो इस page को देखना शुरू करें:


{{#ref}}
../../
{{#endref}}

फिलहाल याद रखें कि ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages एक _mach port_ के माध्यम से भेजे जाते हैं, जो mach kernel में निर्मित **single receiver, multiple sender communication** channel है। **Multiple processes messages भेज सकते हैं** किसी mach port पर, लेकिन किसी भी समय **केवल एक single process इसे पढ़ सकता है**। File descriptors और sockets की तरह, mach ports kernel द्वारा allocate और manage किए जाते हैं और processes को केवल एक integer दिखाई देता है, जिसका उपयोग वे kernel को यह बताने के लिए कर सकते हैं कि वे अपने किस mach port का उपयोग करना चाहते हैं।

## XPC Connection

यदि आप नहीं जानते कि XPC connection कैसे establish किया जाता है, तो देखें:


{{#ref}}
../
{{#endref}}

## Vuln Summary

आपके लिए यह जानना महत्वपूर्ण है कि **XPC abstraction एक one-to-one connection है**, लेकिन यह ऐसी technology पर आधारित है जिसमें **multiple senders हो सकते हैं, इसलिए:**

- Mach ports single receiver, **multiple sender** होते हैं।
- XPC connection का audit token **सबसे हाल में received message से copied audit token होता है**।
- XPC connection का **audit token** प्राप्त करना कई **security checks** के लिए critical है।<sup>[[1]](#references)</sup>

हालाँकि पिछली स्थिति promising लगती है, लेकिन कुछ scenarios ऐसे हैं जहाँ इससे problems नहीं होंगी ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens का उपयोग अक्सर authorization check के लिए किया जाता है, ताकि यह तय किया जा सके कि connection accept करना है या नहीं। चूँकि यह service port को भेजे गए message के माध्यम से होता है, इसलिए **अभी कोई connection established नहीं हुआ होता**। इस port पर आने वाले अन्य messages को केवल additional connection requests के रूप में handle किया जाएगा। इसलिए **connection accept करने से पहले किए गए checks vulnerable नहीं हैं** (इसका अर्थ यह भी है कि `-listener:shouldAcceptNewConnection:` के भीतर audit token सुरक्षित है)। इसलिए हम ऐसे XPC connections **ढूँढ रहे हैं जो specific actions को verify करते हैं**।
- XPC event handlers को synchronously handle किया जाता है। इसका अर्थ है कि एक message का event handler पूरा होने के बाद ही अगले message के लिए उसे call किया जाएगा, यहाँ तक कि concurrent dispatch queues पर भी। इसलिए **XPC event handler के अंदर audit token को अन्य normal (non-reply!) messages द्वारा overwrite नहीं किया जा सकता**।<sup>[[1]](#references)</sup>

इसके exploitable होने के दो अलग-अलग methods हैं:

1. Variant1:
- **Exploit** service **A** और service **B** से **connect** करता है।
- Service **B**, service A में ऐसी **privileged functionality** call कर सकता है जिसे user नहीं कर सकता।
- Service **A**, **`xpc_connection_get_audit_token`** को तब call करता है जब वह किसी connection के **event handler** के अंदर **नहीं** होता और **`dispatch_async`** में भी नहीं होता।
- इसलिए कोई **different** message **Audit Token को overwrite** कर सकता है, क्योंकि वह event handler के बाहर asynchronously dispatch किया जा रहा है।
- **Exploit**, **service B को service A का SEND right** पास करता है।
- इसलिए svc **B**, service **A** को वास्तव में **messages send** करेगा।
- **Exploit** **privileged action** call करने का प्रयास करता है। RC में svc **A**, इस **action** की authorization तब **check** करता है जब **svc B ने Audit token overwrite कर दिया हो** (जिससे exploit को privileged action call करने का access मिल जाता है)।
2. Variant 2:
- Service **B**, service A में ऐसी **privileged functionality** call कर सकता है जिसे user नहीं कर सकता।
- Exploit, **service A** से connect करता है, जो exploit को एक **message भेजता है और response की अपेक्षा करता है**, एक specific **replay** **port** में।
- Exploit **service B** को एक message भेजता है और **वह reply port** pass करता है।
- जब service **B reply करता है**, तो वह **message service A को send करता है**, उसी समय **exploit service A को एक अलग message भेजता है**, जिसका उद्देश्य privileged functionality तक पहुँचना होता है और यह अपेक्षा की जाती है कि service B का reply सही समय पर Audit token को overwrite कर देगा (Race Condition)।

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- दो mach services **`A`** और **`B`**, जिनसे हम दोनों connect कर सकते हैं (sandbox profile और connection accept करने से पहले किए गए authorization checks के आधार पर)।
- _**A**_ में किसी specific action के लिए **authorization check** होना चाहिए, जिसे **`B`** pass कर सकता है (लेकिन हमारा app नहीं)।
- उदाहरण के लिए, यदि B के पास कुछ **entitlements** हैं या वह **root** के रूप में run हो रहा है, तो वह A से privileged action perform करने के लिए कह सकता है।
- इस authorization check के लिए **`A`** audit token को asynchronously प्राप्त करता है, उदाहरण के लिए `dispatch_async` से `xpc_connection_get_audit_token` call करके।

> [!CAUTION]
> इस स्थिति में attacker एक **Race Condition** trigger कर सकता है और ऐसा **exploit** बना सकता है जो A से किसी action को कई बार perform करने के लिए कहे, जबकि **B को `A` को messages send** करवाता रहे। जब RC **successful** होती है, तो **B का audit token** memory में copy हो जाएगा, उसी समय जब हमारे **exploit** का request A द्वारा **handle किया जा रहा होगा**। इससे उसे उस privileged action का **access** मिल जाएगा जिसे केवल B request कर सकता था।

यहाँ **`A`** के रूप में `smd` और **`B`** के रूप में `diagnosticd` का उपयोग किया गया था। `smb` से [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) function का उपयोग एक नया privileged helper toot (as **root**) install करने के लिए किया जा सकता है। यदि **root के रूप में run कर रहा process** **`smd` से contact करता है**, तो कोई अन्य checks perform नहीं किए जाएंगे।

इसलिए service **B**, **`diagnosticd`** है, क्योंकि यह **root** के रूप में run होता है और किसी process को **monitor** करने के लिए उपयोग किया जा सकता है। Monitoring शुरू होने के बाद यह **प्रति सेकंड कई messages send करेगा**।

Attack perform करने के लिए:

1. Standard XPC protocol का उपयोग करके `smd` नामक service से एक **connection** initiate करें।
2. `diagnosticd` से एक secondary **connection** बनाएं। Normal procedure के विपरीत, दो नए mach ports create और send करने के बजाय, client port send right को `smd` connection से जुड़े **send right** के duplicate से substitute करें।
3. इसके परिणामस्वरूप, XPC messages को `diagnosticd` तक dispatch किया जा सकता है, लेकिन `diagnosticd` के responses को वापस `smd` पर reroute किया जाता है। `smd` को ऐसा दिखाई देता है जैसे user और `diagnosticd` दोनों के messages एक ही connection से originate हो रहे हों।

![Exploit process को दर्शाने वाली image](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. अगला step `diagnosticd` को चुने गए process (संभवतः user के अपने process) की monitoring शुरू करने का निर्देश देना है। इसी दौरान routine 1004 messages की एक flood `smd` को भेजी जाती है। इसका उद्देश्य elevated privileges के साथ एक tool install करना है।
5. यह action `handle_bless` function के भीतर एक race condition trigger करता है। Timing critical है: `xpc_connection_get_pid` function call को user के process का PID return करना चाहिए (क्योंकि privileged tool user के app bundle में मौजूद है)। लेकिन `xpc_connection_get_audit_token` function को, विशेष रूप से `connection_is_authorized` subroutine के अंदर, `diagnosticd` से संबंधित audit token को reference करना चाहिए।<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

एक XPC (Cross-Process Communication) environment में, हालाँकि event handlers concurrently execute नहीं होते, reply messages को handle करने का behavior unique होता है। विशेष रूप से, reply की अपेक्षा करने वाले messages भेजने के लिए दो अलग-अलग methods मौजूद हैं:

1. **`xpc_connection_send_message_with_reply`**: यहाँ XPC message को एक designated queue पर receive और process किया जाता है।
2. **`xpc_connection_send_message_with_reply_sync`**: इसके विपरीत, इस method में XPC message को current dispatch queue पर receive और process किया जाता है।

यह distinction महत्वपूर्ण है क्योंकि इससे **reply packets को XPC event handler के execution के साथ concurrently parse** किए जाने की संभावना बनती है। विशेष रूप से, `_xpc_connection_set_creds` audit token के partial overwrite से सुरक्षा के लिए locking implement करता है, लेकिन यह protection पूरे connection object तक extend नहीं होती। परिणामस्वरूप, packet को parse करने और उसके event handler के execution के बीच के interval में audit token replace किया जा सकता है।

इस vulnerability को exploit करने के लिए निम्न setup आवश्यक है:

- दो mach services, जिन्हें **`A`** और **`B`** कहा गया है, और दोनों connection establish कर सकते हैं।
- Service **`A`** में किसी specific action के लिए authorization check होना चाहिए, जिसे केवल **`B`** perform कर सकता है (user का application नहीं)।
- Service **`A`** को ऐसा message send करना चाहिए जिसमें reply की अपेक्षा हो।
- User, **`B`** को ऐसा message भेज सके जिसका वह response देगा।

Exploitation process में निम्न steps शामिल हैं:

1. Service **`A`** द्वारा reply की अपेक्षा करने वाला message भेजे जाने की प्रतीक्षा करें।
2. सीधे **`A`** को reply करने के बजाय, reply port को hijack करें और उसका उपयोग service **`B`** को message भेजने के लिए करें।
3. इसके बाद forbidden action से संबंधित एक message dispatch करें और अपेक्षा करें कि इसे **`B`** के reply के साथ concurrently process किया जाएगा।<sup>[[1]](#references)</sup>

नीचे वर्णित attack scenario का visual representation दिया गया है:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instances locate करने में कठिनाइयाँ**: `xpc_connection_get_audit_token` के usage के instances को statically और dynamically, दोनों तरीकों से search करना challenging था।
- **Methodology**: `xpc_connection_get_audit_token` function को hook करने के लिए Frida का उपयोग किया गया और उन calls को filter किया गया जो event handlers से originate नहीं हो रही थीं। हालाँकि, यह method केवल hooked process तक सीमित था और active usage आवश्यक था।
- **Analysis Tooling**: Reachable mach services की examination के लिए IDA/Ghidra जैसे tools का उपयोग किया गया, लेकिन यह process time-consuming था और dyld shared cache से संबंधित calls के कारण और complicated हो गया।
- **Scripting Limitations**: `dispatch_async` blocks से `xpc_connection_get_audit_token` की calls के लिए analysis script करने के attempts blocks को parse करने और dyld shared cache के साथ interactions की complexities के कारण बाधित हुए।<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Apple को एक report submit की गई, जिसमें `smd` के भीतर मिली general और specific issues का विवरण था।
- **Apple's Response**: Apple ने `smd` में `xpc_connection_get_audit_token` को `xpc_dictionary_get_audit_token` से substitute करके issue address किया।<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function को secure माना जाता है, क्योंकि यह audit token को received XPC message से जुड़े mach message से directly retrieve करता है। हालाँकि, `xpc_connection_get_audit_token` की तरह यह भी public API का हिस्सा नहीं है।
- **Absence of a Broader Fix**: यह अभी unclear है कि Apple ने कोई अधिक comprehensive fix क्यों implement नहीं किया, जैसे कि ऐसे messages को discard करना जो connection के saved audit token से match नहीं करते। कुछ scenarios में legitimate audit token changes (जैसे `setuid` usage) की संभावना एक factor हो सकती है।
- **Current Status**: यह issue iOS 17 और macOS 14 में अभी भी मौजूद है, जिससे इसे identify और understand करना कठिन बना हुआ है।<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

इस bug class के लिए XPC services का audit करते समय, message के event handler के बाहर या reply processing के दौरान concurrently perform होने वाले authorization पर ध्यान दें।

Static triage hints:
- `xpc_connection_get_audit_token` की उन calls को search करें जो `dispatch_async`/`dispatch_after` या अन्य worker queues के माध्यम से queued blocks से reachable हों और message handler के बाहर run होती हों।
- ऐसे authorization helpers खोजें जो per-connection और per-message state को mix करते हों (जैसे `xpc_connection_get_pid` से PID fetch करना, लेकिन audit token `xpc_connection_get_audit_token` से लेना)।
- NSXPC code में verify करें कि checks `-listener:shouldAcceptNewConnection:` में किए गए हों या, per-message checks के लिए, implementation per-message audit token का उपयोग करती हो (जैसे lower-level code में message के dictionary के माध्यम से `xpc_dictionary_get_audit_token`)।

Dynamic triage tips:
- `xpc_connection_get_audit_token` को hook करें और उन invocations को flag करें जिनके user stack में event-delivery path (जैसे `_xpc_connection_mach_event`) शामिल नहीं है। Example Frida hook:
```javascript
Interceptor.attach(Module.getExportByName(null, 'xpc_connection_get_audit_token'), {
onEnter(args) {
const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
.map(DebugSymbol.fromAddress).join('\n');
if (!bt.includes('_xpc_connection_mach_event')) {
console.log('[!] xpc_connection_get_audit_token outside handler\n' + bt);
}
}
});
```
Notes:
- macOS पर protected/Apple binaries को instrument करने के लिए SIP disabled या development environment की आवश्यकता हो सकती है; अपने builds या userland services पर testing करना बेहतर है।
- reply-forwarding races (Variant 2) के लिए, `xpc_connection_send_message_with_reply` के timings बनाम normal requests को fuzz करके reply packets की concurrent parsing को monitor करें और जांचें कि authorization के दौरान उपयोग किए गए effective audit token को प्रभावित किया जा सकता है या नहीं।

## Exploitation primitives जिन्हें आपको संभवतः आवश्यक होगा

- Multi-sender setup (Variant 1): A और B से connections बनाएं; A के client port के send right को duplicate करें और उसे B के client port के रूप में उपयोग करें, ताकि B के replies A तक deliver हों।
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A के pending request (reply port) से send-once right capture करें, फिर उस reply port का उपयोग करके B को crafted message भेजें, ताकि आपका privileged request parse किए जाने के दौरान B का reply A तक पहुंचे।

इनके लिए XPC bootstrap और message formats को low-level mach message crafting की आवश्यकता होती है; exact packet layouts और flags के लिए इस section के mach/XPC primer pages देखें।

## Useful tooling

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) connections को enumerate करने और traffic observe करने में सहायता कर सकता है, ताकि multi-sender setups और timing को validate किया जा सके। उदाहरण: `gxpc -p <PID> --whitelist <service-name>`.
- libxpc के लिए Classic dyld interposing: black-box testing के दौरान call sites और stacks को log करने के लिए `xpc_connection_send_message*` और `xpc_connection_get_audit_token` पर interpose करें।



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
