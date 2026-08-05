# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**अधिक जानकारी के लिए original post देखें:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). यह एक summary है:

## Mach Messages Basic Info

यदि आपको Mach Messages के बारे में जानकारी नहीं है, तो इस page को देखना शुरू करें:


{{#ref}}
../../
{{#endref}}

फिलहाल याद रखें कि ([यहां दी गई definition](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages एक _mach port_ के माध्यम से भेजे जाते हैं, जो mach kernel में बना हुआ **single receiver, multiple sender communication** channel है। **Multiple processes किसी mach port पर messages भेज सकते हैं**, लेकिन किसी भी समय **केवल एक process उसे पढ़ सकता है**। File descriptors और sockets की तरह, mach ports kernel द्वारा allocate और manage किए जाते हैं और processes को केवल एक integer दिखाई देता है, जिसका उपयोग वे kernel को यह बताने के लिए कर सकते हैं कि वे अपने किस mach port का उपयोग करना चाहते हैं।

## XPC Connection

यदि आपको पता नहीं है कि XPC connection कैसे स्थापित किया जाता है, तो देखें:


{{#ref}}
../
{{#endref}}

## Vuln Summary

आपके लिए महत्वपूर्ण बात यह है कि **XPC abstraction one-to-one connection है**, लेकिन यह ऐसी technology पर आधारित है जिसमें **multiple senders हो सकते हैं, इसलिए:**

- Mach ports single receiver, **multiple sender** होते हैं।
- XPC connection का audit token **सबसे हाल में प्राप्त message से copied audit token** होता है।
- XPC connection का **audit token** प्राप्त करना कई **security checks** के लिए critical है।<sup>[1]</sup>

हालांकि पिछली स्थिति promising लगती है, कुछ scenarios में इससे problems नहीं होंगी ([यहां से](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens का उपयोग अक्सर authorization check के लिए किया जाता है, ताकि यह तय किया जा सके कि connection स्वीकार करना है या नहीं। चूंकि यह service port को भेजे गए message के माध्यम से होता है, इसलिए **अभी connection स्थापित नहीं हुआ होता**। इस port पर आने वाले अन्य messages को additional connection requests की तरह handle किया जाएगा। इसलिए **connection स्वीकार करने से पहले किए गए checks vulnerable नहीं हैं** (इसका अर्थ यह भी है कि `-listener:shouldAcceptNewConnection:` के अंदर audit token सुरक्षित है)। इसलिए हमें ऐसे XPC connections की तलाश है जो specific actions को verify करते हों।
- XPC event handlers synchronous रूप से handle किए जाते हैं। इसका अर्थ है कि एक message का event handler पूरा होने के बाद ही अगले message के लिए उसे call किया जाएगा, यहां तक कि concurrent dispatch queues पर भी। इसलिए **XPC event handler के अंदर audit token को अन्य सामान्य (non-reply!) messages द्वारा overwrite नहीं किया जा सकता**।<sup>[1]</sup>

यह दो अलग-अलग methods से exploitable हो सकता है:

1. Variant1:
- **Exploit** service **A** और service **B** से **connect** करता है।
- Service **B**, service A में ऐसी **privileged functionality** call कर सकता है जिसे user नहीं कर सकता।
- Service **A**, **`xpc_connection_get_audit_token`** को connection के **`dispatch_async`** में **event handler** के बाहर call करता है।
- इसलिए कोई **अलग message Audit Token को overwrite** कर सकता है, क्योंकि उसे event handler के बाहर asynchronously dispatch किया जा रहा है।
- Exploit **service B को service A का SEND right** देता है।
- इसलिए svc **B**, service **A** को **messages भेजेगा**।
- **Exploit** **privileged action** call करने का प्रयास करता है। RC में svc **A**, इस **action** की authorization check उस समय करता है जब **svc B ने Audit token overwrite कर दिया होता है** (जिससे exploit को privileged action call करने की access मिल जाती है)।
2. Variant 2:
- Service **B**, service A में ऐसी **privileged functionality** call कर सकता है जिसे user नहीं कर सकता।
- Exploit **service A** से connect करता है, जो exploit को एक specific **replay** **port** पर response की अपेक्षा करने वाला **message** भेजता है।
- Exploit **service B** को एक message भेजता है, जिसमें **वह reply port** दिया जाता है।
- जब service **B reply करता है**, तो वह **message service A को भेजता है**, जबकि **exploit service A को privileged functionality तक पहुंचने का प्रयास करने वाला अलग message भेजता है** और यह अपेक्षा करता है कि service B का reply सही समय पर Audit token को overwrite कर देगा (Race Condition)।

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- दो mach services **`A`** और **`B`**, जिनसे हम दोनों connect कर सकते हैं (sandbox profile और connection स्वीकार करने से पहले होने वाले authorization checks के आधार पर)।
- _**A**_ में किसी specific action के लिए **authorization check** होना चाहिए, जिसे **`B`** pass कर सकता है (लेकिन हमारा app नहीं)।
- उदाहरण के लिए, यदि B के पास कुछ **entitlements** हैं या वह **root** के रूप में चल रहा है, तो वह A से privileged action perform करने के लिए कह सकता है।
- इस authorization check के लिए **`A`** audit token asynchronously प्राप्त करता है, उदाहरण के लिए `dispatch_async` से `xpc_connection_get_audit_token` call करके।

> [!CAUTION]
> इस स्थिति में attacker एक **Race Condition** trigger कर सकता है और ऐसा **exploit** बना सकता है जो A से किसी action को कई बार perform करने के लिए कहता है, जबकि **B को `A` पर messages भेजने** के लिए इस्तेमाल करता है। जब RC **successful** होता है, तो **B का audit token memory में copy** हो जाएगा, जबकि A हमारे **exploit के request को handle** कर रहा होगा। इससे exploit को उस privileged action की access मिल जाएगी जिसे केवल B request कर सकता था।

यहां **`A`** के रूप में `smd` और **`B`** के रूप में `diagnosticd` का उपयोग किया गया था। smb का function [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) एक नया privileged helper toot (as **root**) install करने के लिए इस्तेमाल किया जा सकता है। यदि **root के रूप में चल रहा process `smd` से contact करता है**, तो कोई अन्य checks perform नहीं किए जाएंगे।

इसलिए service **B**, **`diagnosticd`** है, क्योंकि यह **root** के रूप में चलता है और किसी process को **monitor** करने के लिए इस्तेमाल किया जा सकता है। Monitoring शुरू होने के बाद यह **प्रति second कई messages भेजेगा**।

Attack करने के लिए:

1. Standard XPC protocol का उपयोग करके `smd` नामक service से **connection** शुरू करें।
2. `diagnosticd` से एक secondary **connection** बनाएं। सामान्य procedure के विपरीत, दो नए mach ports बनाने और भेजने के बजाय, client port send right को `smd` connection से जुड़े **send right** के duplicate से replace किया जाता है।
3. परिणामस्वरूप, XPC messages को `diagnosticd` तक dispatch किया जा सकता है, लेकिन `diagnosticd` के responses को वापस `smd` पर reroute किया जाता है। `smd` को ऐसा लगता है कि user और `diagnosticd` दोनों के messages एक ही connection से originate हो रहे हैं।

![Exploit process दिखाने वाली image](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. अगला step `diagnosticd` को किसी चुने हुए process (संभवतः user के अपने process) की monitoring शुरू करने का निर्देश देना है। साथ ही, routine 1004 messages की एक flood `smd` को भेजी जाती है। उद्देश्य elevated privileges के साथ कोई tool install करना है।
5. यह action `handle_bless` function में Race Condition trigger करता है। Timing critical है: `xpc_connection_get_pid` function call को user के process का PID return करना चाहिए (क्योंकि privileged tool user के app bundle में मौजूद है)। हालांकि, `connection_is_authorized` subroutine के अंदर `xpc_connection_get_audit_token` function call को `diagnosticd` से संबंधित audit token को reference करना चाहिए।<sup>[1]</sup>

## Variant 2: reply forwarding

XPC (Cross-Process Communication) environment में, event handlers concurrent रूप से execute नहीं होते, लेकिन reply messages को handle करने का behavior अलग होता है। विशेष रूप से, reply की अपेक्षा करने वाले messages भेजने के दो अलग methods हैं:

1. **`xpc_connection_send_message_with_reply`**: इसमें XPC message को designated queue पर receive और process किया जाता है।
2. **`xpc_connection_send_message_with_reply_sync`**: इसके विपरीत, इस method में XPC message को current dispatch queue पर receive और process किया जाता है।

यह distinction महत्वपूर्ण है, क्योंकि इससे **reply packets को XPC event handler के execution के साथ concurrently parse** किया जा सकता है। ध्यान दें कि `_xpc_connection_set_creds` audit token के partial overwrite से सुरक्षा के लिए locking implement करता है, लेकिन यह सुरक्षा पूरे connection object तक extend नहीं होती। परिणामस्वरूप, packet को parse करने और उसके event handler को execute करने के बीच audit token को replace किया जा सकता है।

इस vulnerability को exploit करने के लिए निम्न setup आवश्यक है:

- दो mach services, जिन्हें **`A`** और **`B`** कहा गया है, और दोनों connection स्थापित कर सकते हैं।
- Service **`A`** में किसी specific action के लिए authorization check होना चाहिए, जिसे केवल **`B`** perform कर सकता है (user का application नहीं)।
- Service **`A`** को reply की अपेक्षा करने वाला message भेजना चाहिए।
- User, **`B`** को ऐसा message भेज सकता हो जिसका वह response देगा।

Exploitation process में ये steps शामिल हैं:

1. Service **`A`** के reply की अपेक्षा करने वाला message भेजने की प्रतीक्षा करें।
2. सीधे **`A`** को reply करने के बजाय, reply port को hijack किया जाता है और service **`B`** को message भेजने के लिए इस्तेमाल किया जाता है।
3. इसके बाद forbidden action से संबंधित message dispatch किया जाता है, इस अपेक्षा के साथ कि इसे **`B`** के reply के साथ concurrently process किया जाएगा।<sup>[1]</sup>

नीचे वर्णित attack scenario का visual representation है:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instances खोजने में कठिनाई**: `xpc_connection_get_audit_token` के उपयोग वाले instances को statically और dynamically, दोनों तरीकों से खोजना कठिन था।
- **Methodology**: `xpc_connection_get_audit_token` function को hook करने के लिए Frida का उपयोग किया गया और उन calls को filter किया गया जो event handlers से originate नहीं हो रही थीं। हालांकि, यह method केवल hooked process तक सीमित था और active usage की आवश्यकता थी।
- **Analysis Tooling**: Reachable mach services की जांच के लिए IDA/Ghidra जैसे tools का उपयोग किया गया, लेकिन यह process समय लेने वाला था और dyld shared cache से संबंधित calls के कारण और complicated हो गया।
- **Scripting Limitations**: `dispatch_async` blocks से `xpc_connection_get_audit_token` की calls के लिए analysis को script करने के attempts blocks को parse करने और dyld shared cache के साथ interactions की complexities के कारण बाधित हुए।<sup>[1]</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Apple को एक report submit की गई, जिसमें `smd` के अंदर मिली general और specific issues का विवरण था।
- **Apple's Response**: Apple ने `smd` में `xpc_connection_get_audit_token` को `xpc_dictionary_get_audit_token` से replace करके issue को address किया।<sup>[1][2]</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function को secure माना जाता है, क्योंकि यह audit token को received XPC message से जुड़े mach message से directly retrieve करता है। हालांकि, यह `xpc_connection_get_audit_token` की तरह public API का हिस्सा नहीं है।
- **Absence of a Broader Fix**: यह स्पष्ट नहीं है कि Apple ने connection के saved audit token से match न करने वाले messages को discard करने जैसा अधिक comprehensive fix क्यों implement नहीं किया। कुछ scenarios (जैसे `setuid` का उपयोग) में legitimate audit token changes की संभावना एक factor हो सकती है।
- **Current Status**: यह issue iOS 17 और macOS 14 में अभी भी मौजूद है, जिससे इसे identify और understand करना कठिन बना हुआ है।<sup>[1]</sup>

## Finding vulnerable code paths in practice (2024–2025)

इस bug class के लिए XPC services का audit करते समय, message के event handler के बाहर या reply processing के दौरान concurrently किए जाने वाले authorization पर ध्यान दें।

Static triage hints:
- `dispatch_async`/`dispatch_after` या अन्य worker queues के माध्यम से queued blocks से reachable `xpc_connection_get_audit_token` calls खोजें, जो message handler के बाहर run होती हैं।
- ऐसे authorization helpers खोजें जो per-connection और per-message state को मिलाते हों (जैसे `xpc_connection_get_pid` से PID fetch करना, लेकिन `xpc_connection_get_audit_token` से audit token fetch करना)।
- NSXPC code में verify करें कि checks `-listener:shouldAcceptNewConnection:` में किए गए हैं या, per-message checks के लिए, implementation per-message audit token का उपयोग करती है (जैसे lower-level code में message की dictionary के माध्यम से `xpc_dictionary_get_audit_token`)।

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
नोट्स:
- macOS पर protected/Apple binaries को instrument करने के लिए SIP disabled या development environment की आवश्यकता हो सकती है; अपने builds या userland services पर testing को प्राथमिकता दें।
- reply-forwarding races (Variant 2) के लिए, `xpc_connection_send_message_with_reply` के timing को normal requests की तुलना में fuzz करके reply packets की concurrent parsing को monitor करें और जाँचें कि authorization के दौरान उपयोग किए गए effective audit token को प्रभावित किया जा सकता है या नहीं।

## Exploitation primitives जिनकी आपको संभवतः आवश्यकता होगी

- Multi-sender setup (Variant 1): A और B से connections बनाएँ; A के client port के send right को duplicate करें और उसे B के client port के रूप में उपयोग करें, ताकि B के replies A तक पहुँचाए जाएँ।
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A के pending request (reply port) से send-once right capture करें, फिर उस reply port का उपयोग करके B को एक crafted message भेजें, ताकि आपका privileged request parse किए जाने के दौरान B का reply A तक पहुंचे।

इनके लिए XPC bootstrap और message formats की low-level mach message crafting आवश्यक है; exact packet layouts और flags के लिए इस section के mach/XPC primer pages देखें।

## उपयोगी tooling

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) connections enumerate करने और traffic observe करने में मदद कर सकता है, ताकि multi-sender setups और timing को validate किया जा सके। उदाहरण: `gxpc -p <PID> --whitelist <service-name>`.
- libxpc के लिए Classic dyld interposing: black-box testing के दौरान call sites और stacks log करने के लिए `xpc_connection_send_message*` और `xpc_connection_get_audit_token` पर interpose करें।



## References

- [1] [Sector 7 – Don’t Talk All at Once! macOS पर Audit Token Spoofing द्वारा Privileges Elevate करना](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – macOS Ventura 13.4 की security content के बारे में (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
