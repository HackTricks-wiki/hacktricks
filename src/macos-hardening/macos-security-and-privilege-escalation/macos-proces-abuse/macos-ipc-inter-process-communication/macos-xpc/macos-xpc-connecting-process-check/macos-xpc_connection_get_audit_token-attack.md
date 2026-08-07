# macOS xpc_connection_get_audit_token Attack

{{#include ../../../../../../banners/hacktricks-training.md}}

**अधिक जानकारी के लिए original post देखें:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). यह उसका summary है:<sup>[[1]](#references)</sup>

## Mach Messages Basic Info

यदि आप नहीं जानते कि Mach Messages क्या होते हैं, तो इस page को देखना शुरू करें:


{{#ref}}
../../
{{#endref}}

फिलहाल याद रखें कि ([यहाँ से definition](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>\
Mach messages एक _mach port_ के माध्यम से भेजे जाते हैं, जो mach kernel में निर्मित **single receiver, multiple sender communication** channel है। **Multiple processes किसी mach port पर messages भेज सकते हैं**, लेकिन किसी भी समय **केवल एक single process इसे read कर सकता है**। File descriptors और sockets की तरह, mach ports kernel द्वारा allocate और manage किए जाते हैं और processes को केवल एक integer दिखाई देता है, जिसका उपयोग वे kernel को यह बताने के लिए कर सकते हैं कि वे अपने किस mach port का उपयोग करना चाहते हैं।

## XPC Connection

यदि आप नहीं जानते कि XPC connection कैसे establish किया जाता है, तो देखें:


{{#ref}}
../
{{#endref}}

## Vuln Summary

आपके लिए जानना महत्वपूर्ण है कि **XPC का abstraction one-to-one connection है**, लेकिन यह ऐसी technology पर आधारित है जिसमें **multiple senders हो सकते हैं, इसलिए:**

- Mach ports single receiver, **multiple sender** होते हैं।
- XPC connection का audit token **सबसे हाल में received message से copy किया गया audit token होता है**।
- किसी XPC connection का **audit token** प्राप्त करना कई **security checks** के लिए critical है।<sup>[[1]](#references)</sup>

हालाँकि पिछली स्थिति promising लगती है, लेकिन कुछ scenarios में इससे problems नहीं होंगी ([यहाँ से](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):<sup>[[1]](#references)</sup>

- Audit tokens का अक्सर authorization check में उपयोग किया जाता है ताकि यह तय किया जा सके कि connection स्वीकार करना है या नहीं। चूँकि यह service port को एक message भेजकर किया जाता है, इसलिए **अभी कोई connection establish नहीं हुआ होता**। इस port पर आने वाले अन्य messages को additional connection requests के रूप में handle किया जाएगा। इसलिए **connection स्वीकार करने से पहले किए गए checks vulnerable नहीं होते** (इसका यह भी अर्थ है कि `-listener:shouldAcceptNewConnection:` के भीतर audit token safe है)। इसलिए हमें ऐसे XPC connections की तलाश है जो specific actions को verify करते हों।
- XPC event handlers को synchronously handle किया जाता है। इसका अर्थ है कि concurrent dispatch queues पर भी, अगले message के लिए handler call करने से पहले एक message का event handler पूरा होना आवश्यक है। इसलिए **XPC event handler के अंदर audit token को अन्य normal (non-reply!) messages द्वारा overwrite नहीं किया जा सकता**।<sup>[[1]](#references)</sup>

इसे exploit करने के दो अलग-अलग methods हो सकते हैं:

1. Variant1:
- **Exploit** service **A** और service **B** से **connect** करता है।
- Service **B**, service A में ऐसी **privileged functionality** call कर सकता है जिसे user नहीं कर सकता।
- Service **A**, **`dispatch_async`** में किसी connection के **event handler** के अंदर न रहते हुए **`xpc_connection_get_audit_token`** call करता है।
- इसलिए एक **different** message **Audit Token को overwrite** कर सकता है, क्योंकि इसे event handler के बाहर asynchronously dispatch किया जा रहा है।
- Exploit **service B को service A का SEND right** देता है।
- इसलिए svc **B**, service **A** को **messages भेजेगा**।
- **Exploit** **privileged action** call करने का प्रयास करता है। एक RC में svc **A**, इस **action** का authorization check उस समय करता है जब **svc B ने Audit token overwrite कर दिया हो** (जिससे exploit को privileged action call करने की access मिल जाती है)।
2. Variant 2:
- Service **B**, service A में ऐसी **privileged functionality** call कर सकता है जिसे user नहीं कर सकता।
- Exploit **service A** से connect करता है, जो exploit को एक specific **replay** **port** पर response की अपेक्षा करने वाला **message** भेजता है।
- Exploit **service** B को एक message भेजता है जिसमें **वह reply port** pass किया जाता है।
- जब service **B reply करता है**, तो वह **message service A को भेजता है**, जबकि **exploit service A को एक अलग message भेजता है**, जो **privileged functionality** तक पहुँचने का प्रयास करता है और यह उम्मीद करता है कि service B का reply सही समय पर Audit token को overwrite कर देगा (Race Condition)।

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

- दो mach services **`A`** और **`B`**, जिनसे हम दोनों connect कर सकते हैं (sandbox profile और connection स्वीकार करने से पहले किए जाने वाले authorization checks के आधार पर)।
- _**A**_ में किसी specific action के लिए **authorization check** होना चाहिए, जिसे **`B`** pass कर सकता है (लेकिन हमारा app नहीं कर सकता)।
- उदाहरण के लिए, यदि B के पास कुछ **entitlements** हैं या वह **root** के रूप में run हो रहा है, तो वह A से privileged action perform करने के लिए कह सकता है।
- इस authorization check के लिए, **`A`** audit token asynchronously प्राप्त करता है, उदाहरण के लिए `dispatch_async` से `xpc_connection_get_audit_token` call करके।

> [!CAUTION]
> इस स्थिति में attacker एक **Race Condition** trigger कर सकता है और ऐसा **exploit** बना सकता है जो A से किसी action को perform करने के लिए कई बार request करे, जबकि **B** को `A` को **messages भेजने** के लिए उपयोग किया जाए। जब RC **successful** होता है, तो **B** का **audit token** memory में copy हो जाएगा, जबकि A हमारे **exploit** की request को handle कर रहा होगा। इससे exploit को उस privileged action तक **access** मिल जाएगी जिसे केवल B request कर सकता था।

यह स्थिति **`A`** के रूप में `smd` और **`B`** के रूप में `diagnosticd` के साथ हुई। [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) function का उपयोग एक नए privileged helper toot को ( **root** के रूप में) install करने के लिए किया जा सकता है। यदि **root के रूप में चलने वाला process** **smd से contact करता है**, तो कोई अन्य checks perform नहीं किए जाएंगे।

इसलिए service **B**, **`diagnosticd`** है, क्योंकि यह **root** के रूप में run होती है और किसी process को **monitor** करने के लिए उपयोग की जा सकती है। Monitoring शुरू होने के बाद यह **प्रति second कई messages भेजेगी।**

Attack perform करने के लिए:

1. Standard XPC protocol का उपयोग करके `smd` नामक service से एक **connection** initiate करें।
2. `diagnosticd` से एक secondary **connection** बनाएं। Normal procedure के विपरीत, दो नए mach ports बनाने और भेजने के बजाय, client port send right को `smd` connection से जुड़े **send right** के duplicate से substitute करें।
3. परिणामस्वरूप, XPC messages को `diagnosticd` तक dispatch किया जा सकता है, लेकिन `diagnosticd` के responses को `smd` पर reroute किया जाता है। `smd` को ऐसा दिखाई देता है जैसे user और `diagnosticd` दोनों के messages एक ही connection से originate हो रहे हों।

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. अगला step `diagnosticd` को किसी चुने हुए process (संभवतः user के अपने process) की monitoring शुरू करने का निर्देश देना है। साथ ही, routine 1004 messages की एक flood `smd` को भेजी जाती है। इसका उद्देश्य elevated privileges के साथ एक tool install करना है।
5. यह action `handle_bless` function के भीतर race condition trigger करता है। Timing critical है: `xpc_connection_get_pid` function call को user के process का PID return करना चाहिए (क्योंकि privileged tool user के app bundle में मौजूद है)। हालांकि, `connection_is_authorized` subroutine के भीतर विशेष रूप से `xpc_connection_get_audit_token` function को `diagnosticd` से संबंधित audit token को reference करना चाहिए।<sup>[[1]](#references)</sup>

## Variant 2: reply forwarding

XPC (Cross-Process Communication) environment में, event handlers concurrently execute नहीं होते, लेकिन reply messages को handle करने का behavior unique होता है। विशेष रूप से, reply की अपेक्षा करने वाले messages भेजने के दो अलग-अलग methods हैं:

1. **`xpc_connection_send_message_with_reply`**: यहाँ XPC message को एक designated queue पर receive और process किया जाता है।
2. **`xpc_connection_send_message_with_reply_sync`**: इसके विपरीत, इस method में XPC message को current dispatch queue पर receive और process किया जाता है।

यह distinction महत्वपूर्ण है, क्योंकि इससे **reply packets को XPC event handler के execution के साथ concurrently parse** किए जाने की संभावना बनती है। विशेष रूप से, `_xpc_connection_set_creds` audit token के partial overwrite से सुरक्षा के लिए locking implement करता है, लेकिन यह protection पूरे connection object तक extend नहीं होती। परिणामस्वरूप, packet parse होने और उसके event handler के execute होने के बीच audit token replace किया जा सकता है।

इस vulnerability को exploit करने के लिए निम्न setup आवश्यक है:

- दो mach services, जिन्हें **`A`** और **`B`** कहा गया है, और दोनों connection establish कर सकते हों।
- Service **`A`** में किसी specific action के लिए authorization check होना चाहिए, जिसे केवल **`B`** perform कर सकता हो (user का application नहीं)।
- Service **`A`** को ऐसा message भेजना चाहिए जो reply की अपेक्षा करता हो।
- User, **`B`** को ऐसा message भेज सके जिसका वह response देगा।

Exploitation process में निम्न steps शामिल हैं:

1. Service **`A`** के reply की अपेक्षा करने वाला message भेजने की प्रतीक्षा करें।
2. सीधे **`A`** को reply करने के बजाय, reply port hijack करें और इसका उपयोग service **`B`** को message भेजने के लिए करें।
3. इसके बाद forbidden action से संबंधित एक message dispatch करें और उम्मीद करें कि इसे **`B`** के reply के साथ concurrently process किया जाएगा।<sup>[[1]](#references)</sup>

नीचे वर्णित attack scenario का visual representation दिया गया है:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instances Locate करने में Difficulties**: `xpc_connection_get_audit_token` के उपयोग वाली instances को statically और dynamically, दोनों तरीकों से search करना challenging था।
- **Methodology**: `xpc_connection_get_audit_token` function को hook करने के लिए Frida का उपयोग किया गया और उन calls को filter किया गया जो event handlers से originate नहीं हो रही थीं। हालांकि, यह method केवल hooked process तक सीमित था और active usage की आवश्यकता थी।
- **Analysis Tooling**: Reachable mach services की examination के लिए IDA/Ghidra जैसे tools का उपयोग किया गया, लेकिन यह process time-consuming था और dyld shared cache से संबंधित calls के कारण और complicated हो गया।
- **Scripting Limitations**: `dispatch_async` blocks से `xpc_connection_get_audit_token` को होने वाली calls के analysis को script करने के प्रयास blocks को parse करने और dyld shared cache के साथ interactions की complexities के कारण बाधित हुए।<sup>[[1]](#references)</sup>

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: `smd` के भीतर मिली general और specific issues की details वाली report Apple को submit की गई।
- **Apple's Response**: Apple ने `xpc_connection_get_audit_token` को `xpc_dictionary_get_audit_token` से substitute करके `smd` में issue को address किया।<sup>[[1]](#references)[[2]](#references)</sup>
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` function को secure माना जाता है, क्योंकि यह audit token को received XPC message से जुड़े mach message से directly retrieve करता है। हालांकि, `xpc_connection_get_audit_token` की तरह यह भी public API का हिस्सा नहीं है।
- **Absence of a Broader Fix**: यह स्पष्ट नहीं है कि Apple ने अधिक comprehensive fix क्यों implement नहीं किया, जैसे connection के saved audit token से align न करने वाले messages को discard करना। कुछ scenarios (जैसे `setuid` usage) में legitimate audit token changes की संभावना इसका एक कारण हो सकती है।
- **Current Status**: यह issue iOS 17 और macOS 14 में बना हुआ है, जिससे इसे identify और understand करना चाहने वालों के लिए challenge पैदा होता है।<sup>[[1]](#references)</sup>

## Finding vulnerable code paths in practice (2024–2025)

इस bug class के लिए XPC services का auditing करते समय, उन authorization checks पर focus करें जो message के event handler के बाहर या reply processing के साथ concurrently perform किए जाते हैं।

Static triage hints:
- `dispatch_async`/`dispatch_after` या अन्य worker queues के माध्यम से queued blocks से reachable `xpc_connection_get_audit_token` calls को search करें, जो message handler के बाहर run होते हैं।
- ऐसे authorization helpers खोजें जो per-connection और per-message state को mix करते हैं (जैसे `xpc_connection_get_pid` से PID fetch करना लेकिन `xpc_connection_get_audit_token` से audit token प्राप्त करना)।
- NSXPC code में verify करें कि checks `-listener:shouldAcceptNewConnection:` में किए गए हैं या, per-message checks के लिए, implementation per-message audit token का उपयोग करती है (जैसे lower-level code में message के dictionary के माध्यम से `xpc_dictionary_get_audit_token`)।

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
- macOS पर protected/Apple binaries को instrument करने के लिए SIP disabled या development environment आवश्यक हो सकता है; अपने builds या userland services पर testing करना बेहतर है।
- reply-forwarding races (Variant 2) के लिए, `xpc_connection_send_message_with_reply` के concurrent parsing और normal requests के timing को fuzz करके monitor करें और जाँचें कि authorization के दौरान उपयोग किए गए effective audit token को प्रभावित किया जा सकता है या नहीं।

## Exploitation primitives you will likely need

- Multi-sender setup (Variant 1): A और B से connections बनाएँ; A के client port के send right को duplicate करें और उसे B के client port के रूप में उपयोग करें, ताकि B के replies A तक पहुँचाए जाएँ।
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A के pending request (reply port) से send-once right capture करें, फिर उस reply port का उपयोग करके B को crafted message भेजें, ताकि आपका privileged request parse किए जाने के दौरान B का reply A तक पहुंच जाए।

इनके लिए XPC bootstrap और message formats की low-level mach message crafting आवश्यक है; exact packet layouts और flags के लिए इस section के mach/XPC primer pages देखें।

## Useful tooling

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) connections को enumerate करने और traffic observe करने में सहायता कर सकता है, जिससे multi-sender setups और timing को validate किया जा सकता है। Example: `gxpc -p <PID> --whitelist <service-name>`.
- libxpc के लिए classic dyld interposing: black-box testing के दौरान call sites और stacks को log करने के लिए `xpc_connection_send_message*` और `xpc_connection_get_audit_token` पर interpose करें।



## References

- [1] [Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)
- [2] [Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405)](https://support.apple.com/en-us/106333)


{{#include ../../../../../../banners/hacktricks-training.md}}
