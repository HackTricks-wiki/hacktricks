# macOS xpc_connection_get_audit_token हमला

{{#include ../../../../../../banners/hacktricks-training.md}}

**अधिक जानकारी के लिए मूल पोस्ट देखें:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). यह एक सारांश है:

## Mach Messages मूल जानकारी

यदि आप Mach Messages के बारे में नहीं जानते तो इस पृष्ठ को देखें:


{{#ref}}
../../
{{#endref}}

इस समय के लिए याद रखें कि ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach messages एक _mach port_ के माध्यम से भेजे जाते हैं, जो mach kernel में निर्मित एक **single receiver, multiple sender communication** चैनल है। **कई processes संदेश भेज सकते हैं** एक mach port पर, लेकिन किसी भी समय **केवल एक process ही उसे पढ़ सकता है**। file descriptors और sockets की तरह, mach ports kernel द्वारा आवंटित और प्रबंधित किए जाते हैं और processes केवल एक integer देखते हैं, जिसे वे kernel को यह संकेत देने के लिए उपयोग कर सकते हैं कि वे अपने कौन से mach ports का उपयोग करना चाहते हैं।

## XPC Connection

यदि आप नहीं जानते कि XPC connection कैसे स्थापित होता है तो देखें:


{{#ref}}
../
{{#endref}}

## भेद्यता सारांश

जानने लायक महत्वपूर्ण बात यह है कि **XPC की abstraction एक one-to-one connection है**, पर यह एक ऐसी तकनीक के ऊपर बनी है जिसमें **multiple senders हो सकते हैं, इसलिए:**

- Mach ports single receiver, **multiple sender** होते हैं।
- एक XPC connection का audit token वह audit token होता है जो **most recently received message** से copy किया गया होता है।
- किसी XPC connection का **audit token प्राप्त करना** कई **security checks** के लिए महत्वपूर्ण है।

हालाँकि यह स्थिति आशाजनक लगती है पर कुछ परिदृश्यों में यह समस्यात्मक नहीं होगा ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

- Audit tokens प्रायः authorization check के लिए उपयोग होते हैं यह तय करने के लिए कि connection स्वीकार किया जाए या नहीं। चूंकि यह सेवा पोर्ट को भेजे गए संदेश के माध्यम से होता है, उस समय **कोई connection अभी स्थापित नहीं होता**। इस पोर्ट पर और संदेश केवल अतिरिक्त connection अनुरोधों के रूप में व्यवहार किए जाएँगे। इसलिए किसी connection को स्वीकार करने से पहले की कोई भी **जाँच vulnerable नहीं होती** (इसका अर्थ यह भी है कि `-listener:shouldAcceptNewConnection:` के अंदर audit token सुरक्षित है)। इसलिए हम **ऐसी XPC connections की तलाश कर रहे हैं जो specific actions को verify करती हैं**।
- XPC event handlers synchronous ढंग से संभाले जाते हैं। इसका अर्थ है कि एक संदेश के लिए event handler पूरा होना चाहिए अगला संदेश handle करने से पहले, भले ही concurrent dispatch queues पर हों। इसलिए एक **XPC event handler के अंदर audit token अन्य सामान्य (non-reply!) संदेशों द्वारा overwrite नहीं किया जा सकता**।

इसका दुरुपयोग दो अलग-अलग तरीकों से हो सकता है:

1. Variant1:
- **Exploit** सेवा **A** और सेवा **B** दोनों से **connect** करता है
- सेवा **B** सेवा A में एक **privileged functionality** कॉल कर सकती है जिसे user नहीं कर सकता
- सेवा **A** `xpc_connection_get_audit_token` को कॉल करती है जबकि वह **event handler** के अंदर **नहीं** है बल्कि **`dispatch_async`** के अंदर है।
- इसलिए एक **different** संदेश Audit Token को **overwrite** कर सकता है क्योंकि यह event handler के बाहर asynchronous रूप से dispatch हो रहा है।
- exploit, सेवा **A को svc B को SEND right देता है**।
- इसलिए svc **B** वास्तव में सेवा **A** को **messages भेजेगा**।
- **exploit** privileged action को **call** करने की कोशिश करता है। svc **A** इस action के authorization की **जाँच** करता है जबकि **svc B ने Audit token overwrite कर दिया होता है** (जिससे exploit को वही privilege मिल जाता है जो केवल B अनुरोध कर सकता था)।
2. Variant 2:
- सेवा **B** सेवा A में एक **privileged functionality** कॉल कर सकती है जिसे user नहीं कर सकता
- Exploit सेवा **A** से connect करता है जो exploit को एक ऐसा संदेश भेजता है जो एक specific **reply** **port** में response की उम्मीद करता है।
- Exploit उस reply port को पास करते हुए सेवा **B** को एक संदेश भेजता है।
- जब सेवा **B** reply करती है, तो वह संदेश **service A को भेजता है**, **जबकि** exploit एक अलग संदेश service A को भेज कर privileged functionality तक पहुँचने की कोशिश करता है और उम्मीद करता है कि service B का reply perfect moment पर Audit token को overwrite कर देगा (Race Condition)।

## Variant 1: calling xpc_connection_get_audit_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

परिदृश्य:

- दो mach services **`A`** और **`B`** जिनसे हम दोनों connect कर सकते हैं (sandbox profile और connection स्वीकार करने से पहले किए गए authorization checks के आधार पर)।
- _**A**_ के पास एक specific action के लिए एक **authorization check** होना चाहिए जिसे **`B`** पास कर सकता है (पर हमारा app नहीं कर सकता)।
- उदाहरण के लिए, यदि B के पास कुछ **entitlements** हैं या वह **root** के रूप में चल रहा है, तो वह A से privileged action करने के लिए कह सकता है।
- इस authorization check के लिए, **`A`** audit token को asynchronously प्राप्त करता है, उदाहरण के लिए `xpc_connection_get_audit_token` को **`dispatch_async`** से कॉल कर के।

> [!CAUTION]
> इस मामले में एक attacker एक **Race Condition** ट्रिगर कर सकता है जिससे एक **exploit** बने जो **A से एक action करने के लिए** कई बार अनुरोध करता है जबकि **B `A` को संदेश भेज रहा होता है**। जब RC सफल होता है, तो **B का audit token** memory में copy हो जाएगा **जबकि** हमारे **exploit** का अनुरोध A द्वारा **handle** किया जा रहा होता है, जिससे उसे वह **privileged action** करने की अनुमति मिल जाएगी जो केवल B अनुरोध कर सकता था।

यह समस्या `smd` के रूप में **`A`** और `diagnosticd` के रूप में **`B`** के साथ हुई थी। smb का फ़ंक्शन [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) नया privileged helper tool (as **root**) install करने के लिए उपयोग किया जा सकता है। यदि root के रूप में चल रहा कोई process `smd` से संपर्क करता है, तो अन्य चेक किए नहीं जाएंगे।

इसलिए, सेवा **B** `diagnosticd` है क्योंकि यह **root** के रूप में चलता है और किसी process को monitor कर सकता है, अतः monitoring शुरू होने के बाद यह प्रति सेकंड कई संदेश भेजेगा।

Attack करने के लिए:

1. मानक XPC प्रोटोकॉल का उपयोग करके `smd` नामक सेवा से एक **connection** शुरू करें।
2. `diagnosticd` के साथ एक द्वितीयक **connection** बनाएं। सामान्य प्रक्रिया के विपरीत, दो नए mach ports बनाने और भेजने के बजाय, client port send right को `smd` connection से जुड़ी हुई **send right** की duplicate के साथ बदल दिया जाता है।
3. परिणामस्वरूप, XPC संदेश `diagnosticd` को dispatch किए जा सकते हैं, लेकिन `diagnosticd` से responses `smd` पर पुनर्निर्देशित किए जाते हैं। `smd` के लिए, ऐसा प्रतीत होता है जैसे user और `diagnosticd` दोनों से संदेश उसी connection से आ रहे हों।

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. अगला कदम `diagnosticd` को किसी चुने हुए process (संभवतः user का अपना) की monitoring शुरू करने के निर्देश देना है। साथ ही, `smd` को नियमित 1004 संदेशों की बाढ़ भेजी जाती है। उद्देश्य यहाँ elevated privileges वाला एक tool install कराना है।
5. यह क्रिया `handle_bless` फ़ंक्शन में एक race condition को ट्रिगर करती है। समय निर्धारित करने वाली बात महत्वपूर्ण है: `xpc_connection_get_pid` का कॉल user के process का PID लौटाना चाहिए (क्योंकि privileged tool user के app bundle में रहता है)। हालाँकि, `xpc_connection_get_audit_token` कॉल, विशेषकर `connection_is_authorized` उप-रूटीन के भीतर, को `diagnosticd` के audit token का संदर्भ लेना चाहिए।

## Variant 2: reply forwarding

XPC (Cross-Process Communication) वातावरण में, यद्यपि event handlers एक साथ निष्पादित नहीं होते, reply messages के हैंडलिंग का एक अनूठा व्यवहार होता है। विशेष रूप से, reply की उम्मीद करने वाले संदेश भेजने के दो अलग तरीके हैं:

1. **`xpc_connection_send_message_with_reply`**: यहाँ XPC संदेश एक निर्दिष्ट queue पर प्राप्त और प्रोसेस होता है।
2. **`xpc_connection_send_message_with_reply_sync`**: इसके विपरीत, इस तरीके में XPC संदेश वर्तमान dispatch queue पर प्राप्त और प्रोसेस होता है।

यह भेद महत्वपूर्ण है क्योंकि यह अनुमति देता है कि **reply packets को एक XPC event handler के निष्पादन के साथ-साथ parsing किया जा सके**। ध्यान देने वाली बात यह है कि जबकि `_xpc_connection_set_creds` आंशिक overwrite से audit token को बचाने के लिए locking लागू करता है, यह सुरक्षा पूरे connection object पर लागू नहीं करता। परिणामस्वरूप, ऐसा एक vulnerability बनती है जहाँ पैकेट के parsing और उसके event handler के execution के बीच के अंतराल में audit token को replace किया जा सकता है।

इस भेद्यता का दुरुपयोग करने के लिए आवश्यक सेटअप:

- दो mach services, जिनको **`A`** और **`B`** कहा जाता है, जिनसे दोनों connection स्थापित किए जा सकते हैं।
- सेवा **`A`** में एक authorization check होना चाहिए किसी specific action के लिए जिसे केवल **`B`** कर सकता है (user का app नहीं)।
- सेवा **`A`** को एक ऐसा संदेश भेजना चाहिए जो reply की उम्मीद करता हो।
- user सेवा **`B`** को एक संदेश भेज सकता है जिसका वह reply करेगा।

Exploit प्रक्रिया निम्नलिखित चरणों में होती है:

1. सेवा **`A`** के उस संदेश का इंतजार करें जो reply की उम्मीद करता है।
2. सीधे **`A`** को reply करने की बजाय, reply port को hijack कर के सेवा **`B`** को एक संदेश भेजने के लिए उपयोग किया जाता है।
3. तत्पश्चात, एक ऐसा संदेश भेजा जाता है जो निषिद्ध action को शामिल करता है, यह उम्मीद करते हुए कि यह service B के reply के साथ concurrent रूप से process होगा।

नीचे वर्णित attack परिदृश्य का एक विज़ुअल प्रतिनिधित्व है:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../images/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../images/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

- **Instances ढूँढने में कठिनाई**: `xpc_connection_get_audit_token` के उपयोग के उदाहरण खोजना कठिन था, स्टैटिक और डायनेमिक दोनों तरीकों से।
- **कार्यप्रणाली**: Frida का उपयोग `xpc_connection_get_audit_token` फ़ंक्शन को hook करने के लिए किया गया, और उन कॉल्स को फ़िल्टर किया गया जो event handlers से नहीं आ रहे थे। हालांकि, यह तरीका केवल hooked process तक सीमित था और सक्रिय उपयोग की आवश्यकता थी।
- **विश्लेषण टूलिंग**: IDA/Ghidra जैसे टूल्स का उपयोग reachable mach services की जांच के लिए किया गया, पर यह समय-साध्य था, विशेष रूप से dyld shared cache में कॉल्स के कारण जटिलता बढ़ रही थी।
- **Scripting सीमाएँ**: `xpc_connection_get_audit_token` को `dispatch_async` ब्लॉक्स से कॉल किए जाने के मामलों के विश्लेषण के लिए स्क्रिप्टिंग करने का प्रयास ब्लॉक्स के पार्सिंग और dyld shared cache के साथ इंटरैक्शन की जटिलताओं के कारण बाधित हुआ।

## The fix <a href="#the-fix" id="the-fix"></a>

- **Reported Issues**: Apple को `smd` में पाई गई सामान्य और विशिष्ट समस्याओं की रिपोर्ट सबमिट की गई।
- **Apple's Response**: Apple ने `smd` में `xpc_connection_get_audit_token` को बदलकर `xpc_dictionary_get_audit_token` का उपयोग किया।
- **Nature of the Fix**: `xpc_dictionary_get_audit_token` फ़ंक्शन को सुरक्षित माना जाता है क्योंकि यह प्राप्त XPC संदेश से जुड़े mach message से audit token सीधे प्राप्त करता है। हालांकि, यह भी public API का हिस्सा नहीं है, ठीक उसी तरह जैसे `xpc_connection_get_audit_token` नहीं था।
- **Absence of a Broader Fix**: यह स्पष्ट नहीं है कि Apple ने एक और व्यापक फिक्स क्यों नहीं लागू किया, जैसे कि उन संदेशों को discard करना जो connection के saved audit token के साथ मेल नहीं खाते। कुछ परिदृश्यों में legitimate audit token के बदलने की संभावना (उदा., `setuid` उपयोग) एक कारक हो सकती है।
- **Current Status**: यह मुद्दा iOS 17 और macOS 14 में मौजूद रहा, जिससे इसे पहचानना और समझना चुनौतीपूर्ण है।

## Finding vulnerable code paths in practice (2024–2025)

जब XPC सेवाओं का ऑडिट करते हैं इस बग क्लास के लिए, तो ध्यान authorization पर रखें जो message के event handler के बाहर किया जाता है या reply processing के साथ concurrent किया जा रहा हो।

Static triage संकेत:
- `xpc_connection_get_audit_token` कॉल्स की तलाश करें जो `dispatch_async`/`dispatch_after` या अन्य worker queues के माध्यम से queue किए गए blocks से reachable हों जो message handler के बाहर चलते हैं।
- उन authorization helpers की तलाश करें जो per-connection और per-message state को mix करते हैं (उदा., `xpc_connection_get_pid` से PID प्राप्त करना पर audit token `xpc_connection_get_audit_token` से लेना)।
- NSXPC कोड में, सत्यापित करें कि checks `-listener:shouldAcceptNewConnection:` में किए गए हैं या, per-message checks के लिए, implementation per-message audit token का उपयोग कर रही है (उदा., lower-level कोड में संदेश की dictionary से `xpc_dictionary_get_audit_token`)।

Dynamic triage टिप्स:
- `xpc_connection_get_audit_token` को hook करें और उन invocations को flag करें जिनके user stack में event-delivery path (उदा., `_xpc_connection_mach_event`) शामिल नहीं है। उदाहरण Frida hook:
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
- macOS पर, protected/Apple binaries को instrument करना SIP disabled या development environment की आवश्यकता कर सकता है; अपनी खुद की builds या userland services पर टेस्ट करना बेहतर है।
- For reply-forwarding races (Variant 2), reply packets के concurrent parsing को मॉनिटर करें — `xpc_connection_send_message_with_reply` की timings को fuzz करके बनाम normal requests और जांचें कि authorization के दौरान इस्तेमाल होने वाला effective audit token प्रभावित किया जा सकता है या नहीं।

## Exploitation primitives you will likely need

- Multi-sender setup (Variant 1): A और B के लिए connections बनाएँ; A के client port के send right को duplicate करें और इसे B के client port के रूप में उपयोग करें ताकि B की replies A को डिलीवर हों।
```c
// Duplicate a SEND right you already hold
mach_port_t dup;
mach_port_insert_right(mach_task_self(), a_client, a_client, MACH_MSG_TYPE_MAKE_SEND);
dup = a_client; // use `dup` when crafting B’s connect packet instead of a fresh client port
```
- Reply hijack (Variant 2): A के pending request (reply port) से send-once right को capture करें, फिर उस reply port का उपयोग करके B को crafted message भेजें ताकि B का reply तब A पर पहुंचे जब आपका privileged request parse किया जा रहा हो।

These require low-level mach message crafting for the XPC bootstrap and message formats; review the mach/XPC primer pages in this section for the exact packet layouts and flags.

## उपयोगी टूलिंग

- XPC sniffing/dynamic inspection: gxpc (open-source XPC sniffer) कनेक्शनों को enumerate करने और ट्रैफ़िक का निरीक्षण करने में मदद करता है ताकि multi-sender सेटअप और timing को validate किया जा सके। Example: `gxpc -p <PID> --whitelist <service-name>`.
- Classic dyld interposing for libxpc: `xpc_connection_send_message*` और `xpc_connection_get_audit_token` पर interpose करके call sites और stacks को black-box testing के दौरान लॉग करें।


## संदर्भ

- Sector 7 – Don’t Talk All at Once! Elevating Privileges on macOS by Audit Token Spoofing: <https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/>
- Apple – About the security content of macOS Ventura 13.4 (CVE‑2023‑32405): <https://support.apple.com/en-us/106333>


{{#include ../../../../../../banners/hacktricks-training.md}}
