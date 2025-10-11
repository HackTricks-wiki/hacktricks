# Office फ़ाइल विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). यह सिर्फ़ एक सारांश है:

Microsoft ने कई Office दस्तावेज़ फ़ॉर्मेट बनाए हैं, जिनमें मुख्य रूप से दो प्रकार होते हैं: **OLE formats** (जैसे RTF, DOC, XLS, PPT) और **Office Open XML (OOXML) formats** (जैसे DOCX, XLSX, PPTX)। ये फ़ॉर्मेट macros रख सकते हैं, जो इन्हें phishing और malware के लक्ष्यों में बदल देते हैं। OOXML फ़ाइलें zip containers के रूप में संरचित होती हैं, जिन्हें unzip करके उनकी फाइल और फ़ोल्डर हायार्की और XML फ़ाइल की सामग्री देखा जा सकता है।

OOXML फ़ाइल संरचनाओं को एक्सप्लोर करने के लिए, एक दस्तावेज़ को unzip करने का command और उसका आउटपुट संरचना दी जाती है। इन फ़ाइलों में डेटा छिपाने की तकनीकों का दस्तावेजीकरण किया गया है, जो CTF चुनौतियों के भीतर डेटा छिपाने में निरंतर नवाचार को दर्शाता है।

विश्लेषण के लिए, **oletools** और **OfficeDissector** OLE और OOXML दोनों दस्तावेज़ों की जाँच के लिए व्यापक टूलसेट प्रदान करते हैं। ये टूल embedded macros की पहचान और विश्लेषण में मदद करते हैं, जो अक्सर malware delivery के वेक्टर होते हैं, और सामान्यतः अतिरिक्त malicious payloads को डाउनलोड और execute करते हैं। VBA macros का विश्लेषण Microsoft Office के बिना Libre Office का उपयोग करके किया जा सकता है, जो breakpoints और watch variables के साथ debugging की अनुमति देता है।

**oletools** का installation और उपयोग सीधा है, जिसमें pip के माध्यम से install करने और दस्तावेज़ों से macros extract करने के commands दिए गए हैं। macros का automatic execution `AutoOpen`, `AutoExec`, या `Document_Open` जैसे functions द्वारा trigger होता है।
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA मॉडल्स एक [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF) के रूप में संग्रहीत होते हैं। सीरियलाईज़्ड मॉडल storage/stream के अंतर्गत होता है:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` की मुख्य लेआउट (Revit 2025 पर देखा गया):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit ECC trailer का उपयोग करके stream में छोटे परिवर्तन स्वतः ठीक कर देगा और उन स्ट्रीम्स को अस्वीकार कर देगा जो ECC से मेल नहीं खाते। इसलिए, compressed bytes को साधारण तरीके से एडिट करने पर परिवर्तन टिके नहीं रहते: आपके बदलाव या तो पलट दिए जाते हैं या फ़ाइल अस्वीकार कर दी जाती है। यह सुनिश्चित करने के लिए कि deserializer जो देखता है उस पर आपकी बाइट-सटीक नियंत्रण रहे, आपको करना होगा:

- Recompress with a Revit-compatible gzip implementation (so the compressed bytes Revit produces/accepts match what it expects).
- Recompute the ECC trailer over the padded stream so Revit will accept the modified stream without auto-repairing it.

RFA सामग्री को पैच/फज़ करने के लिए व्यावहारिक वर्कफ्लो:

1) Expand the OLE compound document
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Global\Latest को gzip/ECC अनुशासन के साथ संपादित करें

- `Global/Latest` को विघटन करें: header रखें, payload को gunzip करें, बाइट्स बदलें, फिर Revit-compatible deflate parameters का उपयोग करके फिर से gzip करें।
- zero-padding बनाए रखें और ECC trailer को पुनः गणना करें ताकि नए बाइट्स Revit द्वारा स्वीकार किए जाएँ।
- यदि आपको deterministic byte-for-byte reproduction की आवश्यकता है, तो Revit’s DLLs के चारों ओर एक न्यूनतम wrapper बनाएं ताकि उसके gzip/gunzip paths और ECC गणना को invoke किया जा सके (जैसा कि research में प्रदर्शित है), या किसी भी उपलब्ध helper का पुनः उपयोग करें जो इन semantics की नकल करता हो।

3) OLE compound document का पुनर्निर्माण करें
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:

- CompoundFileTool फाइलसिस्टम पर storages/streams को उन characters के लिए escaping करके लिखता है जो NTFS names में अवैध हैं; output tree में जिस stream path की आपको जरूरत है वह ठीक `Global/Latest` है।
- जब आप ecosystem plugins के माध्यम से mass attacks डिलीवर करते हैं जो cloud storage से RFAs फेच करते हैं, तो नेटवर्क injection प्रयास करने से पहले स्थानीय रूप से यह सुनिश्चित करें कि आपका patched RFA Revit की integrity checks पास करता है (gzip/ECC correct)।

Exploitation insight (gzip payload में कौन से bytes रखने हैं, यह मार्गदर्शन):

- The Revit deserializer एक 16-bit class index पढ़ता है और एक object बनाता है। Certain types non‑polymorphic होते हैं और उनमें vtables नहीं होते; destructor handling का दुरुपयोग करने पर type confusion पैदा होता है जहाँ engine एक indirect call को attacker-controlled pointer के माध्यम से execute कर देता है।
- Picking `AString` (class index `0x1F`) places an attacker-controlled heap pointer at object offset 0. During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- ऐसी कई objects serialized graph में रखें ताकि destructor loop का प्रत्येक iteration एक gadget (“weird machine”) चलाए, और एक conventional x64 ROP chain में stack pivot व्यवस्थित करें।

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

टूलिंग:

- CompoundFileTool (OSS) OLE compound files का विस्तार/पुनर्निर्माण करने के लिए: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD reverse/taint के लिए; ट्रेसों को संकुचित रखने के लिए TTD के साथ page heap को disable करें।
- एक local proxy (उदा., Fiddler) टेस्टिंग के लिए plugin traffic में RFAs को बदलकर supply-chain delivery का अनुकरण कर सकता है।

## संदर्भ

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
