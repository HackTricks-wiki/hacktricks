# Office फ़ाइल विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). This is just a sumary:

Microsoft ने कई office document formats बनाए हैं, जिनमें दो मुख्य प्रकार हैं **OLE formats** (जैसे RTF, DOC, XLS, PPT) और **Office Open XML (OOXML) formats** (जैसे DOCX, XLSX, PPTX)। ये फॉर्मैट macros शामिल कर सकते हैं, जिससे ये phishing और malware के लक्ष्य बनते हैं। OOXML फाइलें zip containers के रूप में संरचित होती हैं, जिन्हें unzip करके निरीक्षण किया जा सकता है, जिससे फाइल और फ़ोल्डर हायरेरकी और XML फ़ाइल की सामग्री पता चलती है।

OOXML फ़ाइल संरचनाओं को एक्सप्लोर करने के लिए, एक दस्तावेज़ को unzip करने का command और आउटपुट संरचना दी गई है। इन फाइलों में डेटा छिपाने की techniques दस्तावेजीकृत की गई हैं, जो CTF चुनौतियों में data concealment में निरंतर नवाचार को दर्शाती हैं।

विश्लेषण के लिए, **oletools** और **OfficeDissector** दोनों OLE और OOXML दस्तावेज़ों की जाँच के लिए व्यापक toolsets प्रदान करते हैं। ये tools embedded macros की पहचान और विश्लेषण में मदद करते हैं, जो अक्सर malware delivery के vectors के रूप में काम करते हैं, सामान्यत: अतिरिक्त malicious payloads को डाउनलोड और execute करते हैं। VBA macros का विश्लेषण Microsoft Office के बिना Libre Office का उपयोग करके किया जा सकता है, जो breakpoints और watch variables के साथ debugging की अनुमति देता है।

oletools की installation और उपयोग सरल हैं, pip के जरिए install करने और दस्तावेज़ों से macros extract करने के लिए commands प्रदान किए गए हैं। Macros का automatic execution `AutoOpen`, `AutoExec`, या `Document_Open` जैसे functions द्वारा trigger होता है।
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation and controlled gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

Key layout of `Global\Latest` (observed on Revit 2025):

- Header
- GZIP-compressed payload (the actual serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit छोटे परिवर्तन अपने आप ECC trailer का उपयोग करके stream को auto-repair कर देता है और उन streams को रिजेक्ट कर देता है जो ECC से मेल नहीं खाते। इसलिए, compressed bytes को सरलतापूर्वक edit करने से परिवर्तन कायम नहीं रहते: आपके बदलाव या तो revert हो जाते हैं या फाइल रिजेक्ट हो जाती है। Deserializer को जो बाइट-एक्यूरेट व्यू चाहिए उसे सुनिश्चित करने के लिए आपको:

- Recompress with a Revit-compatible gzip implementation (ताकि compressed bytes जो Revit बनाता/accept करता है, अपेक्षित बाइट्स से मेल खाएं)।
- Padded stream पर ECC trailer को recompute करें ताकि Revit modified stream को auto-repair किए बिना accept कर ले।

Practical workflow for patching/fuzzing RFA contents:

1) OLE compound document को expand करें
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) Global\Latest को gzip/ECC प्रक्रिया के अनुसार एडिट करें

- Deconstruct `Global/Latest`: हेडर रखें, payload को gunzip करें, बाइट्स में परिवर्तन करें, फिर Revit-compatible deflate parameters का उपयोग करके उसे दुबारा gzip करें।
- zero-padding को संरक्षित रखें और ECC trailer की पुनः गणना करें ताकि नए बाइट्स Revit द्वारा स्वीकार किए जाएँ।
- यदि आपको deterministic byte-for-byte पुनरुत्पादन चाहिए, तो Revit के DLLs के चारों ओर एक न्यूनतम wrapper बनाएं ताकि उसके gzip/gunzip paths और ECC computation को invoke किया जा सके (जैसा कि शोध में दिखाया गया है), या किसी भी उपलब्ध helper का पुन: उपयोग करें जो इन semantics को replicate करता हो।

3) OLE compound document को पुनर्निर्मित करें
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
नोट्स:

- CompoundFileTool storages/streams को filesystem पर लिखता है, NTFS नामों में अमान्य वर्णों के लिए escaping के साथ; आउटपुट ट्री में जिस stream path की आपको आवश्यकता है वह ठीक `Global/Latest` है।
- जब ecosystem plugins के माध्यम से mass attacks deliver कर रहे हों जो cloud storage से RFAs fetch करते हैं, तो नेटवर्क injection का प्रयास करने से पहले locally यह सुनिश्चित करें कि आपका patched RFA Revit की integrity checks पास करे (gzip/ECC सही)।

Exploitation insight (gzip payload में कौन से bytes रखने हैं, इसका मार्गदर्शन करने के लिए):

- The Revit deserializer 16-bit class index पढ़ता है और एक object बनाता है। कुछ प्रकार non‑polymorphic होते हैं और vtables नहीं रखते; destructor handling के दुरुपयोग से एक type confusion पैदा होता है जहाँ engine एक indirect call execute करता है जो attacker-controlled pointer के माध्यम से होता है।
- `AString` चुनने पर (class index `0x1F`) attacker-controlled heap pointer object offset 0 पर रख दिया जाता है। destructor loop के दौरान, Revit प्रभावी रूप से execute करता है:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- इन जैसी कई objects को serialized graph में रखें ताकि destructor loop का प्रत्येक iteration एक gadget (“weird machine”) को execute करे, और एक पारंपरिक x64 ROP chain में stack pivot की व्यवस्था करें।

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

उपकरण:

- CompoundFileTool (OSS) — OLE compound files को expand/rebuild करने के लिए: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD reverse/taint के लिए; ट्रेस को कॉम्पैक्ट रखने के लिए TTD के साथ page heap disable करें।
- एक स्थानीय proxy (उदा., Fiddler) परीक्षण के लिए plugin traffic में RFAs को swap करके supply-chain delivery का अनुकरण कर सकता है।

## संदर्भ

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
