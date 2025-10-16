# Office फ़ाइल विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}


For further information check [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/). यह बस एक सारांश है:

Microsoft ने कई office दस्तावेज़ फ़ॉर्मैट बनाए हैं, जिनमें दो मुख्य प्रकार हैं **OLE formats** (जैसे RTF, DOC, XLS, PPT) और **Office Open XML (OOXML) formats** (जैसे DOCX, XLSX, PPTX)। इन फ़ॉर्मैट्स में macros हो सकते हैं, जिससे ये phishing और malware के लक्ष्यों बन जाते हैं। OOXML फ़ाइलें zip कंटेनर के रूप में संरचित होती हैं, जिन्हें unzip करके उनका फ़ाइल और फ़ोल्डर hierarchy और XML फ़ाइलों की सामग्री देखा जा सकता है।

OOXML फ़ाइल संरचनाओं का अन्वेषण करने के लिए, एक दस्तावेज़ को unzip करने का कमांड और आउटपुट संरचना दी गई है। इन फ़ाइलों में डेटा छिपाने की techniques दस्तावेजीकृत की गई हैं, जो CTF चुनौतियों में डेटा छिपाने में निरंतर नवाचार को दर्शाती हैं।

विश्लेषण के लिए, **oletools** और **OfficeDissector** OLE और OOXML दोनों दस्तावेज़ों की जाँच के लिए व्यापक टूलसेट प्रदान करते हैं। ये टूल्स embedded macros की पहचान और विश्लेषण में मदद करते हैं, जो अक्सर malware delivery के वेक्टर होते हैं और आमतौर पर अतिरिक्त malicious payloads को डाउनलोड और execute करते हैं। VBA macros का विश्लेषण Microsoft Office के बिना भी Libre Office का उपयोग करके किया जा सकता है, जो breakpoints और watch variables के साथ debugging की अनुमति देता है।

**oletools** की installation और उपयोग सरल हैं, pip द्वारा install करने और दस्तावेज़ों से macros extract करने के लिए कमांड्स दिए गए हैं। Macros का automatic execution उन functions से ट्रिगर होता है जैसे `AutoOpen`, `AutoExec`, या `Document_Open`.
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC की पुनर्गणना और नियंत्रित gzip

Revit RFA models are stored as an [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (aka CFBF). The serialized model is under storage/stream:

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` की प्रमुख संरचना (Revit 2025 पर देखी गई):

- Header
- GZIP-compressed payload (वास्तविक सीरियलाइज़्ड ऑब्जेक्ट ग्राफ)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit छोटे परिवर्तनों को ECC ट्रेलर का उपयोग करके stream पर auto-repair कर देता है और उन स्ट्रीम को अस्वीकार कर देता है जो ECC से मेल नहीं खाते। इसलिए, साधारणतया compressed बाइट्स को एडिट करने पर परिवर्तन टिकते नहीं हैं: आपके परिवर्तन या तो वापस कर दिए जाते हैं या फ़ाइल अस्वीकार कर दी जाती है। deserializer को दिखने वाले बाइट-सटीक नियंत्रण को सुनिश्चित करने के लिए आपको:

- Recompress with a Revit-compatible gzip implementation (ताकि compressed बाइट्स जो Revit उत्पन्न/स्वीकार करता है, अपेक्षित बाइट्स से मेल खाएँ)।
- padded stream पर ECC ट्रेलर की पुनर्गणना करें ताकि Revit auto-repair किए बिना संशोधित स्ट्रीम को स्वीकार करे।

RFA सामग्री के पैचिंग/fuzzing के लिए व्यावहारिक कार्यप्रवाह:

1) OLE compound document को विस्तारित करें
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC अनुशासन के साथ Global\Latest को संपादित करें

- `Global/Latest` को विखंडित करें: हेडर को रखें, payload को gunzip करें, bytes में परिवर्तन करें, फिर Revit-compatible deflate parameters का उपयोग करके gzip करें।
- zero-padding को बनाए रखें और ECC trailer को पुनः गणना करें ताकि नए bytes Revit द्वारा स्वीकार किए जाएं।
- यदि आपको deterministic byte-for-byte reproduction की आवश्यकता है, तो Revit की DLLs के चारों ओर एक minimal wrapper बनाएं ताकि इसके gzip/gunzip पाथ और ECC computation को इनवोक किया जा सके (जैसा कि research में दर्शाया गया है), या किसी भी उपलब्ध helper का पुन: उपयोग करें जो इन semantics की नकल करता हो।

3) OLE compound document को पुनर्निर्मित करें
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:

- CompoundFileTool writes storages/streams to the filesystem with escaping for characters invalid in NTFS names; the stream path you want is exactly `Global/Latest` in the output tree.
- When delivering mass attacks via ecosystem plugins that fetch RFAs from cloud storage, ensure your patched RFA passes Revit’s integrity checks locally first (gzip/ECC correct) before attempting network injection.

Exploitation insight (to guide what bytes to place in the gzip payload):

- Revit deserializer एक 16-bit class index पढ़ता है और एक object बनाता है। कुछ types non‑polymorphic होते हैं और vtables नहीं होते; destructor handling का दुरुपयोग करने से type confusion उत्पन्न होता है जहाँ engine एक indirect call execute करता है attacker-controlled pointer के माध्यम से।
- Picking `AString` (class index `0x1F`) object के offset 0 पर attacker-controlled heap pointer रखता है। During the destructor loop, Revit effectively executes:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- ऐसे कई objects को serialized graph में रखें ताकि destructor loop का प्रत्येक iteration एक gadget (“weird machine”) execute करे, और एक conventional x64 ROP chain में stack pivot की व्यवस्था करें।

See Windows x64 pivot/gadget building details here:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting-ebp2ret-ebp-chaining.md
{{#endref}}

and general ROP guidance here:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

उपकरण:

- CompoundFileTool (OSS) to expand/rebuild OLE compound files: https://github.com/thezdi/CompoundFileTool
- IDA Pro + WinDBG TTD के लिए reverse/taint; ट्रेस को कॉम्पैक्ट रखने के लिए TTD के साथ page heap अक्षम करें।
- एक स्थानीय प्रॉक्सी (उदा., Fiddler) परीक्षण के लिए plugin ट्रैफ़िक में RFAs बदलकर supply-chain delivery का अनुकरण कर सकता है।

## संदर्भ

- [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)

{{#include ../../../banners/hacktricks-training.md}}
