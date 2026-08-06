# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}


अधिक जानकारी के लिए [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) देखें। यह केवल एक summary है:<sup>[[4]](#references)</sup>

Microsoft ने कई office document formats बनाए हैं, जिनमें दो मुख्य प्रकार **OLE formats** (जैसे RTF, DOC, XLS, PPT) और **Office Open XML (OOXML) formats** (जैसे DOCX, XLSX, PPTX) हैं। इन formats में macros शामिल हो सकते हैं, जिससे ये phishing और malware के targets बन जाते हैं। OOXML files zip containers के रूप में structured होती हैं, जिससे उन्हें unzip करके inspect किया जा सकता है और file तथा folder hierarchy के साथ XML file contents दिखाई देते हैं।

OOXML file structures को explore करने के लिए document को unzip करने की command और output structure दी गई है। इन files में data छिपाने की techniques documented हैं, जो CTF challenges में data concealment के क्षेत्र में निरंतर innovation को दर्शाती हैं।

Analysis के लिए, **oletools** और **OfficeDissector** OLE तथा OOXML documents की examination के लिए comprehensive toolsets प्रदान करते हैं। ये tools embedded macros की पहचान और analysis में सहायता करते हैं, जो अक्सर malware delivery के vectors के रूप में काम करते हैं और सामान्यतः additional malicious payloads को download तथा execute करते हैं। VBA macros का analysis Microsoft Office के बिना Libre Office का उपयोग करके किया जा सकता है, जो breakpoints और watch variables के साथ debugging की अनुमति देता है।

**oletools** की installation और usage straightforward है; documents से macros extract करने के लिए pip के माध्यम से install करने और macros extract करने की commands दी गई हैं। Macros का automatic execution `AutoOpen`, `AutoExec`, या `Document_Open` जैसी functions से trigger होता है।
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation और controlled gzip

Revit RFA models को एक [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (जिसे CFBF भी कहा जाता है) के रूप में store किया जाता है। Serialized model storage/stream के अंतर्गत होता है:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` का मुख्य layout (Revit 2025 पर observed):

- Header
- GZIP-compressed payload (वास्तविक serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit ECC trailer का उपयोग करके stream में हुए छोटे perturbations को auto-repair करेगा और उन streams को reject कर देगा जो ECC से match नहीं करते। इसलिए, compressed bytes को naïvely edit करने पर changes persist नहीं होंगे: आपके changes या तो revert कर दिए जाएंगे या file reject कर दी जाएगी। Deserializer को दिखाई देने वाली चीज़ों पर byte-accurate control सुनिश्चित करने के लिए आपको:

- Revit-compatible gzip implementation के साथ recompress करना होगा (ताकि Revit द्वारा produce/accept किए जाने वाले compressed bytes अपेक्षित bytes से match करें)।
- Padded stream पर ECC trailer को recompute करना होगा, ताकि Revit modified stream को auto-repair किए बिना accept कर सके।

RFA contents को patching/fuzzing करने का practical workflow:<sup>[[1]](#references)</sup>

1) OLE compound document को expand करें
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC discipline के साथ `Global/Latest` को Edit करें

- `Global/Latest` को Deconstruct करें: header को रखें, payload को gunzip करें, bytes को mutate करें, फिर Revit-compatible deflate parameters का उपयोग करके दोबारा gzip करें।
- zero-padding को सुरक्षित रखें और ECC trailer को फिर से compute करें, ताकि नए bytes Revit द्वारा स्वीकार किए जाएँ।
- यदि आपको deterministic byte-for-byte reproduction चाहिए, तो Revit की DLLs के चारों ओर एक minimal wrapper बनाएँ, ताकि उसके gzip/gunzip paths और ECC computation को invoke किया जा सके (जैसा कि research में प्रदर्शित किया गया है), या इन semantics को replicate करने वाले किसी उपलब्ध helper का फिर से उपयोग करें।

3) OLE compound document को Rebuild करें
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)</sup>

- CompoundFileTool NTFS names में invalid characters के लिए escaping के साथ storages/streams को filesystem पर लिखता है; आपको जिस stream path की आवश्यकता है, वह output tree में ठीक `Global/Latest` है।
- जब ecosystem plugins के माध्यम से mass attacks deliver किए जाते हैं और वे cloud storage से RFAs fetch करते हैं, तो network injection आज़माने से पहले सुनिश्चित करें कि आपका patched RFA स्थानीय रूप से Revit के integrity checks पास करता हो (gzip/ECC सही हों)।

Exploitation insight (gzip payload में कौन-से bytes रखने हैं, इसका मार्गदर्शन):<sup>[[1]](#references)</sup>

- Revit deserializer 16-bit class index पढ़ता है और एक object बनाता है। कुछ types non-polymorphic होते हैं और उनमें vtables नहीं होते; destructor handling का दुरुपयोग type confusion उत्पन्न करता है, जिससे engine attacker-controlled pointer के माध्यम से indirect call execute करता है।
- `AString` (class index `0x1F`) चुनने पर object offset 0 पर attacker-controlled heap pointer रखा जाता है। Destructor loop के दौरान, Revit प्रभावी रूप से यह execute करता है:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- Serialized graph में ऐसे कई objects रखें ताकि destructor loop का प्रत्येक iteration एक gadget (“weird machine”) execute करे, और conventional x64 ROP chain में stack pivot की व्यवस्था करें।

Windows x64 pivot/gadget building के विवरण यहाँ देखें:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

और सामान्य ROP guidance यहाँ देखें:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS), OLE compound files को expand/rebuild करने के लिए: https://github.com/thezdi/CompoundFileTool<sup>[[2]](#references)</sup>
- Reverse/taint analysis के लिए IDA Pro + WinDBG TTD; traces को compact रखने के लिए TTD के साथ page heap disable करें।
- एक local proxy (जैसे Fiddler), testing के लिए plugin traffic में RFAs को बदलकर supply-chain delivery simulate कर सकता है।

## References

- [1] [Crafting a Full Exploit RCE from a Crash in Autodesk Revit RFA File Parsing (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}
