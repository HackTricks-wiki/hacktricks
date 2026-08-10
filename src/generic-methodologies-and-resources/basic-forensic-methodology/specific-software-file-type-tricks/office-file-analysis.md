# Office file analysis

अधिक जानकारी के लिए [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) देखें। यह केवल एक संक्षिप्त सारांश है:<sup>[[4]](#references)</sup>

Microsoft Office documents आमतौर पर legacy formats जैसे RTF और OLE/CFBF-आधारित DOC, XLS और PPT, या नए **Office Open XML (OOXML)** formats जैसे DOCX, XLSX और PPTX के रूप में दिखाई देते हैं। Office documents में macros जैसी active content हो सकती है, जिससे वे phishing और malware के सामान्य वाहक बन जाते हैं। OOXML files ZIP containers होती हैं, जिनकी file hierarchy और XML contents को उन्हें unzip करके inspect किया जा सकता है।<sup>[[3]](#references)[[4]](#references)</sup>

OOXML file structures को explore करने के लिए document को unzip करने की command और output structure दी गई है। इन files में data छिपाने की techniques documented हैं, जो CTF challenges में data concealment के निरंतर innovation का संकेत देती हैं।<sup>[[4]](#references)</sup>

Analysis के लिए **oletools** और **OfficeDissector**, OLE और OOXML दोनों documents की जांच करने के लिए comprehensive toolsets प्रदान करते हैं। ये tools embedded macros की पहचान और analysis में सहायता करते हैं, जो अक्सर malware delivery के vectors के रूप में काम करते हैं और आमतौर पर additional malicious payloads को download और execute करते हैं। VBA macros का analysis Microsoft Office के बिना Libre Office का उपयोग करके किया जा सकता है, जो breakpoints और watch variables के साथ debugging की सुविधा देता है।<sup>[[4]](#references)</sup>

**oletools** की installation और usage straightforward है; documents से macros extract करने के लिए pip के माध्यम से install करने और commands प्रदान की गई हैं। Word में automatic macros में `AutoExec` और `AutoOpen` शामिल हैं, जबकि `Document_Open` एक open-event procedure है।<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC recomputation और controlled gzip

Revit RFA models एक [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (जिसे CFBF भी कहा जाता है) के रूप में stored होते हैं। Serialized model निम्न storage/stream के अंतर्गत होता है:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` का मुख्य layout (Revit 2025 पर observed):

- Header
- GZIP-compressed payload (वास्तविक serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit ECC trailer का उपयोग करके stream में हुए छोटे बदलावों को auto-repair करेगा और उन streams को reject कर देगा जो ECC से match नहीं करतीं। इसलिए, compressed bytes को naïvely edit करने पर बदलाव persist नहीं होंगे: आपके changes या तो revert हो जाएंगे या file reject हो जाएगी। Deserializer को मिलने वाले content पर byte-accurate control सुनिश्चित करने के लिए आपको:<sup>[[1]](#references)</sup>

- Revit-compatible gzip implementation के साथ recompress करना होगा (ताकि Revit द्वारा produce/accept किए जाने वाले compressed bytes अपेक्षित bytes से match करें)।
- Padded stream पर ECC trailer को recompute करना होगा, ताकि Revit modified stream को auto-repair किए बिना accept कर सके।

RFA contents को patch/fuzz करने का practical workflow:<sup>[[1]](#references)</sup>

1) OLE compound document को expand करें।<sup>[[2]](#references)</sup>
```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```
2) gzip/ECC discipline के साथ `Global\Latest` को Edit करें

- `Global/Latest` को deconstruct करें: header को बनाए रखें, payload को gunzip करें, bytes को mutate करें, फिर Revit-compatible deflate parameters का उपयोग करके दोबारा gzip करें।
- zero-padding को बनाए रखें और ECC trailer को फिर से compute करें, ताकि नए bytes Revit द्वारा स्वीकार किए जाएँ।
- यदि आपको byte-for-byte deterministic reproduction चाहिए, तो Revit की DLLs के चारों ओर एक minimal wrapper बनाएँ, जिससे उसके gzip/gunzip paths और ECC computation को invoke किया जा सके (जैसा कि research में प्रदर्शित किया गया है), या इन semantics को replicate करने वाले किसी उपलब्ध helper का पुनः उपयोग करें।

3) OLE compound document को फिर से बनाएँ।<sup>[[2]](#references)</sup>
```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```
Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool storages/streams को filesystem में ऐसे escaping के साथ लिखता है, जो NTFS names में invalid characters के लिए होता है; output tree में आपको जिस stream path की आवश्यकता है, वह ठीक `Global/Latest` है।
- जब cloud storage से RFAs fetch करने वाले ecosystem plugins के माध्यम से mass attacks deliver करें, तो network injection का प्रयास करने से पहले सुनिश्चित करें कि आपका patched RFA स्थानीय रूप से Revit के integrity checks (gzip/ECC correct) को पास करता हो।

Exploitation insight (gzip payload में कौन-से bytes रखने हैं, इसका मार्गदर्शन देने के लिए):<sup>[[1]](#references)</sup>

- Revit deserializer एक 16-bit class index पढ़ता है और एक object construct करता है। कुछ types non‑polymorphic होते हैं और उनमें vtables नहीं होते; destructor handling का दुरुपयोग करने पर type confusion उत्पन्न होता है, जिसमें engine attacker-controlled pointer के माध्यम से indirect call execute करता है।
- `AString` (class index `0x1F`) चुनने पर object offset 0 पर attacker-controlled heap pointer रखा जाता है। destructor loop के दौरान, Revit प्रभावी रूप से यह execute करता है:
```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```
- ऐसे कई objects को serialized graph में रखें ताकि destructor loop का प्रत्येक iteration एक gadget (“weird machine”) execute करे, और conventional x64 ROP chain में stack pivot की व्यवस्था करें।

Windows x64 pivot/gadget building की details यहाँ देखें:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

और general ROP guidance यहाँ देखें:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

Tooling:<sup>[[1]](#references)</sup>

- CompoundFileTool (OSS), OLE compound files को expand/rebuild करने के लिए: https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- IDA Pro + WinDBG TTD, reverse/taint के लिए; traces को compact रखने के लिए TTD के साथ page heap disable करें।
- एक local proxy (जैसे Fiddler), testing के लिए plugin traffic में RFAs को swap करके supply-chain delivery simulate कर सकता है।

## References

- [1] [Crash से Autodesk Revit RFA File Parsing का Full Exploit RCE तैयार करना (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) docs](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF Field Guide](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba documentation (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
