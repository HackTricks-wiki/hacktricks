# Office फ़ाइल विश्लेषण

{{#include ../../../banners/hacktricks-training.md}}

अधिक जानकारी के लिए [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/) देखें। यह केवल एक सारांश है:<sup>[[4]](#references)</sup>

Microsoft Office दस्तावेज़ आमतौर पर पुराने फ़ॉर्मैट, जैसे RTF और OLE/CFBF-आधारित DOC, XLS और PPT, या नए **Office Open XML (OOXML)** फ़ॉर्मैट, जैसे DOCX, XLSX और PPTX, में मिलते हैं। Office दस्तावेज़ों में macros जैसी सक्रिय सामग्री हो सकती है, जिससे वे आम phishing और malware वाहक बन जाते हैं। OOXML फ़ाइलें ZIP containers होती हैं; उन्हें unzip करके उनकी फ़ाइल hierarchy और XML सामग्री की जाँच की जा सकती है।<sup>[[3]](#references)[[4]](#references)</sup>

OOXML फ़ाइल संरचनाओं को देखने के लिए, दस्तावेज़ को unzip करने की command और उसके output की संरचना दी गई है। इन फ़ाइलों में डेटा छिपाने की तकनीकें दर्ज की गई हैं, जो CTF challenges में डेटा छिपाने के तरीकों में निरंतर नवाचार का संकेत देती हैं।<sup>[[4]](#references)</sup>

विश्लेषण के लिए, **oletools** और **OfficeDissector**, OLE और OOXML दोनों दस्तावेज़ों की जाँच हेतु व्यापक toolsets प्रदान करते हैं। ये tools embedded macros की पहचान और विश्लेषण में मदद करते हैं, जो अक्सर malware पहुँचाने के माध्यम होते हैं और आमतौर पर अतिरिक्त malicious payloads download करके execute करते हैं। Libre Office का उपयोग करके Microsoft Office के बिना भी VBA macros का विश्लेषण किया जा सकता है; इसमें breakpoints और watch variables के साथ debugging की सुविधा है।<sup>[[4]](#references)</sup>

**oletools** को install करना और उपयोग करना आसान है; दस्तावेज़ों से macros निकालने और pip के ज़रिए install करने की commands दी गई हैं। Word में, automatic macros में `AutoExec` और `AutoOpen` शामिल हैं, जबकि `Document_Open` एक open-event procedure है।<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup>

```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```

पासवर्ड से encrypted Office दस्तावेज़ों के लिए, [grammar-driven offline recovery workflow](../../../generic-hacking/brute-force.md#grammar-driven-combinator-attacks-encrypted-office-example) देखें।

---

## OLE Compound File exploitation: Autodesk Revit RFA – ECC की पुनर्गणना और नियंत्रित gzip

Revit RFA मॉडल [OLE Compound File](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation) (जिसे CFBF भी कहते हैं) में संग्रहित होते हैं। Serialized मॉडल इस storage/stream में होता है:<sup>[[1]](#references)[[3]](#references)</sup>

- Storage: `Global`
- Stream: `Latest` → `Global\Latest`

`Global\Latest` का मुख्य layout (Revit 2025 में देखा गया):

- Header
- GZIP-compressed payload (वास्तविक serialized object graph)
- Zero padding
- Error-Correcting Code (ECC) trailer

Revit, ECC trailer का इस्तेमाल करके stream में हुए छोटे बदलावों को अपने-आप ठीक कर देगा और उन streams को अस्वीकार कर देगा जो ECC से मेल नहीं खाते। इसलिए, compressed bytes को सीधे edit करने से बदलाव कायम नहीं रहेंगे: या तो वे वापस पहले जैसे हो जाएंगे या फ़ाइल अस्वीकार कर दी जाएगी। Deserializer को दिखने वाली सामग्री पर byte-accurate नियंत्रण सुनिश्चित करने के लिए आपको:<sup>[[1]](#references)</sup>

- Revit-संगत gzip implementation से फिर से compress करना होगा (ताकि Revit द्वारा बनाए या स्वीकार किए गए compressed bytes अपेक्षित bytes से मेल खाएँ)।
- Padded stream पर ECC trailer की फिर से गणना करनी होगी, ताकि Revit संशोधित stream को बिना auto-repair किए स्वीकार करे।

RFA की सामग्री को patch/fuzz करने का व्यावहारिक workflow:<sup>[[1]](#references)</sup>

1) OLE compound document को expand करें।<sup>[[2]](#references)</sup>

```bash
# Expand RFA into a folder tree (storages → folders, streams → files)
CompoundFileTool /e model.rfa /o rfa_out
# rfa_out/Global/Latest is the serialized stream of interest
```

2) gzip/ECC अनुशासन के साथ `Global\Latest` संपादित करें

- `Global/Latest` को अलग करें: header बनाए रखें, payload को gunzip करें, bytes में बदलाव करें, फिर Revit-संगत deflate parameters का उपयोग करके दोबारा gzip करें।
- zero-padding बनाए रखें और ECC trailer को फिर से compute करें, ताकि Revit नए bytes स्वीकार करे।
- यदि आपको byte-for-byte deterministic reproduction चाहिए, तो Revit की DLLs के चारों ओर एक minimal wrapper बनाएँ, जो इसके gzip/gunzip paths और ECC computation को invoke करे (जैसा research में दिखाया गया है), या इन semantics को दोहराने वाला कोई उपलब्ध helper फिर से उपयोग करें।

3) OLE compound document फिर से बनाएँ।<sup>[[2]](#references)</sup>

```bash
# Repack the folder tree back into an OLE file
CompoundFileTool /c rfa_out /o model_patched.rfa
```

Notes:<sup>[[1]](#references)[[2]](#references)</sup>

- CompoundFileTool, NTFS नामों में अमान्य वर्णों को escape करके, storages/streams को filesystem पर लिखता है; output tree में आपको जिस stream path की ज़रूरत है, वह ठीक `Global/Latest` है।
- Cloud storage से RFA फ़ेच करने वाले ecosystem plugins के ज़रिए mass attacks भेजते समय, network injection की कोशिश करने से पहले सुनिश्चित करें कि आपका patched RFA स्थानीय रूप से Revit की integrity checks पास करता है (gzip/ECC सही हों)।

Exploitation insight (gzip payload में कौन-से bytes रखने हैं, यह तय करने के लिए):<sup>[[1]](#references)</sup>

- Revit deserializer 16-bit class index पढ़कर एक object बनाता है। कुछ types non‑polymorphic होते हैं और उनमें vtables नहीं होते; destructor handling का दुरुपयोग करने से type confusion होता है, जिसमें engine attacker-controlled pointer के ज़रिए indirect call करता है।
- `AString` (class index `0x1F`) चुनने पर object के offset 0 पर attacker-controlled heap pointer रखा जाता है। Destructor loop के दौरान, Revit प्रभावी रूप से यह execute करता है:

```asm
rcx = [rbx]              ; object pointer (e.g., AString*)
rax = [rcx]              ; attacker-controlled pointer to AString buffer
call qword ptr [rax]     ; one attacker-chosen gadget per object
```

- Serialized graph में ऐसे कई objects रखें ताकि destructor loop का हर iteration एक gadget (“weird machine”) execute करे, और stack pivot को conventional x64 ROP chain में ले जाने की व्यवस्था करें।

Windows x64 pivot/gadget बनाने की जानकारी यहाँ देखें:

{{#ref}}
../../../binary-exploitation/stack-overflow/stack-pivoting.md
{{#endref}}

और सामान्य ROP मार्गदर्शन यहाँ देखें:

{{#ref}}
../../../binary-exploitation/rop-return-oriented-programing/README.md
{{#endref}}

टूलिंग:<sup>[[1]](#references)</sup>

- OLE compound files को expand/rebuild करने के लिए CompoundFileTool (OSS): https://github.com/thezdi/CompoundFileTool.<sup>[[2]](#references)</sup>
- Reverse/taint के लिए IDA Pro + WinDBG TTD; traces को compact रखने के लिए TTD के साथ page heap disable करें।
- एक local proxy (जैसे Fiddler), testing के लिए plugin traffic में RFAs को बदलकर supply-chain delivery का simulation कर सकता है।

## References

- [1] [Autodesk Revit RFA फ़ाइल parsing में crash से पूर्ण Exploit RCE तैयार करना (ZDI blog)](https://www.thezdi.com/blog/2025/10/6/crafting-a-full-exploit-rce-from-a-crash-in-autodesk-revit-rfa-file-parsing)
- [2] [CompoundFileTool (GitHub)](https://github.com/thezdi/CompoundFileTool)
- [3] [OLE Compound File (CFBF) दस्तावेज़](https://learn.microsoft.com/en-us/windows/win32/stg/istorage-compound-file-implementation)
- [4] [Forensics CTF फ़ील्ड गाइड](https://trailofbits.github.io/ctf/forensics/)
- [5] [olevba दस्तावेज़ (GitHub)](https://github.com/decalage2/oletools/wiki/olevba)
- [6] [Auto Macros (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
- [7] [Document.Open event (Word) (Microsoft Learn)](https://learn.microsoft.com/en-us/office/vba/api/word/document.open)
{{#include ../../../banners/hacktricks-training.md}}
