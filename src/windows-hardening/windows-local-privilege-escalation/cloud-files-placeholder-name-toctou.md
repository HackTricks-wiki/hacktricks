# Windows MDL-Mapped User Buffer Double-Fetch

{{#include ../../banners/hacktricks-training.md}}

Windows kernel driver तब double-fetch पैदा करता है, जब वह caller-backed pages में मौजूद data को validate करता है और बाद में उन्हीं pages के pointer को security-sensitive API में पास करता है। Pages को lock और map करने से उनमें मौजूद content immutable नहीं हो जाता। `cldflt.sys` में CVE-2025-55680 इस pattern का उदाहरण है: driver ने Cloud Files placeholder का relative name validate किया, फिर भी caller के mutable buffer को reference करते हुए object बनाया।<sup>[[1]](#references)[[3]](#references)</sup>

`CfCreatePlaceholders()` registered Cloud Files sync root के नीचे files या directories बनाता है। Vulnerable path में, validation के बाद name बदलने से privileged creation उस root के बाहर redirect हो सकती थी।<sup>[[1]](#references)[[2]](#references)</sup>

## Pages को lock करने से data lock क्यों नहीं हुआ

Vulnerable `HsmpOpCreatePlaceholders()` path ने caller के payload के लिए MDL allocate किया, `ProbeForRead()` और `MmProbeAndLockPages()` call किया, और उन pages को kernel virtual address space में map किया। MDL physical pages का वर्णन करता है और उन्हें lock करता है, ताकि वे memory में resident रहें। यह उनके bytes का snapshot **नहीं** लेता। इसलिए user mode उसी physical memory को तब भी बदल सकता है, जब driver उसे system mapping के ज़रिए पढ़ रहा हो।<sup>[[1]](#references)[[3]](#references)</sup>

संबंधित request और use path यह था:<sup>[[1]](#references)</sup>

1. `cldapi.dll` ने Cloud Files control code `0x903BC`, tag `IO_REPARSE_TAG_CLOUD` (`0x9000001A`) और create-placeholder operation `0xC0000001` के साथ भेजा।
2. हर payload record में relative name और file identity के लिए 16-bit offset/length pairs थे। ज़्यादातर fixed fields को stack record में copy किया गया, लेकिन variable-length name mapped user pages में ही रहा।
3. Driver ने UTF-16 name को scan किया और backslash या colon होने पर उसे अस्वीकार कर दिया।
4. इसके बाद उसने एक `UNICODE_STRING` बनाया, जिसका `Buffer` अब भी mapped payload की ओर point कर रहा था, और उसे `OBJECT_ATTRIBUTES.ObjectName` को assign किया।
5. `FltCreateFileEx2()` ने उस pointer को फिर से पढ़ा। इसलिए concurrent writer validation के दौरान एक string और file creation के दौरान दूसरी string दिखा सकता था।

यह **double-fetch** है, भले ही दोनों reads में kernel virtual address का इस्तेमाल हो: security boundary backing storage पर निर्भर करती है, न कि इस पर कि driver किस virtual mapping को dereference करता है।<sup>[[1]](#references)</sup>

## Cloud Files race layout

प्रकाशित exploit strategy ने double-fetch को path redirection में बदलने के लिए बार-बार requests, mutator threads और एक junction का इस्तेमाल किया:<sup>[[1]](#references)</sup>

1. `CfRegisterSyncRoot()` से attacker-controlled directory register करें और उसके नीचे `JUSTASTRING` को protected destination के junction के रूप में बनाएँ।
2. `JUSTASTRINGDnewfile.dll` नाम वाला एक valid single-component name रखकर shared placeholder record तैयार करें।
3. Mutator threads से UTF-16 `D` code unit को `D` और `\` के बीच बदलते रहें। दूसरा रूप `JUSTASTRING\newfile.dll` है।
4. समान payload को reference करने वाली create-placeholder requests बार-बार submit करने के लिए worker threads चलाएँ, जबकि एक monitor protected destination को जाँचता रहे।
5. सफल iteration में separator-रहित रूप validate होता है, फिर बाद में create operation में `\` वाला रूप दिखने पर junction follow होता है।

यह primitive केवल protected file या directory बनाने की क्षमता देता है। इसे code execution में बदलने के लिए अब भी बनी हुई file के contents पर control और किसी privileged consumer की ज़रूरत होती है, जैसे उपयुक्त DLL side-loading target। मूल analysis में इस अंतिम प्रकार की chain का इस्तेमाल किया गया था, लेकिन loader, payload या पूरा standalone exploit प्रकाशित नहीं किया गया।<sup>[[1]](#references)</sup>

Windows path-lookup races को जानबूझकर बढ़ाने वाली पूरक techniques के लिए, [Object Manager Slow Paths के ज़रिए Kernel Race Condition Exploitation](kernel-race-condition-object-manager-slowdown.md) देखें।

## References

- [1] [Exodus Intelligence - Microsoft Windows Cloud Files Minifilter TOCTOU Privilege Escalation](https://blog.exodusintel.com/2025/10/20/microsoft-windows-cloud-files-minifilter-toctou-privilege-escalation/)
- [2] [Microsoft Learn - CfCreatePlaceholders function](https://learn.microsoft.com/en-us/windows/win32/api/cfapi/nf-cfapi-cfcreateplaceholders)
- [3] [Microsoft Learn - MmProbeAndLockPages function](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
{{#include ../../banners/hacktricks-training.md}}
