# Windows Kernel Rootkits and DKOM

{{#include ../../banners/hacktricks-training.md}}

## दायरा

Compromise के बाद लोड किया गया implant, किसी signed kernel driver को service के रूप में लोड कर सकता है और `IRP_MJ_DEVICE_CONTROL` के ज़रिए user-mode control plane उपलब्ध करा सकता है। Driver signing से सिर्फ़ यह प्रमाणित होता है कि Windows image को स्वीकार करता है; इससे IOCTL authorization, memory operations, callbacks या hooks सुरक्षित नहीं हो जाते। विश्लेषण किए गए एक rootkit ने सामान्य संचालन के दौरान तीन handlers इस्तेमाल किए, लेकिन post-exploitation के लिए दर्जनों अतिरिक्त primitives उपलब्ध कराए। इसलिए reverse engineering में केवल malware trace में दिखे requests ही नहीं, बल्कि पूरे dispatcher को शामिल करना चाहिए।<sup>[[1]](#references)</sup>

## Signed-driver और IOCTL की प्रारंभिक जाँच

`DriverEntry` से शुरुआत करें, device objects और DOS symbolic links दर्ज करें, `MajorFunction[IRP_MJ_DEVICE_CONTROL]` routine का पता लगाएँ, और हर उस comparison/table entry को map करें जो किसी handler तक पहुँचाती है। User mode द्वारा खोले गए नामों का मिलान driver द्वारा वास्तव में बनाए गए नामों से करें: एक देखी गई chain ने `\\.\msagent` खोला, जबकि उसके driver ने `\Device\ToolTool` और `\DosDevices\ToolTool` बनाए। इस mismatch से किसी अन्य sample/configuration, setup logic के गायब होने या analysis में असंगति का पता चल सकता है।<sup>[[1]](#references)</sup>

Input structure को फिर से बनाने से पहले हर control code को decode करें।<sup>[[1]](#references)</sup>

```python
def decode_ioctl(code):
    return {
        "device_type": code >> 16,
        "access": (code >> 14) & 3,
        "function": (code >> 2) & 0xfff,
        "method": code & 3,
    }

for code in (0x2220F0, 0x222120, 0x2221E0):
    print(hex(code), decode_ioctl(code))
```

इन तीन codes का decode क्रमशः `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS`, और `METHOD_BUFFERED` होता है। इससे यह **साबित नहीं होता** कि कोई unprivileged caller उन तक पहुँच सकता है: device DACL, create/open dispatch, प्रति-request caller checks, अपेक्षित buffer lengths, embedded pointers, PID lifetime handling, और यह भी जाँचें कि handler caller द्वारा दिए गए PID या flag पर भरोसा तो नहीं करता।<sup>[[1]](#references)</sup>

जब implant केवल commands के एक subset का उपयोग करता है, तो बाकी handlers को dead code मानकर खारिज करने के बजाय primitive के आधार पर समूहित करें। एक multifunction driver ने निम्नलिखित सभी classes उजागर की हैं:<sup>[[1]](#references)</sup>

- **नियंत्रण/configuration:** rootkit state को toggle करना; protected paths, processes, और C2 addresses जोड़ना, हटाना, query करना या clear करना।
- **Process manipulation:** किसी PID को terminate करना, उसकी image unmap करना, `NtCreateThreadEx` से inject करना, processes या user modules को hide/restore करना, और PPL protection हटाना।
- **Kernel manipulation:** loaded driver को unlink करना, notification callbacks enumerate/disable/restore करना, किसी अन्य driver को manually map करना, और किसी arbitrary kernel address पर लिखना।
- **Object manipulation:** files को delete/decrypt करना और registry values बनाना या modify करना।

## Vulnerable signed driver के ज़रिए manual kernel mapping

Kernel-memory read/write operations वाला signed driver, unsigned driver image को loader के रूप में load कर सकता है—इसके लिए Windows से उस image को सामान्य driver की तरह load करने को कहने की ज़रूरत नहीं होती।<sup>[[2]](#references)[[7]](#references)</sup> LocalStranger का उदाहरण मौजूदा `\\.\WinNotify` device खोलता है; इसका source यह नहीं दिखाता कि कोई unprivileged user किसी मनमाने host पर driver install, start या open कर सकता है।<sup>[[2]](#references)[[3]](#references)</sup> Mapper image path लेता है, loaded kernel का base query करता है, और device के virtual-memory read/write IOCTLs का उपयोग करता है।<sup>[[4]](#references)[[9]](#references)[[10]](#references)</sup>

उस read/write access को kernel call में बदलने के लिए mapper, `MmGetVirtualForPhysical` से PTE-base immediate पढ़ता है और `NtAddAtom` को cover करने वाली paging entries को walk करता है।<sup>[[5]](#references)[[7]](#references)</sup> इसकी PTE calculation `PteBase + ((VA >> 9) & 0x7FFFFFFFF8)` है; code large-page PDE भी जाँचता है।<sup>[[5]](#references)[[7]](#references)</sup> यह अस्थायी रूप से covering entry को writable बनाता है, syscall entry को इच्छित kernel function पर jump से बदलता है, user-mode `NtAddAtom` stub को invoke करता है, फिर original bytes और page entry—दोनों restore करता है।<sup>[[6]](#references)</sup>

Mapper इस call path का उपयोग `ExAllocatePool` के लिए करता है, PE sections, imports और relocations को image में map करता है, उसे allocation में लिखता है, और उसके entry point को call करता है।<sup>[[7]](#references)[[8]](#references)</sup> यह implementation केवल x64, relocatable PE images स्वीकार करता है; इसका PTE-base read भी `MmGetVirtualForPhysical + 34` के fixed layout को मानकर चलता है।<sup>[[5]](#references)[[8]](#references)</sup> इसे build-dependent मानें—यह कोई स्वतंत्र KASLR bypass नहीं है और न ही इस बात का प्रमाण कि HVCI या PatchGuard इस mapping की अनुमति देते हैं।<sup>[[5]](#references)[[8]](#references)</sup> Kernel R/W के data-only उपयोग के लिए [SYSTEM token theft](arbitrary-kernel-rw-token-theft.md) देखें।

## Trusted-process exemptions

एक उपयोगी design pattern ऐसा IOCTL है जो PID और **trusted** flag register करता है। फिर वही trust lookup file, registry, process और thread filters द्वारा उपयोग की जाती है: untrusted tools को filtered enumeration results, कम handle rights, या `STATUS_ACCESS_DENIED` मिलता है, जबकि implant अपने hidden objects को update कर सकता है। इसे authorization boundary मानें और जाँचें कि entries authenticate और synchronize कैसे होती हैं, तथा process exit या PID reuse के बाद उन्हें हटाया जाता है या नहीं।<sup>[[1]](#references)</sup>

Rootkits policy को `REG_MULTI_SZ` values में persist कर सकते हैं और file, directory, registry-key, registry-value, ignored-image, protected-image, तथा hidden-image lists को AVL trees में compile कर सकते हैं। Analysis के दौरान इन shared trees के हर reader और writer को trace करें; इससे registry configuration, IOCTLs, callbacks और filtering logic के बीच संबंध पता चलता है—भले ही function names हटा दिए गए हों।<sup>[[1]](#references)</sup>

## DKOM process और module hiding

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` offsets, Windows build के अनुसार बदलते हैं। Version-tolerant rootkit ज्ञात candidates जाँच सकता है और फिर `EPROCESS` में ऐसे self-consistent `LIST_ENTRY` को scan कर सकता है जिसके neighbors, candidate की ओर वापस point करते हों। यह खोजा गया offset रखता है, neighbors के `Flink`/`Blink` को फिर से जोड़कर process को hide करता है, और बाद में entry को relink करने के लिए state सुरक्षित रखता है। Process चलता रहता है, लेकिन active-process list को walk करने वाले enumerators को दिखाई नहीं देता।<sup>[[1]](#references)</sup>

यह **DKOM** है, termination नहीं। Detection के लिए list-based results की तुलना स्वतंत्र evidence से करें, जैसे pool/object scans, thread ownership, handle tables, scheduler artifacts, और kernel memory inspection। किसी scan में दिखने वाला, लेकिन canonical list से गायब process—अकेले किसी एक view से ज़्यादा महत्वपूर्ण है।<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Module-hiding का समकक्ष primitive, `PsLoadedModuleList` में target entry ढूँढ़ता है और आस-पास के `Flink`/`Blink` pointers को patch करता है। Driver mapped और executable रहता है, लेकिन list-backed module queries उसे शामिल नहीं करतीं। Loader list की तुलना executable kernel mappings, pool tags, device/driver objects, service keys, callback addresses, और उन dispatch pointers से करें जो किसी listed image के बाहर point करते हों।<sup>[[1]](#references)</sup>

## Callback-based protection और cloaking

Rootkit documented callback frameworks को DKOM और hooks के साथ जोड़ सकता है:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` के `PsProcessType` और `PsThreadType` के लिए pre-operation handlers, जब कोई untrusted caller protected target को open करता है, तो termination, VM access, duplication, या thread manipulation में इस्तेमाल होने वाले rights हटा देते हैं। Callback altitude दर्ज करें और हर callback address को उसके owning module से resolve करें।
- `PsSetCreateProcessNotifyRoutineEx` और `PsSetLoadImageNotifyRoutine` processes और images के आने पर protected/ignored/hidden process state को maintain करते हैं; registration से पहले मौजूद objects को एक बार की process walk से backfill किया जा सकता है।
- Filesystem minifilter configured paths तक access रोकता है। कोई असामान्य implementation अपनी `Instances` key बना सकता है, altitude को dynamically चुन सकता है, और `FltRegisterFilter` द्वारा collision report किए जाने पर उसे बढ़ाकर retry कर सकता है।
- `CmRegisterCallbackEx` routine enumeration से protected names छिपा सकती है और direct open, rename, set या delete operations रोक सकती है—साथ ही registered trusted processes को छूट दे सकती है।

`ObRegisterCallbacks` registrations, registry-callback altitudes, `fltmc filters` output, service `Instances` keys, और callback addresses को correlate करें। अगर सामान्य tools के results filter हो रहे हों, तो offline memory image या किसी अन्य trusted acquisition layer से इन structures की जाँच करें।<sup>[[1]](#references)</sup>

## Nsiproxy result filtering

Network concealment `\Driver\Nsiproxy` को target कर सकता है: `ObReferenceObjectByName` से driver object प्राप्त करें, handler pointer सुरक्षित रखें, उसे wrapper से replace करें, और user mode तक पहुँचने से पहले IOCTL-managed C2 list से मेल खाने वाले returned IPv4 records हटा दें। Filtered NSI data पर निर्भर applications अब connection नहीं दिखा सकतीं, जबकि traffic मौजूद रहता है।<sup>[[1]](#references)</sup>

Host connection views की तुलना packet capture, WFP/ETW telemetry, और kernel-memory network objects से करें। `Nsiproxy` dispatch/handler pointers की भी जाँच करें और पुष्टि करें कि हर pointer अपेक्षित signed module के अंदर resolve होता है; किसी unlisted mapping में pointer, network filtering को `PsLoadedModuleList` DKOM से जोड़ सकता है।<sup>[[1]](#references)</sup>

## जाँच-सूची

सबसे मज़बूत संकेत अलग-अलग layers के बीच असहमति है, न कि कोई एक filename या hash। इन चीज़ों को correlate करें:<sup>[[1]](#references)</sup>

1. Kernel-service creation और ऐसा signed driver जिसका certificate age, publisher या path, installed product से मेल न खाता हो।
2. Device creation, DOS links, और IOCTL traffic—इसमें user-mode और kernel device names के बीच mismatch भी शामिल है।
3. PID registration request के बाद, अन्य processes का उन्हीं objects को open, enumerate, modify या delete न कर पाना।
4. Object/registry/process/image callbacks, minifilter instances, और ऐसे hooks जिनके addresses सामान्य रूप से enumerated driver के नहीं हैं।
5. List-based और scan-based process, module, callback, तथा network inventories के बीच अंतर।

## References

- [1] [Kaspersky Securelist - HoneyMyte, Signed Windows Kernel Rootkit के साथ CoolClient को बेहतर बनाता है](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
- [2] [LocalStranger README](https://github.com/nbs32k/LocalStranger/blob/master/README.md)
- [3] [LocalStranger driver initialization](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/init.c)
- [4] [LocalStranger mapper command line](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/main.cpp)
- [5] [LocalStranger kernel export और PTE-base resolution](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/utils.cpp)
- [6] [LocalStranger kernel-call trampoline](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.h)
- [7] [LocalStranger mapper allocation और entry call](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/mapper.cpp)
- [8] [LocalStranger PE mapping](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/mapper/pe.cpp)
- [9] [LocalStranger kernel और syscall context](https://github.com/nbs32k/LocalStranger/blob/master/lsmapper/core/context.cpp)
- [10] [LocalStranger virtual-memory IOCTL wrappers](https://github.com/nbs32k/LocalStranger/blob/master/lsapi/virtual.c)
{{#include ../../banners/hacktricks-training.md}}
