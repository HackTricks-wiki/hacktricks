# Windows Kernel Rootkits और DKOM

{{#include ../../banners/hacktricks-training.md}}

## दायरा

एक post-compromise implant signed kernel driver को service के रूप में load कर सकता है और `IRP_MJ_DEVICE_CONTROL` के माध्यम से user-mode control plane उपलब्ध करा सकता है। Driver signing केवल यह स्थापित करता है कि Windows image को स्वीकार करता है; यह IOCTL authorization, memory operations, callbacks या hooks को सुरक्षित नहीं बनाता। एक analyzed rootkit ने सामान्य operation के दौरान तीन handlers का उपयोग किया, लेकिन दर्जनों अतिरिक्त post-exploitation primitives expose किए। इसलिए reverse engineering को malware trace में देखी गई requests तक सीमित रखने के बजाय complete dispatcher को cover करना चाहिए।<sup>[[1]](#references)</sup>

## Signed-driver और IOCTL triage

`DriverEntry` से शुरू करें, device objects और DOS symbolic links को record करें, `MajorFunction[IRP_MJ_DEVICE_CONTROL]` routine को locate करें, और हर उस comparison/table entry का map बनाएं जो किसी handler तक पहुंचती है। User mode द्वारा खोले गए names की तुलना उन names से करें जिन्हें driver वास्तव में create करता है: एक observed chain ने `\\.\msagent` खोला, जबकि उसके driver ने `\Device\ToolTool` और `\DosDevices\ToolTool` create किए। यह mismatch किसी अन्य sample/configuration, missing setup logic या analysis inconsistency की पहचान कर सकता है।<sup>[[1]](#references)</sup>

Input structure को reconstruct करने से पहले प्रत्येक control code को decode करें।<sup>[[1]](#references)</sup>
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
ये तीन codes क्रमशः `FILE_DEVICE_UNKNOWN`, `FILE_ANY_ACCESS`, और `METHOD_BUFFERED` के रूप में decode होते हैं। इससे यह **सिद्ध नहीं होता** कि कोई unprivileged caller इन्हें access कर सकता है: device DACL, create/open dispatch, प्रत्येक request पर caller checks, अपेक्षित buffer lengths, embedded pointers, PID lifetime handling, और यह भी जांचें कि handler caller-supplied PID या flag पर भरोसा करता है या नहीं।<sup>[[1]](#references)</sup>

जब implant commands के केवल एक subset का उपयोग करता है, तो बाकी handlers को dead code मानकर खारिज करने के बजाय primitive के अनुसार group करें। एक single multifunction driver ने निम्नलिखित सभी classes expose की हैं:<sup>[[1]](#references)</sup>

- **Control/configuration:** rootkit state को toggle करना; protected paths, processes और C2 addresses को add, remove, query या clear करना।
- **Process manipulation:** किसी PID को terminate करना, उसकी image को unmap करना, `NtCreateThreadEx` से inject करना, processes या user modules को hide/restore करना, और PPL protection हटाना।
- **Kernel manipulation:** loaded driver को unlink करना, notification callbacks को enumerate/disable/restore करना, किसी अन्य driver को manually map करना, और arbitrary kernel address पर write करना।
- **Object manipulation:** files को delete/decrypt करना और registry values को create या modify करना।

## Trusted-process exemptions

एक उपयोगी design pattern ऐसा IOCTL है जो PID के साथ एक **trusted** flag register करता है। इसी trust lookup को फिर file, registry, process और thread filters consult करते हैं: untrusted tools को filtered enumeration results, कम handle rights, या `STATUS_ACCESS_DENIED` मिलते हैं, जबकि implant अपने hidden objects को update कर सकता है। इसे एक authorization boundary मानें और verify करें कि entries को authenticate और synchronize कैसे किया जाता है तथा process exit या PID reuse के बाद उन्हें कैसे हटाया जाता है।<sup>[[1]](#references)</sup>

Rootkits policy को `REG_MULTI_SZ` values में persist कर सकते हैं और file, directory, registry-key, registry-value, ignored-image, protected-image और hidden-image lists को AVL trees में compile कर सकते हैं। Analysis के दौरान इन shared trees के प्रत्येक reader और writer को trace करें; इससे registry configuration, IOCTLs, callbacks और filtering logic आपस में जुड़ जाते हैं, भले ही function names stripped हों।<sup>[[1]](#references)</sup>

## DKOM process और module hiding

### `EPROCESS.ActiveProcessLinks`

`ActiveProcessLinks` offsets Windows build के अनुसार बदलते हैं। एक version-tolerant rootkit ज्ञात candidates को test कर सकता है और फिर `EPROCESS` में ऐसे self-consistent `LIST_ENTRY` को scan कर सकता है जिसके neighbors candidate की ओर वापस point करते हों। यह discovered offset को retain करता है, neighbors के `Flink`/`Blink` को reconnect करके process को hide करता है, और बाद में entry को relink करने के लिए state preserve करता है। Process चलता रहता है, लेकिन active-process list को walk करने वाले enumerators से गायब हो जाता है।<sup>[[1]](#references)</sup>

यह termination नहीं, बल्कि **DKOM** है। Detection में list-based results की तुलना independent evidence जैसे pool/object scans, thread ownership, handle tables, scheduler artifacts और kernel memory inspection से करनी चाहिए। किसी scan में दिखाई देने वाला लेकिन canonical list से अनुपस्थित process, दोनों views में से किसी एक की तुलना में अधिक meaningful संकेत है।<sup>[[1]](#references)</sup>

### `PsLoadedModuleList`

Equivalent module-hiding primitive target entry को `PsLoadedModuleList` में ढूंढता है और adjacent `Flink`/`Blink` pointers को patch करता है। Driver mapped और executable रहता है, लेकिन list-backed module queries उसे omit करती हैं। Loader list की तुलना executable kernel mappings, pool tags, device/driver objects, service keys, callback addresses और उन dispatch pointers से करें जो किसी listed image के बाहर land करते हैं।<sup>[[1]](#references)</sup>

## Callback-based protection और cloaking

एक rootkit documented callback frameworks को DKOM और hooks के साथ layer कर सकता है:<sup>[[1]](#references)</sup>

- `ObRegisterCallbacks` के `PsProcessType` और `PsThreadType` के लिए pre-operation handlers, जब कोई untrusted caller protected target को open करता है, तो termination, VM access, duplication या thread manipulation के लिए उपयोग होने वाले rights को remove कर देते हैं। Callback altitude record करें और प्रत्येक callback address को उसके owning module से resolve करें।
- `PsSetCreateProcessNotifyRoutineEx` और `PsSetLoadImageNotifyRoutine` processes और images के appear होने पर protected/ignored/hidden process state maintain करते हैं; registration से पहले मौजूद objects को backfill करने के लिए one-time process walk किया जा सकता है।
- एक filesystem minifilter configured paths तक access deny करता है। कोई unusual implementation अपनी `Instances` key create कर सकती है, altitude dynamically चुन सकती है, और जब `FltRegisterFilter` collision report करे तो उसे increment/retry कर सकती है।
- एक `CmRegisterCallbackEx` routine protected names को enumeration से suppress कर सकती है और direct open, rename, set या delete operations deny कर सकती है, जबकि registered trusted processes को exempt रखती है।

`ObRegisterCallbacks` registrations, registry-callback altitudes, `fltmc filters` output, service `Instances` keys और callback addresses को correlate करें। यदि normal tools को filter किया जा रहा हो, तो इन structures को offline memory image या किसी अन्य trusted acquisition layer से inspect करें।<sup>[[1]](#references)</sup>

## Nsiproxy result filtering

Network concealment `\Driver\Nsiproxy` को target कर सकता है: `ObReferenceObjectByName` से driver object प्राप्त करें, handler pointer save करें, उसे wrapper से replace करें, और user mode तक पहुंचने से पहले returned IPv4 records को IOCTL-managed C2 list से match होने पर remove करें। Filtered NSI data पर आधारित applications connection को display नहीं कर सकतीं, भले ही traffic अभी मौजूद हो।<sup>[[1]](#references)</sup>

Host connection views की तुलना packet capture, WFP/ETW telemetry और kernel-memory network objects से करें। `Nsiproxy` dispatch/handler pointers को भी inspect करें और confirm करें कि प्रत्येक expected signed module के अंदर resolve होता है; किसी unlisted mapping के अंदर मौजूद pointer network filtering को `PsLoadedModuleList` DKOM से जोड़ सकता है।<sup>[[1]](#references)</sup>

## Investigation checklist

सबसे मजबूत signal layers के बीच disagreement है, न कि कोई एक filename या hash। निम्नलिखित को correlate करें:<sup>[[1]](#references)</sup>

1. Kernel-service creation और ऐसा signed driver जिसके certificate age, publisher या path का installed product से मेल न हो।
2. Device creation, DOS links और IOCTL traffic, जिनमें user-mode और kernel device names के बीच mismatch शामिल हो।
3. PID registration request के बाद अन्य processes का उन्हीं objects को open, enumerate, modify या delete करने में fail होना।
4. Object/registry/process/image callbacks, minifilter instances और ऐसे hooks जिनके addresses normally enumerated driver से संबंधित न हों।
5. List-based और scan-based process, module, callback और network inventories के बीच differences।

## References

- [1] [Kaspersky Securelist - HoneyMyte Enhances CoolClient with a Signed Windows Kernel Rootkit](https://securelist.com/honeymyte-coolclient-driver-rootkit/121028)
{{#include ../../banners/hacktricks-training.md}}
