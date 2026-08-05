# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

सबसे पहले, remote task से thread list प्राप्त करने के लिए task port पर `task_threads()` function को invoke किया जाता है। Hijacking के लिए एक thread चुना जाता है। यह approach conventional code-injection methods से अलग है, क्योंकि `thread_create_running()` को block करने वाले mitigation के कारण नया remote thread बनाना निषिद्ध है।<sup>[[1]](#references)</sup>

Thread को नियंत्रित करने के लिए `thread_suspend()` call किया जाता है, जिससे उसका execution रुक जाता है।<sup>[[1]](#references)</sup>

Remote thread पर अनुमत एकमात्र operations उसे **stopping** और **starting** करने तथा उसके register values को **retrieving**/**modifying** करने से संबंधित होते हैं। Remote function calls, registers `x0` से `x7` को **arguments** पर set करके, `pc` को इच्छित function पर configure करके और thread को resume करके शुरू की जाती हैं। Return के बाद thread को crash होने से रोकने के लिए return का detection आवश्यक है।<sup>[[1]](#references)</sup>

एक strategy में `thread_set_exception_ports()` का उपयोग करके remote thread के लिए एक **exception handler** register करना और function call से पहले `lr` register को invalid address पर set करना शामिल है। इससे function execution के बाद exception trigger होता है और exception port पर एक message भेजा जाता है, जिससे return value प्राप्त करने के लिए thread की state inspect की जा सकती है। वैकल्पिक रूप से, Ian Beer के *triple_fetch* exploit से अपनाए गए तरीके में `lr` को infinitely loop करने के लिए set किया जाता है; इसके बाद thread के registers को लगातार monitor किया जाता है, जब तक `pc` उस instruction की ओर point न करे।<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

अगले phase में remote thread के साथ communication को सक्षम करने के लिए Mach ports establish किए जाते हैं। ये ports tasks के बीच arbitrary send/receive rights transfer करने में महत्वपूर्ण भूमिका निभाते हैं।<sup>[[1]](#references)</sup>

Bidirectional communication के लिए दो Mach receive rights बनाए जाते हैं: एक local task में और दूसरा remote task में। इसके बाद प्रत्येक port के लिए एक send right counterpart task को transfer किया जाता है, जिससे message exchange संभव होता है।<sup>[[1]](#references)</sup>

Local port पर ध्यान दें तो receive right local task के पास रहता है। Port को `mach_port_allocate()` से बनाया जाता है। चुनौती local port का send right remote task में transfer करने की होती है।<sup>[[1]](#references)</sup>

एक strategy में `thread_set_special_port()` का उपयोग करके local port का send right remote thread के `THREAD_KERNEL_PORT` में रखने की प्रक्रिया शामिल है। इसके बाद remote thread को `mach_thread_self()` call करने का निर्देश दिया जाता है, ताकि वह send right प्राप्त कर सके।<sup>[[1]](#references)</sup>

Remote port के लिए process मूलतः उलट होता है। Remote thread को `mach_reply_port()` के माध्यम से Mach port generate करने का निर्देश दिया जाता है, क्योंकि इसके return mechanism के कारण `mach_port_allocate()` उपयुक्त नहीं है। Port बनने के बाद, send right establish करने के लिए remote thread में `mach_port_insert_right()` invoke किया जाता है। इसके बाद इस right को `thread_set_special_port()` का उपयोग करके kernel में stash किया जाता है। Local task में वापस आकर, remote thread पर `thread_get_special_port()` का उपयोग करके remote task में newly allocated Mach port का send right प्राप्त किया जाता है।<sup>[[1]](#references)</sup>

इन steps के पूरा होने पर Mach ports establish हो जाते हैं, जो bidirectional communication की foundation तैयार करते हैं।<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

इस section में execute primitive का उपयोग करके basic memory read/write primitives establish करने पर ध्यान दिया गया है। ये प्रारंभिक steps remote process पर अधिक control प्राप्त करने के लिए महत्वपूर्ण हैं, हालांकि इस stage पर ये primitives अधिक उपयोगी नहीं होंगे। जल्द ही इन्हें अधिक advanced versions में upgrade किया जाएगा।<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

लक्ष्य specific functions का उपयोग करके memory reading और writing करना है। **reading memory** के लिए:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
**Memory में लिखने के लिए:**
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
ये functions निम्नलिखित assembly के अनुरूप हैं:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### उपयुक्त functions की पहचान

Common libraries के scan से इन operations के लिए उपयुक्त candidates मिले:<sup>[[1]](#references)</sup>

1. **Memory पढ़ना — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **मेमोरी लिखना — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
किसी भी address पर 64-bit write करने के लिए:
```c
_xpc_int64_set_value(address - 0x18, value);
```
इन primitives के स्थापित हो जाने के बाद, shared memory बनाने का चरण आता है, जो remote process को नियंत्रित करने की दिशा में एक महत्वपूर्ण प्रगति है।<sup>[[1]](#references)</sup>

## 4. Shared Memory Setup

उद्देश्य local और remote tasks के बीच shared memory स्थापित करना है, जिससे data transfer सरल होता है और कई arguments वाले functions को call करना संभव बनता है। यह approach `libxpc` और इसके `OS_xpc_shmem` object type का उपयोग करती है, जो Mach memory entries पर आधारित है।<sup>[[1]](#references)</sup>

### Process overview

1. **Memory allocation**
* sharing के लिए `mach_vm_allocate()` का उपयोग करके memory allocate करें।
* allocated region के लिए `OS_xpc_shmem` object बनाने हेतु `xpc_shmem_create()` का उपयोग करें।
2. **Creating shared memory in the remote process**
* remote process में `OS_xpc_shmem` object के लिए memory allocate करें (`remote_malloc`)।
* local template object को copy करें; offset `0x18` पर embedded Mach send right का fix-up अभी आवश्यक है।
3. **Correcting the Mach memory entry**
* `thread_set_special_port()` के साथ एक send right insert करें और `0x18` field को remote entry के name से overwrite करें।
4. **Finalising**
* remote object को validate करें और `xpc_shmem_remote()` पर remote call करके उसे map करें।

## 5. Achieving Full Control

Arbitrary execution और shared-memory back-channel उपलब्ध होने के बाद, target process प्रभावी रूप से आपके नियंत्रण में होता है:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — local और shared regions के बीच `memcpy()` का उपयोग करें।
* **Function calls with > 8 args** — arm64 calling convention के अनुसार extra arguments को stack पर रखें।
* **Mach port transfer** — स्थापित ports के माध्यम से Mach messages में rights pass करें।
* **File-descriptor transfer** — fileports का उपयोग करें (*triple_fetch* देखें)।

इन सभी सुविधाओं को [`threadexec`](https://github.com/bazad/threadexec) library में आसान re-use के लिए wrap किया गया है।

---

## 6. Apple Silicon (arm64e) Nuances

Apple Silicon devices (arm64e) पर **Pointer Authentication Codes (PAC)** सभी return addresses और कई function pointers की सुरक्षा करते हैं। *existing code* को **reuse** करने वाली Thread-hijacking techniques काम करती रहती हैं, क्योंकि `lr`/`pc` में मौजूद original values पहले से valid PAC signatures रखती हैं। समस्याएँ तब आती हैं जब आप attacker-controlled memory पर jump करने का प्रयास करते हैं:

1. target के अंदर executable memory allocate करें (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`)।
2. अपना payload copy करें।
3. *remote* process के अंदर pointer को sign करें:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Hijacked thread state में `pc = ptr` सेट करें।

वैकल्पिक रूप से, मौजूदा gadgets/functions को chain करके PAC-compliant बने रहें (traditional ROP)।

## 7. EndpointSecurity के साथ Detection और Hardening

**EndpointSecurity (ES)** framework kernel events उपलब्ध कराता है, जो defenders को thread-injection attempts को observe या block करने की अनुमति देते हैं:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – तब trigger होता है जब कोई process किसी अन्य task के port का अनुरोध करता है (जैसे `task_for_pid()` )।
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – जब भी किसी *different task* में thread बनाया जाता है, तब emit होता है।<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (macOS 14 Sonoma में जोड़ा गया) – किसी existing thread के register manipulation को दर्शाता है।

Remote-thread events को print करने वाला Minimal Swift client:
```swift
import EndpointSecurity

let client = try! ESClient(subscriptions: [.notifyRemoteThreadCreate]) {
(_, msg) in
if let evt = msg.remoteThreadCreate {
print("[ALERT] remote thread in pid \(evt.target.pid) by pid \(evt.thread.pid)")
}
}
RunLoop.main.run()
```
**osquery** ≥ 5.8 के साथ Query करना:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime संबंधी विचार

अपना application `com.apple.security.get-task-allow` entitlement के बिना **वितरित** करने से non-root attackers को उसका task-port प्राप्त करने से रोका जाता है। System Integrity Protection (SIP) अभी भी कई Apple binaries तक access को block करता है, लेकिन third-party software को स्पष्ट रूप से opt-out करना होगा।

## 8. हालिया Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Compact PoC, जो Ventura/Sonoma पर PAC-aware thread hijacking प्रदर्शित करता है |
| `remote_thread_es` | 2024 | कई EDR vendors द्वारा `REMOTE_THREAD_CREATE` events को surface करने के लिए उपयोग किया जाने वाला EndpointSecurity helper |

> इन projects का source code पढ़ना macOS 13/14 में introduced API changes को समझने और Intel ↔ Apple Silicon के बीच compatible बने रहने के लिए उपयोगी है।

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
