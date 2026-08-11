# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Mwanzoni, function ya `task_threads()` inaitwa kwenye task port ili kupata orodha ya threads kutoka kwenye task ya mbali. Thread moja huchaguliwa kwa ajili ya hijacking. Mbinu hii inatofautiana na njia za kawaida za code-injection kwa sababu kuunda thread mpya ya mbali hairuhusiwi kutokana na mitigation inayozuia `thread_create_running()`.<sup>[[1]](#references)</sup>

Ili kudhibiti thread, `thread_suspend()` huitwa, na hivyo kusimamisha utekelezaji wake.<sup>[[1]](#references)</sup>

Operations pekee zinazoruhusiwa kwenye thread ya mbali ni **kuisimamisha** na **kuianzisha**, pamoja na **kupata**/**kubadilisha** thamani za registers zake. Remote function calls huanzishwa kwa kuweka registers `x0` hadi `x7` kuwa **arguments**, kusanidi `pc` ilenge function inayotakiwa, kisha kuendelea na thread. Ili kuhakikisha thread hai-crash baada ya return, ni lazima kugundua return hiyo.<sup>[[1]](#references)</sup>

Mbinu moja inahusisha kusajili **exception handler** kwa thread ya mbali kwa kutumia `thread_set_exception_ports()`, na kuweka register ya `lr` kuwa address isiyokuwa halali kabla ya function call. Hii husababisha exception baada ya function kutekelezwa, na kutuma message kwenye exception port, hivyo kuwezesha kukagua state ya thread ili kupata return value. Vinginevyo, kama ilivyotumika katika exploit ya Ian Beer iitwayo *triple_fetch*, `lr` huwekwa ili ku-loop bila mwisho; registers za thread hufuatiliwa mfululizo hadi `pc` ielekee kwenye instruction hiyo.<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

Hatua inayofuata inahusisha kuanzisha Mach ports ili kuwezesha mawasiliano na thread ya mbali. Ports hizi hutumika kuhamisha arbitrary send/receive rights kati ya tasks.<sup>[[1]](#references)</sup>

Kwa mawasiliano ya pande mbili, Mach receive rights mbili huundwa: moja kwenye task ya ndani na nyingine kwenye task ya mbali. Kisha, send right ya kila port huhamishiwa kwenye task inayolingana, na kuwezesha kubadilishana messages.<sup>[[1]](#references)</sup>

Tukizingatia port ya ndani, receive right inashikiliwa na task ya ndani. Port huundwa kwa kutumia `mach_port_allocate()`. Changamoto iko katika kuhamisha send right ya port hii kwenda kwenye task ya mbali.<sup>[[1]](#references)</sup>

Mbinu moja inahusisha kutumia `thread_set_special_port()` kuweka send right ya port ya ndani kwenye `THREAD_KERNEL_PORT` ya thread ya mbali. Kisha thread ya mbali huagizwa kuita `mach_thread_self()` ili kupata send right hiyo.<sup>[[1]](#references)</sup>

Kwa port ya mbali, mchakato huo hubadilishwa kimsingi. Thread ya mbali huagizwa kuunda Mach port kupitia `mach_reply_port()` (kwa sababu `mach_port_allocate()` haifai kutokana na namna inavyorudisha thamani). Baada ya port kuundwa, `mach_port_insert_right()` huitwa kwenye thread ya mbali ili kuanzisha send right. Right hii huhifadhiwa kwenye kernel kwa kutumia `thread_set_special_port()`. Kwenye task ya ndani, `thread_get_special_port()` hutumika kwenye thread ya mbali ili kupata send right ya Mach port mpya iliyotengewa kwenye task ya mbali.<sup>[[1]](#references)</sup>

Kukamilika kwa hatua hizi husababisha Mach ports kuanzishwa, na kuweka msingi wa mawasiliano ya pande mbili.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

Katika sehemu hii, lengo ni kutumia execute primitive kuanzisha memory read/write primitives za msingi. Hatua hizi za awali ni muhimu kwa kupata udhibiti zaidi wa process ya mbali, ingawa primitives katika hatua hii hazitatumika kwa mambo mengi. Hivi karibuni, zitaboreshwa kuwa versions za hali ya juu zaidi.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

Lengo ni kusoma na kuandika memory kwa kutumia functions maalum. Kwa **kusoma memory**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Kwa kumbukumbu ya uandishi:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Kazi hizi zinalingana na assembly ifuatayo:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Kutambua functions zinazofaa

Uchunguzi wa libraries za kawaida ulifichua candidates zinazofaa kwa operations hizi:<sup>[[1]](#references)</sup>

1. **Kusoma memory — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Kuandika kwenye memory — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Ili kutekeleza uandishi wa 64-bit kwenye anwani yoyote:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Kwa kutumia primitives hizi, mazingira sasa yako tayari kwa kuunda shared memory, hatua muhimu katika kudhibiti remote process.<sup>[[1]](#references)</sup>

## 4. Usanidi wa Shared Memory

Lengo ni kuanzisha shared memory kati ya local na remote tasks, kurahisisha uhamishaji wa data na kuwezesha kuita functions zenye arguments nyingi. Mbinu hii hutumia `libxpc` na aina ya object ya `OS_xpc_shmem`, ambayo imejengwa juu ya Mach memory entries.<sup>[[1]](#references)</sup>

### Muhtasari wa mchakato

1. **Kutenga memory**
* Tenga memory kwa ajili ya sharing ukitumia `mach_vm_allocate()`.
* Tumia `xpc_shmem_create()` kuunda object ya `OS_xpc_shmem` kwa eneo lililotengwa.
2. **Kuunda shared memory katika remote process**
* Tenga memory kwa ajili ya object ya `OS_xpc_shmem` katika remote process (`remote_malloc`).
* Nakili template object ya local; fix-up ya embedded Mach send right kwenye offset `0x18` bado inahitajika.
3. **Kusahihisha Mach memory entry**
* Ingiza send right kwa kutumia `thread_set_special_port()` na overwrite field ya `0x18` kwa jina la remote entry.
4. **Kukamilisha**
* Validate remote object na uimap kwa remote call ya `xpc_shmem_remote()`.

## 5. Kufikia Udhibiti Kamili

Mara tu arbitrary execution na shared-memory back-channel zinapopatikana, kwa ufanisi unamiliki target process:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — tumia `memcpy()` kati ya local na shared regions.
* **Function calls zenye > 8 args** — weka arguments za ziada kwenye stack kwa kufuata arm64 calling convention.
* **Mach port transfer** — pitisha rights katika Mach messages kupitia ports zilizoanzishwa.
* **File-descriptor transfer** — tumia fileports (tazama *triple_fetch*).

Yote haya yamefungwa katika library ya [`threadexec`](https://github.com/bazad/threadexec) kwa matumizi rahisi tena.

---

## 6. Nuances za Apple Silicon (arm64e)

Kwenye vifaa vya Apple Silicon (arm64e), **Pointer Authentication Codes (PAC)** hulinda return addresses zote na function pointers nyingi. Mbinu za thread-hijacking zinazotumia tena *existing code* zinaendelea kufanya kazi kwa sababu values asili katika `lr`/`pc` tayari zina PAC signatures halali. Matatizo hutokea unapojaribu kuruka kwenye memory inayodhibitiwa na attacker:

1. Tenga executable memory ndani ya target (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Nakili payload yako.
3. Ndani ya *remote* process, sign pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Weka `pc = ptr` katika hali ya thread iliyotekwa.

Vinginevyo, dumisha ufuataji wa PAC kwa kuunganisha gadgets/functions zilizopo (ROP ya kawaida).

## 7. Utambuzi na Uimarishaji wa Usalama kwa EndpointSecurity

Framework ya **EndpointSecurity (ES)** hufichua matukio ya kernel yanayowawezesha watetezi kuchunguza au kuzuia majaribio ya thread-injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – hutokea wakati process inaomba port ya task nyingine (kwa mfano, `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – hutolewa kila wakati thread inapoanzishwa katika task *tofauti*.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (imeongezwa katika macOS 14 Sonoma) – huonyesha mabadiliko ya registers ya thread iliyopo.

Swift client rahisi inayochapisha matukio ya remote-thread:
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
Kuuliza kwa kutumia **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Mazingatio ya hardened-runtime

Kusambaza application yako **bila** entitlement ya `com.apple.security.get-task-allow` huwazuia attackers wasio-root kupata task-port yake. System Integrity Protection (SIP) bado huzuia ufikiaji wa Apple binaries nyingi, lakini third-party software lazima ijiondoe waziwazi.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Compact PoC inayoonyesha PAC-aware thread hijacking kwenye Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | EndpointSecurity helper inayotumiwa na wauzaji kadhaa wa EDR kufichua matukio ya `REMOTE_THREAD_CREATE` |

> Kusoma source code ya projects hizi ni muhimu kwa kuelewa mabadiliko ya API yaliyoletwa kwenye macOS 13/14 na kudumisha compatibility kati ya Intel ↔ Apple Silicon.

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}
