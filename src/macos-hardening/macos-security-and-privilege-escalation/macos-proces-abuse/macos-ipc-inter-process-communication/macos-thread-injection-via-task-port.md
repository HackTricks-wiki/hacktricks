# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Mwanzoni, function ya `task_threads()` inaitwa kwenye task port ili kupata orodha ya threads kutoka kwenye remote task. Thread moja huchaguliwa kwa ajili ya hijacking. Mbinu hii hutofautiana na conventional code-injection methods kwa sababu kuunda remote thread mpya hairuhusiwi kutokana na mitigation inayozuia `thread_create_running()`.<sup>[[1]](#references)</sup>

Ili kuidhibiti thread, `thread_suspend()` huitwa, na kusimamisha execution yake.<sup>[[1]](#references)</sup>

Operations pekee zinazoruhusiwa kwenye remote thread ni **kuisimamisha** na **kuiwasha**, pamoja na **kupata**/**kubadilisha** values za registers zake. Remote function calls huanzishwa kwa kuweka registers `x0` hadi `x7` kuwa **arguments**, kusanidi `pc` kuelekeza kwenye function inayolengwa, kisha kuendelea na thread. Kuhakikisha kwamba thread hai-crash baada ya return kunahitaji kutambua return hiyo.<sup>[[1]](#references)</sup>

Mbinu moja ni kusajili **exception handler** kwa ajili ya remote thread kwa kutumia `thread_set_exception_ports()`, na kuweka register ya `lr` kwenye invalid address kabla ya function call. Hii husababisha exception baada ya function kumaliza execution, na kutuma message kwenye exception port, hivyo kuruhusu kukagua state ya thread ili kurejesha return value. Vinginevyo, kama ilivyotumika katika exploit ya *triple_fetch* ya Ian Beer, `lr` huwekwa ili kufanya loop bila mwisho; registers za thread hufuatiliwa mfululizo hadi `pc` ielekeze kwenye instruction hiyo.<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

Hatua inayofuata inahusisha kuanzisha Mach ports ili kuwezesha communication na remote thread. Ports hizi hutumika kuhamisha arbitrary send/receive rights kati ya tasks.<sup>[[1]](#references)</sup>

Kwa communication ya pande mbili, Mach receive rights mbili huundwa: moja kwenye local task na nyingine kwenye remote task. Kisha, send right ya kila port huhamishiwa kwenye task inayolingana, na kuwezesha message exchange.<sup>[[1]](#references)</sup>

Tukizingatia local port, receive right inamilikiwa na local task. Port huundwa kwa kutumia `mach_port_allocate()`. Changamoto ni kuhamisha send right ya port hii kwenda kwenye remote task.<sup>[[1]](#references)</sup>

Mbinu moja ni kutumia `thread_set_special_port()` kuweka send right ya local port kwenye `THREAD_KERNEL_PORT` ya remote thread. Kisha remote thread huagizwa kuita `mach_thread_self()` ili kupata send right hiyo.<sup>[[1]](#references)</sup>

Kwa remote port, mchakato huwa kinyume chake. Remote thread huagizwa kuunda Mach port kupitia `mach_reply_port()` (kwa sababu `mach_port_allocate()` haifai kutokana na return mechanism yake). Baada ya port kuundwa, `mach_port_insert_right()` huitwa kwenye remote thread ili kuanzisha send right. Right hii huhifadhiwa kwenye kernel kwa kutumia `thread_set_special_port()`. Kwenye local task, `thread_get_special_port()` hutumiwa kwenye remote thread ili kupata send right ya Mach port mpya iliyotengezwa kwenye remote task.<sup>[[1]](#references)</sup>

Kukamilika kwa hatua hizi huanzisha Mach ports, na kuweka msingi wa communication ya pande mbili.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

Katika sehemu hii, lengo ni kutumia execute primitive kuanzisha basic memory read/write primitives. Hatua hizi za mwanzo ni muhimu kwa kupata udhibiti zaidi wa remote process, ingawa primitives katika hatua hii hazitakuwa na matumizi mengi. Hivi karibuni, zitaboreshwa kuwa versions za advanced zaidi.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

Lengo ni kufanya memory reading na writing kwa kutumia functions maalum. Kwa **kusoma memory**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Kwa **kuandika kwenye memory**:
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

Scan ya libraries za kawaida ilibaini candidates wanaofaa kwa operations hizi:<sup>[[1]](#references)</sup>

1. **Kusoma memory — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Kuandika kwenye kumbukumbu — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Ili kutekeleza uandishi wa 64-bit kwenye anwani ya kiholela:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Kwa kuwa primitives hizi zimewekwa tayari, hatua sasa iko tayari kwa kuunda shared memory, jambo linalowakilisha maendeleo makubwa katika kudhibiti remote process.<sup>[[1]](#references)</sup>

## 4. Usanidi wa Shared Memory

Lengo ni kuanzisha shared memory kati ya local na remote tasks, kurahisisha uhamishaji wa data na kuwezesha kuitisha functions zenye arguments nyingi. Mbinu hii hutumia `libxpc` na aina ya object ya `OS_xpc_shmem`, ambayo imejengwa juu ya Mach memory entries.<sup>[[1]](#references)</sup>

### Muhtasari wa mchakato

1. **Ugawaji wa memory**
* Tenga memory ya kushirikisha kwa kutumia `mach_vm_allocate()`.
* Tumia `xpc_shmem_create()` kuunda object ya `OS_xpc_shmem` kwa eneo lililotengwa.
2. **Kuunda shared memory katika remote process**
* Tenga memory kwa ajili ya object ya `OS_xpc_shmem` katika remote process (`remote_malloc`).
* Nakili template object ya local; bado unahitaji kufanya fix-up ya Mach send right iliyopachikwa kwenye offset `0x18`.
3. **Kusahihisha Mach memory entry**
* Ingiza send right kwa kutumia `thread_set_special_port()` na overwrite field ya `0x18` kwa jina la entry ya remote.
4. **Kukamilisha**
* Validate remote object na ui-map kwa remote call ya `xpc_shmem_remote()`.

## 5. Kupata Udhibiti Kamili

Mara tu arbitrary execution na shared-memory back-channel zinapopatikana, kwa ufanisi unamiliki target process:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — tumia `memcpy()` kati ya local na shared regions.
* **Function calls zenye > 8 args** — weka arguments za ziada kwenye stack kwa kufuata arm64 calling convention.
* **Mach port transfer** — pitisha rights katika Mach messages kupitia ports zilizowekwa.
* **File-descriptor transfer** — tumia fileports (tazama *triple_fetch*).

Yote haya yamefungwa katika library ya [`threadexec`](https://github.com/bazad/threadexec) kwa matumizi rahisi tena.

---

## 6. Nuances za Apple Silicon (arm64e)

Kwenye vifaa vya Apple Silicon (arm64e), **Pointer Authentication Codes (PAC)** hulinda return addresses zote na function pointers nyingi. Mbinu za Thread-hijacking zinazotumia tena code iliyopo zinaendelea kufanya kazi kwa sababu values za awali katika `lr`/`pc` tayari zina PAC signatures halali. Matatizo hutokea unapojaribu kuruka hadi kwenye memory inayodhibitiwa na attacker:

1. Tenga executable memory ndani ya target (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Nakili payload yako.
3. Ndani ya *remote* process, sign pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Weka `pc = ptr` katika hali ya thread iliyotekwa nyara.

Vinginevyo, endelea kuzingatia PAC kwa kuunganisha gadgets/functions zilizopo (traditional ROP).

## 7. Detection & Hardening with EndpointSecurity

Framework ya **EndpointSecurity (ES)** hufichua kernel events zinazoruhusu defenders kuchunguza au kuzuia majaribio ya thread-injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – hutokea mchakato unapoomba port ya task ya mchakato mwingine (kwa mfano, `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – hutolewa kila thread inapoundwa katika task *tofauti*.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (iliongezwa katika macOS 14 Sonoma) – huashiria manipulation ya registers za thread iliyopo.

Swift client ndogo inayochapisha remote-thread events:
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

Kusambaza application yako **bila** entitlement ya `com.apple.security.get-task-allow` huwazuia attackers wasio na root kupata task-port yake. System Integrity Protection (SIP) bado huzuia ufikiaji wa Apple binaries nyingi, lakini third-party software lazima ijiondoe kwenye ulinzi huo waziwazi.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Compact PoC inayoonyesha PAC-aware thread hijacking kwenye Ventura/Sonoma<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | EndpointSecurity helper inayotumiwa na vendors kadhaa wa EDR kuonyesha matukio ya `REMOTE_THREAD_CREATE` |

> Kusoma source code ya projects hizi ni muhimu kwa kuelewa mabadiliko ya API yaliyoletwa kwenye macOS 13/14 na kudumisha compatibility kati ya Intel ↔ Apple Silicon.

## Marejeleo

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
