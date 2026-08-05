# macOS Thread Injection kupitia Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Mwanzoni, function ya `task_threads()` inaitwa kwenye task port ili kupata orodha ya threads kutoka kwenye task ya mbali. Thread moja huchaguliwa kwa ajili ya hijacking. Mbinu hii inatofautiana na conventional code-injection methods kwa sababu kuunda remote thread mpya hairuhusiwi kutokana na mitigation inayozuia `thread_create_running()`.<sup>[1]</sup>

Ili kuidhibiti thread, `thread_suspend()` huitwa, na hivyo kusimamisha execution yake.<sup>[1]</sup>

Operations pekee zinazoruhusiwa kwenye remote thread ni **kuisimamisha** na **kuianzisha**, pamoja na **kupata**/**kubadilisha** values za registers zake. Remote function calls huanzishwa kwa kuweka registers `x0` hadi `x7` kuwa **arguments**, kusanidi `pc` ilenge function inayotakiwa, kisha kuendelea na thread. Kuhakikisha kwamba thread hai-crash baada ya return kunahitaji kugundua return hiyo.<sup>[1]</sup>

Mbinu moja inahusisha kusajili **exception handler** kwa ajili ya remote thread kwa kutumia `thread_set_exception_ports()`, na kuweka register ya `lr` kwenye address isiyo halali kabla ya function call. Hii husababisha exception baada ya function kutekelezwa, na kutuma message kwenye exception port, hivyo kuwezesha kukagua state ya thread ili kupata return value. Vinginevyo, kama ilivyotumiwa kutoka kwenye exploit ya Ian Beer *triple_fetch*, `lr` huwekwa ili ku-loop bila kikomo; registers za thread hufuatiliwa kila mara hadi `pc` ielekeze kwenye instruction hiyo.<sup>[1]</sup>

## 2. Mach ports for communication

Hatua inayofuata inahusisha kuanzisha Mach ports ili kuwezesha mawasiliano na remote thread. Ports hizi hutumika kuhamisha arbitrary send/receive rights kati ya tasks.<sup>[1]</sup>

Kwa mawasiliano ya pande mbili, Mach receive rights mbili huundwa: moja kwenye local task na nyingine kwenye remote task. Kisha, send right ya kila port huhamishiwa kwenye task inayolingana, na hivyo kuwezesha kubadilishana messages.<sup>[1]</sup>

Tukizingatia local port, receive right inashikiliwa na local task. Port huundwa kwa kutumia `mach_port_allocate()`. Changamoto ni kuhamisha send right ya port hii kwenda kwenye remote task.<sup>[1]</sup>

Mbinu moja inahusisha kutumia `thread_set_special_port()` kuweka send right ya local port kwenye `THREAD_KERNEL_PORT` ya remote thread. Kisha remote thread huagizwa kuita `mach_thread_self()` ili kupata send right hiyo.<sup>[1]</sup>

Kwa remote port, mchakato hubadilishwa kwa kiasi kikubwa. Remote thread huagizwa kuunda Mach port kupitia `mach_reply_port()` (kwa sababu `mach_port_allocate()` haifai kutokana na namna inavyorudisha value yake). Baada ya port kuundwa, `mach_port_insert_right()` huitwa kwenye remote thread ili kuanzisha send right. Right hii huhifadhiwa kwenye kernel kwa kutumia `thread_set_special_port()`. Kwenye local task, `thread_get_special_port()` hutumiwa kwenye remote thread ili kupata send right ya Mach port mpya iliyotengezwa kwenye remote task.<sup>[1]</sup>

Kukamilika kwa hatua hizi husababisha Mach ports kuanzishwa, na kuweka msingi wa mawasiliano ya pande mbili.<sup>[1]</sup>

## 3. Basic Memory Read/Write Primitives

Katika sehemu hii, lengo ni kutumia execute primitive kuanzisha basic memory read/write primitives. Hatua hizi za awali ni muhimu kwa kupata udhibiti zaidi wa remote process, ingawa primitives katika hatua hii hazitatumika kwa mambo mengi. Hivi karibuni, zitaboreshwa kuwa versions za juu zaidi.<sup>[1]</sup>

### Memory reading and writing using the execute primitive

Lengo ni kusoma na kuandika memory kwa kutumia functions maalum. Kwa ajili ya **kusoma memory**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Kwa **kuandika memory**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Functions hizi zinalingana na assembly ifuatayo:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Kutambua functions zinazofaa

Uchunguzi wa libraries za kawaida ulifichua candidates wanaofaa kwa operations hizi:<sup>[1]</sup>

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
Ili kutekeleza uandishi wa 64-bit kwenye anwani ya kiholela:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Kwa kuwa primitives hizi zimewekwa tayari, hatua inayofuata ni kuunda shared memory, jambo linalowakilisha maendeleo makubwa katika kudhibiti mchakato wa mbali.<sup>[1]</sup>

## 4. Usanidi wa Shared Memory

Lengo ni kuanzisha shared memory kati ya tasks za local na remote, kurahisisha uhamishaji wa data na kuwezesha kuitwa kwa functions zenye arguments nyingi. Mbinu hii hutumia `libxpc` na aina ya object ya `OS_xpc_shmem`, ambayo imejengwa juu ya Mach memory entries.<sup>[1]</sup>

### Muhtasari wa mchakato

1. **Ugawaji wa memory**
* Gawa memory kwa ajili ya kushirikishwa kwa kutumia `mach_vm_allocate()`.
* Tumia `xpc_shmem_create()` kuunda object ya `OS_xpc_shmem` kwa eneo lililogawiwa.
2. **Kuunda shared memory katika mchakato wa remote**
* Gawa memory kwa ajili ya object ya `OS_xpc_shmem` katika mchakato wa remote (`remote_malloc`).
* Nakili template object ya local; bado inahitajika kufanya fix-up ya embedded Mach send right kwenye offset `0x18`.
3. **Kurekebisha Mach memory entry**
* Ingiza send right kwa `thread_set_special_port()` na overwrite field ya `0x18` kwa jina la entry ya remote.
4. **Kukamilisha**
* Validate object ya remote na u-map kwa remote call kwenda `xpc_shmem_remote()`.

## 5. Kupata Udhibiti Kamili

Baada ya arbitrary execution na shared-memory back-channel kupatikana, kwa ufanisi unamiliki target process:<sup>[1]</sup>

* **Arbitrary memory R/W** — tumia `memcpy()` kati ya maeneo ya local na shared.
* **Function calls zenye args zaidi ya 8** — weka arguments za ziada kwenye stack kwa kufuata arm64 calling convention.
* **Uhamishaji wa Mach port** — pitisha rights katika Mach messages kupitia ports zilizoanzishwa.
* **Uhamishaji wa file-descriptor** — tumia fileports (tazama *triple_fetch*).

Yote haya yamefungwa katika library ya [`threadexec`](https://github.com/bazad/threadexec) kwa ajili ya kutumiwa tena kwa urahisi.

---

## 6. Nuances za Apple Silicon (arm64e)

Kwenye vifaa vya Apple Silicon (arm64e), **Pointer Authentication Codes (PAC)** hulinda return addresses zote na function pointers nyingi. Mbinu za Thread-hijacking zinazotumia tena code iliyopo huendelea kufanya kazi kwa sababu values za awali katika `lr`/`pc` tayari zina PAC signatures halali. Matatizo hutokea unapojaribu kuruka kwenda kwenye memory inayodhibitiwa na attacker:

1. Gawa executable memory ndani ya target (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Nakili payload yako.
3. Ndani ya mchakato wa *remote*, sign pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Weka `pc = ptr` katika hali ya thread iliyotekwa.

Vinginevyo, endelea kuzingatia PAC kwa kuunganisha gadgets/functions zilizopo (ROP ya jadi).

## 7. Ugunduzi na Hardening kwa kutumia EndpointSecurity

Framework ya **EndpointSecurity (ES)** hufichua matukio ya kernel yanayowawezesha watetezi kuchunguza au kuzuia majaribio ya thread-injection:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – hutokea process inapoomba port ya task ya process nyingine (kwa mfano, `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – hutolewa kila thread inapoundwa katika task *tofauti*.<sup>[3]</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (imeongezwa katika macOS 14 Sonoma) – huashiria uchezewaji wa registers za thread iliyopo.

Swift client ndogo inayochapisha matukio ya remote-thread:
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
### Mazingatio ya hardened runtime

Kusambaza application yako **bila** entitlement ya `com.apple.security.get-task-allow` huwazuia washambuliaji wasio `root` kupata task-port yake. System Integrity Protection (SIP) bado huzuia ufikiaji wa Apple binaries nyingi, lakini third-party software lazima ijiondoe waziwazi.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Compact PoC inayoonyesha PAC-aware thread hijacking kwenye Ventura/Sonoma |
| `remote_thread_es` | 2024 | EndpointSecurity helper inayotumiwa na EDR vendors kadhaa kuonyesha matukio ya `REMOTE_THREAD_CREATE` |

> Kusoma source code ya projects hizi ni muhimu kwa kuelewa mabadiliko ya API yaliyoletwa kwenye macOS 13/14 na kudumisha compatibility kati ya Intel ↔ Apple Silicon.

## Marejeo

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
