# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Kwanza, kazi ya `task_threads()` inaitwa kwenye task port ili kupata orodha ya thread kutoka kwa kazi ya mbali. Thread moja inachaguliwa kwa ajili ya hijacking. Njia hii inatofautiana na mbinu za kawaida za code-injection kwani kuunda thread mpya ya mbali kunakatazwa kutokana na ulinzi unaozuia `thread_create_running()`.

Ili kudhibiti thread, `thread_suspend()` inaitwa, ikisimamisha utekelezaji wake.

Operesheni pekee zinazoruhusiwa kwenye thread ya mbali zinahusisha **kusimamisha** na **kuanzisha** na **kupata**/**kubadilisha** thamani za register zake. Kuitwa kwa kazi za mbali kunaanzishwa kwa kuweka register `x0` hadi `x7` kwa **hoja**, kuunda `pc` ili kuelekeza kwenye kazi inayotakiwa, na kuendelea na thread. Kuwa na uhakika kwamba thread haiporomoki baada ya kurudi kunahitaji kugundua kurudi.

Stratejia moja inahusisha kujiandikisha kwa **mshughulikiaji wa makosa** kwa thread ya mbali kwa kutumia `thread_set_exception_ports()`, kuweka register `lr` kwenye anwani isiyo sahihi kabla ya wito wa kazi. Hii inasababisha makosa baada ya utekelezaji wa kazi, ikituma ujumbe kwenye bandari ya makosa, ikiruhusu ukaguzi wa hali ya thread ili kupata thamani ya kurudi. Vinginevyo, kama ilivyopitishwa kutoka kwa *triple_fetch* exploit ya Ian Beer, `lr` inawekwa ili kuzunguka bila kikomo; register za thread kisha zinafuatiliwa mara kwa mara hadi `pc` inapoelekeza kwenye amri hiyo.

## 2. Mach ports for communication

Awamu inayofuata inahusisha kuanzisha Mach ports ili kuwezesha mawasiliano na thread ya mbali. Bandari hizi ni muhimu katika kuhamasisha haki za kutuma/pokea zisizo na mipaka kati ya kazi.

Kwa mawasiliano ya pande mbili, haki mbili za kupokea Mach zinaundwa: moja katika kazi ya ndani na nyingine katika kazi ya mbali. Kisha, haki ya kutuma kwa kila bandari inahamishwa kwa kazi ya upande mwingine, ikiruhusu kubadilishana ujumbe.

Kuzingatia bandari ya ndani, haki ya kupokea inashikiliwa na kazi ya ndani. Bandari inaundwa kwa `mach_port_allocate()`. Changamoto iko katika kuhamasisha haki ya kutuma kwa bandari hii kwenye kazi ya mbali.

Stratejia moja inahusisha kutumia `thread_set_special_port()` kuweka haki ya kutuma kwa bandari ya ndani kwenye `THREAD_KERNEL_PORT` ya thread ya mbali. Kisha, thread ya mbali inaagizwa kuita `mach_thread_self()` ili kupata haki ya kutuma.

Kwa bandari ya mbali, mchakato kimsingi unarudiwa. Thread ya mbali inaelekezwa kuzalisha bandari ya Mach kupitia `mach_reply_port()` (kama `mach_port_allocate()` haiwezi kutumika kutokana na mekanismu yake ya kurudi). Baada ya kuundwa kwa bandari, `mach_port_insert_right()` inaitwa kwenye thread ya mbali ili kuanzisha haki ya kutuma. Haki hii kisha inahifadhiwa kwenye kernel kwa kutumia `thread_set_special_port()`. Kurudi kwenye kazi ya ndani, `thread_get_special_port()` inatumika kwenye thread ya mbali ili kupata haki ya kutuma kwa bandari mpya ya Mach iliyotolewa kwenye kazi ya mbali.

Kukamilika kwa hatua hizi kunasababisha kuanzishwa kwa Mach ports, kuweka msingi wa mawasiliano ya pande mbili.

## 3. Basic Memory Read/Write Primitives

Katika sehemu hii, lengo ni kutumia primitive ya execute kuanzisha primitive za msingi za kusoma/kandika kumbukumbu. Hatua hizi za awali ni muhimu kwa kupata udhibiti zaidi juu ya mchakato wa mbali, ingawa primitive katika hatua hii hazitakuwa na matumizi mengi. Hivi karibuni, zitaimarishwa kuwa toleo za juu zaidi.

### Memory reading and writing using the execute primitive

Lengo ni kufanya kusoma na kuandika kumbukumbu kwa kutumia kazi maalum. Kwa **kusoma kumbukumbu**:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Kwa **kuandika kumbukumbu**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Hizi kazi zinahusiana na mkusanyiko ufuatao:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Kutambua kazi zinazofaa

Kuchunguza maktaba za kawaida kumefichua wagombea wanaofaa kwa shughuli hizi:

1. **Kusoma kumbukumbu — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Kuandika kumbukumbu — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Ili kufanya andiko la 64-bit katika anwani isiyo ya kawaida:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Kwa kutumia hizi primitives zilizowekwa, hatua imewekwa kwa ajili ya kuunda kumbukumbu ya pamoja, ikionyesha maendeleo makubwa katika kudhibiti mchakato wa mbali.

## 4. Kuanzisha Kumbukumbu ya Pamoja

Lengo ni kuanzisha kumbukumbu ya pamoja kati ya kazi za ndani na za mbali, kuifanya iwe rahisi kuhamasisha data na kuwezesha wito wa kazi zenye hoja nyingi. Mbinu hii inatumia `libxpc` na aina ya kitu chake `OS_xpc_shmem`, ambayo imejengwa juu ya entries za kumbukumbu za Mach.

### Muonekano wa Mchakato

1. **Kugawa Kumbukumbu**
* Gawa kumbukumbu kwa ajili ya kushiriki kwa kutumia `mach_vm_allocate()`.
* Tumia `xpc_shmem_create()` kuunda kitu cha `OS_xpc_shmem` kwa ajili ya eneo lililogawiwa.
2. **Kuunda kumbukumbu ya pamoja katika mchakato wa mbali**
* Gawa kumbukumbu kwa ajili ya kitu cha `OS_xpc_shmem` katika mchakato wa mbali (`remote_malloc`).
* Nakili kitu cha template cha ndani; kurekebisha haki ya kutuma ya Mach iliyojumuishwa kwenye offset `0x18` bado inahitajika.
3. **Kurekebisha entry ya kumbukumbu ya Mach**
* Ingiza haki ya kutuma kwa kutumia `thread_set_special_port()` na uandike upya uwanja wa `0x18` kwa jina la entry ya mbali.
4. **Kumaliza**
* Thibitisha kitu cha mbali na uweke ramani yake kwa wito wa mbali kwa `xpc_shmem_remote()`.

## 5. Kufikia Udhibiti Kamili

Mara tu utekelezaji wa kiholela na njia ya nyuma ya kumbukumbu ya pamoja inapatikana, unamiliki mchakato wa lengo:

* **Kumbukumbu ya kiholela R/W** — tumia `memcpy()` kati ya maeneo ya ndani na ya pamoja.
* **Wito wa kazi zenye > 8 hoja** — weka hoja za ziada kwenye stack kufuata kanuni ya wito ya arm64.
* **Uhamisho wa bandari ya Mach** — pitisha haki katika ujumbe wa Mach kupitia bandari zilizowekwa.
* **Uhamisho wa file-descriptor** — tumia fileports (angalia *triple_fetch*).

Yote haya yamefungwa katika maktaba ya [`threadexec`](https://github.com/bazad/threadexec) kwa ajili ya urahisi wa matumizi tena.

---

## 6. Mambo Maalum ya Apple Silicon (arm64e)

Katika vifaa vya Apple Silicon (arm64e) **Mikodi ya Uthibitishaji wa Pointer (PAC)** inalinda anwani zote za kurudi na viashiria vingi vya kazi. Mbinu za kuiba thread ambazo *zinatumia msimbo uliopo* zinaendelea kufanya kazi kwa sababu thamani za awali katika `lr`/`pc` tayari zina saini halali za PAC. Matatizo yanatokea unapojaribu kuruka kwenye kumbukumbu inayodhibitiwa na mshambuliaji:

1. Gawa kumbukumbu inayoweza kutekelezwa ndani ya lengo (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Nakili payload yako.
3. Ndani ya mchakato *wa mbali* saini pointer:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Weka `pc = ptr` katika hali ya nyuzi iliyotekwa.

Vinginevyo, baki kuwa PAC-mwafaka kwa kuunganisha vifaa/funzo zilizopo (ROP ya jadi).

## 7. Ugunduzi & Uimarishaji na EndpointSecurity

Muundo wa **EndpointSecurity (ES)** unatoa matukio ya kernel ambayo yanawawezesha walinzi kuona au kuzuia majaribio ya kuingiza nyuzi:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – inawaka wakati mchakato unapoomba bandari ya kazi nyingine (kwa mfano `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – inatolewa kila wakati nyuzi inapotengenezwa katika kazi *tofauti*.
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (iliyoongezwa katika macOS 14 Sonoma) – inaonyesha ushawishi wa register wa nyuzi iliyopo.

Mteja mdogo wa Swift unaochapisha matukio ya nyuzi za mbali:
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
Kuchunguza na **osquery** ≥ 5.8:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Maoni ya Hardened-runtime

Kusambaza programu yako **bila** ruhusa ya `com.apple.security.get-task-allow` kunazuia washambuliaji wasiokuwa na mizizi kupata task-port yake. Ulinzi wa Uadilifu wa Mfumo (SIP) bado unazuia ufikiaji wa binaries nyingi za Apple, lakini programu za wahusika wengine lazima ziondoe wazi.

## 8. Zana za Hivi Karibuni za Umma (2023-2025)

| Zana | Mwaka | Maelezo |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | PoC fupi inayonyesha hijacking ya thread inayojua PAC kwenye Ventura/Sonoma |
| `remote_thread_es` | 2024 | Msaada wa EndpointSecurity unaotumiwa na wauzaji kadhaa wa EDR kuonyesha matukio ya `REMOTE_THREAD_CREATE` |

> Kusoma msimbo wa chanzo wa miradi hii ni muhimu kuelewa mabadiliko ya API yaliyowekwa katika macOS 13/14 na kubaki sambamba kati ya Intel ↔ Apple Silicon.

## Marejeleo

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
