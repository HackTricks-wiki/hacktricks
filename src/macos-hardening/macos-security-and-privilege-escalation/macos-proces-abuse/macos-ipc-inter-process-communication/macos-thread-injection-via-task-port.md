# Task port Üzerinden macOS Thread Injection

{{#include ../../../../banners/hacktricks-training.md}}

## Kod

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

İlk olarak, uzak task'tan bir thread listesi almak için task port üzerinde `task_threads()` function'ı çağrılır. Hijacking için bir thread seçilir. `thread_create_running()` çağrısını engelleyen mitigation nedeniyle yeni bir remote thread oluşturulması yasak olduğundan, bu yaklaşım conventional code-injection yöntemlerinden ayrılır.<sup>[[1]](#references)</sup>

Thread'i kontrol etmek için `thread_suspend()` çağrılır ve execution durdurulur.<sup>[[1]](#references)</sup>

Remote thread üzerinde izin verilen tek operations, thread'i **durdurmak** ve **başlatmak** ile register değerlerini **almak**/**değiştirmek**tir. Remote function call'lar, `x0` ile `x7` arasındaki register'lar **arguments** olarak ayarlanıp `pc` hedef function'ı gösterecek şekilde yapılandırılarak ve thread resume edilerek başlatılır. Return sonrasında thread'in crash olmamasını sağlamak için return'ün tespit edilmesi gerekir.<sup>[[1]](#references)</sup>

Bir strategy, `thread_set_exception_ports()` kullanarak remote thread için bir **exception handler** kaydetmek ve function call'dan önce `lr` register'ını geçersiz bir address'e ayarlamaktır. Bu, function execution sonrasında bir exception tetikler ve exception port'a bir message gönderir; böylece return value'yu kurtarmak için thread state incelenebilir. Alternatif olarak, Ian Beer'ın *triple_fetch* exploit'inden uyarlanan yöntemde `lr` sonsuz loop yapacak şekilde ayarlanır; ardından `pc` bu instruction'ı gösterene kadar thread'in register'ları sürekli olarak izlenir.<sup>[[1]](#references)</sup>

## 2. İletişim için Mach ports

Sonraki aşama, remote thread ile iletişimi kolaylaştırmak için Mach ports oluşturmaktır. Bu ports, tasks arasında arbitrary send/receive rights aktarımında kullanılır.<sup>[[1]](#references)</sup>

Bidirectional communication için iki Mach receive right oluşturulur: biri local, diğeri remote task'ta. Ardından her port için bir send right karşılık gelen task'a aktarılır ve message exchange mümkün hâle gelir.<sup>[[1]](#references)</sup>

Local port'a odaklanıldığında receive right local task tarafından tutulur. Port, `mach_port_allocate()` ile oluşturulur. Buradaki zorluk, bu port için bir send right'ın remote task'a aktarılmasıdır.<sup>[[1]](#references)</sup>

Bir strategy, local port için bir send right'ı remote thread'in `THREAD_KERNEL_PORT` alanına yerleştirmek üzere `thread_set_special_port()` kullanmaktır. Ardından remote thread'e send right'ı almak için `mach_thread_self()` çağırması söylenir.<sup>[[1]](#references)</sup>

Remote port için process temelde tersine çevrilir. Remote thread'e `mach_reply_port()` aracılığıyla bir Mach port oluşturması söylenir (`mach_port_allocate()` return mechanism nedeniyle uygun değildir). Port oluşturulduktan sonra bir send right oluşturmak için remote thread içinde `mach_port_insert_right()` çağrılır. Bu right, `thread_set_special_port()` kullanılarak kernel içinde saklanır. Local task'a dönüldüğünde, remote task'ta yeni oluşturulan Mach port için bir send right edinmek amacıyla remote thread üzerinde `thread_get_special_port()` kullanılır.<sup>[[1]](#references)</sup>

Bu adımların tamamlanması, Mach ports'un oluşturulmasını ve bidirectional communication için temel hazırlanmasını sağlar.<sup>[[1]](#references)</sup>

## 3. Temel Memory Read/Write Primitives

Bu bölümde odak noktası, temel memory read/write primitives oluşturmak için execute primitive'ı kullanmaktır. Bu initial steps, remote process üzerinde daha fazla control elde etmek için kritik öneme sahiptir; ancak bu aşamadaki primitives çok fazla amaca hizmet etmeyecektir. Kısa süre içinde daha gelişmiş version'lara upgrade edileceklerdir.<sup>[[1]](#references)</sup>

### Execute primitive kullanarak memory reading ve writing

Amaç, belirli functions kullanarak memory reading ve writing gerçekleştirmektir. **Memory reading** için:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
**Belleğe yazmak için:**
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Bu işlevler aşağıdaki assembly'ye karşılık gelir:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Uygun işlevlerin belirlenmesi

Yaygın library'lerin taranması, bu işlemler için uygun adayları ortaya çıkardı:<sup>[[1]](#references)</sup>

1. **Bellek okuma — `property_getName()`** (libobjc):
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
2. **Bellek yazma — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Keyfi bir adrese 64-bit write gerçekleştirmek için:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Bu primitive'ler oluşturulduğunda, shared memory oluşturma aşamasına geçilebilir; bu da remote process üzerinde kontrol sağlama açısından önemli bir ilerlemedir.<sup>[[1]](#references)</sup>

## 4. Shared Memory Setup

Amaç, local ve remote task'ler arasında shared memory oluşturarak data transferini basitleştirmek ve birden fazla argümanla function çağrılmasını kolaylaştırmaktır. Bu yaklaşım, Mach memory entries üzerine kurulmuş `OS_xpc_shmem` object type'ını ve `libxpc`'yi kullanır.<sup>[[1]](#references)</sup>

### Process overview

1. **Memory allocation**
* Sharing için `mach_vm_allocate()` kullanarak memory allocate edin.
* Allocate edilen bölge için bir `OS_xpc_shmem` object oluşturmak üzere `xpc_shmem_create()` kullanın.
2. **Creating shared memory in the remote process**
* Remote process içinde `OS_xpc_shmem` object için memory allocate edin (`remote_malloc`).
* Local template object'i kopyalayın; offset `0x18` konumundaki embedded Mach send right için fix-up işlemi hâlâ gereklidir.
3. **Correcting the Mach memory entry**
* `thread_set_special_port()` ile bir send right ekleyin ve `0x18` field'ını remote entry'nin name'iyle overwrite edin.
4. **Finalising**
* Remote object'i validate edin ve `xpc_shmem_remote()` çağrısıyla map edin.

## 5. Achieving Full Control

Arbitrary execution ve shared-memory back-channel kullanılabilir olduğunda target process üzerinde etkili olarak tam kontrol sahibi olursunuz:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — local ve shared region'lar arasında `memcpy()` kullanın.
* **Function calls with > 8 args** — arm64 calling convention'ı izleyerek ekstra argümanları stack üzerine yerleştirin.
* **Mach port transfer** — oluşturulan port'lar üzerinden Mach message'larda rights aktarın.
* **File-descriptor transfer** — fileports kullanın (bkz. *triple_fetch*).

Tüm bunlar, kolayca yeniden kullanılabilmesi için [`threadexec`](https://github.com/bazad/threadexec) library'si içinde bir araya getirilmiştir.

---

## 6. Apple Silicon (arm64e) Nuances

Apple Silicon cihazlarda (arm64e), **Pointer Authentication Codes (PAC)** tüm return address'leri ve birçok function pointer'ı korur. Mevcut code'u *reuse* eden thread-hijacking teknikleri çalışmaya devam eder; çünkü `lr`/`pc` içindeki orijinal değerler zaten geçerli PAC signature'larını taşır. Attacker-controlled memory'ye jump etmeye çalıştığınızda sorunlar ortaya çıkar:

1. Target içinde executable memory allocate edin (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Payload'unuzu kopyalayın.
3. *Remote* process içinde pointer'ı sign edin:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Hijacked thread state içinde `pc = ptr` ayarlayın.

Alternatif olarak, mevcut gadget/function'ları birbirine zincirleyerek PAC uyumlu kalın (geleneksel ROP).

## 7. EndpointSecurity ile Tespit ve Hardening

**EndpointSecurity (ES)** framework'ü, savunma ekiplerinin thread-injection girişimlerini gözlemlemesine veya engellemesine olanak tanıyan kernel event'lerini kullanıma sunar:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – bir process başka bir task'ın portunu istediğinde tetiklenir (ör. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – bir thread *farklı* bir task içinde oluşturulduğunda yayımlanır.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (macOS 14 Sonoma'da eklendi) – mevcut bir thread'in register'larının manipüle edildiğini gösterir.

Remote-thread event'lerini yazdıran minimal Swift client:
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
**osquery** ≥ 5.8 ile sorgulama:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime değerlendirmeleri

Uygulamanızı `com.apple.security.get-task-allow` entitlement'ı **olmadan** dağıtmak, root olmayan saldırganların uygulamanın task-port'unu elde etmesini engeller. System Integrity Protection (SIP) hâlâ birçok Apple binary'sine erişimi engeller, ancak third-party software açıkça opt-out yapmalıdır.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma üzerinde PAC-aware thread hijacking'i gösteren kompakt bir PoC<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | Çeşitli EDR sağlayıcıları tarafından `REMOTE_THREAD_CREATE` event'lerini ortaya çıkarmak için kullanılan EndpointSecurity helper'ı |

> Bu projelerin source code'unu okumak, macOS 13/14 ile sunulan API değişikliklerini anlamak ve Intel ↔ Apple Silicon arasında uyumluluğu korumak için faydalıdır.

## Referanslar

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
