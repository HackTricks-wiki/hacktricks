# macOS Task port üzerinden Thread Injection

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Başlangıçta, uzak task'ten bir thread listesi almak için task port üzerinde `task_threads()` işlevi çağrılır. Hijacking için bir thread seçilir. `thread_create_running()` işlevini engelleyen mitigation nedeniyle yeni bir remote thread oluşturulması yasak olduğundan, bu yaklaşım geleneksel code-injection yöntemlerinden farklıdır.<sup>[[1]](#references)</sup>

Thread'i kontrol etmek için `thread_suspend()` çağrılır ve thread'in yürütülmesi durdurulur.<sup>[[1]](#references)</sup>

Remote thread üzerinde izin verilen tek işlemler onu **durdurmak**, **başlatmak** ve register değerlerini **almak**/**değiştirmek**tir. Remote function call işlemleri, `x0` ile `x7` arasındaki register'lar **arguments** olarak ayarlanıp `pc` hedeflenen function'ı gösterecek şekilde yapılandırılarak ve thread devam ettirilerek başlatılır. Return sonrasında thread'in crash olmamasını sağlamak için return'ün tespit edilmesi gerekir.<sup>[[1]](#references)</sup>

Bir strateji, `thread_set_exception_ports()` kullanarak remote thread için bir **exception handler** kaydetmek ve function call öncesinde `lr` register'ını geçersiz bir adrese ayarlamaktır. Bu işlem, function yürütüldükten sonra bir exception tetikler ve exception port'una bir message gönderir; böylece thread'in state'i incelenerek return value kurtarılabilir. Alternatif olarak, Ian Beer'ın *triple_fetch* exploit'inden uyarlanan yöntemde `lr` sonsuza kadar loop yapacak şekilde ayarlanır; ardından `pc` bu instruction'ı gösterene kadar thread'in register'ları sürekli olarak izlenir.<sup>[[1]](#references)</sup>

## 2. İletişim için Mach ports

Sonraki aşama, remote thread ile iletişimi kolaylaştırmak için Mach ports oluşturmaktır. Bu port'lar, task'ler arasında arbitrary send/receive rights aktarılması için kullanılır.<sup>[[1]](#references)</sup>

Bidirectional communication için iki Mach receive right oluşturulur: biri local, diğeri remote task'te. Ardından her port için bir send right karşılık gelen task'e aktarılır ve message exchange mümkün hale gelir.<sup>[[1]](#references)</sup>

Local port'a odaklanıldığında, receive right local task tarafından tutulur. Port, `mach_port_allocate()` ile oluşturulur. Zorluk, bu port için bir send right'ın remote task'e aktarılmasında yatar.<sup>[[1]](#references)</sup>

Bir strateji, local port'a ait bir send right'ı remote thread'in `THREAD_KERNEL_PORT` alanına yerleştirmek için `thread_set_special_port()` işlevinden yararlanmaktır. Daha sonra remote thread'e send right'ı almak için `mach_thread_self()` çağrısı yaptırılır.<sup>[[1]](#references)</sup>

Remote port için süreç esasen tersine çevrilir. Remote thread'e `mach_reply_port()` aracılığıyla bir Mach port oluşturması talimatı verilir (`mach_port_allocate()` return mekanizması nedeniyle uygun değildir). Port oluşturulduktan sonra remote thread içinde bir send right oluşturmak için `mach_port_insert_right()` çağrılır. Bu right, `thread_set_special_port()` kullanılarak kernel içinde saklanır. Local task'e dönüldüğünde, remote task'te yeni allocate edilmiş Mach port'a ait bir send right elde etmek için remote thread üzerinde `thread_get_special_port()` kullanılır.<sup>[[1]](#references)</sup>

Bu adımların tamamlanması, Mach ports'un oluşturulmasını ve bidirectional communication için gerekli temelin hazırlanmasını sağlar.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

Bu bölümde odak noktası, basic memory read/write primitives oluşturmak için execute primitive'i kullanmaktır. Bu ilk adımlar remote process üzerinde daha fazla control elde etmek açısından kritik öneme sahiptir; ancak bu aşamadaki primitives çok fazla amaca hizmet etmeyecektir. Kısa süre içinde daha gelişmiş versiyonlara yükseltileceklerdir.<sup>[[1]](#references)</sup>

### Execute primitive kullanarak memory okuma ve yazma

Amaç, belirli function'ları kullanarak memory okuma ve yazma işlemlerini gerçekleştirmektir. **Memory okumak** için:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
**Belleğe yazmak için**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Bu işlevler aşağıdaki assembly koduna karşılık gelir:
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
2. **Belleğe yazma — `_xpc_int64_set_value()`** (libxpc):
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Keyfi bir adrese 64-bit write gerçekleştirmek için:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Bu primitive'ler oluşturulduğunda, shared memory oluşturmanın ve remote process üzerinde kontrol sağlamada önemli bir ilerlemenin önü açılır.<sup>[[1]](#references)</sup>

## 4. Shared Memory Setup

Amaç, local ve remote task'ler arasında shared memory oluşturarak data transferini basitleştirmek ve birden fazla argümanla function çağrılmasını kolaylaştırmaktır. Bu yaklaşım, Mach memory entry'leri üzerine kurulu `OS_xpc_shmem` object type'ını ve `libxpc`'yi kullanır.<sup>[[1]](#references)</sup>

### Process overview

1. **Memory allocation**
* Paylaşım için `mach_vm_allocate()` kullanarak memory allocate edin.
* Allocate edilen bölge için bir `OS_xpc_shmem` object oluşturmak üzere `xpc_shmem_create()` kullanın.
2. **Creating shared memory in the remote process**
* Remote process içinde `OS_xpc_shmem` object için memory allocate edin (`remote_malloc`).
* Local template object'i kopyalayın; `0x18` offset'indeki embedded Mach send right için fix-up işlemi hâlâ gereklidir.
3. **Correcting the Mach memory entry**
* `thread_set_special_port()` ile bir send right ekleyin ve `0x18` field'ını remote entry'nin name'iyle overwrite edin.
4. **Finalising**
* Remote object'i validate edin ve `xpc_shmem_remote()` çağrısıyla map edin.

## 5. Achieving Full Control

Arbitrary execution ve shared-memory back-channel kullanılabilir olduğunda hedef process üzerinde fiilen tam kontrole sahip olursunuz:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — local ve shared region'lar arasında `memcpy()` kullanın.
* **Function calls with > 8 args** — arm64 calling convention'ı izleyerek ek argümanları stack üzerine yerleştirin.
* **Mach port transfer** — oluşturulan port'lar üzerinden Mach message'larında rights aktarın.
* **File-descriptor transfer** — fileport'lardan yararlanın (bkz. *triple_fetch*).

Bunların tümü, kolayca yeniden kullanılabilmesi için [`threadexec`](https://github.com/bazad/threadexec) library'si içinde kapsüllenmiştir.

---

## 6. Apple Silicon (arm64e) Nuances

Apple Silicon cihazlarda (arm64e) **Pointer Authentication Codes (PAC)** tüm return address'leri ve birçok function pointer'ı korur. Mevcut code'u *reuse* eden thread-hijacking teknikleri çalışmaya devam eder; çünkü `lr`/`pc` içindeki orijinal değerler zaten geçerli PAC signature'larını taşır. Attacker-controlled memory'ye jump etmeye çalıştığınızda sorunlar ortaya çıkar:

1. Hedef içinde executable memory allocate edin (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Payload'unuzu kopyalayın.
3. *Remote* process içinde pointer'ı sign edin:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Ele geçirilmiş thread state içinde `pc = ptr` ayarlayın.

Alternatif olarak, mevcut gadget/function'ları zincirleyerek (geleneksel ROP) PAC uyumluluğunu koruyun.

## 7. EndpointSecurity ile Detection & Hardening

**EndpointSecurity (ES)** framework'ü, savunma yapanların thread-injection girişimlerini gözlemlemesine veya engellemesine olanak tanıyan kernel event'lerini kullanıma sunar:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – bir process başka bir task'ın portunu istediğinde tetiklenir (ör. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – farklı bir task içinde thread oluşturulduğunda yayınlanır.<sup>[[3]](#references)</sup>
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (macOS 14 Sonoma'da eklendi) – mevcut bir thread'in register'larının manipüle edildiğini belirtir.

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

Uygulamanızı `com.apple.security.get-task-allow` entitlement'ı **olmadan** dağıtmak, root olmayan saldırganların uygulamanın task-port'unu elde etmesini engeller. System Integrity Protection (SIP) hâlâ birçok Apple binary'sine erişimi engeller, ancak üçüncü taraf yazılımların açıkça opt-out yapması gerekir.

## 8. Güncel Public Tooling (2023-2025)

| Tool | Yıl | Açıklamalar |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma üzerinde PAC-aware thread hijacking gösteren kompakt bir PoC |
| `remote_thread_es` | 2024 | Çeşitli EDR vendor'ları tarafından `REMOTE_THREAD_CREATE` event'lerini görünür hâle getirmek için kullanılan EndpointSecurity helper'ı |

> macOS 13/14 ile sunulan API değişikliklerini anlamak ve Intel ↔ Apple Silicon arasındaki uyumluluğu korumak için bu projelerin source code'unu incelemek faydalıdır.

## Referanslar

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
