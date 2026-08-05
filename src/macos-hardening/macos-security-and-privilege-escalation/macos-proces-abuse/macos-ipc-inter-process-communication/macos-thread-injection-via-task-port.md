# Task port üzerinden macOS Thread Injection

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

İlk olarak, remote task'tan bir thread listesi almak için task port üzerinde `task_threads()` fonksiyonu çağrılır. Hijacking için bir thread seçilir. `thread_create_running()` fonksiyonunu engelleyen mitigation nedeniyle yeni bir remote thread oluşturulması yasak olduğundan, bu yaklaşım geleneksel code-injection yöntemlerinden farklıdır.<sup>[1]</sup>

Thread'i kontrol etmek için `thread_suspend()` çağrılarak çalışması durdurulur.<sup>[1]</sup>

Remote thread üzerinde izin verilen tek işlemler onu **durdurmak** ve **başlatmak** ile register değerlerini **almak**/**değiştirmek**tir. Remote function call işlemleri, `x0` ile `x7` arasındaki register'lar **arguments** olacak şekilde ayarlanıp `pc` hedeflenen fonksiyonu gösterecek biçimde yapılandırılarak ve thread yeniden başlatılarak gerçekleştirilir. Return sonrasında thread'in crash olmamasını sağlamak için return'ün tespit edilmesi gerekir.<sup>[1]</sup>

Bir yöntem, `thread_set_exception_ports()` kullanarak remote thread için bir **exception handler** kaydetmek ve function call öncesinde `lr` register'ını geçersiz bir adrese ayarlamaktır. Bu, function execution sonrasında bir exception tetikleyerek exception port'a bir message gönderir ve return value'yu kurtarmak için thread state'inin incelenmesini sağlar. Alternatif olarak, Ian Beer'ın *triple_fetch* exploit'inden uyarlanan yöntemde `lr` sonsuz döngüye ayarlanır; ardından `pc` bu instruction'ı gösterene kadar thread'in register'ları sürekli izlenir.<sup>[1]</sup>

## 2. İletişim için Mach ports

Sonraki aşama, remote thread ile iletişimi kolaylaştırmak için Mach ports oluşturmaktır. Bu port'lar, task'lar arasında arbitrary send/receive rights aktarımında kullanılır.<sup>[1]</sup>

Bidirectional communication için iki Mach receive right oluşturulur: biri local, diğeri remote task'ta. Ardından her port için bir send right karşılık gelen task'a aktarılır ve message exchange mümkün hale gelir.<sup>[1]</sup>

Local port'a odaklanıldığında receive right local task tarafından tutulur. Port, `mach_port_allocate()` ile oluşturulur. Zorluk, bu port'a ait bir send right'ın remote task'a aktarılmasında yatar.<sup>[1]</sup>

Bir yöntem, local port'a ait send right'ı remote thread'in `THREAD_KERNEL_PORT` alanına yerleştirmek için `thread_set_special_port()` kullanmaktır. Ardından remote thread'e send right'ı almak için `mach_thread_self()` çağırması talimatı verilir.<sup>[1]</sup>

Remote port için süreç esasen tersine çevrilir. Remote thread'e `mach_reply_port()` aracılığıyla bir Mach port oluşturması talimatı verilir (`mach_port_allocate()` return mechanism nedeniyle uygun değildir). Port oluşturulduktan sonra, bir send right oluşturmak için remote thread içinde `mach_port_insert_right()` çağrılır. Bu right daha sonra `thread_set_special_port()` kullanılarak kernel'da saklanır. Local task'a dönüldüğünde, remote task'ta yeni allocate edilmiş Mach port'a ait bir send right edinmek için remote thread üzerinde `thread_get_special_port()` kullanılır.<sup>[1]</sup>

Bu adımların tamamlanması, Mach ports'un oluşturulmasını sağlar ve bidirectional communication için temel oluşturur.<sup>[1]</sup>

## 3. Basic Memory Read/Write Primitives

Bu bölümde, basic memory read/write primitives oluşturmak için execute primitive'in kullanılmasına odaklanılır. Bu ilk adımlar remote process üzerinde daha fazla kontrol elde etmek açısından kritik olsa da, bu aşamadaki primitives fazla işlev sağlamayacaktır. Kısa süre içinde daha gelişmiş versiyonlara yükseltileceklerdir.<sup>[1]</sup>

### execute primitive kullanarak memory reading ve writing

Amaç, belirli fonksiyonları kullanarak memory reading ve writing gerçekleştirmektir. **Memory reading** için:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
**Bellek yazmak için:**
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
### Uygun fonksiyonları belirleme

Yaygın library'lerin taranması, bu işlemler için uygun adayları ortaya çıkardı:<sup>[1]</sup>

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
Keyfi bir adrese 64 bitlik bir yazma işlemi gerçekleştirmek için:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Bu primitive'ler oluşturulduğunda, shared memory oluşturmanın ve remote process üzerinde kontrol sağlamada önemli bir ilerleme kaydetmenin zemini hazırlanmış olur.<sup>[1]</sup>

## 4. Shared Memory Setup

Amaç, local ve remote task'ler arasında shared memory oluşturarak data transferini basitleştirmek ve birden fazla argümanla function çağrılmasını kolaylaştırmaktır. Yaklaşım, Mach memory entry'leri üzerine kurulmuş `OS_xpc_shmem` object type'ını ve `libxpc`'yi kullanır.<sup>[1]</sup>

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
* Remote object'i validate edin ve remote call ile `xpc_shmem_remote()` kullanarak map edin.

## 5. Achieving Full Control

Arbitrary execution ve shared-memory back-channel elde edildiğinde hedef process üzerinde fiilen tam kontrol sahibi olursunuz:<sup>[1]</sup>

* **Arbitrary memory R/W** — local ve shared bölgeler arasında `memcpy()` kullanın.
* **Function calls with > 8 args** — arm64 calling convention'ı izleyerek ek argümanları stack üzerine yerleştirin.
* **Mach port transfer** — oluşturulan port'lar üzerinden Mach message'larında right'ları aktarın.
* **File-descriptor transfer** — fileport'ları kullanın (*triple_fetch*'e bakın).

Bunların tümü, kolayca yeniden kullanılabilmesi için [`threadexec`](https://github.com/bazad/threadexec) library'si içinde wrapper'lanmıştır.

---

## 6. Apple Silicon (arm64e) Nuances

Apple Silicon cihazlarda (arm64e), **Pointer Authentication Codes (PAC)** tüm return address'leri ve birçok function pointer'ı korur. Mevcut code'u *reuse* eden thread-hijacking teknikleri çalışmaya devam eder; çünkü `lr`/`pc` içindeki original value'lar zaten geçerli PAC signature'larını taşır. Attacker-controlled memory'ye jump etmeye çalıştığınızda sorunlar ortaya çıkar:

1. Target içinde executable memory allocate edin (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Payload'ınızı kopyalayın.
3. *Remote* process içinde pointer'ı sign edin:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Ele geçirilen thread state içinde `pc = ptr` ayarlayın.

Alternatif olarak, mevcut gadget/function'ları zincirleyerek (geleneksel ROP) PAC uyumluluğunu koruyun.

## 7. EndpointSecurity ile Detection & Hardening

**EndpointSecurity (ES)** framework'ü, savunma ekiplerinin thread-injection girişimlerini gözlemlemesine veya engellemesine olanak tanıyan kernel event'lerini sunar:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – bir process başka bir task'ın portunu istediğinde tetiklenir (ör. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – farklı bir task içinde thread oluşturulduğunda gönderilir.<sup>[3]</sup>
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
### Hardened-runtime hususları

Uygulamanızı **`com.apple.security.get-task-allow` entitlement'ı olmadan** dağıtmak, non-root saldırganların uygulamanın task-port'unu elde etmesini engeller. System Integrity Protection (SIP) hâlâ birçok Apple binary'sine erişimi engeller, ancak üçüncü taraf yazılımların açıkça opt-out yapması gerekir.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma üzerinde PAC-aware thread hijacking'i gösteren kompakt bir PoC |
| `remote_thread_es` | 2024 | Birkaç EDR vendor'ının `REMOTE_THREAD_CREATE` event'lerini görünür hâle getirmek için kullandığı EndpointSecurity helper'ı |

> Bu projelerin source code'unu incelemek, macOS 13/14'te sunulan API değişikliklerini anlamak ve Intel ↔ Apple Silicon arasında uyumluluğu korumak için faydalıdır.

## References

- [1] [Bypassing platform binary restrictions with task_threads() - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Documentation](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
