# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Başlangıçta, uzak task'tan bir thread listesi almak için task port üzerinde `task_threads()` işlevi çağrılır. Ele geçirilecek bir thread seçilir. `thread_create_running()` işlevini engelleyen mitigation nedeniyle yeni bir remote thread oluşturulması yasak olduğundan, bu yaklaşım geleneksel code-injection yöntemlerinden farklıdır.<sup>[[1]](#references)</sup>

Thread'i kontrol etmek için `thread_suspend()` çağrılır ve thread'in çalışması durdurulur.<sup>[[1]](#references)</sup>

Remote thread üzerinde izin verilen tek işlemler onu **durdurmak** ve **başlatmak** ile register değerlerini **almak**/**değiştirmek**tir. Remote function çağrıları, `x0` ile `x7` arasındaki register'lar **arguments** olarak ayarlanarak, `pc` istenen function'ı hedefleyecek şekilde yapılandırılarak ve thread devam ettirilerek başlatılır. Return sonrasında thread'in crash olmamasını sağlamak için return'ün tespit edilmesi gerekir.<sup>[[1]](#references)</sup>

Bir strateji, `thread_set_exception_ports()` kullanarak remote thread için bir **exception handler** kaydetmek ve function çağrısından önce `lr` register'ını geçersiz bir adrese ayarlamaktır. Bu işlem, function yürütüldükten sonra bir exception tetikler ve exception port'una bir message gönderir; böylece thread'in state'i incelenerek return value elde edilebilir. Alternatif olarak, Ian Beer'ın *triple_fetch* exploit'inden uyarlanan yöntemde `lr` sonsuz döngü oluşturacak şekilde ayarlanır; ardından `pc` bu instruction'ı gösterene kadar thread'in register'ları sürekli izlenir.<sup>[[1]](#references)</sup>

## 2. Mach ports for communication

Sonraki aşama, remote thread ile iletişimi kolaylaştırmak için Mach port'ları oluşturmaktır. Bu port'lar, task'lar arasında rastgele send/receive rights aktarımı için kullanılır.<sup>[[1]](#references)</sup>

Çift yönlü iletişim için iki Mach receive right oluşturulur: biri local, diğeri remote task'ta. Ardından her port için bir send right karşılık gelen task'a aktarılır ve message alışverişi mümkün hale gelir.<sup>[[1]](#references)</sup>

Local port'a odaklanıldığında receive right local task tarafından tutulur. Port, `mach_port_allocate()` ile oluşturulur. Zorluk, bu port'a ait bir send right'ı remote task'a aktarmaktır.<sup>[[1]](#references)</sup>

Bir strateji, local port'a ait bir send right'ı remote thread'in `THREAD_KERNEL_PORT` alanına yerleştirmek için `thread_set_special_port()` işlevinden yararlanır. Ardından remote thread'e send right'ı almak için `mach_thread_self()` çağrısı yaptırılır.<sup>[[1]](#references)</sup>

Remote port için süreç esasen tersine çevrilir. Remote thread'e `mach_reply_port()` aracılığıyla bir Mach port oluşturması söylenir (`mach_port_allocate()` return mekanizması nedeniyle uygun değildir). Port oluşturulduktan sonra, bir send right oluşturmak için remote thread içinde `mach_port_insert_right()` çağrılır. Bu right, `thread_set_special_port()` kullanılarak kernel'da saklanır. Local task'a dönüldüğünde, remote task'ta yeni tahsis edilen Mach port'a ait bir send right elde etmek için remote thread üzerinde `thread_get_special_port()` kullanılır.<sup>[[1]](#references)</sup>

Bu adımların tamamlanmasıyla Mach port'lar oluşturulur ve çift yönlü iletişim için temel hazırlanır.<sup>[[1]](#references)</sup>

## 3. Basic Memory Read/Write Primitives

Bu bölümde odak noktası, temel memory read/write primitives oluşturmak için execute primitive'inden yararlanmaktır. Bu ilk adımlar remote process üzerinde daha fazla kontrol elde etmek açısından kritik öneme sahiptir; ancak bu aşamadaki primitives fazla işlev sağlamaz. Kısa süre içinde daha gelişmiş sürümlere yükseltileceklerdir.<sup>[[1]](#references)</sup>

### Memory reading and writing using the execute primitive

Amaç, belirli function'ları kullanarak memory reading ve writing gerçekleştirmektir. **Reading memory** için:
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
### Uygun işlevleri belirleme

Yaygın kütüphanelerin taranması, bu işlemler için uygun adayları ortaya çıkardı:<sup>[[1]](#references)</sup>

1. **Belleği okuma — `property_getName()`** (libobjc):
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
Keyfi bir adrese 64 bitlik yazma gerçekleştirmek için:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Bu primitive’ler oluşturulduğunda, paylaşılan bellek oluşturmanın ve uzak process’i kontrol etmede önemli bir ilerleme sağlamanın önü açılır.<sup>[[1]](#references)</sup>

## 4. Paylaşılan Bellek Kurulumu

Amaç, local ve remote task’ler arasında paylaşılan bellek oluşturarak veri aktarımını basitleştirmek ve birden fazla argüman alan function’ların çağrılmasını kolaylaştırmaktır. Bu yaklaşım, Mach memory entry’leri üzerine kurulu olan `libxpc` ve `OS_xpc_shmem` object type’ından yararlanır.<sup>[[1]](#references)</sup>

### Process overview

1. **Bellek ayırma**
* Paylaşım için `mach_vm_allocate()` kullanarak bellek ayırın.
* Ayrılan bölge için bir `OS_xpc_shmem` object oluşturmak üzere `xpc_shmem_create()` kullanın.
2. **Remote process’te paylaşılan bellek oluşturma**
* Remote process’te `OS_xpc_shmem` object’i için bellek ayırın (`remote_malloc`).
* Local template object’i kopyalayın; `0x18` offset’indeki gömülü Mach send right için fix-up işlemi hâlâ gereklidir.
3. **Mach memory entry’yi düzeltme**
* `thread_set_special_port()` ile bir send right ekleyin ve `0x18` alanının üzerine remote entry’nin name değerini yazın.
4. **Sonlandırma**
* Remote object’i doğrulayın ve remote call ile `xpc_shmem_remote()` kullanarak map edin.

## 5. Full Control Sağlama

Arbitrary execution ve paylaşılan bir memory back-channel kullanılabilir olduğunda hedef process üzerinde fiilen tam kontrol sahibi olursunuz:<sup>[[1]](#references)</sup>

* **Arbitrary memory R/W** — local ve shared bölgeler arasında `memcpy()` kullanın.
* **8’den fazla argümanla function çağrıları** — arm64 calling convention’ı izleyerek ek argümanları stack üzerine yerleştirin.
* **Mach port transferi** — oluşturulan port’lar üzerinden Mach message’larında right’ları aktarın.
* **File-descriptor transferi** — fileport’lardan yararlanın (*triple_fetch*’e bakın).

Tüm bunlar, kolayca yeniden kullanılabilmesi için [`threadexec`](https://github.com/bazad/threadexec) library’si içinde paketlenmiştir.

---

## 6. Apple Silicon (arm64e) Ayrıntıları

Apple Silicon cihazlarda (arm64e) **Pointer Authentication Codes (PAC)** tüm return address’leri ve birçok function pointer’ı korur. *Mevcut code’u yeniden kullanan* thread-hijacking teknikleri çalışmaya devam eder; çünkü `lr`/`pc` içindeki orijinal değerler zaten geçerli PAC signature’larına sahiptir. Saldırgan tarafından kontrol edilen memory’ye jump etmeye çalıştığınızda sorunlar ortaya çıkar:

1. Hedef içinde executable memory ayırın (remote `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Payload’unuzu kopyalayın.
3. *Remote* process içinde pointer’ı sign edin:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Hijacked thread state içinde `pc = ptr` ayarlayın.

Alternatif olarak, mevcut gadget/function'ları zincirleyerek (geleneksel ROP) PAC uyumluluğunu koruyun.

## 7. EndpointSecurity ile Tespit ve Hardening

**EndpointSecurity (ES)** framework'ü, savunmacıların thread-injection girişimlerini gözlemlemesine veya engellemesine olanak tanıyan kernel event'lerini açığa çıkarır:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – bir process başka bir task'ın portunu istediğinde tetiklenir (ör. `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – bir thread *farklı* bir task içinde oluşturulduğunda yayınlanır.<sup>[[3]](#references)</sup>
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
**osquery ≥ 5.8 ile sorgulama:**
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime değerlendirmeleri

Uygulamanızı `com.apple.security.get-task-allow` entitlement'ı **olmadan** dağıtmak, root olmayan saldırganların task-port'unu elde etmesini önler. System Integrity Protection (SIP) hâlâ birçok Apple binary'sine erişimi engeller, ancak third-party software açıkça opt-out yapmalıdır.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma üzerinde PAC-aware thread hijacking gösteren kompakt PoC<sup>[[2]](#references)</sup> |
| `remote_thread_es` | 2024 | Çeşitli EDR vendor'ları tarafından `REMOTE_THREAD_CREATE` event'lerini ortaya çıkarmak için kullanılan EndpointSecurity yardımcı aracı |

> Bu projelerin source code'unu okumak, macOS 13/14'te sunulan API değişikliklerini anlamak ve Intel ↔ Apple Silicon arasında uyumluluğu korumak için faydalıdır.

## References

- [1] [task_threads() kullanarak platform binary kısıtlamalarını aşma - bazad.github.io](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [2] [rodionovd/task_vaccine - GitHub](https://github.com/rodionovd/task_vaccine)
- [3] [ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE - Apple Developer Belgeleri](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)
{{#include ../../../../banners/hacktricks-training.md}}
