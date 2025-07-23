# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Başlangıçta, `task_threads()` fonksiyonu, uzaktaki görevden bir iş parçacığı listesi almak için görev portu üzerinde çağrılır. Bir iş parçacığı ele geçirilmek üzere seçilir. Bu yaklaşım, `thread_create_running()`'i engelleyen önlemler nedeniyle yeni bir uzaktan iş parçacığı oluşturmanın yasak olduğu geleneksel kod enjekte etme yöntemlerinden sapmaktadır.

İş parçacığını kontrol etmek için, `thread_suspend()` çağrılır ve yürütmesi durdurulur.

Uzaktaki iş parçacığı üzerinde yalnızca **durdurma** ve **başlatma** ile **kayıt değerlerini alma/değiştirme** işlemlerine izin verilir. Uzaktan fonksiyon çağrıları, `x0` ile `x7` kayıtlarını **argümanlar** ile ayarlayarak, `pc`'yi hedeflenen fonksiyona yapılandırarak ve iş parçacığını yeniden başlatarak başlatılır. İş parçacığının dönüşten sonra çökmediğinden emin olmak, dönüşün tespit edilmesini gerektirir.

Bir strateji, uzaktaki iş parçacığı için `thread_set_exception_ports()` kullanarak bir **istisna işleyici** kaydetmektir; bu işlem, fonksiyon çağrısından önce `lr` kaydını geçersiz bir adrese ayarlamayı içerir. Bu, fonksiyon yürütüldükten sonra bir istisna tetikler ve istisna portuna bir mesaj gönderir, böylece iş parçacığının durumunu inceleyerek dönüş değerini kurtarmaya olanak tanır. Alternatif olarak, Ian Beer’in *triple_fetch* istismarından alınan bir yöntemle, `lr` sonsuz döngüye ayarlanır; iş parçacığının kayıtları, `pc` o talimata işaret edene kadar sürekli izlenir.

## 2. Mach ports for communication

Sonraki aşama, uzaktaki iş parçacığı ile iletişimi kolaylaştırmak için Mach portları kurmaktır. Bu portlar, görevler arasında keyfi gönderme/alma haklarının aktarımında önemlidir.

İki yönlü iletişim için, bir yerel ve diğeri uzaktaki görevde olmak üzere iki Mach alma hakkı oluşturulur. Ardından, her port için bir gönderme hakkı karşıt göreve aktarılır ve mesaj alışverişine olanak tanır.

Yerel port üzerinde odaklanıldığında, alma hakkı yerel görev tarafından tutulur. Port, `mach_port_allocate()` ile oluşturulur. Bu port için bir gönderme hakkını uzaktaki göreve aktarmak zorluk teşkil eder.

Bir strateji, `thread_set_special_port()` kullanarak yerel port için bir gönderme hakkını uzaktaki iş parçacığının `THREAD_KERNEL_PORT`'una yerleştirmeyi içerir. Ardından, uzaktaki iş parçacığına `mach_thread_self()` çağrısı yapması talimatı verilir, böylece gönderme hakkı alınır.

Uzaktaki port için süreç esasen tersine çevrilir. Uzaktaki iş parçacığı, `mach_reply_port()` aracılığıyla bir Mach portu oluşturması için yönlendirilir (çünkü `mach_port_allocate()` dönüş mekanizması nedeniyle uygun değildir). Port oluşturulduktan sonra, uzaktaki iş parçacığında bir gönderme hakkı oluşturmak için `mach_port_insert_right()` çağrılır. Bu hak daha sonra `thread_set_special_port()` kullanılarak çekirdekte saklanır. Yerel görevde, uzaktaki iş parçacığı üzerinde `thread_get_special_port()` kullanılarak uzaktaki görevde yeni tahsis edilen Mach portuna bir gönderme hakkı alınır.

Bu adımların tamamlanması, Mach portlarının kurulmasını sağlar ve iki yönlü iletişim için zemin hazırlar.

## 3. Basic Memory Read/Write Primitives

Bu bölümde, temel bellek okuma/yazma ilkelilerini oluşturmak için yürütme ilkesinin kullanılması üzerine odaklanılmaktadır. Bu ilk adımlar, uzaktaki süreç üzerinde daha fazla kontrol elde etmek için kritik öneme sahiptir, ancak bu aşamadaki ilkeliler pek çok amaca hizmet etmeyecektir. Kısa süre içinde daha gelişmiş versiyonlara yükseltilecektir.

### Memory reading and writing using the execute primitive

Amaç, belirli fonksiyonlar kullanarak bellek okuma ve yazma gerçekleştirmektir. **Bellek okuma** için:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
**bellek yazma**:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Bu fonksiyonlar aşağıdaki assembly'e karşılık gelir:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Uygun Fonksiyonların Belirlenmesi

Yaygın kütüphanelerin taranması, bu işlemler için uygun adayları ortaya çıkardı:

1. **Belleği Okuma — `property_getName()`** (libobjc):
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
Rastgele bir adrese 64-bit yazma işlemi gerçekleştirmek için:
```c
_xpc_int64_set_value(address - 0x18, value);
```
Bu ilkelere dayanarak, paylaşılan bellek oluşturmak için sahne hazırlandı ve bu, uzaktaki süreci kontrol etmede önemli bir ilerleme kaydedildi.

## 4. Paylaşılan Bellek Kurulumu

Amaç, yerel ve uzaktaki görevler arasında paylaşılan bellek oluşturarak veri transferini basitleştirmek ve birden fazla argümanla fonksiyon çağrılarını kolaylaştırmaktır. Bu yaklaşım, Mach bellek girişleri üzerine inşa edilmiş `libxpc` ve onun `OS_xpc_shmem` nesne türünü kullanır.

### Süreç genel görünümü

1. **Bellek tahsisi**
* `mach_vm_allocate()` kullanarak paylaşım için bellek tahsis edin.
* Tahsis edilen bölge için bir `OS_xpc_shmem` nesnesi oluşturmak üzere `xpc_shmem_create()` kullanın.
2. **Uzaktaki süreçte paylaşılan bellek oluşturma**
* Uzaktaki süreçte `OS_xpc_shmem` nesnesi için bellek tahsis edin (`remote_malloc`).
* Yerel şablon nesnesini kopyalayın; gömülü Mach gönderim hakkının `0x18` ofsetinde düzeltilmesi hala gereklidir.
3. **Mach bellek girişini düzeltme**
* `thread_set_special_port()` ile bir gönderim hakkı ekleyin ve `0x18` alanını uzaktaki girişin adıyla üzerine yazın.
4. **Tamamlama**
* Uzaktaki nesneyi doğrulayın ve `xpc_shmem_remote()` ile uzaktan bir çağrı yaparak haritalayın.

## 5. Tam Kontrol Sağlama

Rastgele yürütme ve paylaşılan bellek geri kanalı mevcut olduğunda, hedef süreci etkili bir şekilde kontrol altına alırsınız:

* **Rastgele bellek R/W** — yerel ve paylaşılan bölgeler arasında `memcpy()` kullanın.
* **> 8 argümanlı fonksiyon çağrıları** — ek argümanları arm64 çağrı konvansiyonunu takip ederek yığın üzerine yerleştirin.
* **Mach port transferi** — kurulan portlar aracılığıyla Mach mesajlarında hakları geçirin.
* **Dosya tanımlayıcı transferi** — dosya portlarını kullanın (bkz. *triple_fetch*).

Tüm bunlar, kolay yeniden kullanım için [`threadexec`](https://github.com/bazad/threadexec) kütüphanesinde sarılmıştır.

---

## 6. Apple Silicon (arm64e) Nuanları

Apple Silicon cihazlarında (arm64e) **Pointer Authentication Codes (PAC)** tüm dönüş adreslerini ve birçok fonksiyon işaretçisini korur. Mevcut kodu *yeniden kullanan* thread-hijacking teknikleri, `lr`/`pc` içindeki orijinal değerler zaten geçerli PAC imzaları taşıdığı için çalışmaya devam eder. Saldırgan kontrolündeki belleğe atlamaya çalıştığınızda sorunlar ortaya çıkar:

1. Hedef içinde yürütülebilir bellek tahsis edin (uzak `mach_vm_allocate` + `mprotect(PROT_EXEC)`).
2. Payload'unuzu kopyalayın.
3. *Uzak* süreçte işaretçiyi imzalayın:
```c
uint64_t ptr = (uint64_t)payload;
ptr = ptrauth_sign_unauthenticated((void*)ptr, ptrauth_key_asia, 0);
```
4. Ele geçirilmiş thread durumunda `pc = ptr` olarak ayarlayın.

Alternatif olarak, mevcut gadget'ları/fonksiyonları zincirleyerek PAC uyumlu kalın (geleneksel ROP).

## 7. Tespit & EndpointSecurity ile Güçlendirme

**EndpointSecurity (ES)** çerçevesi, savunucuların thread-enjeksiyon girişimlerini gözlemlemesine veya engellemesine olanak tanıyan çekirdek olaylarını açığa çıkarır:

* `ES_EVENT_TYPE_AUTH_GET_TASK` – bir süreç başka bir görevin portunu talep ettiğinde tetiklenir (örneğin `task_for_pid()`).
* `ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE` – bir thread *farklı* bir görevde oluşturulduğunda yayımlanır.
* `ES_EVENT_TYPE_NOTIFY_THREAD_SET_STATE` (macOS 14 Sonoma'da eklendi) – mevcut bir thread'in kayıt manipülasyonunu gösterir.

Uzak-thread olaylarını yazdıran minimal Swift istemcisi:
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
**osquery** ≥ 5.8 ile Sorgulama:
```sql
SELECT target_pid, source_pid, target_path
FROM es_process_events
WHERE event_type = 'REMOTE_THREAD_CREATE';
```
### Hardened-runtime considerations

Uygulamanızı `com.apple.security.get-task-allow` yetkisi **olmadan** dağıtmak, kök olmayan saldırganların görev-portunu elde etmesini engeller. Sistem Bütünlüğü Koruması (SIP) hala birçok Apple ikili dosyasına erişimi engelliyor, ancak üçüncü taraf yazılımlar açıkça opt-out yapmalıdır.

## 8. Recent Public Tooling (2023-2025)

| Tool | Year | Remarks |
|------|------|---------|
| [`task_vaccine`](https://github.com/rodionovd/task_vaccine) | 2023 | Ventura/Sonoma üzerinde PAC farkında thread kaçırmayı gösteren kompakt PoC |
| `remote_thread_es` | 2024 | Birçok EDR satıcısı tarafından `REMOTE_THREAD_CREATE` olaylarını yüzeye çıkarmak için kullanılan EndpointSecurity yardımcı programı |

> Bu projelerin kaynak kodunu okumak, macOS 13/14'te tanıtılan API değişikliklerini anlamak ve Intel ↔ Apple Silicon arasında uyumlu kalmak için faydalıdır.

## References

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
- [https://github.com/rodionovd/task_vaccine](https://github.com/rodionovd/task_vaccine)
- [https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_remote_thread_create)

{{#include ../../../../banners/hacktricks-training.md}}
