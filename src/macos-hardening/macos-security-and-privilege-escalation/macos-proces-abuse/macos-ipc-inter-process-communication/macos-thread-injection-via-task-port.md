# macOS Thread Injection via Task port

{{#include ../../../../banners/hacktricks-training.md}}

## Code

- [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
- [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

## 1. Thread Hijacking

Başlangıçta, **`task_threads()`** fonksiyonu, uzaktaki görevden bir iş parçacığı listesi almak için görev portunda çağrılır. Ele geçirilmek üzere bir iş parçacığı seçilir. Bu yaklaşım, yeni önlemlerin `thread_create_running()`'i engellemesi nedeniyle yeni bir uzaktan iş parçacığı oluşturmanın yasak olduğu geleneksel kod enjeksiyon yöntemlerinden sapmaktadır.

İş parçacığını kontrol etmek için, **`thread_suspend()`** çağrılır ve yürütmesi durdurulur.

Uzaktaki iş parçacığında yalnızca **durdurma** ve **başlatma**, **kayıt değerlerini alma** ve **değiştirme** işlemlerine izin verilir. Uzaktan fonksiyon çağrıları, `x0` ile `x7` kayıtlarını **argümanlar** ile ayarlayarak, **`pc`**'yi hedeflenen fonksiyona yapılandırarak ve iş parçacığını etkinleştirerek başlatılır. İş parçacığının dönüşten sonra çökmediğinden emin olmak, dönüşün tespit edilmesini gerektirir.

Bir strateji, uzaktaki iş parçacığı için `thread_set_exception_ports()` kullanarak **bir istisna işleyicisi kaydetmektir**, `lr` kaydını fonksiyon çağrısından önce geçersiz bir adrese ayarlamaktır. Bu, fonksiyon yürütüldükten sonra bir istisna tetikler, istisna portuna bir mesaj gönderir ve dönüş değerini kurtarmak için iş parçacığının durumunu incelemeyi sağlar. Alternatif olarak, Ian Beer’in triple_fetch istismarından benimsenen bir yöntemle, `lr` sonsuz döngüye ayarlanır. İş parçacığının kayıtları, **`pc` o talimata işaret edene kadar** sürekli izlenir.

## 2. Mach ports for communication

Sonraki aşama, uzaktaki iş parçacığı ile iletişimi kolaylaştırmak için Mach portları kurmaktır. Bu portlar, görevler arasında keyfi gönderme ve alma haklarının aktarımında önemli bir rol oynar.

İki yönlü iletişim için, bir yerel ve diğeri uzaktaki görevde olmak üzere iki Mach alma hakkı oluşturulur. Ardından, her port için bir gönderme hakkı karşıt göreve aktarılır ve mesaj alışverişine olanak tanır.

Yerel port üzerinde odaklanıldığında, alma hakkı yerel görev tarafından tutulur. Port, `mach_port_allocate()` ile oluşturulur. Bu port için bir gönderme hakkını uzaktaki göreve aktarmak zorluk teşkil eder.

Bir strateji, `thread_set_special_port()` kullanarak yerel port için bir gönderme hakkını uzaktaki iş parçacığının `THREAD_KERNEL_PORT`'una yerleştirmektir. Ardından, uzaktaki iş parçacığına `mach_thread_self()` çağrısı yapması talimatı verilir, böylece gönderme hakkını alır.

Uzaktaki port için süreç esasen tersine çevrilir. Uzaktaki iş parçacığı, `mach_reply_port()` aracılığıyla bir Mach portu oluşturması için yönlendirilir (çünkü `mach_port_allocate()` dönüş mekanizması nedeniyle uygun değildir). Port oluşturulduktan sonra, uzaktaki iş parçacığında bir gönderme hakkı oluşturmak için `mach_port_insert_right()` çağrılır. Bu hak daha sonra `thread_set_special_port()` kullanılarak çekirdekte saklanır. Yerel görevde, uzaktaki iş parçacığı üzerinde `thread_get_special_port()` kullanılarak uzaktaki görevde yeni tahsis edilen Mach portuna bir gönderme hakkı edinilir.

Bu adımların tamamlanması, Mach portlarının kurulmasını sağlar ve iki yönlü iletişim için zemin hazırlar.

## 3. Basic Memory Read/Write Primitives

Bu bölümde, temel bellek okuma ve yazma ilkelini oluşturmak için yürütme ilkesinin kullanılması üzerine odaklanılmaktadır. Bu ilk adımlar, uzaktaki süreç üzerinde daha fazla kontrol elde etmek için kritik öneme sahiptir, ancak bu aşamadaki ilkelere pek çok amaç için hizmet etmeyeceklerdir. Yakında, daha gelişmiş versiyonlara yükseltileceklerdir.

### Memory Reading and Writing Using Execute Primitive

Amaç, belirli fonksiyonlar kullanarak bellek okuma ve yazma gerçekleştirmektir. Bellek okumak için, aşağıdaki yapıya benzeyen fonksiyonlar kullanılır:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
Ve belleğe yazmak için, bu yapıya benzer fonksiyonlar kullanılır:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Bu fonksiyonlar verilen assembly talimatlarına karşılık gelir:
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

1. **Belleği Okuma:**
`property_getName()` fonksiyonu, [Objective-C runtime kütüphanesi](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) için bellek okumak üzere uygun bir fonksiyon olarak belirlenmiştir. Fonksiyon aşağıda özetlenmiştir:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Bu fonksiyon, `objc_property_t`'nin ilk alanını döndürerek `read_func` gibi etkili bir şekilde çalışır.

2. **Bellek Yazma:**
Bellek yazmak için önceden oluşturulmuş bir fonksiyon bulmak daha zordur. Ancak, libxpc'den `_xpc_int64_set_value()` fonksiyonu, aşağıdaki ayrıştırma ile uygun bir adaydır:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Belirli bir adrese 64-bit yazma işlemi gerçekleştirmek için, uzak çağrı şu şekilde yapılandırılır:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Bu temel unsurlar belirlendikten sonra, paylaşılan bellek oluşturmak için sahne hazırlanmış olur ve bu, uzaktaki süreci kontrol etmede önemli bir ilerlemeyi işaret eder.

## 4. Paylaşılan Bellek Kurulumu

Amaç, yerel ve uzaktaki görevler arasında paylaşılan bellek oluşturarak veri transferini basitleştirmek ve birden fazla argümanla fonksiyon çağrısını kolaylaştırmaktır. Yaklaşım, Mach bellek girişleri üzerine inşa edilmiş `libxpc` ve onun `OS_xpc_shmem` nesne türünü kullanmayı içerir.

### Süreç Genel Görünümü:

1. **Bellek Tahsisi**:

- Paylaşım için belleği `mach_vm_allocate()` kullanarak tahsis edin.
- Tahsis edilen bellek bölgesi için bir `OS_xpc_shmem` nesnesi oluşturmak üzere `xpc_shmem_create()` kullanın. Bu fonksiyon, Mach bellek girişinin oluşturulmasını yönetecek ve `OS_xpc_shmem` nesnesinin `0x18` ofsetinde Mach gönderim hakkını saklayacaktır.

2. **Uzaktaki Süreçte Paylaşılan Bellek Oluşturma**:

- Uzaktaki süreçte `OS_xpc_shmem` nesnesi için bellek tahsis edin ve `malloc()` ile uzaktan çağrı yapın.
- Yerel `OS_xpc_shmem` nesnesinin içeriğini uzaktaki sürece kopyalayın. Ancak, bu ilk kopya `0x18` ofsetinde yanlış Mach bellek girişi adlarına sahip olacaktır.

3. **Mach Bellek Girişini Düzeltme**:

- Uzaktaki görevde Mach bellek girişi için bir gönderim hakkı eklemek üzere `thread_set_special_port()` yöntemini kullanın.
- Uzaktaki bellek girişinin adını yazarak `0x18` ofsetindeki Mach bellek girişi alanını düzeltin.

4. **Paylaşılan Bellek Kurulumunu Tamamlama**:
- Uzaktaki `OS_xpc_shmem` nesnesini doğrulayın.
- `xpc_shmem_remote()` ile uzaktan çağrı yaparak paylaşılan bellek haritasını oluşturun.

Bu adımları izleyerek, yerel ve uzaktaki görevler arasında paylaşılan bellek verimli bir şekilde kurulacak ve veri transferleri ile birden fazla argüman gerektiren fonksiyonların yürütülmesi kolaylaşacaktır.

## Ek Kod Parçacıkları

Bellek tahsisi ve paylaşılan bellek nesnesi oluşturma için:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Uzak süreçte paylaşılan bellek nesnesini oluşturmak ve düzeltmek için:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
Mach portları ve bellek giriş adlarını doğru bir şekilde ele almayı unutmayın, böylece paylaşılan bellek kurulumu düzgün çalışsın.

## 5. Tam Kontrol Sağlama

Paylaşılan belleği başarıyla kurduktan ve keyfi yürütme yetenekleri kazandıktan sonra, esasen hedef süreç üzerinde tam kontrol elde etmiş oluyoruz. Bu kontrolü sağlayan ana işlevler şunlardır:

1. **Keyfi Bellek İşlemleri**:

- Paylaşılan bölgeden veri kopyalamak için `memcpy()` çağrısını yaparak keyfi bellek okumaları gerçekleştirin.
- Paylaşılan bölgeye veri aktarmak için `memcpy()` kullanarak keyfi bellek yazmaları gerçekleştirin.

2. **Birden Fazla Argümanla Fonksiyon Çağrıları Yönetimi**:

- 8'den fazla argüman gerektiren fonksiyonlar için, ek argümanları çağrı konvansiyonuna uygun olarak yığında düzenleyin.

3. **Mach Port Transferi**:

- Daha önce kurulmuş portlar aracılığıyla görevler arasında Mach portlarını Mach mesajları ile aktarın.

4. **Dosya Tanımlayıcı Transferi**:
- `triple_fetch` tekniği ile Ian Beer tarafından vurgulanan dosyaportları kullanarak süreçler arasında dosya tanımlayıcılarını aktarın.

Bu kapsamlı kontrol, [threadexec](https://github.com/bazad/threadexec) kütüphanesi içinde kapsüllenmiştir ve kurban süreci ile etkileşim için ayrıntılı bir uygulama ve kullanıcı dostu bir API sağlar.

## Önemli Hususlar:

- Sistem kararlılığını ve veri bütünlüğünü korumak için bellek okuma/yazma işlemleri için `memcpy()`'nin doğru kullanımını sağlayın.
- Mach portları veya dosya tanımlayıcıları aktarırken, uygun protokollere uyun ve kaynakları sorumlu bir şekilde yönetin, sızıntıları veya istenmeyen erişimleri önleyin.

Bu yönergelere uyarak ve `threadexec` kütüphanesini kullanarak, süreçleri ayrıntılı bir düzeyde etkili bir şekilde yönetebilir ve etkileşimde bulunarak hedef süreç üzerinde tam kontrol elde edebilirsiniz.

## Referanslar

- [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{{#include ../../../../banners/hacktricks-training.md}}
