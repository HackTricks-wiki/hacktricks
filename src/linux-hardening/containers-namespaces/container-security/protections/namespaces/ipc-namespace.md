# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

IPC namespace, **System V IPC objects** ve **POSIX message queues**'u izole eder. Buna, aksi takdirde host üzerindeki ilgisiz process'ler arasında görünür olacak shared memory segment'leri, semaphore'lar ve message queue'lar dahildir. Pratikte bu, bir container'ın diğer workload'lara veya host'a ait IPC object'lerine gelişigüzel şekilde bağlanmasını engeller.

Mount, PID veya user namespace'lerle karşılaştırıldığında IPC namespace hakkında daha az konuşulur; ancak bu, önemsiz olduğu anlamına gelmemelidir. Shared memory ve ilişkili IPC mekanizmaları oldukça değerli state içerebilir. Host IPC namespace'i açığa çıkarsa workload, container sınırını aşması hiç amaçlanmamış inter-process coordination object'lerine veya verilere görünürlük kazanabilir.

## İşleyiş

Runtime yeni bir IPC namespace oluşturduğunda process, kendisine ait izole bir IPC identifier kümesi edinir. Bu, `ipcs` gibi komutların yalnızca o namespace'te kullanılabilen object'leri göstermesi anlamına gelir. Container bunun yerine host IPC namespace'ine katılırsa bu object'ler paylaşılan global görünümün parçası olur.

Bu durum özellikle application'ların veya service'lerin shared memory'yi yoğun şekilde kullandığı ortamlarda önemlidir. Container yalnızca IPC üzerinden doğrudan breakout gerçekleştiremese bile namespace, daha sonraki bir attack'a kayda değer ölçüde yardımcı olacak şekilde bilgi sızdırabilir veya process'ler arası interference'ı etkinleştirebilir.

## Lab

Şu komutla private bir IPC namespace oluşturabilirsiniz:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Ve runtime davranışını şununla karşılaştırın:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Runtime Kullanımı

Docker ve Podman, IPC'yi varsayılan olarak izole eder. Kubernetes genellikle Pod'a kendi IPC namespace'ini verir; bu namespace aynı Pod içindeki container'lar arasında paylaşılır, ancak varsayılan olarak host ile paylaşılmaz. Host IPC paylaşımı mümkündür, ancak bunun küçük bir runtime seçeneği yerine izolasyonda kayda değer bir azalma olarak değerlendirilmesi gerekir.

## Yanlış Yapılandırmalar

En bariz hata, `--ipc=host` veya `hostIPC: true` kullanmaktır. Bu, legacy yazılımlarla uyumluluk ya da kolaylık amacıyla yapılabilir, ancak trust model'i büyük ölçüde değiştirir. Sık karşılaşılan başka bir sorun da IPC'nin, host PID veya host networking kadar çarpıcı görünmediği için gözden kaçırılmasıdır. Gerçekte workload browser'lar, database'ler, scientific workload'lar veya shared memory'yi yoğun biçimde kullanan başka yazılımlar çalıştırıyorsa IPC yüzeyi son derece önemli olabilir.

## Abuse

Host IPC paylaşıldığında attacker, shared memory object'lerini inceleyebilir veya bunlara müdahale edebilir, host ya da komşu workload'ların davranışı hakkında yeni bilgiler edinebilir veya burada öğrenilen bilgileri process visibility ve ptrace-style capabilities ile birleştirebilir. IPC paylaşımı çoğu zaman tam breakout path yerine destekleyici bir weakness'tir; ancak destekleyici weakness'ler önemlidir, çünkü gerçek attack chain'leri kısaltır ve daha kararlı hâle getirir.

İlk yararlı adım, görünür olan IPC object'lerinin tamamını listelemektir:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Host IPC namespace paylaşılıyorsa, büyük paylaşılan bellek segmentleri veya ilgi çekici nesne sahipleri uygulama davranışını anında ortaya çıkarabilir:
```bash
ipcs -m -p
ipcs -q -p
```
Bazı ortamlarda, `/dev/shm` içerikleri kontrol edilmeye değer dosya adlarını, artifact'leri veya token'ları leak edebilir:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC paylaşımı nadiren tek başına anında host root erişimi sağlar, ancak sonraki process saldırılarını çok daha kolay hâle getiren veri ve koordinasyon kanallarını açığa çıkarabilir.

### Tam Örnek: `/dev/shm` Secret Recovery

En gerçekçi kapsamlı abuse senaryosu doğrudan escape yerine veri hırsızlığıdır. Host IPC veya geniş bir paylaşılan bellek düzeni açığa çıkarsa hassas artefaktlar bazen doğrudan kurtarılabilir:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Etki:

- paylaşılan bellekte bırakılmış secret veya oturum materyalinin çıkarılması
- host üzerinde hâlihazırda etkin olan uygulamalar hakkında bilgi edinilmesi
- sonraki PID-namespace veya ptrace tabanlı saldırılar için daha iyi hedefleme

Bu nedenle IPC paylaşımı, tek başına bir host-escape primitive olmaktan çok bir **saldırı güçlendirici** olarak anlaşılmalıdır.

## Kontroller

Bu komutlar; workload'un özel bir IPC görünümüne sahip olup olmadığını, anlamlı paylaşımlı bellek veya ileti nesnelerinin görünür olup olmadığını ve `/dev/shm`'nin kendisinin yararlı artifact'ler açığa çıkarıp çıkarmadığını belirlemek içindir.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Burada ilginç olanlar:

- `ipcs -a` beklenmeyen kullanıcılara veya servislere ait nesneleri ortaya çıkarıyorsa namespace beklenildiği kadar izole olmayabilir.
- Büyük veya alışılmadık shared memory segment'leri genellikle daha fazla incelenmeye değerdir.
- Geniş bir `/dev/shm` mount'u otomatik olarak bir bug değildir, ancak bazı ortamlarda dosya adlarını, artifact'leri ve geçici secret'ları leak edebilir.

IPC, daha büyük namespace türleri kadar nadiren ilgi görür; ancak yoğun şekilde kullanıldığı ortamlarda host ile paylaşılması kesinlikle bir security kararıdır.
{{#include ../../../../../banners/hacktricks-training.md}}
