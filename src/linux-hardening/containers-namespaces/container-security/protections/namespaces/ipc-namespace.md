# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

IPC namespace, **System V IPC objects** ve **POSIX message queues**'u izole eder. Buna, aksi takdirde host üzerindeki ilgisiz process'ler arasında görünür olacak shared memory segment'leri, semaphore'lar ve message queue'lar dahildir. Pratikte bu, bir container'ın diğer workload'lara veya host'a ait IPC object'lerine gelişigüzel şekilde bağlanmasını engeller.

Mount, PID veya user namespace'leriyle karşılaştırıldığında IPC namespace hakkında daha az konuşulur; ancak bu, önemsiz olduğu anlamına gelmemelidir. Shared memory ve ilgili IPC mekanizmaları oldukça faydalı state içerebilir. Host IPC namespace'i expose edilirse workload, container sınırını aşması amaçlanmayan inter-process coordination object'lerini veya verilerini görebilir.

## Operation

Runtime yeni bir IPC namespace oluşturduğunda process, kendisine ait izole bir IPC identifier set'i alır. Bu, `ipcs` gibi komutların yalnızca o namespace'te kullanılabilen object'leri göstermesi anlamına gelir. Container bunun yerine host IPC namespace'ine katılırsa bu object'ler paylaşılan global görünümün parçası hâline gelir.

Bu durum özellikle application'ların veya service'lerin yoğun şekilde shared memory kullandığı ortamlarda önemlidir. Container yalnızca IPC üzerinden doğrudan breakout gerçekleştiremese bile namespace, bilgi leak edilmesine veya cross-process interference etkinleştirilmesine neden olabilir; bu da sonraki bir attack'e kayda değer ölçüde yardımcı olur.

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

Docker ve Podman varsayılan olarak IPC'yi izole eder. Kubernetes genellikle Pod'a kendi IPC namespace'ini verir; bu namespace aynı Pod içindeki container'lar tarafından paylaşılır, ancak varsayılan olarak host ile paylaşılmaz. Host IPC paylaşımı mümkündür, ancak küçük bir runtime seçeneği yerine izolasyonda anlamlı bir azalma olarak değerlendirilmelidir.

## Yanlış Yapılandırmalar

En bariz hata `--ipc=host` veya `hostIPC: true` kullanmaktır. Bu, eski yazılımlarla uyumluluk veya kolaylık amacıyla yapılabilir, ancak trust model'i önemli ölçüde değiştirir. Tekrarlanan başka bir sorun da IPC'nin host PID veya host networking kadar çarpıcı görünmediği için gözden kaçırılmasıdır. Gerçekte workload browser'lar, veritabanları, bilimsel workload'lar veya shared memory'yi yoğun şekilde kullanan başka yazılımlar çalıştırıyorsa IPC yüzeyi oldukça önemli olabilir.

## Kötüye Kullanım

Host IPC paylaşıldığında attacker, shared memory nesnelerini inceleyebilir veya bunlara müdahale edebilir, host ya da komşu workload'ların davranışları hakkında yeni bilgiler edinebilir veya burada öğrenilen bilgileri process görünürlüğü ve ptrace-style yeteneklerle birleştirebilir. IPC paylaşımı çoğu zaman tam breakout path yerine destekleyici bir zayıflıktır, ancak destekleyici zayıflıklar önemlidir; çünkü gerçek attack chain'leri kısaltır ve daha kararlı hâle getirir.

İlk faydalı adım, hangi IPC nesnelerinin görünür olduğunu enumerate etmektir:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Host IPC namespace'i paylaşılıyorsa, büyük paylaşılan bellek segmentleri veya ilgi çekici nesne sahipleri uygulama davranışını hemen ortaya çıkarabilir:
```bash
ipcs -m -p
ipcs -q -p
```
Bazı ortamlarda `/dev/shm` içerikleri, kontrol edilmeye değer dosya adlarını, artifact'leri veya token'ları leak edebilir:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC paylaşımı tek başına nadiren anında host root erişimi sağlar, ancak sonraki process attack işlemlerini çok daha kolay hâle getiren veri ve koordinasyon kanallarını açığa çıkarabilir.

### Tam Örnek: `/dev/shm` Secret Recovery

En gerçekçi tam abuse senaryosu, doğrudan escape yerine veri hırsızlığıdır. Host IPC veya geniş bir paylaşılan bellek düzeni açığa çıkarsa hassas artefaktlar bazen doğrudan elde edilebilir:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Etki:

- paylaşılan bellekte bırakılmış secrets veya session material bilgilerinin çıkarılması
- host üzerinde o anda etkin olan uygulamalar hakkında bilgi edinilmesi
- sonraki PID-namespace veya ptrace tabanlı saldırılar için daha iyi hedefleme

Bu nedenle IPC paylaşımı, bağımsız bir host-escape primitive olmaktan ziyade bir **attack amplifier** olarak değerlendirilmelidir.

## Kontroller

Bu komutlar; workload'un özel bir IPC görünümüne sahip olup olmadığını, anlamlı paylaşılan bellek veya mesaj nesnelerinin görünür olup olmadığını ve `/dev/shm`'nin kendisinin yararlı artifact'ler sunup sunmadığını belirlemeyi amaçlar.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Burada ilgi çekici olanlar:

- `ipcs -a` beklenmeyen kullanıcılar veya servisler tarafından sahiplenilen nesneleri gösteriyorsa namespace beklenildiği kadar izole olmayabilir.
- Büyük veya alışılmadık paylaşılan bellek segmentleri genellikle daha fazla incelenmeye değerdir.
- Geniş bir `/dev/shm` mount'u otomatik olarak bir bug değildir, ancak bazı ortamlarda dosya adlarını, artifact'leri ve geçici secret'ları leaks edebilir.

IPC, daha büyük namespace türleri kadar nadiren ilgi görür, ancak yoğun şekilde kullanan ortamlarda bunu host ile paylaşmak kesinlikle bir security kararıdır.

{{#include ../../../../../banners/hacktricks-training.md}}
