# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

IPC namespace, **System V IPC objects** ve **POSIX message queues**'ı izole eder. Bu, aksi takdirde host üzerindeki ilgisiz işlemler tarafından görülebilecek shared memory segments, semaphores ve message queues'u kapsar. Pratikte bu, bir container'ın diğer workload'lara veya host'a ait IPC nesnelerine rastgele bağlanmasını engeller.

mount, PID veya user namespaces ile kıyaslandığında IPC namespace genellikle daha az bahsedilir; ancak bu, önemsiz olduğu anlamına gelmemelidir. Paylaşılan bellek ve ilişkili IPC mekanizmaları çok faydalı durum bilgileri içerebilir. Eğer host IPC namespace açığa çıkarsa, workload inter-process koordinasyon nesneleri veya container sınırını aşması amaçlanmamış verilere görünürlük kazanabilir.

## İşleyiş

runtime yeni bir IPC namespace oluşturduğunda, process kendi izole IPC identifier setini alır. Bu, `ipcs` gibi komutların yalnızca o namespace'te bulunan nesneleri gösterdiği anlamına gelir. Eğer container host IPC namespace'e katılırsa, bu nesneler paylaşılan global görünümün parçası haline gelir.

Bu durum özellikle uygulamaların veya servislerin paylaşılan belleği yoğun kullandığı ortamlarda önem kazanır. Container sadece IPC üzerinden doğrudan çıkış yapamasa bile, namespace bilgi leak edebilir veya süreçler arası müdahaleye izin vererek sonraki bir saldırıya maddi olarak yardımcı olabilir.

## Lab

Özel bir IPC namespace oluşturabilirsiniz:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Ve çalışma zamanı davranışını ... ile karşılaştırın:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Çalışma Zamanı Kullanımı

Docker ve Podman varsayılan olarak IPC'yi izole eder. Kubernetes genellikle Pod'a kendi IPC ad alanını verir; aynı Pod içindeki containers tarafından paylaşılır, ancak varsayılan olarak host ile paylaşılmaz. Host IPC paylaşımı mümkün olmakla birlikte, bu duruma izolasyonda önemsiz bir runtime seçeneği olarak değil, anlamlı bir azalma olarak yaklaşılmalıdır.

## Yanlış Yapılandırmalar

Bariz hata `--ipc=host` veya `hostIPC: true` kullanmaktır. Bu, legacy yazılımlarla uyumluluk veya kolaylık için yapılmış olabilir, ancak trust modelinde önemli değişiklikler yapar. Tekrarlayan başka bir sorun da IPC'nin, host PID veya host networking kadar dramatik hissettirmediği için gözden kaçırılmasıdır. Gerçekte, iş yükü tarayıcılar, veritabanları, bilimsel uygulamalar veya paylaşılan belleği yoğun kullanan diğer yazılımları çalıştırıyorsa, IPC yüzeyi çok önemli olabilir.

## Kötüye Kullanım

Host IPC paylaşıldığında, saldırgan paylaşılan bellek nesnelerini inceleyebilir veya müdahale edebilir, host veya komşu iş yükü davranışları hakkında yeni bilgiler edinebilir veya orada öğrenilen bilgileri işlem görünürlüğü ve ptrace tarzı yeteneklerle birleştirebilir. IPC paylaşımı genellikle tam bir breakout yolu yerine destekleyici bir zayıflıktır, ancak destekleyici zayıflıklar önemlidir çünkü gerçek saldırı zincirlerini kısaltır ve kararlı hale getirir.

İlk faydalı adım, hangi IPC nesnelerinin en başta görünür olduğunu listelemektir:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Ana makinenin IPC namespace'i paylaşılıyorsa, büyük paylaşılan bellek segmentleri veya ilginç nesne sahipleri uygulama davranışını hemen ortaya çıkarabilir:
```bash
ipcs -m -p
ipcs -q -p
```
Bazı ortamlarda, `/dev/shm` içeriği dosya adları, artifacts veya tokens leak edebilir; kontrol etmeye değer:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC paylaşımı nadiren tek başına anında host root sağlar, ancak daha sonraki process saldırılarını çok daha kolaylaştıran veri ve koordinasyon kanallarını açığa çıkarabilir.

### Tam Örnek: `/dev/shm` Gizli Bilgi Kurtarma

En gerçekçi tam kötüye kullanım durumu doğrudan escape yerine veri hırsızlığıdır. Eğer host IPC veya geniş bir shared-memory düzeni açığa çıkarsa, hassas artefaktlar bazen doğrudan kurtarılabilir:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Etkiler:

- paylaşılan bellekte kalan gizli bilgilerin veya oturum materyallerinin çıkarılması
- host üzerinde şu anda aktif olan uygulamalar hakkında bilgi edinme
- daha sonra yapılacak PID-namespace veya ptrace-based attacks için daha iyi hedefleme

IPC paylaşımı bu yüzden tek başına bir host-escape primitive olmaktan ziyade bir **saldırı güçlendiricisi** olarak daha iyi anlaşılmalıdır.

## Kontroller

Bu komutlar, workload'un özel bir IPC görünümüne sahip olup olmadığını, anlamlı paylaşılan bellek veya mesaj nesnelerinin görünür olup olmadığını ve `/dev/shm`'nin kendisinin kullanışlı artefaktlar açığa çıkarıp çıkarmadığını yanıtlamak için tasarlanmıştır.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
Burada dikkat çekenler:

- Eğer `ipcs -a` beklenmedik kullanıcılar veya servisler tarafından sahip olunan nesneleri gösteriyorsa, namespace beklenildiği kadar izole olmayabilir.
- Büyük veya alışılmadık paylaşılan bellek segmentleri genellikle araştırmaya değerdir.
- Geniş bir `/dev/shm` mount'u otomatik olarak bir hata değildir, ancak bazı ortamlarda dosya adlarını, artefaktları ve geçici sırları leaks.

IPC genellikle daha büyük namespace türleri kadar ilgi görmez, ancak onu yoğun kullanan ortamlarda host ile paylaşmak önemli bir güvenlik kararıdır.
{{#include ../../../../../banners/hacktricks-training.md}}
