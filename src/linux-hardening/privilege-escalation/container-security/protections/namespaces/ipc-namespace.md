# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

The IPC namespace isolates **System V IPC objects** and **POSIX message queues**. Bu, aksi halde host üzerindeki ilgisiz süreçler arasında görünür olacak paylaşılan bellek segmentleri, semaforlar ve mesaj kuyruklarını kapsar. Pratikte bu, bir konteynerin diğer iş yüklerine veya host'a ait IPC nesnelerine rastgele bağlanmasını engeller.

mount, PID, or user namespaces ile karşılaştırıldığında, IPC namespace genellikle daha az tartışılır; ancak bu, onun önemsiz olduğu anlamına gelmemelidir. Paylaşılan bellek ve ilgili IPC mekanizmaları son derece faydalı durum bilgileri içerebilir. Eğer host IPC namespace açığa çıkarsa, iş yükü konteyner sınırını aşması amaçlanmamış prosesler arası koordinasyon nesneleri veya verilere görünürlük kazanabilir.

## Çalışma Şekli

When the runtime creates a fresh IPC namespace, the process gets its own isolated set of IPC identifiers. Bu, `ipcs` gibi komutların sadece o namespace'de mevcut nesneleri gösterdiği anlamına gelir. Eğer konteyner bunun yerine host IPC namespace'e katılırsa, bu nesneler paylaşılan küresel görünümün parçası olur.

Bu, uygulamaların veya servislerin paylaşılan belleği yoğun kullandığı ortamlarda özellikle önemlidir. Konteyner IPC üzerinden tek başına doğrudan çıkış yapamasa bile, namespace bilgi leak'ine veya sonraki bir saldırıya önemli ölçüde yardımcı olabilecek prosesler arası müdahaleye olanak verebilir.

## Laboratuvar

You can create a private IPC namespace with:
```bash
sudo unshare --ipc --fork bash
ipcs
```
Ve çalışma zamanı davranışını şu ile karşılaştırın:
```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```
## Çalışma Zamanı Kullanımı

Docker ve Podman varsayılan olarak IPC'yi izole eder. Kubernetes tipik olarak Pod'a kendi IPC namespace'ini verir; aynı Pod içindeki container'lar arasında paylaşılır fakat varsayılan olarak host ile paylaşılmaz. Host IPC paylaşımı mümkündür, ancak bu bir runtime seçeneği olarak küçük bir tercih değil, izolasyonda anlamlı bir azalma olarak değerlendirilmelidir.

## Yanlış Yapılandırmalar

Açık hata `--ipc=host` veya `hostIPC: true` kullanmaktır. Bu, legacy yazılımlarla uyumluluk veya kullanım kolaylığı için yapılabilir, ancak güven modelini önemli ölçüde değiştirir. Tekrarlayan başka bir sorun ise IPC'yi gözden kaçırmaktır; çünkü host PID veya host networking kadar dramatik görünmeyebilir. Gerçekte, eğer iş yükü tarayıcılar, veritabanları, bilimsel uygulamalar veya paylaşılan bellek yoğun kullanan diğer yazılımlarla uğraşıyorsa, IPC yüzeyi oldukça önemli olabilir.

## Kötüye Kullanım

Host IPC paylaşıldığında, bir saldırgan paylaşılan bellek nesnelerini inceleyebilir veya müdahale edebilir, host veya komşu iş yükü davranışı hakkında yeni bilgiler edinebilir veya orada öğrenilen bilgileri süreç görünürlüğü ve ptrace-style yetenekleri ile birleştirebilir. IPC paylaşımı genellikle tam bir kaçış yolundan ziyade destekleyici bir zayıflıktır, ancak destekleyici zayıflıklar önemlidir çünkü gerçek saldırı zincirlerini kısaltır ve kararlı hale getirir.

İlk faydalı adım, hangi IPC nesnelerinin görünür olduğunu listelemektir:
```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```
Eğer host IPC namespace paylaşılıyorsa, büyük paylaşılan bellek segmentleri veya ilginç nesne sahipleri uygulama davranışını hemen ortaya çıkarabilir:
```bash
ipcs -m -p
ipcs -q -p
```
Bazı ortamlarda, `/dev/shm` içeriği kendi başına kontrol etmeye değer dosya adları, artifacts veya tokens leak edebilir:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```
IPC paylaşımı tek başına nadiren doğrudan host root sağlar, ancak sonraki işlem saldırılarını çok daha kolay hale getiren veri ve koordinasyon kanallarını açığa çıkarabilir.

### Tam Örnek: `/dev/shm` Gizli Bilgi Kurtarma

En gerçekçi tam kötüye kullanım vakası doğrudan kaçıştan ziyade veri hırsızlığıdır. Host IPC veya geniş bir paylaşılan bellek düzeni açığa çıkarsa, hassas artefaktlar bazen doğrudan kurtarılabilir:
```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```
Etki:

- paylaşılan bellekte kalan sırların veya oturum materyalinin çıkarılması
- host üzerinde şu anda aktif olan uygulamalar hakkında içgörü
- sonraki PID-namespace veya ptrace tabanlı saldırılar için daha iyi hedefleme

IPC paylaşımı bu nedenle bağımsız bir host-escape primitive'den ziyade bir **saldırı güçlendiricisi** olarak daha iyi anlaşılmalıdır.

## Kontroller

Bu komutlar, iş yükünün özel bir IPC görünümüne sahip olup olmadığını, anlamlı paylaşılan bellek veya mesaj nesnelerinin görünür olup olmadığını ve `/dev/shm`'in kendisinin yararlı artifaktlar açığa çıkarıp çıkarmadığını yanıtlamak içindir.
```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```
What is interesting here:

- If `ipcs -a` reveals objects owned by unexpected users or services, the namespace may not be as isolated as expected.
- Büyük veya olağandışı paylaşılan bellek segmentleri genellikle araştırılmaya değerdir.
- Geniş bir `/dev/shm` mount'u otomatik olarak bir bug değildir, ancak bazı ortamlarda it leaks dosya adlarını, artefaktları ve geçici sırları.

IPC genellikle daha büyük namespace türleri kadar ilgi görmez, ancak bunu yoğun şekilde kullanan ortamlarda host ile paylaşılması büyük ölçüde bir güvenlik kararıdır.
