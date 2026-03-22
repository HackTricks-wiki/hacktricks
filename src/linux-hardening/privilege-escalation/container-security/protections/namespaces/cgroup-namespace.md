# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

cgroup namespace, cgroup'ların yerine geçmez ve kendisi kaynak limitlerini uygulamaz. Bunun yerine, bir sürecin **cgroup hiyerarşisini nasıl gördüğünü** değiştirir. Başka bir deyişle, görünür cgroup yol bilgilerini sanallaştırır; böylece iş yükü tam host hiyerarşisini değil container-ölçekli bir görünümü görür.

Bu esasen görünürlük ve bilgi azaltma özelliğidir. Ortamın kendine yeten görünmesini sağlar ve host'un cgroup düzeni hakkında daha az bilgi açığa çıkarır. Bu önemsiz görünebilir, ancak gereksiz host yapı görünürlüğü keşif yapılmasını kolaylaştırabilir ve ortama bağımlı exploit zincirlerini basitleştirebilir.

## İşleyiş

Özel bir cgroup namespace'i olmadan bir süreç, makinenin hiyerarşisinin gerektiğinden daha fazlasını açığa çıkaran host-relatif cgroup yollarını görebilir. Özel bir cgroup namespace ile `/proc/self/cgroup` ve ilgili gözlemler container'ın kendi bakış açısına daha lokal hale gelir. Bu, iş yükünün daha temiz, host'u daha az ifşa eden bir ortam görmesini isteyen modern runtime yığınlarında özellikle faydalıdır.

## Laboratuvar

Bir cgroup namespace'ini şu şekilde inceleyebilirsiniz:
```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```
Ve çalışma zamanı davranışını şununla karşılaştırın:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Bu değişiklik çoğunlukla sürecin ne görebileceğiyle ilgilidir; cgroup enforcement'ın varlığıyla ilgili değildir.

## Güvenlik Etkisi

cgroup namespace en iyi bir **görünürlük-sıkılaştırma katmanı** olarak anlaşılır. Tek başına, container'ın writable cgroup mounts'a, geniş capabilities'e veya tehlikeli bir cgroup v1 ortamına sahip olması durumunda bir breakout'u durdurmaz. Ancak host cgroup namespace paylaşılıyorsa, süreç sistemin nasıl organize edildiği hakkında daha fazla bilgi edinir ve host-relative cgroup paths'i diğer gözlemlerle hizalamayı daha kolay bulabilir.

Dolayısıyla bu namespace genellikle container breakout writeups'ın yıldızı olmasa da, host information leakage'ını minimize etme gibi daha geniş bir hedefe katkıda bulunur.

## Kötüye Kullanım

Anlık abuse değeri büyük ölçüde reconnaissance ile sınırlıdır. Eğer host cgroup namespace paylaşılıyorsa, görünür yolları karşılaştırın ve host-revealing hiyerarşi detaylarına bakın:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Eğer yazılabilir cgroup yolları da açığa çıkmışsa, bu görünürlüğü tehlikeli eski arayüzleri aramakla birleştirin:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Namespace kendisi nadiren anında escape sağlar, ancak cgroup-based abuse primitives'i test etmeden önce ortamı haritalamayı sıklıkla kolaylaştırır.

### Tam Örnek: Shared cgroup Namespace + Writable cgroup v1

Cgroup namespace tek başına genellikle escape için yeterli değildir. Pratik yükseltme, host-revealing cgroup paths ile writable cgroup v1 interfaces'in birleşmesiyle gerçekleşir:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Eğer bu dosyalara erişilebiliyor ve yazılabiliyorsa, hemen [cgroups.md](../cgroups.md) içindeki tam `release_agent` exploitation akışına geçin. Etkisi, container içinden host üzerinde kod çalıştırmadır.

Yazılabilir cgroup arabirimleri yoksa, etki genellikle sadece keşif ile sınırlıdır.

## Kontroller

Bu komutların amacı, işlemin özel bir cgroup namespace görünümüne sahip olup olmadığını veya host hiyerarşisi hakkında gerçekten ihtiyaç duyduğundan daha fazlasını öğrenip öğrenmediğini kontrol etmektir.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
Burada ilginç olan:

- Eğer namespace identifier ilgilendiğiniz bir host process ile eşleşiyorsa, cgroup namespace paylaşılmış olabilir.
- `/proc/self/cgroup` içindeki host'u ifşa eden yollar, doğrudan istismar edilemeseler bile faydalı keşif sağlar.
- Eğer cgroup mounts aynı zamanda yazılabiliyorsa, görünürlük meselesi çok daha önemli hale gelir.

cgroup namespace, birincil bir kaçış-önleme mekanizması yerine görünürlüğü sertleştiren bir katman olarak ele alınmalıdır. Host cgroup yapısını gereksiz yere açığa çıkarmak saldırgan için keşif değerini artırır.
{{#include ../../../../../banners/hacktricks-training.md}}
