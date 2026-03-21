# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

cgroup namespace, cgroup'ları değiştirmez ve kendisi kaynak sınırlamalarını uygulamaz. Bunun yerine, işlemin gördüğü **cgroup hiyerarşisinin nasıl göründüğünü** değiştirir. Başka bir deyişle, görünen cgroup yol bilgisini sanallaştırır; böylece çalışma yükü tam host hiyerarşisi yerine konteyner'e özgü bir görünüm görür.

Bu esasen bir görünürlük ve bilgi azaltma özelliğidir. Ortamın kendi içinde kapalı görünmesine yardımcı olur ve host'un cgroup düzeni hakkında daha az bilgi açığa çıkarır. Bu önemsiz gibi gelebilir, ama gereksiz host yapısı görünürlüğü keşif faaliyetlerine yardımcı olabilir ve ortama bağlı exploit zincirlerini basitleştirebilir, bu yüzden önemlidir.

## İşleyiş

Özel bir cgroup namespace'i olmadan, bir süreç host'a göreli cgroup yollarını görebilir ve bu da makinenin hiyerarşisinin gereğinden fazla kısmını açığa çıkarır. Özel bir cgroup namespace ile `/proc/self/cgroup` ve ilgili gözlemler konteynerin kendi görünümüne daha yerel hale gelir. Bu, çalışma yükünün daha temiz ve host'u daha az ifşa eden bir ortam görmesini isteyen modern runtime yığınlarında özellikle faydalıdır.

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
Değişiklik büyük ölçüde işlemin neleri görebildiğiyle ilgilidir, cgroup enforcement'ın varlığıyla değil.

## Security Impact

The cgroup namespace en iyi şekilde bir **görünürlük-sertleştirme katmanı** olarak anlaşılmalıdır. Tek başına, eğer container'da yazılabilir cgroup mount'ları, geniş capabilities veya tehlikeli bir cgroup v1 environment varsa breakout'u durdurmaz. Ancak, host cgroup namespace paylaşılıyorsa, işlem sistemin nasıl düzenlendiği hakkında daha fazla bilgi edinir ve host-relative cgroup yollarını diğer gözlemlerle hizalamayı daha kolay bulabilir.

Bu namespace genellikle container breakout yazılarının yıldızı olmasa da, host hakkında bilgi sızıntısını en aza indirme gibi daha geniş hedefe yine de katkı sağlar.

## Abuse

The immediate abuse value is mostly reconnaissance. Eğer host cgroup namespace paylaşılıyorsa, görünen yolları karşılaştırın ve host'u açığa çıkaran hiyerarşi detaylarına bakın:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```
Yazılabilir cgroup yolları da açığa çıktıysa, bu görünürlüğü tehlikeli eski arayüzleri aramakla birleştirin:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
namespace'ın kendisi nadiren anında escape sağlar, ancak genellikle cgroup-based abuse primitives'i test etmeden önce ortamı haritalamayı kolaylaştırır.

### Tam Örnek: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace tek başına genellikle escape için yeterli değildir. Pratik escalation, host-revealing cgroup paths ile writable cgroup v1 interfaces birleştirildiğinde gerçekleşir:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Eğer bu dosyalara erişilebiliyor ve yazılabiliyorsa, hemen [cgroups.md](../cgroups.md)'deki tam `release_agent` exploitation flow'a pivot yapın. Etki, container içinden host üzerinde kod yürütmedir.

Yazılabilir cgroup arayüzleri yoksa, etki genellikle sadece reconnaissance ile sınırlıdır.

## Kontroller

Bu komutların amacı, işlemin özel bir cgroup namespace görünümüne sahip olup olmadığını veya gerçekte ihtiyaç duyduğundan daha fazla host hiyerarşisi hakkında bilgi edinip edinmediğini görmektir.
```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```
- Eğer namespace tanımlayıcısı ilgilendiğiniz bir host işlemiyle eşleşiyorsa, cgroup namespace paylaşılmış olabilir.
- `/proc/self/cgroup` içindeki host bilgisi açığa çıkaran yollar, doğrudan sömürülebilir olmasalar bile faydalı reconnaissance sağlar.
- Eğer cgroup mounts aynı zamanda yazılabilirse, görünürlük meselesi çok daha önemli hale gelir.

cgroup namespace, birincil bir escape-prevention mekanizması olarak değil, visibility-hardening katmanı olarak ele alınmalıdır. Host cgroup yapısını gereksiz yere açığa çıkarmak, saldırgan için reconnaissance değerini artırır.
