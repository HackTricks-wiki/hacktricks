# Zaman İsim Alanı

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Zaman isim alanı seçili saatleri sanallaştırır, özellikle **`CLOCK_MONOTONIC`** ve **`CLOCK_BOOTTIME`**. mount, PID, network veya user isim alanlarından daha yeni ve daha özelleşmiş bir isim alanıdır ve konteyner sertleştirmesi tartışılırken bir işletmecinin genellikle ilk aklına gelen şey değildir. Buna rağmen modern isim alanı ailesinin bir parçasıdır ve kavramsal olarak anlaşılmaya değerdir.

Ana amaç, bir sürecin ana makinenin genel zaman görünümünü değiştirmeden belirli saatler için kontrollü ofsetleri gözlemlemesine izin vermektir. Bu, checkpoint/restore iş akışları, deterministik testler ve bazı gelişmiş runtime davranışları için faydalıdır. Genellikle mount veya user isim alanları gibi başlıca bir izolasyon kontrolü olarak öne çıkmaz, ancak süreç ortamının daha kendi kendine yeten hale gelmesine yine de katkı sağlar.

## Lab

Eğer host kernel ve userspace bunu destekliyorsa, isim alanını şu komutla inceleyebilirsiniz:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Support varies by kernel and tool versions, so this page is more about understanding the mechanism than expecting it to be visible in every lab environment.

### Zaman Ofsetleri

Linux time namespace'leri `CLOCK_MONOTONIC` ve `CLOCK_BOOTTIME` için ofsetleri sanallaştırır. Mevcut her-namespace ofsetleri `/proc/<pid>/timens_offsets` üzerinden açığa çıkarılır; destekleyen kernel'lerde ilgili namespace içinde `CAP_SYS_TIME` sahibi bir süreç tarafından da değiştirilebilir:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Dosya nanosaniye farkları içeriyor. `monotonic`'i iki gün ayarlamak, host duvar saatini değiştirmeden o namespace içindeki uptime-benzeri gözlemleri değiştirir.

### `unshare` Yardımcı Bayraklar

Güncel `util-linux` sürümleri, offsetleri otomatik olarak yazan yardımcı bayraklar sağlar:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Bu bayraklar büyük ölçüde kullanılabilirlik iyileştirmesidir, ancak belgelerde ve testlerde özelliğin tanınmasını da kolaylaştırır.

## Çalışma Zamanı Kullanımı

`time` namespace'ları mount veya PID namespace'lerine göre daha yeni ve daha az yaygın olarak kullanılıyor. OCI Runtime Specification v1.1, `time` namespace'i ve `linux.timeOffsets` alanı için açık destek ekledi; daha yeni `runc` sürümleri modelin bu bölümünü uyguluyor. Minimal bir OCI fragmanı şöyle görünür:
```json
{
"linux": {
"namespaces": [
{ "type": "time" }
],
"timeOffsets": {
"monotonic": 86400,
"boottime": 600
}
}
}
```
Bu önemlidir çünkü time namespacing'i niş bir kernel primitive'inden runtimes'ın taşınabilir şekilde talep edebileceği bir şeye dönüştürür.

## Güvenlik Etkisi

Diğer namespace türlerine kıyasla time namespace etrafında klasik breakout hikâyeleri daha azdır. Buradaki risk genellikle time namespace'in doğrudan escape sağlaması değil; asıl risk, ilgililerin onu tamamen görmezden gelmesi ve bu nedenle gelişmiş runtimes'ın süreç davranışını nasıl şekillendirebileceğini kaçırmalarıdır. Özelleşmiş ortamlarda değiştirilmiş saat görünümleri checkpoint/restore, observability veya adli varsayımları etkileyebilir.

## Kötüye Kullanım

Genellikle burada doğrudan bir breakout primitive'i yoktur, ancak değiştirilmiş saat davranışı yürütme ortamını anlamak ve gelişmiş runtime özelliklerini tespit etmek için yine de faydalı olabilir:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
İki işlemi karşılaştırıyorsanız, burada görülen farklar garip zamanlama davranışlarını, checkpoint/restore artefaktlarını veya ortama özgü günlük uyuşmazlıklarını açıklamaya yardımcı olabilir.

Impact:

- neredeyse her zaman keşif veya ortamın anlaşılması
- logging, uptime veya checkpoint/restore anomalilerini açıklamak için faydalı
- kendi başına normalde doğrudan bir container-escape mekanizması değildir

Önemli kötüye kullanım nüansı, time namespace'lerinin `CLOCK_REALTIME`'i sanallaştırmamasıdır; bu yüzden tek başlarına bir saldırganın host duvar saatini tahrif etmesine veya sertifika-süresi-dolma kontrollerini sistem genelinde doğrudan bozmasına izin vermezler. Değerleri çoğunlukla monotonik-zamana dayalı mantığı karıştırmak, ortama özgü hataları yeniden üretmek veya gelişmiş runtime davranışını anlamaktır.

## Checks

Bu kontrollerin çoğu, runtime'ın özel bir time namespace kullanıp kullanmadığını doğrulamaya yöneliktir.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Burada ilginç olanlar:

- Birçok ortamda bu değerler doğrudan bir güvenlik bulgusuna yol açmayabilir, ancak özel bir runtime özelliğinin devrede olup olmadığını gösterir.
- İki işlemi karşılaştırıyorsanız, buradaki farklar kafa karıştırıcı zamanlama veya checkpoint/restore davranışını açıklayabilir.

Çoğu container breakouts için, time namespace inceleyeceğiniz ilk kontrol değildir. Yine de eksiksiz bir container-security bölümü bundan bahsetmelidir; çünkü bu, modern kernel modelinin bir parçasıdır ve ara sıra gelişmiş runtime senaryolarında önem taşır.
{{#include ../../../../../banners/hacktricks-training.md}}
