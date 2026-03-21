# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Time namespace, özellikle **`CLOCK_MONOTONIC`** ve **`CLOCK_BOOTTIME`** olmak üzere seçilmiş saatleri sanallaştırır. mount, PID, network, or user namespaces'den daha yeni ve daha özelleşmiş bir namespace'tir ve konteyner sertleştirmesi konuşulurken bir operatörün genellikle ilk aklına gelen şey değildir. Yine de modern namespace ailesinin bir parçasıdır ve kavramsal olarak anlaşılmaya değerdir.

Ana amaç, bir sürecin host'un küresel zaman görünümünü değiştirmeden belirli saatler için kontrollü kaymaları gözlemlemesine izin vermektir. Bu, checkpoint/restore iş akışları, deterministik testler ve bazı gelişmiş runtime davranışları için faydalıdır. Genellikle mount veya user namespaces gibi başlıca bir izolasyon kontrolü olarak görülmez, ancak yine de süreç ortamını daha kendi kendine yeten hale getirmeye katkıda bulunur.

## Laboratuvar

Host çekirdeği ve kullanıcı alanı bunu destekliyorsa, namespace'i şu şekilde inceleyebilirsiniz:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
```
Destek, çekirdek ve araç sürümlerine göre değişir; bu yüzden bu sayfa, her laboratuvar ortamında görüleceğini beklemektense mekanizmayı anlamaya yöneliktir.

### Zaman Ofsetleri

Linux zaman namespace'leri `CLOCK_MONOTONIC` ve `CLOCK_BOOTTIME` için ofsetleri sanallaştırır. Her namespace'e ait mevcut ofsetler `/proc/<pid>/timens_offsets` üzerinden görüntülenir; destekleyen çekirdeklerde ilgili namespace içinde `CAP_SYS_TIME` yetkisine sahip bir süreç tarafından da değiştirilebilir:
```bash
sudo unshare -Tr --mount-proc bash
cat /proc/$$/timens_offsets
echo "monotonic 172800000000000" > /proc/$$/timens_offsets
cat /proc/uptime
```
Dosya nanosaniye farkları içerir. `monotonic`'i iki gün ayarlamak, ana makinenin duvar saatini değiştirmeden o namespace içindeki uptime-benzeri gözlemleri değiştirir.

### `unshare` Yardımcı Seçenekler

Son `util-linux` sürümleri, offset'leri otomatik olarak yazan kullanışlı seçenekler sağlar:
```bash
sudo unshare -T --monotonic="+24h" --boottime="+7d" --mount-proc bash
```
Bu bayraklar çoğunlukla kullanılabilirliği artırır, ancak dokümantasyon ve testlerde özelliğin tanınmasını da kolaylaştırır.

## Çalışma Zamanı Kullanımı

`time` namespace'ları, mount veya PID namespace'lerine göre daha yeni ve daha az yaygın olarak kullanılıyor. OCI Runtime Specification v1.1, `time` namespace ve `linux.timeOffsets` alanı için açık destek ekledi; daha yeni `runc` sürümleri modelin bu kısmını uyguluyor. Minimal bir OCI fragmanı şöyle görünür:
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

Diğer namespace türlerine kıyasla time namespace etrafında daha az klasik breakout hikâyesi vardır. Buradaki risk genellikle time namespace'in doğrudan escape'e izin vermesi değil, okuyucuların onu tamamen göz ardı etmesi ve bu yüzden gelişmiş runtimes'ın süreç davranışını nasıl şekillendirebileceğini kaçırmalarıdır. Özelleşmiş ortamlarda, değişmiş saat görünümleri checkpoint/restore, observability veya forensic varsayımlarını etkileyebilir.

## Kötüye Kullanım

Genellikle burada doğrudan bir breakout primitive yoktur, ancak değişmiş saat davranışı yine de yürütme ortamını anlamak ve gelişmiş runtime özelliklerini tespit etmek için yararlı olabilir:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
date
cat /proc/uptime
```
If you are comparing two processes, differences here can help explain odd timing behavior, checkpoint/restore artifacts, or environment-specific logging mismatches.

Impact:

- neredeyse her zaman reconnaissance veya ortamın anlaşılması
- logging, uptime veya checkpoint/restore anomalilerini açıklamak için faydalıdır
- normalde tek başına doğrudan bir container-escape mekanizması değildir

Önemli kötüye kullanım nüansı şudur: time namespaces `CLOCK_REALTIME`'ı sanallaştırmaz, bu yüzden tek başlarına bir saldırganın host duvar saatini sahtelemesine veya sistem genelinde certificate-expiry kontrollerini doğrudan bozmasına izin vermezler. Değerleri çoğunlukla monotonik zamana dayalı mantığı karıştırmak, ortama özgü hataları yeniden üretmek veya gelişmiş runtime davranışını anlamaktır.

## Checks

Bu kontroller çoğunlukla runtime'ın özel bir time namespace kullanıp kullanmadığını doğrulamaya yöneliktir.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
```
Burada ilginç olanlar:

- Birçok ortamda bu değerler doğrudan bir güvenlik bulgusuna yol açmayabilir, ancak özel bir runtime özelliğinin devrede olup olmadığını size söyler.
- Eğer iki süreci karşılaştırıyorsanız, buradaki farklılıklar kafa karıştıran zamanlama veya checkpoint/restore davranışını açıklayabilir.

Çoğu container breakout için time namespace ilk inceleyeceğiniz kontrol değildir. Yine de, eksiksiz bir container-security bölümü bunu belirtmelidir çünkü modern kernel modelinin bir parçasıdır ve zaman zaman gelişmiş runtime senaryolarında önem taşır.
