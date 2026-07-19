# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Time namespace, host wall clock yerine seçili monotonic-style clock'ları sanallaştırır. Pratikte bu, **`CLOCK_MONOTONIC`** ve **`CLOCK_BOOTTIME`** için private offset'ler ile bunlarla yakından ilişkili **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** ve **`CLOCK_BOOTTIME_ALARM`** görünümleri anlamına gelir. **`CLOCK_REALTIME`** sanallaştırılmaz; bu nedenle başka bir mekanizma müdahale etmediği sürece `date` ve certificate-expiry mantığı host wall clock'u gözlemler.

Temel amaç, bir process'in host'un global time görünümünü değiştirmeden kontrollü elapsed-time offset'lerini gözlemlemesini sağlamaktır. Bu özellik checkpoint/restore workflow'ları, deterministic testing ve gelişmiş runtime davranışları için kullanışlıdır. Genellikle mount veya user namespace'ler kadar öne çıkan bir isolation control değildir, ancak process ortamının daha self-contained hâle getirilmesine katkıda bulunur.

Offensive açıdan bu namespace, doğrudan bir breakout'tan çok **reconnaissance, timer skew ve runtime understanding** için önemlidir. Yine de önemi vardır; çünkü daha fazla container runtime'ı ve checkpoint/restore workflow'u artık bunu açıkça talep edebilmektedir.

## Lab

Host kernel'i ve userspace destekliyorsa namespace'i şu şekilde inceleyebilirsiniz:
```bash
sudo unshare --time --fork bash
ls -l /proc/self/ns/time /proc/self/ns/time_for_children
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
cat /proc/uptime
date
```
Destek, kernel ve araç sürümlerine göre değişir; bu nedenle bu sayfa, mekanizmayı anlamaya odaklanır ve her lab ortamında görünür olmasını beklemez. Önemli gözlem, `date` değerinin host wall clock değerini yansıtmaya devam etmesi; nonzero offset yapılandırıldığında değişen değerlerin ise monotonic/boottime tabanlı değerler olmasıdır.

### Oluşturma Nuance'ı

Time namespace'ler, mount, PID veya network namespace'lere kıyasla biraz sıra dışıdır:

- `unshare(CLONE_NEWTIME)`, **gelecekte oluşturulacak child'lar** için yeni bir time namespace oluşturur.
- Çağrıyı yapan task, mevcut time namespace'inde kalır.
- Bu nedenle runtime setup'ı debug edilirken `/proc/<pid>/ns/time_for_children`, `/proc/<pid>/ns/time` değerinden genellikle daha ilgi çekicidir.

Write window da özeldir. `/proc/<pid>/timens_offsets` içindeki offset'ler, yeni time namespace'i çalışan task'larla tamamen doldurulmadan önce yazılmalıdır; pratikte runtime'lar bunu namespace oluşturma ile son payload'u başlatma arasındaki dar setup window sırasında yapar. Bir task burada zaten çalışıyorsa sonraki write işlemleri `EACCES` ile başarısız olur. Bu nedenle low-level runtime'lar time-namespace setup'ını, zaten başlatılmış bir container process'inin içinden offset'leri patch etmeye çalışmak yerine, erken bir bootstrap adımı olarak ele alır.

### Time Offset'leri

Linux time namespace'ler, namespace'e özel offset'leri `/proc/<pid>/timens_offsets` üzerinden sunar. Format; clock name veya ID'lerinden ve initial time namespace'e göre saniye/nanosaniye delta değerlerinden oluşur.

Pratikte, user-facing en güvenilir workflow, bu offset'leri sizin için `unshare`'ın yazmasını sağlamaktır:
```bash
sudo unshare -UrT --fork --mount-proc --monotonic 86400 --boottime 604800 bash
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
Önemli nokta tam komut sözdizimi değil, davranıştır: Bir container, host wall clock değerini değiştirmeden farklı bir uptime benzeri görünüm gözlemleyebilir.

### `unshare` Helper Flags

Güncel `util-linux` sürümleri, namespace oluşturma sırasında offset değerlerini otomatik olarak yazan kolaylık bayrakları sağlar:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Bu flag'ler çoğunlukla kullanım kolaylığı sağlar; ancak özelliğin documentation, test harness'leri ve runtime wrapper'larında tanınmasını da kolaylaştırır.

## Runtime Kullanımı

Time namespace'leri, mount veya PID namespace'lerine kıyasla daha yenidir ve daha az evrensel olarak kullanılır. OCI Runtime Specification v1.1, `time` namespace'i ve `linux.timeOffsets` alanı için açık destek ekledi; modern runtime'lar bu verileri kernel bootstrap akışına aktarabilir. Minimal bir OCI parçası şöyledir:
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
Bu önemlidir çünkü time namespacing'i niş bir kernel primitive'inden runtime'ların taşınabilir şekilde talep edebileceği bir özelliğe dönüştürür. Ayrıca runtime internals'ın neden açık bir synchronization adımına ihtiyaç duyduğunu da açıklar: container payload tamamen yeni namespace'e girmeden önce offset, `/proc/<pid>/timens_offsets` konumuna yazılmalıdır.

CRIU gibi checkpoint/restore stack'leri, bunun gerçekte var olmasının başlıca nedenlerinden biridir. Time namespaces olmadan, askıya alınmış bir workload'u geri yüklemek monotonic ve boot-time clock'larının, workload'un suspend durumda kaldığı süre kadar ileri sıçramasına neden olur.

## Güvenlik Etkisi

Diğer namespace türlerine kıyasla time namespace merkezli klasik breakout hikâyeleri daha azdır. Buradaki risk genellikle time namespace'in doğrudan escape sağlaması değil, okuyucuların bunu tamamen göz ardı ederek gelişmiş runtime'ların process davranışını nasıl şekillendirebileceğini gözden kaçırmasıdır.

Özelleştirilmiş ortamlarda, değiştirilmiş monotonic veya boottime görünümleri şunları etkileyebilir:

- timeout ve retry davranışı
- watchdog'lar ve lease mantığı
- `timerfd`, `nanosleep` ve `clock_nanosleep` davranışı
- checkpoint/restore forensics
- elapsed-time telemetry ve uptime tabanlı heuristics

Bu nedenle genellikle abuse edeceğiniz ilk namespace olmasa da assessment sırasında "imkânsız" görünen timing davranışlarını kesinlikle açıklayabilir.

## Kötüye Kullanım

Burada genellikle doğrudan bir breakout primitive'i yoktur; ancak değiştirilmiş clock davranışı execution environment'ı anlamak, gelişmiş runtime özelliklerini tespit etmek ve wall clock time yerine monotonic clock'lara göre ölçülen timer tabanlı mantığı fark etmek için yine de yararlı olabilir:
```bash
readlink /proc/self/ns/time
readlink /proc/self/ns/time_for_children
cat /proc/$$/timens_offsets 2>/dev/null
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
print("uptime   :", open("/proc/uptime").read().split()[0])
PY
```
İki process'i karşılaştırıyorsanız buradaki farklılıklar, garip zamanlama davranışlarını, checkpoint/restore kalıntılarını veya ortama özgü logging uyumsuzluklarını açıklamaya yardımcı olabilir.

Pratik, attacker açısından önemli noktalar:

- monotonic clock'larla uygulanan backoff, sleep veya watchdog mantığını şaşırtmak
- `/proc/uptime` ve timer-driven davranışların host tarafındaki wall-clock beklentileriyle neden uyuşmadığını açıklamak
- CRIU/checkpoint-restore workflow'larını ve diğer gelişmiş runtime özelliklerini tanımak
- debugging veya post-exploitation amacıyla `nsenter -T -t <pid> -- ...` ile bir target time namespace'e katılmanın container'a özgü timer davranışını yeniden üretip üretemeyeceğini tespit etmek

Etki:

- neredeyse her zaman reconnaissance veya ortamı anlamaya yöneliktir
- logging, uptime veya checkpoint/restore anomalilerini açıklamak için faydalıdır
- monotonic-time tabanlı sleep, retry ve timer'ları analiz etmek için faydalıdır
- tek başına normalde doğrudan bir container-escape mekanizması değildir

Önemli abuse ayrıntısı, time namespace'lerin `CLOCK_REALTIME` değerini virtualize etmemesidir. Bu nedenle tek başlarına bir attacker'ın host wall clock değerini sahteleştirmesine veya sistem genelinde certificate-expiry kontrollerini doğrudan bozmasına izin vermezler. Değerleri çoğunlukla monotonic-time tabanlı mantığı şaşırtmak, ortama özgü bug'ları yeniden üretmek veya gelişmiş runtime davranışını anlamaktır.

## Checks

Bu kontroller temel olarak runtime'ın private bir time namespace kullanıp kullanmadığını ve gerçekten sıfır olmayan offset'ler ayarlayıp ayarlamadığını doğrulamaya yöneliktir.
```bash
readlink /proc/self/ns/time                 # Current time namespace identifier
readlink /proc/self/ns/time_for_children    # Time namespace inherited by children
cat /proc/$$/timens_offsets 2>/dev/null     # Monotonic and boottime offsets when supported
lsns -t time 2>/dev/null                    # Host-side inventory when available
python3 - <<'PY'
import time
print("realtime :", time.time())
print("monotonic:", time.clock_gettime(time.CLOCK_MONOTONIC))
print("boottime :", time.clock_gettime(time.CLOCK_BOOTTIME))
PY
```
Burada ilginç olanlar:

- Birçok ortamda bu değerler hemen bir security finding oluşturmaz, ancak özel bir runtime özelliğinin kullanılıp kullanılmadığını gösterir.
- `time_for_children`, `time` değerinden farklıysa, caller kendisinin girmediği, yalnızca child süreçler için hazırlanmış bir time namespace oluşturmuş olabilir.
- `date` host ile eşleşiyor, ancak monotonic/boottime tabanlı değerler eşleşmiyorsa, muhtemelen wall-clock tampering yerine time namespacing ile karşı karşıyasınızdır.
- İki process karşılaştırıyorsanız, buradaki farklılıklar kafa karıştırıcı timing veya checkpoint/restore davranışını açıklayabilir.

Çoğu container breakout senaryosunda time namespace, inceleyeceğiniz ilk kontrol değildir. Yine de modern kernel modelinin bir parçası olduğu ve gelişmiş runtime senaryolarında zaman zaman önemli olabildiği için eksiksiz bir container-security bölümü bundan bahsetmelidir.

## Referanslar

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
