# Zaman Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Time namespace, host wall clock yerine seçili monotonic-style clock'ları virtualize eder. Pratikte bu, **`CLOCK_MONOTONIC`** ve **`CLOCK_BOOTTIME`** için private offset'ler ile bunlarla yakından ilişkili **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** ve **`CLOCK_BOOTTIME_ALARM`** görünümleri anlamına gelir. **`CLOCK_REALTIME`** virtualize edilmez; bu nedenle başka bir mekanizma müdahale etmediği sürece `date` ve certificate-expiry logic, host wall clock'u gözlemlemeye devam eder.<sup>[[1]](#references)</sup>

Temel amaç, bir process'in host'un global time view'ını değiştirmeden kontrollü elapsed-time offset'lerini gözlemlemesini sağlamaktır. Bu özellik checkpoint/restore workflow'ları, deterministic testing ve advanced runtime behavior için kullanışlıdır. Genellikle mount veya user namespaces ile aynı düzeyde öne çıkan bir isolation control değildir, ancak process environment'ını daha self-contained hâle getirmeye yine de katkı sağlar.

Offensive açıdan bu namespace, doğrudan bir breakout'tan ziyade genellikle **reconnaissance, timer skew ve runtime understanding** için daha önemlidir. Yine de daha fazla container runtime ve checkpoint/restore workflow'u artık bunu açıkça request edebildiği için önem taşır.

## Lab

Host kernel ve userspace bunu destekliyorsa namespace'i şu şekilde inspect edebilirsiniz:
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
Destek kernel ve tool sürümlerine göre değişir; bu nedenle bu sayfa, her lab ortamında görünür olmasını beklemekten çok mekanizmayı anlamaya yöneliktir. Önemli gözlem, `date` değerinin hâlâ host wall clock değerini yansıtması gerekirken, sıfır olmayan offset'ler yapılandırıldığında değişen değerlerin monotonic/boottime tabanlı değerler olmasıdır.

### Oluşturma Ayrıntısı

Time namespace'ler, mount, PID veya network namespace'lerine kıyasla biraz sıra dışıdır:<sup>[[1]](#references)</sup>

- `unshare(CLONE_NEWTIME)`, **gelecekteki child process'ler** için yeni bir time namespace oluşturur.
- Çağrıyı yapan task mevcut time namespace'inde kalır.
- Bu nedenle runtime setup'ı debug ederken `/proc/<pid>/ns/time_for_children`, `/proc/<pid>/ns/time` değerinden genellikle daha ilgi çekicidir.

Write window da özeldir. `/proc/<pid>/timens_offsets` içindeki offset'ler, yeni time namespace'i çalışan task'lerle tamamen doldurulmadan önce yazılmalıdır; pratikte runtime'lar bunu namespace oluşturma ile final payload'ı başlatma arasındaki dar setup window sırasında yapar. Bir task burada zaten çalışıyorsa sonraki write işlemleri `EACCES` ile başarısız olur. Bu nedenle low-level runtime'lar time-namespace setup işlemini, zaten başlatılmış bir container process içinden offset'leri patch etmeye çalışmak yerine, erken bir bootstrap adımı olarak ele alır.<sup>[[1]](#references)</sup>

### Time Offset'leri

Linux time namespace'leri, namespace başına offset'leri `/proc/<pid>/timens_offsets` üzerinden sunar. Format, initial time namespace'e göre saniye/nanosaniye delta'larıyla birlikte bir dizi clock adı veya ID'den oluşur.<sup>[[1]](#references)</sup>

Pratikte, user-facing en güvenilir workflow, bu offset'leri sizin için `unshare` komutunun yazmasını sağlamaktır:
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
Önemli nokta tam komut söz dizimi değil, davranıştır: Bir container, host wall clock'unu değiştirmeden farklı bir uptime benzeri görünüm gözlemleyebilir.

### `unshare` Helper Flag'leri

Güncel `util-linux` sürümleri, namespace oluşturma sırasında offset'leri otomatik olarak yazan kolaylık flag'leri sağlar:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Bu flag'ler çoğunlukla kullanılabilirlik iyileştirmesidir; ancak özelliğin dokümantasyonda, test harness'lerinde ve runtime wrapper'larında tanınmasını da kolaylaştırır.

## Runtime Kullanımı

Time namespace'ler, mount veya PID namespace'lerine kıyasla daha yenidir ve daha az kapsamlı şekilde kullanılır. OCI Runtime Specification v1.1, `time` namespace'i ve `linux.timeOffsets` alanı için açık destek ekledi; modern runtime'lar bu veriyi kernel bootstrap akışına aktarabilir. Minimal bir OCI parçası şöyledir:
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
Bu önemlidir çünkü time namespacing'i niş bir kernel primitive'inden runtime'ların portably isteyebileceği bir özelliğe dönüştürür. Ayrıca runtime internals'ın neden açık bir synchronization adımına ihtiyaç duyduğunu da açıklar: container payload yeni namespace'e tamamen girmeden önce offset'in `/proc/<pid>/timens_offsets` dosyasına yazılması gerekir.

CRIU gibi checkpoint/restore stack'leri bunun var olmasının başlıca gerçek dünya nedenlerinden biridir. Time namespaces olmadan, duraklatılmış bir workload'u geri yüklemek monotonic ve boot-time clock'larının, workload'un suspended durumda geçirdiği süre kadar ileri atlamasına neden olur.<sup>[[2]](#references)</sup>

## Security Impact

Diğer namespace türlerine kıyasla time namespace merkezli klasik breakout hikâyeleri daha azdır. Buradaki risk genellikle time namespace'in doğrudan escape sağlaması değil, okuyucuların bunu tamamen göz ardı ederek advanced runtime'ların process behavior'ı nasıl şekillendirebileceğini gözden kaçırmasıdır.

Specialized environment'larda değiştirilmiş monotonic veya boottime görünümleri şunları etkileyebilir:

- timeout ve retry davranışı
- watchdog'lar ve lease logic
- `timerfd`, `nanosleep` ve `clock_nanosleep` davranışı
- checkpoint/restore forensics
- elapsed-time telemetry ve uptime-based heuristics

Dolayısıyla bu, abuse edeceğiniz ilk namespace olmasa da bir assessment sırasında "impossible" timing behavior'ı kesinlikle açıklayabilir.

## Abuse

Burada genellikle doğrudan bir breakout primitive'i yoktur; ancak değiştirilmiş clock behavior yine de execution environment'ı anlamak, advanced runtime özelliklerini belirlemek ve wall clock time yerine monotonic clock'lara göre ölçülen timer-based logic'i tespit etmek için yararlı olabilir:
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
İki process'i karşılaştırıyorsanız buradaki farklılıklar, olağandışı timing davranışlarını, checkpoint/restore artifaktlarını veya ortama özgü logging uyumsuzluklarını açıklamaya yardımcı olabilir.

Pratikte attacker açısından önemli noktalar:

- monotonic clock'larla uygulanmış backoff, sleep veya watchdog mantığını karıştırmak
- `/proc/uptime` ile timer-driven davranışın host tarafındaki wall-clock beklentileriyle neden uyuşmadığını açıklamak
- CRIU/checkpoint-restore workflow'larını ve diğer gelişmiş runtime özelliklerini tanımak
- debugging veya post-exploitation için `nsenter -T -t <pid> -- ...` ile hedef time namespace'e katılmanın container-local timer davranışını yeniden üretip üretemeyeceğini tespit etmek

Etki:

- neredeyse her zaman reconnaissance veya ortamı anlamaya yöneliktir
- logging, uptime veya checkpoint/restore anomalilerini açıklamak için kullanışlıdır
- monotonic-time tabanlı sleep, retry ve timer'ları analiz etmek için kullanışlıdır
- normalde tek başına doğrudan bir container-escape mekanizması değildir

Önemli abuse ayrıntısı, time namespace'lerin `CLOCK_REALTIME` değerini virtualize etmemesidir; bu nedenle tek başlarına attacker'ın host wall clock'unu değiştirmesine veya sistem genelinde certificate-expiry kontrollerini doğrudan bozmasına olanak tanımazlar. Değerleri çoğunlukla monotonic-time tabanlı mantığı karıştırmakta, ortama özgü bug'ları yeniden üretmekte veya gelişmiş runtime davranışını anlamaktadır.

## Kontroller

Bu kontroller temel olarak runtime'ın private bir time namespace kullanıp kullanmadığını ve gerçekten nonzero offset'ler ayarlayıp ayarlamadığını doğrulamaya yöneliktir.
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

- Birçok ortamda bu değerler hemen bir güvenlik bulgusuna yol açmaz, ancak özel bir runtime özelliğinin devrede olup olmadığını gösterir.
- `time_for_children`, `time` değerinden farklıysa caller, kendisinin girmediği yalnızca child süreçlere özel bir time namespace hazırlamış olabilir.
- `date` host ile eşleşiyor ancak monotonic/boottime tabanlı değerler eşleşmiyorsa, muhtemelen wall-clock tampering yerine time namespacing ile karşı karşıyasınızdır.
- İki process'i karşılaştırıyorsanız buradaki farklılıklar, kafa karıştırıcı timing veya checkpoint/restore davranışını açıklayabilir.

Çoğu container breakout senaryosunda time namespace, inceleyeceğiniz ilk kontrol değildir. Yine de modern kernel modelinin bir parçası olduğu ve gelişmiş runtime senaryolarında zaman zaman önem taşıdığı için kapsamlı bir container-security bölümünde bundan bahsedilmelidir.

## Referanslar

- [1] [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [2] [Time Namespaces: Per-Container Clock Offsets for CLOCK_MONOTONIC / CLOCK_BOOTTIME - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
