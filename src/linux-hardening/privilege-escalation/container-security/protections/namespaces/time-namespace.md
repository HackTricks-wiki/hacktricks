# Time Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

time namespace, host wall clock yerine seçilmiş monotonic tarzı clock’ları virtualize eder. Pratikte bu, **`CLOCK_MONOTONIC`** ve **`CLOCK_BOOTTIME`** için private offset’ler anlamına gelir; ayrıca yakından ilişkili **`CLOCK_MONOTONIC_COARSE`**, **`CLOCK_MONOTONIC_RAW`** ve **`CLOCK_BOOTTIME_ALARM`** görünümleri de dahildir. **`CLOCK_REALTIME`**’ı virtualize etmez, bu yüzden `date` ve certificate-expiry mantığı, başka bir mekanizma müdahale etmediği sürece host wall clock’u görmeye devam eder.

Ana amaç, host’un global time görünümünü değiştirmeden bir process’in kontrollü elapsed-time offset’leri gözlemlemesini sağlamaktır. Bu, checkpoint/restore iş akışları, deterministic testing ve advanced runtime davranışı için kullanışlıdır. Genellikle mount veya user namespaces kadar öne çıkan bir isolation control değildir, ancak process environment’ı daha self-contained hale getirmeye yine de katkı sağlar.

Offensive açıdan bakıldığında, bu namespace genellikle doğrudan bir breakout’tan çok **reconnaissance, timer skew ve runtime understanding** için daha önemlidir. Yine de önemlidir; çünkü daha fazla container runtime ve checkpoint/restore iş akışı artık bunu explicit olarak talep edebilmektedir.

## Lab

Eğer host kernel ve userspace bunu destekliyorsa, namespace’i şu şekilde inceleyebilirsiniz:
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
Destek çekirdek ve tool sürümlerine göre değişir, bu yüzden bu sayfa her lab ortamında görünmesini beklemekten çok mekanizmayı anlamakla ilgilidir. Önemli gözlem şudur: `date` hâlâ host wall clock’u yansıtmalıdır, while monotonic/boottime-based values are the ones that change when nonzero offsets are configured.

### Creation Nuance

Time namespaces, mount, PID veya network namespaces ile karşılaştırıldığında biraz sıra dışıdır:

- `unshare(CLONE_NEWTIME)` yeni bir time namespace oluşturur, **future children** için.
- Çağıran task kendi current time namespace’inde kalır.
- Bu nedenle `/proc/<pid>/ns/time_for_children`, runtime setup debug edilirken çoğu zaman `/proc/<pid>/ns/time`’dan daha ilginçtir.

Write window da özeldir. `/proc/<pid>/timens_offsets` içindeki offsets, yeni time namespace running tasks ile tamamen populated edilmeden önce yazılmalıdır; pratikte runtimes bunu namespace creation ile final payload’ın başlatılması arasındaki dar setup window sırasında yapar. Orada bir task zaten running ise, sonraki writes `EACCES` ile başarısız olur. Bu yüzden low-level runtimes, time-namespace setup’ını zaten başlamış bir container process’in içinden offsets patch etmeye çalışmak yerine erken bir bootstrap step olarak ele alır.

### Time Offsets

Linux time namespaces, namespace başına offsets’i `/proc/<pid>/timens_offsets` üzerinden expose eder. Format, initial time namespace’e göre clock names veya IDs ile second/nanosecond deltas kümesidir.

Pratikte, en güvenilir user-facing workflow, `unshare`’in bu offsets’i sizin için yazmasına izin vermektir:
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
Önemli nokta tam komut sözdizimi değil, davranıştır: bir container, host wall clock'u değiştirmeden farklı bir uptime-benzeri görünümü gözlemleyebilir.

### `unshare` Helper Flags

Son `util-linux` sürümleri, namespace oluşturma sırasında offset'leri otomatik olarak yazan kolaylık flags sağlar:
```bash
sudo unshare -T --fork --monotonic 86400 --boottime 604800 --mount-proc bash
```
Bu bayraklar çoğunlukla bir kullanılabilirlik iyileştirmesidir, ancak aynı zamanda özelliği documentation, test harnesses ve runtime wrappers içinde tanımayı da kolaylaştırırlar.

## Runtime Usage

Time namespaces daha yenidir ve mount veya PID namespaces kadar evrensel olarak kullanılmaz. OCI Runtime Specification v1.1, `time` namespace ve `linux.timeOffsets` alanı için açık destek ekledi ve modern runtimes bu veriyi kernel bootstrap flow içine map edebilir. Minimal bir OCI fragment şu şekilde görünür:
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
Bu önemlidir çünkü time namespacing’i niş bir kernel primitive olmaktan çıkarıp runtime’ların taşınabilir şekilde talep edebileceği bir şeye dönüştürür. Ayrıca runtime internal’larının neden açık bir synchronization step’e ihtiyaç duyduğunu da açıklar: offset, container payload yeni namespace’e tamamen girmeden önce `/proc/<pid>/timens_offsets` içine yazılmalıdır.

CRIU gibi checkpoint/restore stack’leri, bunun var olmasının başlıca gerçek dünya nedenlerinden biridir. Time namespaces olmadan, duraklatılmış bir workload’u restore etmek, monotonic ve boot-time clock’ların workload’un askıda kaldığı süre kadar ileri sıçramasına neden olurdu.

## Security Impact

Time namespace etrafında, diğer namespace türlerine kıyasla daha az klasik breakout hikayesi vardır. Buradaki risk genellikle time namespace’in doğrudan escape sağlaması değil, reader’ların onu tamamen göz ardı etmesi ve bu yüzden advanced runtimes’ın process davranışını nasıl şekillendirebileceğini kaçırmasıdır.

Özel ortamlarda, değiştirilmiş monotonic veya boottime görünümleri şunları etkileyebilir:

- timeout ve retry behavior
- watchdogs ve lease logic
- `timerfd`, `nanosleep`, ve `clock_nanosleep` behavior
- checkpoint/restore forensics
- elapsed-time telemetry ve uptime-based heuristics

Dolayısıyla bu genellikle istismar edeceğiniz ilk namespace olmasa da, bir assessment sırasında "imkansız" timing behavior’ını kesinlikle açıklayabilir.

## Abuse

Burada genellikle doğrudan bir breakout primitive yoktur, ancak değiştirilmiş clock behavior yine de execution environment’i anlamak, advanced runtime features’ı belirlemek ve wall clock time yerine monotonic clocks’a göre ölçülen timer-based logic’i tespit etmek için faydalı olabilir:
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
İki processi karşılaştırıyorsanız, buradaki farklar tuhaf timing davranışını, checkpoint/restore artifacts’ını veya environment-specific logging uyuşmazlıklarını açıklamaya yardımcı olabilir.

Practical attacker-relevant angles:

- monotonic clocks ile implemente edilen backoff, sleep veya watchdog logic’ini karıştırmak
- `/proc/uptime` ve timer-driven davranışın host-side wall-clock beklentileriyle neden uyuşmadığını açıklamak
- CRIU/checkpoint-restore workflows ve diğer advanced runtime features’ı tanımak
- `nsenter -T -t <pid> -- ...` ile bir target time namespace’e katılmanın debugging veya post-exploitation için container-local timer davranışını yeniden üretmeye yardımcı olabileceği environment’ları tespit etmek

Impact:

- neredeyse her zaman reconnaissance veya environment understanding
- logging, uptime veya checkpoint/restore anomalies’lerini açıklamak için faydalı
- monotonic-time-based sleeps, retries ve timers’ı analiz etmek için faydalı
- normalde tek başına doğrudan bir container-escape mechanism değildir

Önemli abuse nuance şu: time namespaces `CLOCK_REALTIME`’ı virtualize etmez, bu yüzden tek başlarına bir attacker’ın host wall clock’u sahte göstermesine veya sistem genelinde certificate-expiry checks’i doğrudan bozmasına izin vermez. Değerleri çoğunlukla monotonic-time-based logic’i karıştırmak, environment-specific bugs’ı yeniden üretmek veya advanced runtime behavior’ı anlamaktır.

## Checks

Bu checks çoğunlukla runtime’ın hiç private time namespace kullanıp kullanmadığını ve gerçekten nonzero offsets ayarlayıp ayarlamadığını doğrulamakla ilgilidir.
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
Burada ilginç olan:

- Birçok ortamda bu değerler anında bir güvenlik bulgusu oluşturmaz, ancak size özel bir runtime özelliğinin devrede olup olmadığını söylerler.
- Eğer `time_for_children`, `time` değerinden farklıysa, çağıran taraf kendisinin girmediği child-only bir time namespace hazırlamış olabilir.
- Eğer `date` host ile eşleşiyor ancak monotonic/boottime tabanlı değerler eşleşmiyorsa, büyük olasılıkla wall-clock tampering yerine time namespacing görüyorsunuzdur.
- İki process karşılaştırıyorsanız, buradaki farklar kafa karıştırıcı timing veya checkpoint/restore davranışını açıklayabilir.

Çoğu container breakout için time namespace ilk inceleyeceğiniz control değildir. Yine de eksiksiz bir container-security bölümü bunu belirtmelidir, çünkü modern kernel modelinin bir parçasıdır ve gelişmiş runtime senaryolarında zaman zaman önem kazanır.

## References

- [Linux `time_namespaces(7)` manual page](https://man7.org/linux/man-pages/man7/time_namespaces.7.html)
- [Time Namespaces - Linux Kernel Internals](https://kernel-internals.org/time/time-namespaces/)

{{#include ../../../../../banners/hacktricks-training.md}}
