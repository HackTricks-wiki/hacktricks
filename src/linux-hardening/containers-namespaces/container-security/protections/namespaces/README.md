# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces, bir container'ın aslında yalnızca host üzerindeki bir process ağacı olmasına rağmen "kendi makinesi" gibi hissetmesini sağlayan kernel özelliğidir. Yeni bir kernel oluşturmaz ve her şeyi virtualize etmez; ancak kernel'in seçili kaynakların farklı görünümlerini farklı process gruplarına sunmasını sağlar. Container illüzyonunun temeli budur: workload, altyapı sistemi ortak olsa bile kendisine yerel görünen bir filesystem, process tablosu, network stack'i, hostname'i, IPC kaynakları ve user/group identity modeli görür.

Bu nedenle Namespaces, çoğu kişinin container'ların nasıl çalıştığını öğrenirken karşılaştığı ilk kavramdır. Aynı zamanda en sık yanlış anlaşılan kavramlardan biridir; çünkü okuyucular genellikle "namespaces var" ifadesinin "güvenli şekilde izole edilmiş" anlamına geldiğini varsayar. Gerçekte bir namespace yalnızca tasarlandığı belirli kaynak sınıfını izole eder. Bir process private PID namespace'e sahip olabilir ve yine de writable bir host bind mount'u olduğu için tehlikeli olabilir. Private network namespace'e sahip olabilir ve yine de `CAP_SYS_ADMIN` yetkisini koruduğu ve seccomp olmadan çalıştığı için tehlikeli olabilir. Namespaces temel bir katmandır, ancak nihai sınırdaki yalnızca tek katmandır.

## Namespace Türleri

Linux container'ları genellikle aynı anda birden fazla namespace türüne dayanır. **Mount namespace**, process'e ayrı bir mount tablosu ve dolayısıyla kontrollü bir filesystem görünümü sağlar. **PID namespace**, process görünürlüğünü ve numaralandırmasını değiştirerek workload'un kendi process ağacını görmesini sağlar. **Network namespace**, interface'leri, route'ları, socket'leri ve firewall durumunu izole eder. **IPC namespace**, SysV IPC'yi ve POSIX message queue'larını izole eder. **UTS namespace**, hostname'i ve NIS domain name'i izole eder. **User namespace**, user ve group ID'lerini yeniden eşleyerek container içindeki root'un host üzerinde de mutlaka root anlamına gelmemesini sağlar. **Cgroup namespace**, görünür cgroup hiyerarşisini virtualize eder; **time namespace** ise daha yeni kernel'lerde seçili clock'ları virtualize eder.

Bu namespace'lerin her biri farklı bir problemi çözer. Bu nedenle pratik container security analizi genellikle **hangi namespace'lerin izole edildiğini** ve **hangilerinin host ile kasıtlı olarak paylaşıldığını** kontrol etmeye dayanır.

## Host Namespace Paylaşımı

Birçok container breakout, kernel vulnerability ile başlamaz. Isolation modelini kasıtlı olarak zayıflatan bir operator ile başlar. Burada `--pid=host`, `--network=host` ve `--userns=host` örnekleri, host namespace paylaşımını somutlaştırmak için kullanılan **Docker/Podman-style CLI flag'leridir**. Diğer runtime'lar aynı fikri farklı şekilde ifade eder. Kubernetes'te karşılıkları genellikle `hostPID: true`, `hostNetwork: true` veya `hostIPC: true` gibi Pod ayarları olarak görünür. Containerd veya CRI-O gibi daha düşük seviyeli runtime stack'lerinde aynı davranışa çoğunlukla kullanıcıya sunulan ve aynı ada sahip bir flag üzerinden değil, oluşturulan OCI runtime configuration aracılığıyla ulaşılır. Tüm bu durumlarda sonuç benzerdir: workload artık varsayılan izole namespace görünümünü almaz.

Bu nedenle namespace incelemeleri asla "process bir namespace içinde" noktasında durmamalıdır. Önemli soru, namespace'in container'a özel mi, sibling container'larla paylaşılmış mı, yoksa doğrudan host'a mı katılmış olduğudur. Kubernetes'te aynı fikir `hostPID`, `hostNetwork` ve `hostIPC` gibi flag'lerle ortaya çıkar. Platformlar arasında isimler değişir, ancak risk pattern'i aynıdır: paylaşılan bir host namespace, container'ın kalan yetkilerini ve erişebildiği host durumunu çok daha önemli hâle getirir.

## İnceleme

En basit genel bakış şöyledir:
```bash
ls -l /proc/self/ns
```
Her giriş, inode benzeri bir tanımlayıcıya sahip sembolik bir bağlantıdır. İki process aynı namespace tanımlayıcısını gösteriyorsa, o türdeki aynı namespace içindedir. Bu nedenle `/proc`, mevcut process'i makinedeki diğer ilgi çekici process'lerle karşılaştırmak için çok kullanışlı bir yerdir.

Başlangıç için genellikle şu hızlı komutlar yeterlidir:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Buradan sonraki adım, container process'ini host veya komşu process'lerle karşılaştırmak ve bir namespace'in gerçekten private olup olmadığını belirlemektir.

### Host Üzerinden Namespace Instance'larını Listeleme

Host erişiminiz zaten varsa ve belirli bir türde kaç farklı namespace bulunduğunu anlamak istiyorsanız, `/proc` hızlı bir envanter sunar:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name pid    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name net    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name ipc    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name uts    -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name user   -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
sudo find /proc -maxdepth 3 -type l -name time   -exec readlink {} \; 2>/dev/null | sort -u
```
Belirli bir namespace identifier'a ait süreçleri bulmak istiyorsanız `readlink` yerine `ls -l` kullanın ve hedef namespace numarasını grep ile arayın:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Bu komutlar, bir host üzerinde tek bir yalıtılmış iş yükünün, birden çok yalıtılmış iş yükünün veya paylaşılan ve özel namespace örneklerinin bir karışımının çalışıp çalışmadığını belirlemenizi sağladıkları için kullanışlıdır.

### Hedef Namespace'e Girme

Çağrıyı yapan yeterli ayrıcalığa sahip olduğunda, başka bir process'in namespace'ine katılmanın standart yolu `nsenter` kullanmaktır:
```bash
nsenter -m TARGET_PID --pid /bin/bash   # mount
nsenter -t TARGET_PID --pid /bin/bash   # pid
nsenter -n TARGET_PID --pid /bin/bash   # network
nsenter -i TARGET_PID --pid /bin/bash   # ipc
nsenter -u TARGET_PID --pid /bin/bash   # uts
nsenter -U TARGET_PID --pid /bin/bash   # user
nsenter -C TARGET_PID --pid /bin/bash   # cgroup
nsenter -T TARGET_PID --pid /bin/bash   # time
```
Bu formların birlikte listelenmesinin amacı, her assessment'ın hepsine ihtiyaç duyması değil; namespace-specific post-exploitation işlemlerinin, operatör yalnızca all-namespaces biçimini hatırlamak yerine tam giriş sözdizimini bildiğinde çoğu zaman çok daha kolay hâle gelmesidir.

## Sayfalar

Aşağıdaki sayfalar her namespace'i daha ayrıntılı olarak açıklar:

{{#ref}}
mount-namespace.md
{{#endref}}

{{#ref}}
pid-namespace.md
{{#endref}}

{{#ref}}
network-namespace.md
{{#endref}}

{{#ref}}
ipc-namespace.md
{{#endref}}

{{#ref}}
uts-namespace.md
{{#endref}}

{{#ref}}
user-namespace.md
{{#endref}}

{{#ref}}
cgroup-namespace.md
{{#endref}}

{{#ref}}
time-namespace.md
{{#endref}}

Bunları okurken iki fikri aklınızda tutun. İlk olarak, her namespace yalnızca tek bir görünüm türünü izole eder. İkinci olarak, özel bir namespace yalnızca ayrıcalık modelinin geri kalanı bu izolasyonu anlamlı kılmaya devam ediyorsa kullanışlıdır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan namespace yapısı | Yaygın manuel zayıflatma |
| --- | --- | --- |
| Docker Engine | Varsayılan olarak yeni mount, PID, network, IPC ve UTS namespace'leri oluşturur; user namespace'leri kullanılabilir ancak standart rootful kurulumlarda varsayılan olarak etkin değildir | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Varsayılan olarak yeni namespace'ler oluşturur; rootless Podman otomatik olarak bir user namespace kullanır; cgroup namespace varsayılanları cgroup sürümüne bağlıdır | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pod'lar varsayılan olarak host PID, network veya IPC'yi paylaşmaz; Pod networking'i her bir container'a değil, Pod'a özeldir; desteklenen cluster'larda user namespace'leri `spec.hostUsers: false` ile opt-in olarak etkinleştirilir | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / user-namespace opt-in ayarının atlanması, privileged workload ayarları |
| Kubernetes altında containerd / CRI-O | Genellikle Kubernetes Pod varsayılanlarını izler | Kubernetes satırıyla aynı; doğrudan CRI/OCI spec'leri de host namespace'lerine katılmayı talep edebilir |

Ana portability kuralı basittir: host namespace paylaşımı kavramı runtime'lar arasında ortaktır, ancak sözdizimi runtime'a özeldir.
{{#include ../../../../../banners/hacktricks-training.md}}
