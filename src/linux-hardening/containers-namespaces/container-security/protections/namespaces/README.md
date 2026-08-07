# Namespaces

{{#include ../../../../../banners/hacktricks-training.md}}

Namespaces, bir container'ın aslında yalnızca host üzerindeki bir process tree olmasına rağmen "kendi makinesi" gibi hissetmesini sağlayan kernel özelliğidir. Yeni bir kernel oluşturmaz ve her şeyi virtualize etmez; ancak kernel'in seçili kaynakların farklı görünümlerini farklı process gruplarına sunmasını sağlar. Container illüzyonunun temeli budur: workload, temel sistem paylaşımlı olsa da kendisine yerel görünen bir filesystem, process table, network stack, hostname, IPC kaynakları ve user/group identity modeli görür.

Bu nedenle namespaces, çoğu kişinin container'ların nasıl çalıştığını öğrenirken karşılaştığı ilk kavramdır. Aynı zamanda en sık yanlış anlaşılan kavramlardan biridir; çünkü okuyucular genellikle "namespaces var" ifadesinin "güvenli şekilde izole edilmiştir" anlamına geldiğini varsayar. Gerçekte bir namespace yalnızca tasarlandığı belirli kaynak sınıfını izole eder. Bir process private PID namespace'e sahip olabilir ve yine de writable host bind mount nedeniyle tehlikeli olabilir. Private network namespace'e sahip olabilir ve yine de `CAP_SYS_ADMIN` yetkisini koruduğu ve seccomp olmadan çalıştığı için tehlikeli olabilir. Namespaces temel bir katmandır, ancak nihai sınırın yalnızca bir parçasıdır.

## Namespace Types

Linux container'ları genellikle aynı anda birkaç namespace türüne dayanır. **mount namespace**, process'e ayrı bir mount table ve dolayısıyla kontrollü bir filesystem görünümü sağlar. **PID namespace**, process görünürlüğünü ve numaralandırmasını değiştirerek workload'un kendi process tree'sini görmesini sağlar. **network namespace**, interface'leri, route'ları, socket'leri ve firewall durumunu izole eder. **IPC namespace**, SysV IPC'yi ve POSIX message queue'larını izole eder. **UTS namespace**, hostname'i ve NIS domain name'i izole eder. **user namespace**, user ve group ID'lerini yeniden eşleyerek container içindeki root'un host üzerinde de root olmak zorunda kalmamasını sağlar. **cgroup namespace**, görünür cgroup hierarchy'yi virtualize eder; **time namespace** ise daha yeni kernel'lerde seçili clock'ları virtualize eder.

Bu namespace'lerin her biri farklı bir problemi çözer. Bu nedenle pratik container security analysis çoğu zaman **hangi namespace'lerin izole edildiğini** ve **hangilerinin host ile kasıtlı olarak paylaşıldığını** kontrol etmeye dayanır.

## Host Namespace Sharing

Birçok container breakout'i kernel vulnerability ile başlamaz. Isolation model'ini kasıtlı olarak zayıflatan bir operator ile başlar. `--pid=host`, `--network=host` ve `--userns=host` örnekleri, burada host namespace sharing için somut örnekler olarak kullanılan **Docker/Podman-style CLI flags**'tir. Diğer runtime'lar aynı fikri farklı şekilde ifade eder. Kubernetes'te karşılıkları genellikle `hostPID: true`, `hostNetwork: true` veya `hostIPC: true` gibi Pod ayarları olarak görülür. containerd veya CRI-O gibi lower-level runtime stack'lerinde aynı davranışa çoğunlukla kullanıcıya sunulan ve aynı ada sahip bir flag yerine, oluşturulan OCI runtime configuration üzerinden ulaşılır. Tüm bu durumlarda sonuç benzerdir: workload artık varsayılan isolated namespace görünümünü almaz.

Bu nedenle namespace review'ları "process bir namespace içinde" noktasında asla durmamalıdır. Önemli soru, namespace'in container'a özel mi olduğu, sibling container'lar ile mi paylaşıldığı veya doğrudan host'a mı join edildiğidir. Kubernetes'te aynı fikir `hostPID`, `hostNetwork` ve `hostIPC` gibi flag'lerle ifade edilir. Platformlar arasında isimler değişir, ancak risk pattern'i aynıdır: paylaşılan bir host namespace, container'ın kalan privileges'larını ve erişilebilir host state'i çok daha anlamlı hâle getirir.

## Inspection

En basit genel görünüm şudur:
```bash
ls -l /proc/self/ns
```
Her giriş, inode benzeri bir tanımlayıcıya sahip sembolik bir bağlantıdır. İki process aynı namespace tanımlayıcısını gösteriyorsa, o namespace türünde aynı namespace içindedirler. Bu nedenle `/proc`, mevcut process'i makinedeki diğer ilgi çekici process'lerle karşılaştırmak için oldukça kullanışlı bir yerdir.

Başlangıç için genellikle şu hızlı komutlar yeterlidir:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Buradan sonraki adım, container process'ini host veya komşu process'lerle karşılaştırmak ve bir namespace'in gerçekten private olup olmadığını belirlemektir.

### Host Üzerinden Namespace Instance'larını Listeleme

Host erişiminiz zaten varsa ve belirli bir türden kaç farklı namespace bulunduğunu anlamak istiyorsanız, `/proc` hızlı bir envanter sunar:
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
Belirli bir namespace identifier'a ait süreçleri bulmak istiyorsanız, `readlink` yerine `ls -l` kullanın ve hedef namespace numarasını grep ile arayın:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Bu komutlar kullanışlıdır; çünkü bir host'un tek bir yalıtılmış workload, birden fazla yalıtılmış workload veya paylaşılan ve özel namespace örneklerinin bir karışımını çalıştırıp çalıştırmadığını yanıtlamanızı sağlar.

### Bir Target Namespace'e Girme

Caller yeterli ayrıcalığa sahip olduğunda, `nsenter` başka bir process'in namespace'ine katılmanın standart yoludur:
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
Bu formların birlikte listelenmesinin amacı, her assessment'ın bunların tümüne ihtiyaç duyması değil; operator yalnızca tüm-namespace biçimini hatırlamak yerine, kesin giriş syntax'ını bildiğinde namespace-specific post-exploitation işlemlerinin çoğu zaman çok daha kolay hale gelmesidir.

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

Bunları okurken iki fikri aklınızda bulundurun. İlk olarak, her namespace yalnızca tek bir görünüm türünü izole eder. İkinci olarak, private bir namespace yalnızca privilege modelinin geri kalanı bu izolasyonu anlamlı kılmaya devam ediyorsa kullanışlıdır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan namespace durumu | Yaygın manuel zayıflatma |
| --- | --- | --- |
| Docker Engine | Varsayılan olarak yeni mount, PID, network, IPC ve UTS namespace'leri oluşturulur; user namespace'leri kullanılabilir ancak standart rootful kurulumlarda varsayılan olarak etkin değildir | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Varsayılan olarak yeni namespace'ler oluşturulur; rootless Podman otomatik olarak bir user namespace kullanır; cgroup namespace varsayılanları cgroup sürümüne bağlıdır | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pod'lar varsayılan olarak host PID, network veya IPC'yi **paylaşmaz**; Pod networking'i her bir container'a değil, Pod'a özeldir; desteklenen cluster'larda user namespace'leri `spec.hostUsers: false` ile opt-in olarak etkinleştirilir | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / user-namespace opt-in ayarının çıkarılması, privileged workload ayarları |
| Kubernetes altında containerd / CRI-O | Genellikle Kubernetes Pod varsayılanlarını izler | Kubernetes satırıyla aynı; doğrudan CRI/OCI spec'leri de host namespace'lerine katılmayı talep edebilir |

Ana portability kuralı basittir: host namespace paylaşımı **kavramı** runtime'lar arasında ortaktır, ancak **syntax'ı** runtime'a özeldir.

{{#include ../../../../../banners/hacktricks-training.md}}
