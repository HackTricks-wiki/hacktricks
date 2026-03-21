# İsim alanları

{{#include ../../../../../banners/hacktricks-training.md}}

İsim alanları, bir container'ı "kendi makinesiymiş gibi" hissettiren çekirdek özelliğidir; aslında yalnızca bir host süreç ağacıdır. Yeni bir kernel oluşturmazlar ve her şeyi sanallaştırmazlar, ancak çekirdeğin seçili kaynakların farklı görünümlerini farklı süreç gruplarına sunmasına izin verirler. Bu, container illüzyonunun özüdür: iş yükü bir dosya sistemi, süreç tablosu, network stack'i, hostname'i, IPC kaynakları ve kullanıcı/grup kimlik modeli görür gibi olur; oysa alttaki sistem paylaşımlıdır.

Bu yüzden isim alanları, container'ların nasıl çalıştığını öğrenenlerin karşılaştığı ilk kavramlardan biridir. Aynı zamanda en çok yanlış anlaşılan kavramlardan biridir çünkü okuyucular sıklıkla "isim alanı var" ifadesinin "güvenli şekilde izole" anlamına geldiğini varsayarlar. Oysa gerçekte bir isim alanı yalnızca tasarlandığı belirli kaynak sınıfını izole eder. Bir süreç özel bir PID isim alanına sahip olabilir ama yazılabilir bir host bind mount'u olduğu için hâlâ tehlikeli olabilir. Özel bir network isim alanına sahip olabilir ama `CAP_SYS_ADMIN` hakkını koruyor ve seccomp olmadan çalışıyorsa yine tehlikelidir. İsim alanları temeldir, ama nihai sınırda yalnızca bir katmandır.

## İsim alanı türleri

Linux container'ları genellikle aynı anda birkaç isim alanı türüne dayanır. **mount isim alanı** sürece ayrı bir mount tablosu vererek kontrollü bir dosya sistemi görünümü sağlar. **PID isim alanı** süreç görünürlüğünü ve numaralandırmayı değiştirir; böylece iş yükü kendi süreç ağacını görür. **network isim alanı** arayüzleri, rotaları, soketleri ve firewall durumunu izole eder. **IPC isim alanı** SysV IPC ve POSIX message queue'larını izole eder. **UTS isim alanı** hostname ve NIS domain adını izole eder. **user isim alanı** kullanıcı ve grup kimliklerini yeniden eşler; böylece container içindeki root host'ta root anlamına gelmeyebilir. **cgroup isim alanı** görünür cgroup hiyerarşisini sanallaştırır ve **time isim alanı** yeni kernel'lerde seçili saatleri sanallaştırır.

Bu isim alanlarının her biri farklı bir problemi çözer. Bu yüzden pratik container güvenlik analizi sıklıkla **hangi isim alanlarının izole edildiğinin** ve **hangilerinin kasıtlı olarak host ile paylaşıldığının** kontrol edilmesine dayanır.

## Host isim alanı paylaşımı

Pek çok container breakout'u bir kernel açığı ile başlamaz. Bir operatörün izole etme modelini kasten zayıflatmasıyla başlar. Örnekler `--pid=host`, `--network=host` ve `--userns=host` burada host isim alanı paylaşımına somut örnekler olarak kullanılan **Docker/Podman-style CLI flags**'dir. Diğer runtime'lar aynı fikri farklı şekilde ifade eder. Kubernetes'te eşdeğerler genellikle Pod ayarları olarak `hostPID: true`, `hostNetwork: true` veya `hostIPC: true` şeklinde görünür. containerd veya CRI-O gibi daha düşük seviyeli runtime yığınlarında ise aynı davranış genellikle aynı isimli kullanıcıya yönelik bir bayrak yerine üretilen OCI runtime konfigürasyonu üzerinden elde edilir. Tüm bu durumlarda sonuç benzerdir: iş yükü artık varsayılan izole isim alanı görünümünü almaz.

Bu yüzden isim alanı incelemeleri asla "süreç bir isim alanında" ifadesiyle bitmemelidir. Önemli soru, isim alanının konteynere özel mi, kardeş konteynerlarla mı paylaşıldığı yoksa doğrudan host'a mı bağlandığıdır. Kubernetes'te aynı fikir `hostPID`, `hostNetwork` ve `hostIPC` gibi bayraklarla ortaya çıkar. İsimler platformlar arasında değişir, fakat risk paterni aynıdır: paylaşılan bir host isim alanı, konteynerin kalan ayrıcalıklarını ve ulaşılabilir host durumunu çok daha anlamlı hale getirir.

## İnceleme

En basit genel bakış:
```bash
ls -l /proc/self/ns
```
Her giriş, inode-benzeri bir tanımlayıcıya sahip sembolik bir bağlantıdır. Eğer iki işlem aynı namespace tanımlayıcısına işaret ediyorsa, o türde aynı namespace içindedirler. Bu, `/proc`'u mevcut işlemi makinedeki diğer ilginç işlemlerle karşılaştırmak için çok kullanışlı bir yer yapar.

Başlamak için bu hızlı komutlar genellikle yeterlidir:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
### Host Üzerinden Namespace Örneklerini Listeleme

Bundan sonra, container process'i host veya komşu işlemlerle karşılaştırarak bir namespace'in gerçekten private olup olmadığını belirlemek sonraki adımdır.

Zaten host access'e sahipseniz ve belirli bir türde kaç farklı namespace olduğunu anlamak istiyorsanız, `/proc` kısa bir envanter sağlar:
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
Belirli bir namespace kimliğine ait hangi processes'in olduğunu bulmak istiyorsanız, `readlink` yerine `ls -l` kullanın ve hedef namespace numarası için grep yapın:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Bu komutlar kullanışlıdır çünkü bir hostun tek bir izole iş yükü, birçok izole iş yükü veya paylaşılan ve özel namespace örneklerinin bir karışımını çalıştırıp çalıştırmadığını belirlemenizi sağlar.

### Hedef namespace'e girme

Çağıranın yeterli ayrıcalığa sahip olması durumunda, `nsenter` başka bir işlemin namespace'ine katılmanın standart yoludur:
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
Bu biçimleri birlikte listelemenin amacı her değerlendirmede hepsinin gerekli olması değil; namespace'e özgü post-exploitation genellikle operatör yalnızca all-namespaces biçimini hatırlamak yerine tam giriş sözdizimini bildiğinde çok daha kolay olur.

## Sayfalar

Aşağıdaki sayfalar her namespace'i daha ayrıntılı açıklar:

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

Okurken iki fikri aklınızda tutun. Birincisi, her namespace yalnızca tek bir tür görünümü izole eder. İkincisi, bir özel namespace ancak geri kalan yetki modeli bu izolasyonu hâlâ anlamlı kılıyorsa kullanışlıdır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan namespace duruşu | Yaygın manuel zayıflatmalar |
| --- | --- | --- |
| Docker Engine | Yeni mount, PID, network, IPC ve UTS namespaces varsayılan olarak; user namespaces mevcut ama standart rootful kurulumlarda varsayılan olarak etkin değil | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | Varsayılan olarak yeni namespaces; rootless Podman otomatik olarak bir user namespace kullanır; cgroup namespace varsayılanları cgroup version'a bağlıdır | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Genellikle Kubernetes Pod varsayılanlarını izler | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Ana taşınabilirlik kuralı basittir: host namespace sharing'in **kavram**ı runtimeler arasında ortak, ancak **sözdizimi** runtime'a özgüdür.
