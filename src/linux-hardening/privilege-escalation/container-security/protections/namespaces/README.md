# İsim Alanları

{{#include ../../../../../banners/hacktricks-training.md}}

İsim alanları, bir container'ın "kendi makinesiymiş gibi" hissetmesini sağlayan kernel özelliğidir; oysa aslında sadece bir host işlem ağacıdır. Yeni bir kernel oluşturmazlar ve her şeyi sanallaştırmazlar, fakat kernelin seçili kaynakların farklı görünümlerini farklı işlem gruplarına sunmasına izin verirler. Bu, container illüzyonunun özüdür: iş yükü, altında yatan sistem paylaşılıyor olsa da yerel gibi görünen bir dosya sistemi, işlem tablosu, ağ yığını, host adı, IPC kaynakları ve kullanıcı/grup kimlik modelini görür.

Bu yüzden isim alanları, çoğu kişinin container'ların nasıl çalıştığını öğrendiğinde karşılaştığı ilk kavramdır. Aynı zamanda, okuyucuların genellikle "isim alanlarına sahip olmak"ın "güvenli şekilde izole edilmiş olmak" anlamına geldiğini varsayması nedeniyle en sık yanlış anlaşılan kavramlardan biridir. Gerçekte, bir isim alanı yalnızca tasarlandığı kaynak sınıfını izole eder. Bir işlem özel bir PID namespace'e sahip olabilir ve yine de yazılabilir bir host bind mount'una sahip olduğu için tehlikeli olabilir. Özel bir network namespace'e sahip olabilir ve yine de `CAP_SYS_ADMIN`'ı koruduğu ve seccomp olmadan çalıştırıldığı için tehlikeli olabilir. İsim alanları temel bir yapı taşıdır, ancak nihai sınırda yalnızca bir katmandır.

## İsim Alanı Türleri

Linux container'lar genellikle aynı anda birkaç isim alanı türüne dayanır. **mount namespace** sürece ayrı bir mount tablosu verir ve dolayısıyla kontrol edilmiş bir dosya sistemi görünümü sağlar. **PID namespace** işlem görünürlüğünü ve numaralandırmasını değiştirir, böylece iş yükü kendi işlem ağacını görür. **network namespace** arayüzleri, yönlendirmeleri, soketleri ve firewall durumunu izole eder. **IPC namespace** SysV IPC ve POSIX mesaj kuyruklarını izole eder. **UTS namespace** hostname ve NIS domain adını izole eder. **user namespace** kullanıcı ve grup ID'lerini yeniden eşler; böylece container içindeki root, host'ta root anlamına gelmeyebilir. **cgroup namespace** görünen cgroup hiyerarşisini sanallaştırır ve **time namespace** daha yeni kernel'lerde seçili saatleri sanallaştırır.

Her bir isim alanı farklı bir problemi çözer. Bu yüzden pratik container güvenliği analizi sıklıkla **hangi isim alanlarının izole edildiğini** ve **hangilerinin kasıtlı olarak host ile paylaşıldığını** kontrol etmeye indirgenir.

## Host Namespace Paylaşımı

Birçok container kaçışı bir kernel açığı ile başlamaz. Operatörün kasıtlı olarak izolasyon modelini zayıflatmasıyla başlar. Örnekler olarak `--pid=host`, `--network=host` ve `--userns=host` **Docker/Podman-style CLI flags** olarak burada host isim alanı paylaşımının somut örnekleri olarak kullanılmıştır. Diğer runtime'lar aynı fikri farklı şekilde ifade eder. Kubernetes'te eşdeğerler genellikle `hostPID: true`, `hostNetwork: true` veya `hostIPC: true` gibi Pod ayarları olarak görünür. containerd veya CRI-O gibi daha alt seviye runtime yığınlarında aynı davranış genellikle aynı isimli kullanıcıya yönelik bir bayrak yerine oluşturulan OCI runtime konfigürasyonu aracılığıyla elde edilir. Tüm bu durumlarda sonuç benzerdir: iş yükü artık varsayılan izole isim alanı görünümünü almaz.

Bu nedenle isim alanı incelemeleri asla "sürecin bazı isim alanlarında olduğu" ile bitmemelidir. Önemli soru, isim alanının container'a özel olup olmadığı, kardeş container'larla paylaşılıp paylaşılmadığı veya doğrudan host'a mı katıldığıdır. Kubernetes'te aynı fikir `hostPID`, `hostNetwork` ve `hostIPC` gibi bayraklarla ortaya çıkar. Platformlar arasında isimler değişse de risk deseni aynıdır: paylaşılan bir host isim alanı, container'ın kalan ayrıcalıklarını ve ulaşılabilir host durumunu çok daha anlamlı kılar.

## İnceleme

En basit genel bakış şudur:
```bash
ls -l /proc/self/ns
```
Her giriş inode-benzeri bir tanımlayıcıya sahip sembolik linktir. Eğer iki işlem aynı namespace tanımlayıcısına işaret ediyorsa, aynı tür namespace içindedirler. Bu da /proc'u geçerli işlemi makinedeki diğer ilginç işlemlerle karşılaştırmak için çok yararlı bir yer yapar.

Başlamak için genellikle bu hızlı komutlar yeterlidir:
```bash
readlink /proc/self/ns/mnt
readlink /proc/self/ns/pid
readlink /proc/self/ns/net
readlink /proc/1/ns/mnt
```
Buradan sonraki adım, container process'i host veya komşu process'lerle karşılaştırmak ve bir namespace'in gerçekten private olup olmadığını belirlemektir.

### Host Üzerinden Namespace Örneklerini Listeleme

Eğer zaten host erişiminiz varsa ve belirli bir tür için kaç farklı namespace bulunduğunu anlamak istiyorsanız, `/proc` hızlı bir envanter sağlar:
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
Belirli bir namespace kimliğine ait hangi işlemlerin olduğunu bulmak istiyorsanız, `readlink` yerine `ls -l` kullanın ve hedef namespace numarasını `grep` ile arayın:
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l {} \; 2>/dev/null | grep <ns-number>
```
Bu komutlar faydalıdır çünkü bir host'un tek bir isolated workload, birçok isolated workload veya shared ve private namespace instances karışımı mı çalıştırdığını belirlemenizi sağlar.

### Hedef Namespace'e Girme

Çağıranın yeterli ayrıcalığı olduğunda, `nsenter` başka bir process'in namespace'ine katılmanın standart yoludur:
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
Bu formların bir arada listelenmesinin nedeni her değerlendirmenin hepsine ihtiyaç duyması değil; operatör tam giriş sözdizimini bildiğinde namespace-specific post-exploitation genellikle, yalnızca all-namespaces formunu ezberlemek yerine, çok daha kolaylaşır.

## Sayfalar

Aşağıdaki sayfalar her namespace'i daha detaylı açıklar:

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

Okurken iki fikri aklınızda tutun. Birincisi, her namespace yalnızca tek bir tür görünümü izole eder. İkincisi, özel bir namespace yalnızca geri kalan ayrıcalık modeli (privilege model) bu izolasyonu hâlâ anlamlı kılıyorsa kullanışlıdır.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Default namespace posture | Common manual weakening |
| --- | --- | --- |
| Docker Engine | New mount, PID, network, IPC, and UTS namespaces by default; user namespaces are available but not enabled by default in standard rootful setups | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Podman | New namespaces by default; rootless Podman automatically uses a user namespace; cgroup namespace defaults depend on cgroup version | `--pid=host`, `--network=host`, `--ipc=host`, `--uts=host`, `--userns=host`, `--cgroupns=host`, `--privileged` |
| Kubernetes | Pods do **not** share host PID, network, or IPC by default; Pod networking is private to the Pod, not to each individual container; user namespaces are opt-in via `spec.hostUsers: false` on supported clusters | `hostPID: true`, `hostNetwork: true`, `hostIPC: true`, `spec.hostUsers: true` / omitting user-namespace opt-in, privileged workload settings |
| containerd / CRI-O under Kubernetes | Usually follow Kubernetes Pod defaults | same as Kubernetes row; direct CRI/OCI specs can also request host namespace joins |

Ana taşınabilirlik kuralı basittir: host namespace paylaşımı kavramı runtime'lar arasında ortaktır, ancak sözdizimi runtime'a özgüdür.
{{#include ../../../../../banners/hacktricks-training.md}}
