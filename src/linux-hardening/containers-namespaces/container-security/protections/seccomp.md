# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

**seccomp**, kernel'in bir process'in çağırabileceği syscall'lara filtre uygulamasını sağlayan mekanizmadır. Containerized ortamlarda seccomp normalde filter mode'da kullanılır; böylece process yalnızca belirsiz bir anlamda "restricted" olarak işaretlenmez, bunun yerine somut bir syscall policy'sine tabi olur. Bu önemlidir, çünkü birçok container breakout, çok specific kernel interface'lerine ulaşmayı gerektirir. Process ilgili syscall'ları başarıyla çağırmadığında, namespace veya capability ayrıntıları önem kazanmadan önce çok sayıda attack sınıfı ortadan kalkar.

Temel zihinsel model basittir: namespace'ler **process'in neyi görebileceğine**, capability'ler **process'in nominal olarak hangi privileged action'ları gerçekleştirmeyi deneyebileceğine** ve seccomp ise **kernel'in denenmekte olan action için syscall entry point'ini kabul edip etmeyeceğine** karar verir. Bu nedenle seccomp, yalnızca capability'lere bakıldığında mümkün görünen attack'ları sıklıkla engeller.

## Security Impact

Tehlikeli kernel surface'inin büyük bir kısmına yalnızca görece küçük bir syscall kümesi üzerinden erişilebilir. Container hardening açısından tekrar tekrar önem taşıyan örnekler arasında `mount`, `unshare`, belirli flag'lerle birlikte `clone` veya `clone3`, `bpf`, `ptrace`, `keyctl` ve `perf_event_open` bulunur. Bu syscall'lara ulaşabilen bir attacker yeni namespace'ler oluşturabilir, kernel subsystem'lerini manipüle edebilir veya normal bir application container'ın hiç ihtiyaç duymadığı attack surface'leri kullanabilir.

Default runtime seccomp profile'larının bu kadar önemli olmasının nedeni budur. Bunlar yalnızca "extra defense" değildir. Birçok ortamda, kernel functionality'sinin geniş bir bölümünü kullanabilen bir container ile application'ın gerçekten ihtiyaç duyduğu şeye daha yakın bir syscall surface'i ile sınırlı olan container arasındaki farkı oluştururlar.

## Modlar ve Filtre Oluşturma

seccomp geçmişte yalnızca çok küçük bir syscall kümesinin kullanılabildiği strict mode'a sahipti; ancak modern container runtime'ları açısından önemli olan mode, genellikle **seccomp-bpf** olarak adlandırılan seccomp filter mode'dur. Bu modelde kernel, bir syscall'ın allow edilmesi, errno ile deny edilmesi, trap edilmesi, log'lanması veya process'in kill edilmesi gerekip gerekmediğine karar veren bir filter program'ını değerlendirir.<sup>[[1]](#references)</sup> Container runtime'ları bu mekanizmayı kullanır, çünkü normal application davranışına izin vermeye devam ederken tehlikeli syscall'ların geniş sınıflarını engelleyecek kadar ifade gücüne sahiptir.

İki low-level örnek yararlıdır; çünkü mekanizmayı sihirli olmaktan çıkarıp somut hale getirir. Strict mode, eski "yalnızca minimal bir syscall kümesi hayatta kalır" modelini gösterir:
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
Son `open`, strict mode'un minimal set'inin bir parçası olmadığı için process'in sonlandırılmasına neden olur.

Bir libseccomp filter örneği, modern policy modelini daha açık şekilde gösterir:
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
Bu politika stili, çoğu okuyucunun runtime seccomp profillerini düşündüğünde gözünde canlandırması gereken şeydir.

## Laboratuvar

Bir container içinde seccomp'un etkin olduğunu doğrulamanın basit bir yolu:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Varsayılan profillerin genellikle kısıtladığı bir işlemi de deneyebilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Container normal bir varsayılan seccomp profile altında çalışıyorsa, `unshare` tarzı işlemler genellikle engellenir. Bu, image içinde userspace aracı mevcut olsa bile ihtiyaç duyduğu kernel yolunun hâlâ kullanılamaz durumda olabileceğini göstermesi açısından faydalı bir demonstrasyondur.
Container normal bir varsayılan seccomp profile altında çalışıyorsa, userspace aracı image içinde mevcut olsa bile `unshare` tarzı işlemler genellikle engellenir.

Process durumunu daha genel olarak incelemek için şunu çalıştırın:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime Kullanımı

Docker hem varsayılan hem de özel seccomp profillerini destekler ve yöneticilerin bunları `--security-opt seccomp=unconfined` ile devre dışı bırakmasına olanak tanır.<sup>[[2]](#references)</sup> Podman da benzer desteğe sahiptir ve genellikle seccomp'u rootless çalıştırma ile birleştirerek oldukça makul bir varsayılan güvenlik duruşu sunar. Kubernetes, seccomp'u workload yapılandırması üzerinden kullanıma sunar; burada `RuntimeDefault` genellikle makul temel seçenekken, `Unconfined` kolaylık sağlayan bir aç/kapat seçeneği olarak değil, gerekçelendirme gerektiren bir istisna olarak ele alınmalıdır.<sup>[[3]](#references)</sup>

containerd ve CRI-O tabanlı ortamlarda tam yol daha katmanlıdır, ancak ilke aynıdır: daha üst düzey engine veya orchestrator ne olması gerektiğine karar verir ve runtime sonunda ortaya çıkan seccomp policy'yi container process'i için kurar. Sonuç yine kernel'e ulaşan nihai runtime yapılandırmasına bağlıdır.

### Özel Policy Örneği

Docker ve benzer engine'ler özel bir seccomp profilini JSON'dan yükleyebilir. Diğer her şeye izin verirken `chmod`'u engelleyen minimal bir örnek şöyledir:
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
Şununla uygulanır:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Komut `Operation not permitted` hatasıyla başarısız olur; bu da kısıtlamanın yalnızca normal dosya izinlerinden değil, syscall politikasından kaynaklandığını gösterir. Gerçek hardening uygulamalarında allowlist'ler, küçük bir blacklist içeren permissive varsayılanlardan genellikle daha güçlüdür.

## Yanlış Yapılandırmalar

En kaba hata, bir uygulama varsayılan politika altında çalışmadığında seccomp'u **unconfined** olarak ayarlamaktır. Bu, troubleshooting sırasında yaygındır ve kalıcı bir çözüm olarak oldukça tehlikelidir. Filter kaldırıldığında, özellikle güçlü yetenekler veya host namespace paylaşımı da mevcutsa, syscall tabanlı birçok breakout primitive yeniden erişilebilir hale gelir.

Bir diğer yaygın sorun, dikkatlice incelenmeden bir blogdan veya dahili bir workaround'dan kopyalanmış **custom permissive profile** kullanılmasıdır. Ekipler bazen profili "uygulamanın ihtiyaç duyduğu şeyi yalnızca grant et" yerine "uygulamanın bozulmasını durdur" anlayışıyla oluşturduğu için neredeyse tüm tehlikeli syscall'ları korur. Üçüncü bir yanılgı ise seccomp'un non-root container'lar için daha az önemli olduğunu varsaymaktır. Gerçekte, process UID 0 olmasa bile kernel attack surface'in önemli bir bölümü geçerliliğini korur.

## Abuse

Seccomp yoksa veya ciddi biçimde zayıflatılmışsa, bir attacker namespace-creation syscall'larını çağırabilir, `bpf` veya `perf_event_open` üzerinden erişilebilir kernel attack surface'i genişletebilir, `keyctl`'i abuse edebilir ya da bu syscall yollarını `CAP_SYS_ADMIN` gibi tehlikeli capability'lerle birleştirebilir. Gerçek saldırıların çoğunda seccomp eksik olan tek control değildir; ancak yokluğu exploit path'i önemli ölçüde kısaltır, çünkü riskli bir syscall'ı privilege model'in geri kalanı devreye girmeden durdurabilecek az sayıdaki defense mekanizmasından birini ortadan kaldırır.

En yararlı pratik test, default profile'ların genellikle engellediği syscall family'lerini doğrudan denemektir. Bunlar aniden çalışıyorsa container posture'u büyük ölçüde değişmiştir:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
`CAP_SYS_ADMIN` veya başka bir güçlü capability mevcutsa, mount-based abuse öncesinde eksik olan tek engelin seccomp olup olmadığını test edin:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Bazı hedeflerde asıl amaç tam bir escape değil, bilgi toplamak ve kernel attack surface'ini genişletmektir. Bu komutlar, özellikle hassas syscall yollarına erişilip erişilemediğini belirlemeye yardımcı olur:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Seccomp yoksa ve container başka açılardan da privileged durumdaysa, legacy container-escape sayfalarında zaten belgelenmiş daha spesifik breakout tekniklerine pivot etmek anlamlı hale gelir.

### Tam Örnek: `unshare` İşlemini Engelleyen Tek Şey Seccomp'du

Birçok hedefte seccomp'u kaldırmanın pratik etkisi, namespace oluşturma veya mount system call'larının aniden çalışmaya başlamasıdır. Container'da ayrıca `CAP_SYS_ADMIN` varsa aşağıdaki sequence mümkün hale gelebilir:
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
Tek başına bu henüz bir host escape değildir, ancak mount ile ilgili exploitation'ı engelleyen bariyerin seccomp olduğunu gösterir.

### Tam Örnek: seccomp Devre Dışı + cgroup v1 `release_agent`

seccomp devre dışıysa ve container cgroup v1 hiyerarşilerini mount edebiliyorsa, cgroups bölümündeki `release_agent` tekniğine erişilebilir hale gelir:
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Bu, yalnızca seccomp kullanan bir exploit değildir. Önemli nokta, seccomp unconfined olduğunda daha önce engellenen syscall ağırlıklı breakout chain'lerin tam olarak yazıldıkları şekilde çalışmaya başlayabilmesidir.

## Kontroller

Bu kontrollerin amacı seccomp'nin etkin olup olmadığını, `no_new_privs` seçeneğinin buna eşlik edip etmediğini ve runtime yapılandırmasının seccomp'nin açıkça devre dışı bırakıldığını gösterip göstermediğini belirlemektir.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Burada ilginç olanlar:

- Sıfır olmayan bir `Seccomp` değeri filtrelemenin etkin olduğu anlamına gelir; `0` genellikle seccomp koruması olmadığı anlamına gelir.
- Runtime security options `seccomp=unconfined` içeriyorsa workload, en kullanışlı syscall-level savunmalarından birini kaybetmiştir.
- `NoNewPrivs` tek başına seccomp değildir; ancak her ikisini birlikte görmek, ikisini de görmemeye kıyasla genellikle daha dikkatli bir hardening yaklaşımına işaret eder.

Bir container'da zaten şüpheli mount'lar, geniş capabilities veya paylaşılan host namespaces varsa ve seccomp da unconfined durumdaysa, bu kombinasyon önemli bir escalation sinyali olarak değerlendirilmelidir. Container hâlâ kolayca break edilebilir olmayabilir, ancak attacker için kullanılabilir kernel entry point'lerinin sayısı keskin biçimde artmıştır.

## Runtime Defaults

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Genellikle varsayılan olarak etkin | Override edilmediği sürece Docker'ın yerleşik varsayılan seccomp profile'ını kullanır | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Genellikle varsayılan olarak etkin | Override edilmediği sürece runtime'ın varsayılan seccomp profile'ını uygular | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Varsayılan olarak garanti edilmez** | `securityContext.seccompProfile` ayarlanmamışsa, kubelet `--seccomp-default` etkinleştirmediği sürece varsayılan `Unconfined` olur; aksi durumda `RuntimeDefault` veya `Localhost` açıkça ayarlanmalıdır | `securityContext.seccompProfile.type: Unconfined`, `seccompDefault` olmayan cluster'larda seccomp'u ayarlamamak, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes node ve Pod ayarlarını izler | Kubernetes `RuntimeDefault` istediğinde veya kubelet seccomp defaulting etkinleştirildiğinde runtime profile'ı kullanılır | Kubernetes satırındakiyle aynıdır; doğrudan CRI/OCI configuration da seccomp'u tamamen atlayabilir |

Kubernetes davranışı, operator'leri en sık şaşırtan konudur. Birçok cluster'da Pod bunu talep etmediği veya kubelet `RuntimeDefault` kullanacak şekilde yapılandırılmadığı sürece seccomp hâlâ yoktur.<sup>[[3]](#references)</sup>

## References

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
