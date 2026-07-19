# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

**seccomp**, kernel'in bir process'in çağırabileceği syscall'lara filtre uygulamasını sağlayan mekanizmadır. Containerized ortamlarda seccomp normalde filter mode'da kullanılır; böylece process belirsiz bir anlamda yalnızca "restricted" olarak işaretlenmez, bunun yerine somut bir syscall policy'ye tabi olur. Bu önemlidir çünkü birçok container breakout, çok spesifik kernel interface'lerine erişilmesini gerektirir. Process ilgili syscall'ları başarıyla çağır the proper? if cannot successfully invoke, a large class of attacks disappears before any namespace or capability nuance even becomes relevant.

Temel zihinsel model basittir: namespaces **process'in neyi görebileceğine**, capabilities **process'in nominal olarak hangi privileged action'ları gerçekleştirmeyi deneyebileceğine**, seccomp ise **kernel'in denenmekte olan action için syscall entry point'ini kabul edip etmeyeceğine** karar verir. Bu nedenle seccomp, yalnızca capabilities temelinde mümkün görünen attack'ları sıklıkla engeller.

## Security Impact

Tehlikeli kernel surface alanının büyük bir kısmına yalnızca görece küçük bir syscall set'i üzerinden erişilebilir. Container hardening'de tekrar tekrar önem taşıyan örnekler arasında `mount`, `unshare`, belirli flag'lerle birlikte `clone` veya `clone3`, `bpf`, `ptrace`, `keyctl` ve `perf_event_open` bulunur. Bu syscall'lara erişebilen bir attacker yeni namespaces oluşturabilir, kernel subsystem'lerini manipüle edebilir veya normal bir application container'ın hiç ihtiyaç duymadığı attack surface ile etkileşime girebilir.

Default runtime seccomp profile'larının bu kadar önemli olmasının nedeni budur. Bunlar yalnızca "extra defense" değildir. Birçok ortamda, kernel functionality'sinin geniş bir bölümünü kullanabilen bir container ile application'ın gerçekten ihtiyaç duyduğu şeye daha yakın bir syscall surface ile kısıtlanmış bir container arasındaki farkı oluştururlar.

## Modes And Filter Construction

seccomp tarihsel olarak yalnızca çok küçük bir syscall set'inin kullanılabildiği strict mode'a sahipti; ancak modern container runtime'lar için ilgili mode, sıklıkla **seccomp-bpf** olarak adlandırılan seccomp filter mode'dur. Bu modelde kernel, bir syscall'ın allow edilmesi, errno ile deny edilmesi, trap edilmesi, log'lanması veya process'in kill edilmesi gerektiğine karar veren bir filter programını değerlendirir. Container runtime'ları bu mekanizmayı kullanır; çünkü normal application davranışına izin verirken tehlikeli syscall'ların geniş sınıflarını block edecek kadar ifade gücüne sahiptir.

İki low-level örnek faydalıdır; çünkü mekanizmayı sihirli olmaktan çıkarıp somut hale getirir. Strict mode, eski "yalnızca minimal bir syscall set'i hayatta kalır" modelini gösterir:
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
Son `open`, strict mode'un minimal set'inin bir parçası olmadığı için process'in kill edilmesine neden olur.

Bir libseccomp filter örneği, modern policy modelini daha net gösterir:
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
Bu politika tarzı, çoğu okuyucunun runtime seccomp profillerini düşündüğünde gözünde canlandırması gereken şeydir.

## Lab

Bir container içinde seccomp'un etkin olduğunu doğrulamanın basit bir yolu şudur:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Ayrıca, varsayılan profillerin genellikle kısıtladığı bir işlemi de deneyebilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Container normal bir varsayılan seccomp profili altında çalışıyorsa, `unshare` tarzı işlemler genellikle engellenir. Bu, userspace aracının image içinde mevcut olması durumunda bile ihtiyaç duyduğu kernel yolunun yine de kullanılamayabileceğini göstermesi açısından faydalı bir demonstrasyondur.

Container normal bir varsayılan seccomp profili altında çalışıyorsa, userspace aracı image içinde mevcut olsa bile `unshare` tarzı işlemler genellikle engellenir.

Process durumunu daha genel olarak incelemek için şunu çalıştırın:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime Kullanımı

Docker, hem varsayılan hem de özel seccomp profillerini destekler ve yöneticilerin bunları `--security-opt seccomp=unconfined` ile devre dışı bırakmasına olanak tanır. Podman da benzer desteğe sahiptir ve genellikle rootless çalıştırmayı seccomp ile birleştirerek oldukça mantıklı bir varsayılan güvenlik duruşu sunar. Kubernetes, seccomp'i workload yapılandırması üzerinden sunar; burada `RuntimeDefault` genellikle makul temel ayardır ve `Unconfined`, kolaylık sağlayan bir seçenek olarak değil, gerekçelendirme gerektiren bir istisna olarak değerlendirilmelidir.

containerd ve CRI-O tabanlı ortamlarda tam yol daha katmanlıdır; ancak ilke aynıdır: daha üst düzey engine veya orchestrator ne yapılacağına karar verir ve runtime, sonuçta ortaya çıkan seccomp politikasını container process'i için yükler. Sonuç yine kernel'e ulaşan nihai runtime yapılandırmasına bağlıdır.

### Özel Policy Örneği

Docker ve benzer engine'ler, özel bir seccomp profilini JSON'dan yükleyebilir. Her şeye izin verirken `chmod`'u engelleyen minimal bir örnek şöyledir:
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
Komut `Operation not permitted` hatasıyla başarısız olur; bu da kısıtlamanın yalnızca olağan dosya izinlerinden değil, syscall politikasından kaynaklandığını gösterir. Gerçek hardening uygulamalarında allowlist'ler, küçük bir blacklist içeren permissive varsayılanlardan genellikle daha güçlüdür.

## Misconfigurations

En kaba hata, bir uygulama varsayılan policy altında çalışmadığında seccomp'u **unconfined** olarak ayarlamaktır. Bu, troubleshooting sırasında yaygındır ve kalıcı bir çözüm olarak son derece tehlikelidir. Filter kaldırıldığında, özellikle güçlü capabilities veya host namespace paylaşımı da mevcutsa, syscall tabanlı birçok breakout primitive'ine yeniden erişilebilir.

Bir diğer sık karşılaşılan sorun, bazı bloglardan veya kurum içi workaround'larından kopyalanan ve dikkatlice incelenmemiş **custom permissive profile** kullanılmasıdır. Ekipler bazen profile'ı "uygulamanın bozulmasını durdurma" anlayışıyla oluşturduğu, "uygulamanın gerçekten ihtiyaç duyduğu şeylere yalnızca izin verme" anlayışıyla oluşturmadığı için neredeyse tüm tehlikeli syscall'ları korur. Üçüncü bir yanlış kanı ise seccomp'un non-root container'lar için daha az önemli olduğunu varsaymaktır. Gerçekte, process UID 0 olmadığında bile kernel attack surface'ünün önemli bir bölümü geçerliliğini korur.

## Abuse

seccomp yoksa veya ciddi şekilde zayıflatılmışsa, bir attacker namespace-creation syscall'larını çağırabilir, `bpf` veya `perf_event_open` üzerinden erişilebilir kernel attack surface'ünü genişletebilir, `keyctl`'ı abuse edebilir ya da bu syscall yollarını `CAP_SYS_ADMIN` gibi tehlikeli capabilities ile birleştirebilir. Gerçek saldırıların çoğunda seccomp eksik olan tek kontrol değildir; ancak yokluğu exploit path'ini ciddi ölçüde kısaltır, çünkü privilege modelinin geri kalanı devreye girmeden önce riskli bir syscall'ı durdurabilecek az sayıdaki defense mekanizmasından birini ortadan kaldırır.

En faydalı pratik test, default profile'ların genellikle block ettiği tam syscall family'lerini denemektir. Bunlar aniden çalışıyorsa container posture'u önemli ölçüde değişmiştir:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
`CAP_SYS_ADMIN` veya başka bir güçlü capability mevcutsa, mount-based abuse öncesinde eksik olan tek bariyerin seccomp olup olmadığını test edin:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Bazı hedeflerde immediate value, tam escape elde etmek değil; bilgi toplamak ve kernel attack-surface alanını genişletmektir. Bu komutlar, özellikle hassas syscall yollarına erişilip erişilemediğini belirlemeye yardımcı olur:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
seccomp mevcut değilse ve container başka açılardan da privileged durumdaysa, daha önce legacy container-escape sayfalarında belgelenmiş daha spesifik breakout tekniklerine pivot etmek anlamlı hale gelir.

### Tam Örnek: `unshare` İşlemini Engelleyen Tek Şey seccomp'tu

Birçok hedefte seccomp'u kaldırmanın pratik etkisi, namespace oluşturma veya mount syscall'larının aniden çalışmaya başlamasıdır. Container'da ayrıca `CAP_SYS_ADMIN` varsa aşağıdaki sequence mümkün hale gelebilir:
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
Tek başına bu henüz bir host escape değildir, ancak seccomp’un mount ile ilgili exploitation'ı engelleyen bariyer olduğunu gösterir.

### Tam Örnek: seccomp Devre Dışı + cgroup v1 `release_agent`

seccomp devre dışıysa ve container cgroup v1 hiyerarşilerini mount edebiliyorsa, cgroups bölümündeki `release_agent` tekniğine erişilebilir:
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
Bu, yalnızca seccomp'e özgü bir exploit değildir. Buradaki nokta, seccomp unconfined olduğunda daha önce engellenen syscall ağırlıklı breakout chain'lerinin yazıldıkları hâliyle çalışmaya başlayabilmesidir.

## Kontroller

Bu kontrollerin amacı seccomp'in etkin olup olmadığını, `no_new_privs` özelliğinin ona eşlik edip etmediğini ve runtime yapılandırmasının seccomp'in açıkça devre dışı bırakıldığını gösterip göstermediğini belirlemektir.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Burada ilginç olanlar:

- Sıfır olmayan bir `Seccomp` değeri filtering'in etkin olduğu anlamına gelir; `0` genellikle seccomp korumasının olmadığını gösterir.
- Runtime security options içinde `seccomp=unconfined` yer alıyorsa workload, en kullanışlı syscall-level savunmalarından birini kaybetmiştir.
- `NoNewPrivs` tek başına seccomp değildir; ancak ikisini birlikte görmek, hiçbirini görmemeye kıyasla genellikle daha dikkatli bir hardening yaklaşımına işaret eder.

Bir container zaten şüpheli mount'lara, geniş capabilities'e veya paylaşılan host namespace'lerine sahipse ve seccomp da unconfined durumdaysa, bu kombinasyon önemli bir escalation sinyali olarak değerlendirilmelidir. Container hâlâ kolayca break edilemeyebilir, ancak attacker için kullanılabilir kernel entry point'lerinin sayısı büyük ölçüde artmıştır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Genellikle varsayılan olarak etkin | Override edilmediği sürece Docker'ın yerleşik varsayılan seccomp profilini kullanır | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Genellikle varsayılan olarak etkin | Override edilmediği sürece runtime'ın varsayılan seccomp profilini uygular | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Varsayılan olarak garanti edilmez** | `securityContext.seccompProfile` ayarlanmamışsa ve kubelet `--seccomp-default` seçeneğini etkinleştirmemişse varsayılan `Unconfined` olur; aksi durumda `RuntimeDefault` veya `Localhost` açıkça ayarlanmalıdır | `securityContext.seccompProfile.type: Unconfined`, `seccompDefault` olmayan cluster'larda seccomp'u ayarlamamak, `privileged: true` |
| Kubernetes altında containerd / CRI-O | Kubernetes node ve Pod ayarlarını izler | Kubernetes `RuntimeDefault` istediğinde veya kubelet seccomp varsayılanlarını etkinleştirdiğinde runtime profili kullanılır | Kubernetes satırındakiyle aynıdır; doğrudan CRI/OCI yapılandırması da seccomp'u tamamen devre dışı bırakabilir |

Kubernetes'in bu davranışı, operator'ları en sık şaşırtan konudur. Birçok cluster'da Pod seccomp'u talep etmediği veya kubelet `RuntimeDefault` kullanacak şekilde yapılandırılmadığı sürece seccomp hâlâ devre dışıdır.
{{#include ../../../../banners/hacktricks-training.md}}
