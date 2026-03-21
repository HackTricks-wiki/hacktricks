# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

**seccomp** çekirdeğin bir sürecin çağırabileceği syscall'lara filtre uygulamasına izin veren mekanizmadır. Container'lı ortamlarda, seccomp genellikle filtre modunda kullanılır; böylece süreç belirsiz bir şekilde "restricted" olarak işaretlenmek yerine somut bir syscall politikasına tabi olur. Bu önemlidir çünkü birçok container breakout'u çok spesifik çekirdek arabirimlerine erişmeyi gerektirir. Süreç ilgili syscall'ları başarılı şekilde çağıramazsa, isim alanı veya imtiyaz ayrıntıları önem kazanmadan önce büyük bir saldırı sınıfı ortadan kalkar.

Ana zihinsel model basittir: isim alanları sürecin **ne görebileceğine**, imtiyazlar sürecin **hangi ayrıcalıklı eylemleri nominal olarak denemeye izinli olduğuna**, ve seccomp ise **çekirdeğin denenen eylem için syscall giriş noktasını kabul edip etmeyeceğine** karar verir. Bu yüzden seccomp, yalnızca imtiyazlara dayanarak mümkün görünebilecek saldırıları sıklıkla engeller.

## Güvenlik Etkisi

Tehlikeli çekirdek yüzeyinin büyük bir bölümü yalnızca nispeten küçük bir syscall seti aracılığıyla erişilebilir. Container hardening'de sıkça önemli olan örnekler arasında `mount`, `unshare`, belirli bayraklarla `clone` veya `clone3`, `bpf`, `ptrace`, `keyctl` ve `perf_event_open` bulunur. Bu syscall'lara erişebilen bir saldırgan yeni isim alanları oluşturabilir, çekirdek alt sistemlerini manipüle edebilir veya normal bir uygulama container'ının hiç ihtiyaç duymadığı saldırı yüzeyiyle etkileşime geçebilir.

İşte bu yüzden varsayılan runtime seccomp profilleri çok önemlidir. Bunlar yalnızca "ek savunma" değildir. Birçok ortamda, bunlar bir container'ın çekirdek işlevselliğinin geniş bir bölümünü kullanabilmesi ile uygulamanın gerçekten ihtiyaç duyduğuna daha yakın bir syscall yüzeyiyle kısıtlı olması arasındaki farkı belirler.

## Modlar ve Filtre Oluşturma

seccomp tarihsel olarak yalnızca çok küçük bir syscall kümesinin kullanılabildiği bir strict moduna sahipti, ancak modern container runtime'ları için ilgili mod seccomp filtre modudur, genellikle **seccomp-bpf** olarak adlandırılır. Bu modelde çekirdek, bir syscall'a izin verilip verilmeyeceğine, bir errno ile reddedilip reddedilmeyeceğine, traplenip traplenmeyeceğine, loglanıp loglanmayacağına veya sürecin öldürülüp öldürülmeyeceğine karar veren bir filtre programını değerlendirir. Container runtime'ları, normal uygulama davranışına izin verirken tehlikeli syscall'ların geniş sınıflarını engelleyecek kadar ifade gücüne sahip olduğu için bu mekanizmayı kullanır.

Two low-level examples are useful because they make the mechanism concrete rather than magical. Strict mode demonstrates the old "only a minimal syscall set survives" model:
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
Son `open`, strict mode'un minimal kümesinin parçası olmadığı için sürecin öldürülmesine neden olur.

Bir libseccomp filter örneği modern politika modelini daha net gösterir:
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
Bu tarz bir politika, çoğu okuyucunun runtime seccomp profilleri hakkında düşündüklerinde tasavvur etmeleri gereken şeydir.

## Laboratuvar

Bir container'da seccomp'un etkin olduğunu doğrulamanın basit bir yolu şudur:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Varsayılan profillerin genellikle kısıtladığı bir işlemi de deneyebilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Eğer container normal bir varsayılan seccomp profili altında çalışıyorsa, `unshare`-türü işlemler genellikle engellenir. Bu, userspace aracı image içinde mevcut olsa bile ihtiyaç duyduğu kernel path hâlâ kullanılamayabileceğini gösterdiği için faydalı bir gösterimdir.

Eğer container normal bir varsayılan seccomp profili altında çalışıyorsa, userspace aracı image içinde mevcut olsa bile `unshare`-türü işlemler genellikle engellenir.

İşlem durumunu daha genel olarak incelemek için şunu çalıştırın:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Çalışma Zamanı Kullanımı

Docker hem varsayılan hem de özel seccomp profillerini destekler ve yöneticilerin onları `--security-opt seccomp=unconfined` ile devre dışı bırakmasına izin verir. Podman benzer desteğe sahiptir ve genellikle seccomp'u rootless execution ile mantıklı bir varsayılan konfigürasyonda eşleştirir. Kubernetes, seccomp'u iş yükü yapılandırması üzerinden açığa çıkarır; burada `RuntimeDefault` genellikle makul bir temel seviye olup `Unconfined` kolaylık amaçlı bir anahtar yerine gerekçelendirme gerektiren bir istisna olarak ele alınmalıdır.

containerd ve CRI-O tabanlı ortamlarda süreç daha katmanlıdır, ancak ilke aynıdır: üst düzey motor veya orkestratör ne olması gerektiğine karar verir ve çalışma zamanı sonunda ortaya çıkan seccomp politikasını konteyner süreci için yükler. Sonuç yine çekirdeğe ulaşan nihai çalışma zamanı yapılandırmasına bağlıdır.

### Özel Politika Örneği

Docker ve benzeri engine'ler JSON'dan özel bir seccomp profili yükleyebilir. `chmod`'u reddederken diğer her şeye izin veren minimal bir örnek şu şekildedir:
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
Şununla uygulandı:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Komut `Operation not permitted` ile başarısız oluyor; bu, kısıtlamanın yalnızca dosya izinlerinden değil, syscall politikasından kaynaklandığını gösterir. Gerçek sertleştirmede, allowlists genellikle küçük bir blacklist ile izin verici varsayılanlardan daha güçlüdür.

## Yanlış yapılandırmalar

En kaba hata, bir uygulama varsayılan politika altında başarısız olduğu için seccomp'u **unconfined** olarak ayarlamaktır. Bu, sorun giderme sırasında yaygındır ve kalıcı bir çözüm olarak çok tehlikelidir. Filtre kaldırıldığında, özellikle güçlü capabilities veya host namespace sharing de varsa, birçok syscall tabanlı breakout primitives yeniden erişilebilir hale gelir.

Yaygın bir diğer sorun, bir blogdan veya dahili bir geçici çözümden kopyalanmış ve dikkatlice incelenmemiş bir **custom permissive profile** kullanılmasıdır. Ekipler bazen profili "uygulamanın çökmesini engelle" mantığıyla oluşturdukları için tehlikeli syscalls'ın neredeyse tamamını korurlar; oysa doğru yaklaşım "uygulamanın gerçekten ihtiyaç duyduğu tek şeyi ver" olmalıdır. Üçüncü yanlış anlayış, seccomp'un non-root konteynerler için daha az önemli olduğunu varsaymaktır. Gerçekte, işlem UID 0 olmadığında bile kernel attack surface'ın önemli bir kısmı hâlâ geçerlidir.

## Kötüye kullanım

Eğer seccomp yoksa veya ciddi şekilde zayıflatılmışsa, bir saldırgan namespace-creation syscalls'larını çağırabilir, `bpf` veya `perf_event_open` aracılığıyla ulaşılabilir kernel attack surface'ı genişletebilir, `keyctl`'i kötüye kullanabilir veya bu syscall yollarını `CAP_SYS_ADMIN` gibi tehlikeli capabilities ile birleştirebilir. Birçok gerçek saldırıda seccomp tek eksik kontrol olmayabilir, ancak yokluğu exploit yolunu dramatik şekilde kısaltır; çünkü riskli bir syscall'u ayrıcalık modelinin diğer katmanları devreye girmeden önce durdurabilecek nadir savunmalardan birini ortadan kaldırır.

En faydalı pratik test, default profiles'ların genellikle engellediği tam syscall ailelerini denemektir. Eğer bunlar aniden çalışıyorsa, konteyner duruşu (container posture) büyük ölçüde değişmiş demektir:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Eğer `CAP_SYS_ADMIN` veya başka bir güçlü capability mevcutsa, seccomp'un mount-based abuse'dan önceki tek eksik bariyer olup olmadığını test edin:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Bazı hedeflerde asıl amaç anında tam kaçış değil, bilgi toplama ve kernel saldırı yüzeyinin genişletilmesidir. Bu komutlar, özellikle hassas syscall yollarının erişilebilir olup olmadığını belirlemeye yardımcı olur:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
seccomp yoksa ve container ayrıca başka yollarla da ayrıcalıklara sahipse, işte o zaman legacy container-escape sayfalarında zaten belgelenmiş daha spesifik breakout tekniklerine yönelmek mantıklıdır.

### Tam Örnek: seccomp yalnızca `unshare`'ı engelliyordu

Birçok hedefte, seccomp'in kaldırılmasının pratik etkisi, namespace-creation veya mount syscalls aniden çalışmaya başlamasıdır. Eğer container ayrıca `CAP_SYS_ADMIN`'e sahipse, aşağıdaki sıra mümkün hale gelebilir:
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
Kendi başına bu henüz bir host escape değildir, ancak seccomp'un mount-related exploitation'ı engelleyen bariyer olduğunu gösterir.

### Tam Örnek: seccomp devre dışı + cgroup v1 `release_agent`

Eğer seccomp devre dışıysa ve konteyner cgroup v1 hiyerarşilerini mount edebiliyorsa, cgroups bölümündeki `release_agent` tekniği erişilebilir hale gelir:
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
Bu bir seccomp-only exploit değil. Önemli olan şu: seccomp kısıtlaması kaldırıldığında (unconfined), daha önce engellenmiş olan syscall-heavy breakout chains tam olarak yazıldıkları şekilde çalışmaya başlayabilir.

## Kontroller

Bu kontrollerin amacı seccomp'un tamamen etkin olup olmadığını, `no_new_privs`'un buna eşlik edip etmediğini ve runtime yapılandırmasının seccomp'un açıkça devre dışı bırakıldığını gösterip göstermediğini tespit etmektir.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
What is interesting here:

- A non-zero `Seccomp` value means filtering is active; `0` usually means no seccomp protection.
- If the runtime security options include `seccomp=unconfined`, the workload has lost one of its most useful syscall-level defenses.
- `NoNewPrivs` is not seccomp itself, but seeing both together usually indicates a more careful hardening posture than seeing neither.

If a container already has suspicious mounts, broad capabilities, or shared host namespaces, and seccomp is also unconfined, that combination should be treated as a major escalation signal. The container may still not be trivially breakable, but the number of kernel entry points available to the attacker has increased sharply.

## Runtime Defaults

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatmalar |
| --- | --- | --- | --- |
| Docker Engine | Genellikle varsayılan olarak etkin | Aksi belirtilmediği sürece Docker'ın dahili varsayılan seccomp profilini kullanır | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Genellikle varsayılan olarak etkin | Aksi belirtilmediği sürece runtime'ın varsayılan seccomp profilini uygular | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Varsayılan olarak garanti edilmez** | Eğer `securityContext.seccompProfile` ayarlı değilse, kubelet `--seccomp-default` etkinleştirmedikçe varsayılan `Unconfined`'dır; aksi halde `RuntimeDefault` veya `Localhost` açıkça ayarlanmalıdır | `securityContext.seccompProfile.type: Unconfined`, seccompDefault olmayan kümelerde seccomp'u ayarlamamak, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes node ve Pod ayarlarını izler | Kubernetes `RuntimeDefault` istediğinde veya kubelet seccomp defaulting etkin olduğunda runtime profili kullanılır | Kubernetes satırı ile aynı; doğrudan CRI/OCI yapılandırması ayrıca seccomp'u tamamen atlayabilir |

Kubernetes davranışı operatörleri en çok şaşırtandır. Birçok kümede, Pod bunu talep etmedikçe veya kubelet `RuntimeDefault`'a varsayılan olacak şekilde yapılandırılmadıkça seccomp hâlâ yoktur.
