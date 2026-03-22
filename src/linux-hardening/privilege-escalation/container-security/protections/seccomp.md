# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

**seccomp**, çekirdeğin bir işlemin çağırabileceği syscalls üzerinde filtre uygulamasına izin veren mekanizmadır. Konteynerleştirilmiş ortamlarda, seccomp genellikle filtre modunda kullanılır; böylece işlem belirsiz bir şekilde "restricted" olarak işaretlenmek yerine somut bir syscall politikasına tabi olur. Bu önemlidir çünkü birçok container breakout çok spesifik çekirdek arabirimlerine erişmeyi gerektirir. İşlem ilgili syscalls'ları başarılı şekilde çağıramazsa, namespace veya capability ile ilgili nüanslar önem kazanmadan geniş bir saldırı sınıfı ortadan kalkar.

Ana zihinsel model basittir: namespaces belirler **işlemin ne görebileceğini**, capabilities belirler **işlemin nominal olarak hangi ayrıcalıklı işlemleri denemeye izinli olduğunu**, ve seccomp belirler **çekirdeğin denenen eylem için syscall giriş noktasını kabul edip etmeyeceğini**. Bu yüzden seccomp, capabilities'e bakarak mümkün görünebilecek birçok saldırıyı sık sık engeller.

## Güvenlik Etkisi

Tehlikeli çekirdek yüzeyinin büyük bir bölümü nispeten küçük bir syscall kümesi aracılığıyla ulaşılabilir. Konteyner sertleştirmede sürekli önemli olan örnekler şunlardır: `mount`, `unshare`, `clone` veya belirli flag'lerle `clone3`, `bpf`, `ptrace`, `keyctl` ve `perf_event_open`. Bu syscalls'lara erişebilen bir saldırgan yeni namespaces oluşturabilir, çekirdek alt sistemlerini manipüle edebilir veya normal bir uygulama container'ının hiç ihtiyaç duymadığı saldırı yüzeyiyle etkileşime girebilir.

İşte bu yüzden varsayılan runtime seccomp profilleri çok önemlidir. Bunlar sadece "extra defense" değildir. Birçok ortamda, bunlar geniş bir çekirdek fonksiyonelliğini kullanabilen bir container ile uygulamanın gerçekten ihtiyaç duyduğuna daha yakın bir syscall yüzeyiyle sınırlı bir container arasındaki farkı belirler.

## Modlar ve Filtre Oluşturma

seccomp tarihsel olarak yalnızca çok küçük bir syscall kümesinin kullanılabildiği bir strict moda sahipti, ancak modern container runtimes ile ilgili mod seccomp filter modudur, genellikle **seccomp-bpf** olarak adlandırılır. Bu modelde çekirdek, bir syscall'ın izin verilip verilmeyeceğine, bir errno ile reddedilip reddedilmeyeceğine, trapped edilip edilmeyeceğine, loglanıp loglanmayacağına veya işlemin öldürülüp öldürülmeyeceğine karar veren bir filtre programını değerlendirir. Container runtimes bu mekanizmayı, tehlikeli syscalls'ın geniş sınıflarını engelleyebilecek kadar ifade gücüne sahip olması ve aynı zamanda normal uygulama davranışına izin vermesi nedeniyle kullanır.

İki düşük seviyeli örnek faydalıdır çünkü mekanizmayı sihirli değil, somut kılar. Sıkı mod eski "sadece minimal bir syscall seti hayatta kalır" modelini gösterir:
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
Son `open`, strict modun minimal kümesinin bir parçası olmadığı için sürecin sonlandırılmasına neden olur.

Bir libseccomp filtre örneği modern politika modelini daha net gösterir:
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
Bu tür bir politika, çoğu okuyucunun çalışma zamanı seccomp profillerini düşündüğünde akıllarında canlandırmaları gereken şeydir.

## Laboratuvar

Bir konteynerde seccomp'un etkin olduğunu doğrulamanın basit bir yolu şudur:
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
Varsayılan profillerin genellikle kısıtladığı bir işlemi de deneyebilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
Eğer container normal varsayılan bir seccomp profili altında çalışıyorsa, `unshare` tarzı işlemler genellikle engellenir. Bu yararlı bir gösterimdir çünkü userspace aracı image içinde mevcut olsa bile ihtiyaç duyduğu kernel yolu hâlâ kullanılamıyor olabilir.
Eğer container normal varsayılan bir seccomp profili altında çalışıyorsa, `unshare` tarzı işlemler genellikle userspace aracı image içinde mevcut olsa bile engellenir.

Süreç durumunu daha genel olarak incelemek için şunu çalıştırın:
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Çalışma Zamanı Kullanımı

Docker varsayılan ve özel seccomp profillerinin ikisini destekler ve yöneticilerin bunları `--security-opt seccomp=unconfined` ile devre dışı bırakmasına izin verir. Podman benzer desteğe sahiptir ve genellikle seccomp'i rootless çalıştırma ile eşleştirerek makul bir varsayılan tutum oluşturur. Kubernetes, seccomp'i iş yükü yapılandırması üzerinden açığa çıkarır; burada `RuntimeDefault` genellikle makul bir temel hattır ve `Unconfined` kolay bir anahtar olarak değil, gerekçe gerektiren bir istisna olarak ele alınmalıdır.

containerd ve CRI-O tabanlı ortamlarda, tam yol daha katmanlıdır, ancak ilke aynıdır: üst düzey motor veya orkestratör ne olması gerektiğine karar verir ve runtime nihayetinde konteyner işlemi için ortaya çıkan seccomp politikasını kurar. Sonuç yine çekirdeğe ulaşan nihai runtime yapılandırmasına bağlıdır.

### Özel Politika Örneği

Docker ve benzeri motorlar JSON'dan özel bir seccomp profili yükleyebilir. Her şeyi izin verirken `chmod`'u reddeden minimal bir örnek şöyle görünür:
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
Uygulamada kullanıldı:
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
Komut `Operation not permitted` hatasıyla başarısız oluyor; bu, kısıtlamanın yalnızca normal dosya izinlerinden değil, syscall politikasından kaynaklandığını gösterir. Gerçek sertleştirmede, allowlists genellikle küçük bir blacklist'e kıyasla daha güçlüdür.

## Misconfigurations

En kaba hata, bir uygulama varsayılan politika altında çalışmazken seccomp'i **unconfined** olarak ayarlamaktır. Bu, sorun giderme sırasında yaygındır ve kalıcı bir çözüm olarak çok tehlikelidir. Filtre kalktığında, özellikle güçlü capabilities veya host namespace sharing de mevcutsa, birçok syscall tabanlı breakout primitive yeniden erişilebilir hale gelir.

Diğer sık rastlanan problem, dikkatlice incelenmemiş bir blog yazısından veya dahili bir geçici çözümdən kopyalanmış bir **custom permissive profile** kullanılmasıdır. Ekipler bazen profil "uygulamanın bozulmasını engelle" mantığıyla oluşturulduğu için neredeyse tüm tehlikeli syscalls'ları tutarlar; oysa hedef "uygulamanın gerçekten ihtiyacı olanı ver" olmalıdır. Üçüncü yanlış kanı, seccomp'ın non-root containers için daha az önemli olduğunu varsaymaktır. Gerçekte, process `UID 0` olmasa bile kernel attack surface'ın büyük bir kısmı hâlâ önemlidir.

## Abuse

Seccomp yoksa veya ciddi şekilde zayıflatılmışsa, bir saldırgan namespace-creation syscalls'larını çağırabilir, ulaşılabilir kernel attack surface'ını `bpf` veya `perf_event_open` aracılığıyla genişletebilir, `keyctl`'i kötüye kullanabilir veya bu syscall yollarını `CAP_SYS_ADMIN` gibi tehlikeli capabilities ile birleştirebilir. Birçok gerçek saldırıda seccomp tek eksik kontrol değildir; ancak yokluğu exploit yolunu dramatik şekilde kısaltır çünkü ayrıcalık modelinin geri kalanı devreye girmeden önce riskli bir syscall'u durdurabilecek savunmalardan birini kaldırır.

En kullanışlı pratik test, varsayılan profillerin genellikle engellediği tam syscall ailelerini denemektir. Eğer bunlar aniden çalışıyorsa, container durumu çok değişmiş demektir:
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
Eğer `CAP_SYS_ADMIN` veya başka güçlü bir capability mevcutsa, mount-based abuse'den önce eksik olan tek bariyerin seccomp olup olmadığını test edin:
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
Bazı hedeflerde, hemen elde edilen fayda tam bir kaçış değil; daha çok bilgi toplama ve kernel saldırı yüzeyini genişletmektir. Bu komutlar özellikle hassas syscall yollarına erişilip erişilemeyeceğini belirlemeye yardımcı olur:
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
Seccomp yoksa ve konteyner diğer yönlerden de ayrıcalıklıysa, bu durumda eski container-escape sayfalarında zaten belgelenmiş daha spesifik breakout techniques'e pivot yapmak mantıklıdır.

### Tam Örnek: seccomp `unshare`'ı Engelleyen Tek Şeydi

Birçok hedefte, seccomp kaldırıldığında pratik olarak namespace-creation veya mount syscalls aniden çalışmaya başlar. Eğer konteynerin ayrıca `CAP_SYS_ADMIN`'i varsa, aşağıdaki sıra mümkün hale gelebilir:
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
Tek başına bu henüz bir host escape değil, ancak seccomp'un mount-related exploitation'ı önleyen bariyer olduğunu gösteriyor.

### Tam Örnek: seccomp Devre Dışı + cgroup v1 `release_agent`

Eğer seccomp devre dışıysa ve container cgroup v1 hierarchies'i mount edebiliyorsa, cgroups bölümündeki `release_agent` tekniği erişilebilir hale gelir:
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
Bu sadece seccomp'a yönelik bir exploit değil. Buradaki nokta, seccomp'in kısıtlaması kaldırıldığında, önceden engellenmiş çok sayıda syscall içeren kaçış zincirlerinin tam olarak yazıldığı şekilde çalışmaya başlayabileceğidir.

## Kontroller

Bu kontrollerin amacı seccomp'in etkin olup olmadığını, `no_new_privs` ile birlikte gelip gelmediğini ve çalışma zamanı yapılandırmasının seccomp'i açıkça devre dışı bırakıp bırakmadığını belirlemektir.
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
Burada ilginç olanlar:

- Sıfırdan farklı bir `Seccomp` değeri filtrenin etkin olduğunu gösterir; `0` genellikle seccomp koruması olmadığını belirtir.
- Eğer runtime güvenlik seçenekleri `seccomp=unconfined` içeriyorsa, iş yükü en kullanışlı syscall düzeyindeki savunmalarından birini kaybetmiş olur.
- `NoNewPrivs` seccomp'un kendisi değildir, ancak ikisini birlikte görmek genellikle hiç görmemekten daha dikkatli bir sertleştirme yaklaşımını gösterir.

Eğer bir container zaten şüpheli mounts, geniş capabilities veya paylaşılan host namespaces'e sahipse ve seccomp da unconfined ise, bu kombinasyon büyük bir yükseltme sinyali olarak değerlendirilmelidir. Container hâlâ kolayca kırılabilir olmayabilir, ancak saldırganın erişebileceği kernel giriş noktaları sayısı keskin bir şekilde artmıştır.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatmalar |
| --- | --- | --- | --- |
| Docker Engine | Genellikle varsayılan olarak etkin | Geçersiz kılınmadıkça Docker'ın dahili varsayılan seccomp profilini kullanır | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Genellikle varsayılan olarak etkin | Geçersiz kılınmadıkça runtime varsayılan seccomp profilini uygular | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Varsayılan olarak garanti edilmez** | Eğer `securityContext.seccompProfile` ayarlı değilse, kubelet `--seccomp-default`'u etkinleştirmedikçe varsayılan `Unconfined`'dır; aksi takdirde `RuntimeDefault` veya `Localhost` açıkça ayarlanmalıdır | `securityContext.seccompProfile.type: Unconfined`, seccomp'un ayarlı bırakılması (seccompDefault olmayan kümelerde), `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes node ve Pod ayarlarını takip eder | Kubernetes `RuntimeDefault` isterse veya kubelet seccomp defaulting'i etkinse runtime profili kullanılır | Kubernetes satırıyla aynı; doğrudan CRI/OCI yapılandırması seccomp'u tamamen atlayabilir |

Kubernetes davranışı operatörleri en çok şaşırtandır. Birçok kümede, Pod bunu talep etmedikçe veya kubelet `RuntimeDefault`'a varsayılan yapacak şekilde yapılandırılmadıkça seccomp hâlâ yoktur.
{{#include ../../../../banners/hacktricks-training.md}}
