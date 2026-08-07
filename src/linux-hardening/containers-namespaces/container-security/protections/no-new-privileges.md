# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs`, bir process'in `execve()` üzerinden daha fazla privilege kazanmasını engelleyen bir kernel hardening özelliğidir. Pratikte flag ayarlandıktan sonra bir setuid binary, setgid binary veya Linux file capabilities içeren bir dosyanın çalıştırılması, process'in zaten sahip olduğu privilege seviyesinin ötesinde ek privilege vermez. Containerized ortamlarda bu önemlidir; çünkü birçok privilege-escalation chain, çalıştırıldığında privilege değiştiren bir executable'ın image içinde bulunmasına dayanır.

Defensive açıdan `no_new_privs`, namespaces, seccomp veya capability dropping yerine kullanılabilecek bir çözüm değildir. Bu mekanizmaları güçlendiren ek bir katmandır. Code execution elde edildikten sonra gerçekleşebilecek belirli bir follow-up escalation sınıfını engeller. Bu nedenle images içinde helper binaries, package-manager artifacts veya partial compromise ile birlikte kullanıldığında tehlikeli olabilecek legacy tools bulunan ortamlarda özellikle değerlidir.

## Çalışma Şekli

Bu davranışın arkasındaki kernel flag'i `PR_SET_NO_NEW_PRIVS`'dir. Bir process için ayarlandıktan sonra sonraki `execve()` çağrıları privilege seviyesini artıramaz. Önemli nokta, process'in binary'leri çalıştırmaya devam edebilmesidir; yalnızca bu binary'leri kullanarak kernel'in normalde izin vereceği bir privilege boundary'yi aşamaz.<sup>[[1]](#references)</sup>

Kernel davranışı aynı zamanda **inherit edilir ve geri döndürülemez**: Bir task `no_new_privs` ayarladığında bit `fork()`, `clone()` ve `execve()` üzerinden inherit edilir ve daha sonra unset edilemez.<sup>[[1]](#references)</sup> Bu, assessment'larda kullanışlıdır; çünkü container process'i üzerinde bulunan tek bir `NoNewPrivs: 1` değeri genellikle descendants'ın da tamamen farklı bir process tree incelenmiyorsa bu modda kalması gerektiği anlamına gelir.

Kubernetes-oriented ortamlarda `allowPrivilegeEscalation: false`, container process'i için bu davranışa karşılık gelir.<sup>[[2]](#references)</sup> Docker ve Podman tarzı runtimes'larda eşdeğer ayar genellikle bir security option üzerinden açıkça etkinleştirilir. OCI katmanında aynı kavram `process.noNewPrivileges` olarak görünür.

## Önemli Nuance'lar

`no_new_privs`, her privilege değişikliğini değil, **exec-time** privilege gain'i engeller.<sup>[[1]](#references)</sup> Özellikle:

- setuid ve setgid geçişleri `execve()` üzerinden çalışmaz
- file capabilities, `execve()` sırasında permitted set'e eklenmez
- AppArmor veya SELinux gibi LSM'ler `execve()` sonrasında kısıtlamaları gevşetmez
- zaten sahip olunan privilege, hâlâ zaten sahip olunan privilege'dır

Son nokta operasyonel açıdan önemlidir. Process zaten root olarak çalışıyorsa, tehlikeli bir capability'ye zaten sahipse veya güçlü bir runtime API'ye ya da writable host mount'a zaten erişebiliyorsa, `no_new_privs` bu exposure'ları etkisiz hâle getirmez. Yalnızca bir privilege-escalation chain içindeki yaygın **next step**'lerden birini ortadan kaldırır.

Ayrıca flag'in `execve()`'ye bağlı olmayan privilege değişikliklerini engellemediğini unutmayın.<sup>[[1]](#references)</sup> Örneğin, zaten yeterli privilege'e sahip bir task doğrudan `setuid(2)` çağırmaya veya bir Unix socket üzerinden privileged file descriptor almaya devam edebilir. Bu nedenle `no_new_privs`, tek başına bir çözüm olarak değil, [seccomp](seccomp.md), capability sets ve namespace exposure ile birlikte değerlendirilmelidir.

## Lab

Mevcut process durumunu inceleyin:
```bash
grep NoNewPrivs /proc/self/status
```
Bunu, runtime'ın flag'i etkinleştirdiği bir container ile karşılaştırın:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Sıkılaştırılmış bir workload üzerinde sonuç `NoNewPrivs: 1` göstermelidir.

Gerçek etkiyi bir setuid binary üzerinde de gösterebilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Karşılaştırmanın amacı `su`'nun evrensel olarak exploit edilebilir olduğunu söylemek değildir. Asıl nokta, `execve()`'nin bir ayrıcalık sınırını aşmasına hâlâ izin verilip verilmemesine bağlı olarak aynı image'ın çok farklı davranabilmesidir.

## Güvenlik Etkisi

`no_new_privs` mevcut değilse, container içindeki bir foothold setuid yardımcıları veya file capabilities içeren binary'ler aracılığıyla hâlâ yükseltilebilir. Mevcutsa, exec sonrası gerçekleşen bu ayrıcalık değişiklikleri engellenir. Bu etki, uygulamanın baştan hiç ihtiyaç duymadığı birçok yardımcı programı barındıran geniş base image'larda özellikle önemlidir.

Ayrıca önemli bir seccomp etkileşimi vardır. Ayrıcalıksız task'ların filter mode'da bir seccomp filter kurabilmesi için genellikle önce `no_new_privs` ayarlanmış olmalıdır.<sup>[[1]](#references)</sup> Hardened container'ların çoğunlukla hem `Seccomp` hem de `NoNewPrivs` özelliklerini birlikte etkin göstermesinin nedenlerinden biri budur. Bir attacker açısından her ikisini de görmek, ortamın yanlışlıkla değil, bilinçli olarak yapılandırıldığını gösterir.

## Yanlış Yapılandırmalar

En yaygın sorun, kontrolün uyumlu olacağı ortamlarda basitçe etkinleştirilmemesidir. Kubernetes'te `allowPrivilegeEscalation` özelliğini etkin bırakmak çoğu zaman varsayılan operasyonel hatadır. Docker ve Podman'de ilgili security option'ın atlanması aynı etkiyi yaratır. Tekrarlanan bir diğer hata modu ise bir container'ın "privileged" olmaması nedeniyle exec zamanındaki ayrıcalık geçişlerinin otomatik olarak önemsiz olduğunu varsaymaktır.

Daha ince bir Kubernetes tuzağı, container `privileged` olduğunda veya `CAP_SYS_ADMIN` içerdiğinde `allowPrivilegeEscalation: false` değerinin insanların beklediği şekilde uygulanmamasıdır. Kubernetes API, bu durumlarda `allowPrivilegeEscalation` değerinin fiilen her zaman true olduğunu belirtir.<sup>[[2]](#references)</sup> Pratikte bu, alanın nihai posture'daki sinyallerden yalnızca biri olarak değerlendirilmesi gerektiği ve runtime'ın sonunda `NoNewPrivs: 1` değerine sahip olduğuna dair bir garanti olarak görülmemesi anlamına gelir.

## Abuse

`no_new_privs` ayarlanmamışsa ilk soru, image'ın hâlâ ayrıcalık yükseltebilen binary'ler içerip içermediğidir:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
İlginç sonuçlar şunları içerir:

- `NoNewPrivs: 0`
- `su`, `mount`, `passwd` veya dağıtıma özgü admin araçları gibi setuid yardımcıları
- network veya filesystem ayrıcalıkları sağlayan file capabilities içeren binary'ler

Gerçek bir değerlendirmede bu bulgular tek başına çalışan bir escalation olduğunu kanıtlamaz, ancak sonraki adımda test edilmeye değer binary'leri tam olarak belirler.

Kubernetes'te ayrıca YAML'deki niyetin kernel gerçekliğiyle eşleştiğini doğrulayın:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
İlginç kombinasyonlar şunları içerir:

- Pod spec içinde `allowPrivilegeEscalation: false`, ancak container içinde `NoNewPrivs: 0`
- `cap_sys_admin` mevcut; bu da Kubernetes alanını çok daha az güvenilir hâle getirir
- `Seccomp: 0` ve `NoNewPrivs: 0`; bu genellikle tek bir izole hatadan ziyade runtime güvenlik duruşunun genel olarak zayıflatıldığını gösterir

### Tam Örnek: setuid Üzerinden Container İçinde Privilege Escalation

Bu kontrol genellikle doğrudan host escape yerine **container içindeki privilege escalation** işlemlerini önler. `NoNewPrivs` değeri `0` ise ve bir setuid helper mevcutsa bunu açıkça test edin:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Bilinen bir setuid binary mevcut ve çalışır durumdaysa, ayrıcalık geçişini koruyacak şekilde başlatmayı deneyin:
```bash
/bin/su -c id 2>/dev/null
```
Bu, kendi başına container'dan kaçış sağlamaz; ancak container içindeki düşük ayrıcalıklı bir foothold'u container-root'a dönüştürebilir. Bu da çoğu zaman mounts, runtime sockets veya kernel-facing interfaces üzerinden daha sonra gerçekleştirilecek host escape için ön koşul hâline gelir.

## Kontroller

Bu kontrollerin amacı, exec-time privilege gain işleminin engellenip engellenmediğini ve engellenmiyorsa image içinde önem taşıyabilecek yardımcı araçların hâlâ bulunup bulunmadığını belirlemektir.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
Burada ilginç olanlar:

- `NoNewPrivs: 1` genellikle daha güvenli sonuçtur.
- `NoNewPrivs: 0`, setuid ve file-cap tabanlı escalation yollarının hâlâ önemli olduğu anlamına gelir.
- `NoNewPrivs: 1` ile birlikte `Seccomp: 2` görülmesi, daha bilinçli bir hardening yaklaşımının yaygın işaretidir.
- `allowPrivilegeEscalation: false` belirten bir Kubernetes manifesti faydalıdır, ancak kernel durumu esas gerçektir.
- Çok az veya hiç setuid/file-cap binary içermeyen minimal bir image, `no_new_privs` eksik olsa bile saldırgana post-exploitation sonrasında daha az seçenek bırakır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin değil | `--security-opt no-new-privileges=true` ile açıkça etkinleştirilir; daemon genelinde varsayılan da `dockerd --no-new-privileges` ile ayarlanabilir | flag'i atlamak, `--privileged` |
| Podman | Varsayılan olarak etkin değil | `--security-opt no-new-privileges` veya eşdeğer security configuration ile açıkça etkinleştirilir | seçeneği atlamak, `--privileged` |
| Kubernetes | Workload policy tarafından kontrol edilir | `allowPrivilegeEscalation: false` bu etkiyi talep eder, ancak `privileged: true` ve `CAP_SYS_ADMIN` bunu fiilen true tutar | `allowPrivilegeEscalation: true`, `privileged: true`, `CAP_SYS_ADMIN` eklemek |
| containerd / CRI-O under Kubernetes | Kubernetes workload settings / OCI `process.noNewPrivileges` ayarlarını izler | Genellikle Pod security context'ten devralınır ve OCI runtime config'e dönüştürülür | Kubernetes satırındakiyle aynı |

Bu protection çoğu zaman runtime bunu desteklemediği için değil, hiç kimse etkinleştirmediği için yoktur.

## References

- [1] [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
