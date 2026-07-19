# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs`, bir sürecin `execve()` üzerinden daha fazla ayrıcalık kazanmasını engelleyen bir kernel hardening özelliğidir. Pratikte flag ayarlandıktan sonra setuid binary, setgid binary veya Linux file capabilities içeren bir dosyanın çalıştırılması, sürecin zaten sahip olduğundan daha fazla ayrıcalık vermez. Containerized ortamlarda bu önemlidir; çünkü birçok privilege-escalation zinciri, çalıştırıldığında ayrıcalığı değiştiren bir executable bulmaya dayanır.

Savunma açısından `no_new_privs`, namespaces, seccomp veya capability dropping yerine geçmez. Bir reinforcement layer'dır. Code execution elde edildikten sonra gerçekleşebilecek belirli bir follow-up escalation sınıfını engeller. Bu özellik, image'ların helper binary'ler, package-manager artifact'leri veya partial compromise ile birlikte kullanıldığında normalde tehlikeli olabilecek legacy tool'lar içerdiği ortamlarda özellikle değerlidir.

## Operation

Bu davranışın arkasındaki kernel flag'i `PR_SET_NO_NEW_PRIVS`'tir. Bir process için ayarlandıktan sonra, sonraki `execve()` çağrıları ayrıcalığı artıramaz. Önemli ayrıntı şudur: process binary'leri çalıştırmaya devam edebilir; ancak bu binary'leri, kernel'in normalde izin vereceği bir privilege boundary'yi aşmak için kullanamaz.

Kernel davranışı ayrıca **inherited and irreversible** özelliktedir: Bir task `no_new_privs` ayarladığında bit `fork()`, `clone()` ve `execve()` boyunca miras alınır ve daha sonra kaldırılamaz. Bu, assessment'larda faydalıdır; çünkü container process'i üzerinde tek bir `NoNewPrivs: 1` bulunması genellikle, tamamen farklı bir process tree incelemiyorsanız descendant'ların da bu mode'da kalması gerektiği anlamına gelir.

Kubernetes-oriented ortamlarda `allowPrivilegeEscalation: false`, container process'i için bu davranışa karşılık gelir. Docker ve Podman style runtime'larda eşdeğer ayar genellikle bir security option üzerinden açıkça etkinleştirilir. OCI layer'ında aynı concept `process.noNewPrivileges` olarak görünür.

## Important Nuances

`no_new_privs`, **exec-time** privilege gain'i engeller; her privilege change'i engellemez. Özellikle:

- setuid ve setgid transition'ları `execve()` boyunca çalışmaz
- file capabilities, `execve()` sırasında permitted set'e eklenmez
- AppArmor veya SELinux gibi LSM'ler `execve()` sonrasında constraints'leri gevşetmez
- zaten elde edilmiş privilege, hâlâ elde edilmiş privilege'dır

Son nokta operasyonel olarak önemlidir. Process zaten root olarak çalışıyorsa, zaten tehlikeli bir capability'ye sahipse veya zaten güçlü bir runtime API'ye ya da writable host mount'a erişebiliyorsa, `no_new_privs` ayarlamak bu exposure'ları etkisiz hâle getirmez. Yalnızca bir privilege-escalation zincirindeki yaygın bir **next step**'i ortadan kaldırır.

Ayrıca flag, `execve()`'ye bağlı olmayan privilege change'leri engellemez. Örneğin zaten yeterli ayrıcalığa sahip bir task doğrudan `setuid(2)` çağırmaya veya Unix socket üzerinden privileged file descriptor almaya devam edebilir. Bu nedenle `no_new_privs`, standalone bir çözüm olarak değil, [seccomp](seccomp.md), capability sets ve namespace exposure ile birlikte değerlendirilmelidir.

## Lab

Mevcut process state'i inceleyin:
```bash
grep NoNewPrivs /proc/self/status
```
Bunu runtime'ın flag'i etkinleştirdiği bir container ile karşılaştırın:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Güçlendirilmiş bir workload üzerinde sonuç `NoNewPrivs: 1` göstermelidir.

Gerçek etkiyi bir setuid binary'ye karşı da gösterebilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
Karşılaştırmanın amacı `su` aracının her durumda exploit edilebilir olduğunu söylemek değildir. Amaç, `execve()` bir privilege boundary'yi aşmaya hâlâ izin verip vermediğine bağlı olarak aynı image'ın çok farklı davranabileceğini göstermektir.

## Security Impact

`no_new_privs` mevcut değilse, container içindeki bir foothold setuid yardımcıları veya file capabilities içeren binary'ler aracılığıyla hâlâ yükseltilebilir. Mevcutsa, exec sonrası gerçekleşen bu privilege değişiklikleri engellenir. Bu etki, uygulamanın aslında hiç ihtiyaç duymadığı birçok utility'yi barındıran geniş base image'larda özellikle önemlidir.

Ayrıca önemli bir seccomp etkileşimi vardır. Unprivileged task'ler, filter mode'da bir seccomp filter yükleyebilmeden önce genellikle `no_new_privs` ayarının yapılmasını gerektirir. Hardened container'ların çoğunlukla hem `Seccomp` hem de `NoNewPrivs` ayarlarını birlikte etkin göstermesinin nedenlerinden biri budur. Attacker perspektifinden bakıldığında, her ikisinin de etkin olduğunu görmek genellikle ortamın yanlışlıkla değil, bilinçli olarak yapılandırıldığı anlamına gelir.

## Misconfigurations

En yaygın sorun, kontrolün uyumlu olacağı ortamlarda basitçe etkinleştirilmemesidir. Kubernetes'te `allowPrivilegeEscalation` ayarını etkin bırakmak, çoğu zaman varsayılan operasyonel hatadır. Docker ve Podman'da ilgili security option'ın atlanması da aynı etkiye sahiptir. Tekrarlanan başka bir failure mode ise bir container'ın `"not privileged"` olması nedeniyle exec-time privilege transition'larının otomatik olarak önemsiz olduğunu varsaymaktır.

Daha subtle bir Kubernetes pitfall, container `privileged` olduğunda veya `CAP_SYS_ADMIN` yetkisine sahip olduğunda `allowPrivilegeEscalation: false` ayarının insanların beklediği şekilde uygulanmamasıdır. Kubernetes API, bu durumlarda `allowPrivilegeEscalation` değerinin fiilen her zaman true olduğunu belirtir. Pratikte bu, alanın nihai posture içindeki tek bir sinyal olarak değerlendirilmesi gerektiği ve runtime'ın sonunda `NoNewPrivs: 1` değerini kullandığının garantisi olarak görülmemesi anlamına gelir.

## Abuse

`no_new_privs` ayarlanmamışsa ilk soru, image'ın privilege'ı hâlâ yükseltebilen binary'ler içerip içermediğidir:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
İlginç sonuçlar şunları içerir:

- `NoNewPrivs: 0`
- `su`, `mount`, `passwd` veya dağıtıma özgü admin araçları gibi setuid yardımcıları
- network veya filesystem ayrıcalıkları sağlayan file capabilities içeren binary'ler

Gerçek bir assessment'ta bu bulgular tek başına çalışan bir escalation olduğunu kanıtlamaz, ancak sonraki adımda test edilmeye değer binary'leri kesin olarak belirler.

Kubernetes'te ayrıca YAML intent'inin kernel gerçekliğiyle eşleştiğini doğrulayın:
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
İlginç kombinasyonlar şunlardır:

- Pod spec içinde `allowPrivilegeEscalation: false`, ancak container içinde `NoNewPrivs: 0`
- `cap_sys_admin` mevcut; bu durum Kubernetes alanını çok daha az güvenilir hale getirir
- `Seccomp: 0` ve `NoNewPrivs: 0`; bu genellikle tek bir izole hatadan ziyade runtime güvenlik duruşunun genel olarak zayıflatıldığını gösterir

### Tam Örnek: setuid Üzerinden Container İçi Privilege Escalation

Bu kontrol genellikle doğrudan host escape yerine **container içi privilege escalation** işlemini engeller. `NoNewPrivs` değeri `0` ise ve bir setuid helper mevcutsa bunu açıkça test edin:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Bilinen bir setuid binary mevcut ve çalışır durumdaysa, yetki geçişini koruyacak şekilde başlatmayı deneyin:
```bash
/bin/su -c id 2>/dev/null
```
Bu, tek başına container escape sağlamaz; ancak container içindeki düşük ayrıcalıklı bir foothold'u container-root seviyesine yükseltebilir. Bu da çoğu zaman mounts, runtime sockets veya kernel-facing interfaces üzerinden daha sonra host escape gerçekleştirmek için ön koşul haline gelir.

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
Burada ilgi çekici olanlar:

- `NoNewPrivs: 1` genellikle daha güvenli sonuçtur.
- `NoNewPrivs: 0`, setuid ve file-cap tabanlı escalation yollarının hâlâ geçerli olduğu anlamına gelir.
- `NoNewPrivs: 1` ile birlikte `Seccomp: 2` görülmesi, daha bilinçli bir hardening yaklaşımının yaygın bir işaretidir.
- `allowPrivilegeEscalation: false` belirten bir Kubernetes manifesti faydalıdır; ancak kernel durumu gerçeği gösteren asıl kaynaktır.
- Az sayıda veya hiç setuid/file-cap binary içermeyen minimal bir image, `no_new_privs` eksik olsa bile saldırgana daha az post-exploitation seçeneği bırakır.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin değil | `--security-opt no-new-privileges=true` ile açıkça etkinleştirilir; daemon genelinde varsayılan ayar da `dockerd --no-new-privileges` ile yapılabilir | flag'i atlamak, `--privileged` |
| Podman | Varsayılan olarak etkin değil | `--security-opt no-new-privileges` veya eşdeğer security configuration ile açıkça etkinleştirilir | seçeneği atlamak, `--privileged` |
| Kubernetes | Workload policy tarafından kontrol edilir | `allowPrivilegeEscalation: false` bu etkiyi talep eder; ancak `privileged: true` ve `CAP_SYS_ADMIN` bunu fiilen true tutar | `allowPrivilegeEscalation: true`, `privileged: true`, `CAP_SYS_ADMIN` eklemek |
| Kubernetes altında containerd / CRI-O | Kubernetes workload ayarlarını / OCI `process.noNewPrivileges` değerini izler | Genellikle Pod security context'ten devralınır ve OCI runtime configuration'a dönüştürülür | Kubernetes satırındakiyle aynı |

Bu protection çoğu zaman runtime bunu desteklemediği için değil, kimse etkinleştirmediği için mevcut değildir.

## Referanslar

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
