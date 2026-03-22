# Kullanıcı Ad Alanı

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Kullanıcı ad alanı, kullanıcı ve grup kimliklerinin anlamını değiştirir; çekirdeğin ad alanı içinde görülen kimlikleri dışarıdaki farklı kimliklere eşlemesine izin verir. Bu, klasik container'larda tarihsel olarak en büyük sorunla doğrudan ilgilendiği için modern container korumalarının en önemlilerinden biridir: **container içindeki root, host'taki root'a rahatsız edici derecede yakındı**.

Kullanıcı ad alanları sayesinde bir süreç container içinde UID 0 olarak çalışabilir ve yine de host'ta ayrıcalıksız bir UID aralığına karşılık gelebilir. Bu, sürecin container içindeki birçok görev için root gibi davranabilmesi, ancak host açısından çok daha az yetkili olması demektir. Bu her container güvenlik sorununu çözmez, ancak bir container'ın ele geçirilmesinin sonuçlarını önemli ölçüde değiştirir.

## İşleyiş

Bir kullanıcı ad alanının, namespace ID'lerinin üst ad (parent) ID'lere nasıl çevrildiğini açıklayan `/proc/self/uid_map` ve `/proc/self/gid_map` gibi eşleme dosyaları vardır. Eğer ad alanı içindeki root, host'ta ayrıcalıksız bir UID'ye eşlenmişse, gerçek host root gerektirecek işlemler aynı ağırlığa sahip olmaz. Bu nedenle kullanıcı ad alanları **rootless containers** için merkezidir ve eski rootful container varsayımları ile daha modern en az ayrıcalık (least-privilege) tasarımları arasındaki en büyük farklardan biridir.

Nokta ince ama kritik: container içindeki root ortadan kaldırılmıyor, o **çeviriliyor**. Süreç yerelde root-benzeri bir ortam yaşamaya devam eder, ancak host onu tam root olarak değerlendirmemelidir.

## Laboratuvar

Manuel bir test:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Bu, mevcut kullanıcının namespace içinde root olarak görünmesini sağlar; yine de dışarıda host root değildir. user namespaces'in neden bu kadar değerli olduğunu anlamak için en iyi basit demolarından biridir.

Konteynerlerde, görünür eşlemeyi şununla karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Tam çıktı, motorun user namespace remapping kullanıp kullanmamasına veya daha geleneksel bir rootful yapılandırmaya bağlıdır.

Eşlemeyi host tarafında şu komutla da okuyabilirsiniz:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Çalışma Zamanı Kullanımı

Rootless Podman, user namespace'lerinin birinci sınıf bir güvenlik mekanizması olarak ele alındığı en açık örneklerden biridir. Rootless Docker da onlara bağlıdır. Docker'ın userns-remap desteği rootful daemon dağıtımlarında da güvenliği artırır; ancak tarihsel olarak birçok dağıtım uyumluluk nedenleriyle bunu devre dışı bırakmıştır. Kubernetes'in user namespace desteği iyileşmiştir, fakat benimsenme ve varsayılanlar runtime, distro ve cluster politikalarına göre değişir. Incus/LXC sistemleri ayrıca UID/GID kaydırma ve idmapping fikirlerine büyük ölçüde dayanır.

Genel eğilim açıktır: user namespace'lerini ciddiye alan ortamlar genellikle "container root aslında ne anlama geliyor?" sorusuna, almayan ortamlara göre daha iyi bir cevap sunar.

## Gelişmiş Eşleme Detayları

Yetkisiz bir süreç `uid_map` veya `gid_map`'e yazdığında, kernel yetkili bir üst namespace yazarı için uyguladığından daha sıkı kurallar uygular. Yalnızca sınırlı eşlemelere izin verilir ve `gid_map` için yazar genellikle önce `setgroups(2)`'yi devre dışı bırakmalıdır:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Bu ayrıntı önemlidir çünkü user-namespace kurulumunun bazen rootless deneylerinde neden başarısız olduğunu ve runtimes'ın UID/GID delegasyonu etrafında neden dikkatli yardımcı mantığa ihtiyaç duyduğunu açıklar.

Another advanced feature is the **ID-mapped mount**. Disk üzerindeki sahipliği değiştirmek yerine, bir ID-mapped mount, bir mount'a user-namespace eşlemesi uygular; böylece sahiplik o mount görünümü üzerinden çevrilmiş gibi görünür. Bu, özellikle rootless ve modern runtime kurulumlarında önemlidir çünkü paylaşılan host yollarının recursive `chown` işlemleri olmadan kullanılmasına izin verir. Güvenlik açısından, özellik temel dosya sistemi metadata'sını yeniden yazmasa da, bind mount'un namespace içinden nasıl yazılabilir göründüğünü değiştirir.

Son olarak, bir süreç yeni bir user namespace oluşturduğunda veya içine girdiğinde, **o namespace içinde** tam bir capability set alacağını unutmayın. Bu, aniden host-genel bir güç kazandığı anlamına gelmez. Bu, söz konusu yetkilerin yalnızca namespace modeli ve diğer korumalar izin verdiği yerlerde kullanılabileceği demektir. Bu yüzden `unshare -U`, host root sınırını doğrudan ortadan kaldırmadan mount etme veya namespace-e özgü ayrıcalıklı işlemleri ani bir şekilde mümkün kılabilir.

## Misconfigurations

Ana zayıflık, mümkün olacağı ortamlarda user namespace'lerinin kullanılmamasıdır. Eğer container root'u host root'a çok doğrudan eşlenirse, writable host mounts ve ayrıcalıklı kernel işlemleri çok daha tehlikeli hale gelir. Diğer bir problem, uyumluluk için host user namespace paylaşımını zorlamak veya remapping'i devre dışı bırakmaktır; bunun güven sınırını ne kadar değiştirdiği farkedilmeden yapılırsa büyük risk oluşturur.

User namespace'leri ayrıca modelin geri kalanı ile birlikte ele alınmalıdır. Etkin olsalar bile, geniş bir runtime API açılımı veya çok zayıf bir runtime yapılandırması yine de diğer yollarla privilege escalation'a izin verebilir. Ancak onlar olmadan, birçok eski breakout sınıfı istismarı çok daha kolay hale gelir.

## Abuse

Eğer container user namespace ayrımı olmadan rootful ise, yazılabilir bir host bind mount çok daha tehlikeli hale gelir çünkü süreç gerçekten host root olarak yazıyor olabilir. Tehlikeli capabilities benzer şekilde daha anlamlı olur. Saldırgan artık çeviri sınırıyla bu kadar çok mücadele etmek zorunda değildir çünkü çeviri sınırı neredeyse yoktur.

User namespace'in varlığı veya yokluğu, bir container breakout yolunu değerlendirirken erkenden kontrol edilmelidir. Bu her soruyu cevaplamaz, fakat hemen "root in container"ın host ile doğrudan ilgisi olup olmadığını gösterir.

En pratik kötüye kullanım deseni, eşlemeyi doğrulamak ve ardından hemen host-mounted içeriğin host-ilişkili ayrıcalıklarla yazılabilir olup olmadığını test etmektir:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Eğer dosya gerçek host root olarak oluşturulursa, user namespace isolation o yol için fiilen yok sayılır. Bu noktada klasik host-file abuses gerçekçi hale gelir:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Canlı bir değerlendirmede daha güvenli bir doğrulama, kritik dosyaları değiştirmek yerine zararsız bir işaret yazmaktır:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Bu kontroller önemlidir çünkü gerçek soruyu hızlıca cevaplar: bu container içindeki root, host root ile yeterince yakın şekilde eşlenmiş mi; böylece yazılabilir bir host mount hemen bir host compromise path olur mu?

### Tam Örnek: Namespace-Local Capabilities'i Yeniden Kazanma

Eğer seccomp `unshare`'a izin veriyor ve ortam yeni bir user namespace'e izin veriyorsa, süreç o yeni namespace içinde tam bir capability setini yeniden kazanabilir:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Bu tek başına bir host escape değildir. Önemli olmasının nedeni, user namespaces'in daha sonra zayıf mounts, vulnerable kernels veya kötü açığa çıkmış runtime surfaces ile birleşen privileged namespace-local actions'i yeniden etkinleştirebilmesidir.

## Kontroller

Bu komutlar bu sayfadaki en önemli soruyu cevaplamayı amaçlar: bu container içindeki root host üzerinde hangi hesaba denk geliyor?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Burada ilginç olan:

- Eğer işlem UID 0 ise ve maps doğrudan veya çok yakın bir host-root mapping gösteriyorsa, container çok daha tehlikelidir.
- Eğer root unprivileged host range'e map ediliyorsa, bu daha güvenli bir temel durumdur ve genellikle gerçek user namespace isolation'ı işaret eder.
- Mapping files, tek başına `id`'den daha değerlidir, çünkü `id` yalnızca namespace-local identity'yi gösterir.

Eğer workload UID 0 olarak çalışıyor ve mapping bunun host root ile yakından karşılık geldiğini gösteriyorsa, container'ın kalan ayrıcalıklarını çok daha sıkı yorumlamalısınız.
{{#include ../../../../../banners/hacktricks-training.md}}
