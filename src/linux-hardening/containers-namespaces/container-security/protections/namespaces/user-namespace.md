# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

user namespace, kernel'in namespace içinde görülen user ve group ID'lerini, namespace dışında farklı ID'lere eşlemesine izin vererek user ve group ID'lerinin anlamını değiştirir. Bu, en önemli modern container korumalarından biridir; çünkü klasik container'lardaki en büyük tarihsel sorunu doğrudan ele alır: **container içindeki root, geçmişte host üzerindeki root'a rahatsız edici derecede yakındı**.

user namespace'ler sayesinde bir process container içinde UID 0 olarak çalışabilir ve yine de host üzerinde unprivileged bir UID aralığına karşılık gelebilir. Bu, process'in container içindeki birçok görev için root gibi davranabilmesini, ancak host açısından çok daha az yetkili olmasını sağlar. Bu, her container security sorununu çözmez; ancak bir container compromise'ının sonuçlarını önemli ölçüde değiştirir.

## Çalışma Mantığı

Bir user namespace, namespace ID'lerinin parent ID'lerine nasıl çevrildiğini açıklayan `/proc/self/uid_map` ve `/proc/self/gid_map` gibi mapping dosyalarına sahiptir. Namespace içindeki root, host üzerindeki unprivileged bir UID'ye map edilirse, gerçek host root'u gerektirecek işlemler aynı ağırlığı taşımaz. Bu nedenle user namespace'ler **rootless containers** için merkezî öneme sahiptir ve eski rootful container varsayımları ile daha modern least-privilege tasarımları arasındaki en büyük farklardan biridir.

Buradaki nokta incelikli ama kritiktir: container içindeki root ortadan kaldırılmaz, **çevrilir**. Process yerel olarak root benzeri bir ortam deneyimlemeye devam eder; ancak host onu full root olarak değerlendirmemelidir.

## Lab

Manual bir test şudur:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Bu, mevcut kullanıcının namespace içinde root olarak görünmesini sağlarken namespace dışında hâlâ host root olmamasını sağlar. User namespace'lerin neden bu kadar değerli olduğunu anlamak için en iyi basit demolarından biridir.

Container'larda, görünür eşlemeyi şununla karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Kesin çıktı, engine'in user namespace remapping mi yoksa daha geleneksel bir rootful yapılandırma mı kullandığına bağlıdır.

Mapping'i host tarafından şu şekilde de okuyabilirsiniz:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Çalışma Zamanı Kullanımı

Rootless Podman, user namespaces'in birinci sınıf bir security mechanism olarak ele alınmasının en açık örneklerinden biridir. Rootless Docker da bunlara bağlıdır. Docker'ın userns-remap desteği, rootful daemon deployment'larında da güvenliği artırır; ancak geçmişte birçok deployment, compatibility nedenleriyle bunu devre dışı bıraktı. Kubernetes'in user namespaces desteği gelişmiştir, ancak benimsenme ve varsayılanlar runtime'a, distro'ya ve cluster policy'ye göre değişir. Incus/LXC sistemleri de UID/GID shifting ve idmapping fikirlerine büyük ölçüde dayanır.

Genel eğilim açıktır: user namespaces'i ciddi şekilde kullanan ortamlar, "container root aslında ne anlama gelir?" sorusuna kullanmayan ortamlara kıyasla genellikle daha iyi bir yanıt sağlar.

## Gelişmiş Mapping Ayrıntıları

Unprivileged bir process `uid_map` veya `gid_map` dosyasına yazdığında kernel, privileged parent namespace writer için uyguladığından daha katı kurallar uygular. Yalnızca sınırlı mapping'lere izin verilir ve `gid_map` için writer'ın genellikle önce `setgroups(2)`'yi devre dışı bırakması gerekir:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Bu ayrıntı önemlidir; çünkü user-namespace kurulumunun rootless deneylerinde neden bazen başarısız olduğunu ve runtime'ların UID/GID delegation çevresinde neden dikkatli helper logic gerektirdiğini açıklar.

Bir diğer gelişmiş özellik **ID-mapped mount** özelliğidir. Disk üzerindeki ownership'i değiştirmek yerine, bir ID-mapped mount bir mount'a user-namespace mapping uygular; böylece ownership, bu mount görünümü üzerinden çevrilmiş olarak görünür. Bu özellik, shared host path'lerin recursive `chown` işlemleri olmadan kullanılmasına izin verdiği için rootless ve modern runtime kurulumlarında özellikle önemlidir. Security açısından bu özellik, temel filesystem metadata'sını yeniden yazmasa da bir bind mount'un namespace içinden ne kadar writable göründüğünü değiştirir.

Son olarak, bir process yeni bir user namespace oluşturduğunda veya bu namespace'e girdiğinde, **o namespace içinde** tam bir capability set'i aldığını unutmayın. Bu, aniden host-global power kazandığı anlamına gelmez. Bu capabilities'in yalnızca namespace modeli ve diğer protections izin verdiği yerlerde kullanılabileceği anlamına gelir. `unshare -U` komutunun, host root boundary'sini doğrudan ortadan kaldırmadan mounting veya namespace-local privileged operations işlemlerini mümkün kılabilmesinin nedeni budur.

## Misconfigurations

En büyük weakness, user namespace'leri uygulanabilir oldukları ortamlarda hiç kullanmamaktır. Container root doğrudan host root'a map ediliyorsa, writable host mount'lar ve privileged kernel operations çok daha tehlikeli hale gelir. Bir diğer problem ise compatibility amacıyla host user namespace sharing'i zorlamak veya remapping'i disable etmek ve bunun trust boundary'yi ne kadar değiştirdiğini fark etmemektir.

User namespace'ler modelin geri kalanıyla birlikte değerlendirilmelidir. Aktif olsalar bile, geniş bir runtime API exposure veya çok zayıf bir runtime configuration, diğer yollar üzerinden privilege escalation'a hâlâ izin verebilir. Ancak bunlar olmadan, birçok eski breakout sınıfını exploit etmek çok daha kolay hale gelir.

## Abuse

Container, user namespace separation olmadan rootful ise, writable bir host bind mount çok daha tehlikeli hale gelir; çünkü process gerçekten host root olarak yazıyor olabilir. Dangerous capabilities de aynı şekilde daha anlamlı hale gelir. Attacker'ın translation boundary'ye karşı bu kadar mücadele etmesine artık gerek kalmaz; çünkü translation boundary neredeyse yoktur.

Bir container breakout path'i değerlendirilirken user namespace'in mevcut olup olmadığı erken aşamada kontrol edilmelidir. Bu, her soruyu yanıtlamaz; ancak "container içindeki root"un host açısından doğrudan önem taşıyıp taşımadığını hemen gösterir.

En pratik abuse pattern'i mapping'i doğrulamak ve ardından host-mounted content'in host-relevant privileges ile writable olup olmadığını hemen test etmektir:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Dosya gerçek host root'u olarak oluşturulursa, user namespace izolasyonu o yol için fiilen ortadan kalkar. Bu noktada klasik host-file istismarları gerçekçi hale gelir:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Canlı bir değerlendirmede daha güvenli bir doğrulama yöntemi, kritik dosyaları değiştirmek yerine zararsız bir işaret yazmaktır:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Bu kontroller önemlidir; çünkü asıl soruya hızlıca yanıt verirler: Bu container içindeki root, yazılabilir bir host mount'ının anında host compromise yoluna dönüşebileceği kadar host root'a yakın şekilde mi eşleniyor?

### Full Example: Namespace-Local Capabilities'ı Geri Kazanma

seccomp `unshare` işlemine izin veriyorsa ve ortam yeni bir user namespace oluşturulmasına olanak tanıyorsa process, bu yeni namespace içinde full capability set'ini yeniden kazanabilir:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Bu, tek başına bir host escape değildir. Önemli olmasının nedeni, user namespaces'in daha sonra zayıf mount'lar, güvenlik açığı bulunan kernel'lar veya dışarıya hatalı şekilde açılmış runtime yüzeyleriyle birleşebilen ayrıcalıklı namespace-local işlemleri yeniden etkinleştirebilmesidir.

## Kontroller

Bu komutlar, bu sayfadaki en önemli soruyu yanıtlamayı amaçlar: Bu container'ın içindeki root, host üzerinde neye eşleniyor?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Burada ilginç olanlar:

- Süreç UID 0 ise ve maps dosyaları host root'a doğrudan veya çok yakın bir eşleme gösteriyorsa container çok daha tehlikelidir.
- root ayrıcalıksız bir host aralığına eşleniyorsa bu çok daha güvenli bir temel oluşturur ve genellikle gerçek user namespace izolasyonuna işaret eder.
- Eşleme dosyaları tek başına `id` komutundan daha değerlidir; çünkü `id` yalnızca namespace içindeki kimliği gösterir.

Workload UID 0 olarak çalışıyorsa ve eşleme bunun host root'a yakın bir karşılık geldiğini gösteriyorsa container'ın geri kalan ayrıcalıklarını çok daha katı şekilde değerlendirmelisiniz.

{{#include ../../../../../banners/hacktricks-training.md}}
