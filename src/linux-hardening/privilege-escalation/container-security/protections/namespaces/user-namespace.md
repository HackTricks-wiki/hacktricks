# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

user namespace, çekirdeğin isim alanı içinde görülen kullanıcı ve grup kimliklerini dışarıdaki farklı kimliklere eşlemesine izin vererek kullanıcı ve grup ID'lerinin anlamını değiştirir. Bu, modern container korumalarının en önemli öğelerinden biridir çünkü klasik container'larda tarihsel olarak en büyük soruna doğrudan hitap eder: **container içindeki root, host üzerindeki root'a rahatsız edici derecede yakındı**.

user namespaces ile bir süreç container içinde UID 0 olarak çalışabilir ve yine de host üzerinde ayrıcalıksız bir UID aralığına karşılık gelebilir. Bu, sürecin birçok container içi görev için root gibi davranabileceği, ancak host açısından çok daha az yetkili olduğu anlamına gelir. Bu her container güvenlik sorununu çözmez, ancak bir container ele geçirilmesinin sonuçlarını önemli ölçüde değiştirir.

## İşleyiş

Bir user namespace, namespace ID'lerinin parent ID'lere nasıl çevrildiğini tanımlayan `/proc/self/uid_map` ve `/proc/self/gid_map` gibi eşleme dosyalarına sahiptir. Eğer namespace içindeki root, ayrıcalıksız bir host UID'sine eşlenmişse, gerçek host root gerektirecek işlemler aynı ağırlığa sahip olmaz. Bu yüzden user namespaces, rootless containers için merkezi öneme sahiptir ve eski rootful container varsayımları ile daha modern least-privilege tasarımlar arasındaki en büyük farklardan biridir.

Nokta ince ama hayati: container içindeki root ortadan kaldırılmıyor, o **çeviriliyor**. Süreç yine yerel olarak root-benzeri bir ortam yaşar, ancak host bunun tam root olarak muamele etmemelidir.

## Lab

Manuel bir test şudur:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Bu, mevcut kullanıcının namespace içinde root olarak görünmesini sağlar; ancak dışarıda host root değildir. Bu, user namespaces'in neden bu kadar değerli olduğunu anlamak için en iyi basit demolarından biridir.

Containers'ta, görünür mapping'i şu şekilde karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Tam çıktı, engine'ın user namespace remapping kullanıp kullanmadığına veya daha geleneksel bir rootful yapılandırmanın olup olmadığına bağlıdır.

Eşlemeyi ana makine tarafında şu komutla da okuyabilirsiniz:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Çalışma Zamanı Kullanımı

Rootless Podman, user namespace'larının birinci sınıf bir güvenlik mekanizması olarak ele alındığının en net örneklerinden biridir. Rootless Docker da bunlara bağlıdır. Docker'ın userns-remap desteği, rootful daemon dağıtımlarında da güvenliği artırır; ancak tarihsel olarak birçok dağıtım uyumluluk nedenleriyle bunu devre dışı bıraktı. Kubernetes'in user namespace desteği iyileşti, ancak benimseme ve varsayılanlar runtime, distro ve cluster politikasına göre değişir. Incus/LXC sistemleri de UID/GID kaydırma ve idmapping fikirlerine büyük ölçüde dayanır.

Genel eğilim açıktır: user namespace'ları ciddiye alan ortamlar, container root'un gerçekten ne anlama geldiğine dair genellikle daha iyi bir cevap sunar.

## Gelişmiş Eşleme Detayları

Bir yetkisiz süreç `uid_map` veya `gid_map` dosyalarına yazdığında, kernel yetkili bir üst namespace yazarı için uyguladığından daha katı kurallar uygular. Yalnızca sınırlı eşlemelere izin verilir ve `gid_map` için yazan sürecin genellikle önce `setgroups(2)`'ü devre dışı bırakması gerekir:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
This detail matters because it explains why user-namespace setup sometimes fails in rootless experiments and why runtimes need careful helper logic around UID/GID delegation.

Another advanced feature is the **ID-mapped mount**. Instead of changing on-disk ownership, an ID-mapped mount applies a user-namespace mapping to a mount so that ownership appears translated through that mount view. This is especially relevant in rootless and modern runtime setups because it allows shared host paths to be used without recursive `chown` operations. Security-wise, the feature changes how writable a bind mount appears from inside the namespace, even though it does not rewrite the underlying filesystem metadata.

Finally, remember that when a process creates or enters a new user namespace, it receives a full capability set **inside that namespace**. That does not mean it suddenly gained host-global power. It means those capabilities can be used only where the namespace model and other protections allow them. This is the reason `unshare -U` can suddenly make mounting or namespace-local privileged operations possible without directly making the host root boundary disappear.

## Misconfigurations

The major weakness is simply not using user namespaces in environments where they would be feasible. If container root maps too directly to host root, writable host mounts and privileged kernel operations become much more dangerous. Another problem is forcing host user namespace sharing or disabling remapping for compatibility without recognizing how much that changes the trust boundary.

User namespaces also need to be considered together with the rest of the model. Even when they are active, a broad runtime API exposure or a very weak runtime configuration can still allow privilege escalation through other paths. But without them, many old breakout classes become much easier to exploit.

## Abuse

If the container is rootful without user namespace separation, a writable host bind mount becomes vastly more dangerous because the process may really be writing as host root. Dangerous capabilities likewise become more meaningful. The attacker no longer needs to fight as hard against the translation boundary because the translation boundary barely exists.

User namespace presence or absence should be checked early when evaluating a container breakout path. It does not answer every question, but it immediately shows whether "root in container" has direct host relevance.

The most practical abuse pattern is to confirm the mapping and then immediately test whether host-mounted content is writable with host-relevant privileges:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Eğer dosya gerçek host root olarak oluşturulursa, user namespace izolasyonu o yol için fiilen yoktur. Bu noktada, classic host-file abuses gerçekçi hale gelir:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Canlı bir değerlendirmede daha güvenli bir doğrulama, kritik dosyaları değiştirmek yerine zararsız bir işaret yazmaktır:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Bu kontroller önemlidir çünkü gerçek soruyu hızlıca yanıtlar: bu container içindeki root, host root ile yeterince yakın eşleniyor mu, öyle ki bir writable host mount hemen bir host compromise path'e mi dönüşür?

### Tam Örnek: Namespace-Local Capabilities'i Geri Kazanma

Eğer seccomp `unshare`'a izin veriyorsa ve ortam yeni bir user namespace'e izin veriyorsa, süreç bu yeni namespace içinde tam bir capability setini yeniden kazanabilir:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Bu tek başına bir host escape değildir. Önemli olmasının sebebi, user namespaces'in daha sonra zayıf mounts, savunmasız kernels veya kötü şekilde açığa çıkmış runtime surfaces ile birleşebilecek ayrıcalıklı namespace-yerel eylemleri yeniden etkinleştirebilmesidir.

## Kontroller

Bu komutlar bu sayfadaki en önemli soruyu cevaplamak içindir: bu container içindeki root, host üzerinde neye karşılık geliyor?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- Eğer süreç UID 0 ise ve maps doğrudan veya çok yakın bir host-root mapping gösteriyorsa, container çok daha tehlikelidir.
- Eğer root unprivileged bir host range'e eşleniyorsa, bu çok daha güvenli bir temel durumdur ve genellikle gerçek user namespace isolation'ı gösterir.
- Mapping dosyaları tek başına `id`'den daha değerlidir, çünkü `id` yalnızca namespace-local kimliği gösterir.

Eğer workload UID 0 olarak çalışıyor ve mapping bunun host root ile yakından karşılık geldiğini gösteriyorsa, container'ın kalan privileges'larını çok daha sıkı yorumlamalısınız.
