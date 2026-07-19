# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

cgroup namespace, cgroup'ların yerini almaz ve kaynak sınırlarını kendisi uygulamaz. Bunun yerine, **cgroup hiyerarşisinin** process'e nasıl göründüğünü değiştirir. Başka bir deyişle, görünür cgroup path bilgilerini sanallaştırır; böylece workload, host hiyerarşisinin tamamı yerine container kapsamlı bir görünüm görür.

Bu temel olarak bir görünürlük ve bilgi azaltma özelliğidir. Ortamın kendi kendine yeten bir yapı gibi görünmesine yardımcı olur ve host'un cgroup düzeni hakkında daha az bilgi açığa çıkarır. Bu önemsiz görünebilir, ancak yine de önemlidir; çünkü host yapısına yönelik gereksiz görünürlük reconnaissance faaliyetlerine yardımcı olabilir ve ortama bağlı exploit chain'lerini basitleştirebilir.

## Operation

Private bir cgroup namespace olmadan process, makinenin hiyerarşisinin gereğinden fazlasını açığa çıkaran host-relative cgroup path'lerini görebilir. Private bir cgroup namespace ile `/proc/self/cgroup` ve ilgili gözlemler container'ın kendi görünümüne daha lokal hâle gelir. Bu, özellikle workload'un daha temiz ve host hakkında daha az bilgi açığa çıkaran bir ortam görmesini isteyen modern runtime stack'leri için faydalıdır.

Sanallaştırma yalnızca `/proc/<pid>/cgroup`'u değil, `/proc/<pid>/mountinfo`'yu da etkiler. Farklı bir cgroup-namespace perspektifinden başka bir process'i okuduğunuzda, namespace root'unuzun dışındaki path'ler başında `../` bileşenleriyle gösterilir. Bu, delegated subtree'nizin üstündeki bir konuma baktığınızı gösteren kullanışlı bir ipucudur. Lab'lar ve post-exploitation açısından önemli bir ayrıntı şudur: yeni oluşturulan bir cgroup namespace, `mountinfo`'nun yeni root'u düzgün şekilde yansıtabilmesi için çoğu zaman **bu namespace içinden bir cgroupfs remount** gerektirir. Aksi takdirde `/..` gibi bir mount root görmeye devam edebilirsiniz. Bu, namespace'in kendisi değişmiş olsa bile inherited mount'un hâlâ ancestor-rooted bir görünüm sunduğu anlamına gelir.

## Lab

Bir cgroup namespace'i şu şekilde inceleyebilirsiniz:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Yeni cgroup-namespace root'unu `mountinfo` içinde daha net görmek istiyorsanız, cgroup filesystem'ini yeni namespace'in içinden yeniden mount edin ve tekrar karşılaştırın:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Ve runtime davranışını şununla karşılaştırın:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Değişiklik çoğunlukla process'in neleri görebildiğiyle ilgilidir; cgroup enforcement'ın mevcut olup olmadığıyla değil.

## Security Impact

cgroup namespace en iyi şekilde bir **visibility-hardening katmanı** olarak anlaşılabilir. Tek başına, container'da writable cgroup mount'ları, geniş capabilities veya tehlikeli bir cgroup v1 ortamı varsa breakout'u engellemez. Ancak host cgroup namespace'i paylaşılıyorsa process, sistemin nasıl organize edildiği hakkında daha fazla bilgi edinir ve host-relative cgroup path'lerini diğer gözlemlerle eşleştirmesi kolaylaşabilir.

**cgroup v2** üzerinde namespace biraz daha önemli hale gelir; çünkü delegation kuralları daha sıkıdır. Hierarchy `nsdelegate` ile mount edilmişse kernel, cgroup namespace'lerini delegation sınırları olarak ele alır: ancestor control file'larının delegatee'nin erişim alanı dışında kalması beklenir ve namespace root'undaki write işlemleri `cgroup.procs`, `cgroup.threads` ve `cgroup.subtree_control` gibi delegation açısından güvenli file'larla sınırlandırılır. Bu yine namespace'i tek başına bir escape primitive haline getirmez; ancak compromised workload'un neleri inceleyebileceğini ve sub-cgroup'ları güvenli şekilde nerede oluşturabileceğini değiştirir.

Dolayısıyla bu namespace genellikle container breakout writeup'larının başrolünde olmasa da host information leak'ini en aza indirme ve cgroup delegation'ını sınırlandırma yönündeki daha geniş amaca katkıda bulunur.

## Abuse

Anlık abuse değeri çoğunlukla reconnaissance'tır. Host cgroup namespace'i paylaşılıyorsa görünür path'leri karşılaştırın ve host'u açığa çıkaran hierarchy ayrıntılarını arayın:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Yazılabilir cgroup yolları da açığa çıkıyorsa, bu görünürlüğü tehlikeli legacy arayüzleri aramayla birleştirin:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Namespace tek başına nadiren anında escape sağlar, ancak cgroup tabanlı abuse primitive'lerini test etmeden önce ortamı haritalamayı genellikle kolaylaştırır.

Hızlı bir runtime reality check, attack path'ini önceliklendirmeye de yardımcı olur. Docker, `--cgroupns=host|private` seçeneklerini sunarken Podman `host`, `private`, `container:<id>` ve `ns:<path>` değerlerini destekler. Özellikle Podman'da varsayılan değer genellikle **cgroup v1 üzerinde `host`**, **cgroup v2 üzerinde ise `private`** olur; dolayısıyla yalnızca cgroup sürümünü tespit etmek bile tam OCI config'ini incelemeden önce hangi namespace posture'ının daha olası olduğunu gösterir.

### Modern v2 Recon: Bu Bir Delegated Subtree mi?

Modern host'larda ilgi çekici soru genellikle `release_agent` değil, mevcut process'in nested group'lar oluşturmak için yeterli visibility veya write access'e sahip delegated bir **cgroup v2** subtree içinde bulunup bulunmadığıdır:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Yararlı yorum:

- `cgroup2fs`, unified v2 hiyerarşisinde olduğunuz anlamına gelir; bu nedenle klasik ve yalnızca v1'e özgü `release_agent` zincirleri ilk tahmininiz olmamalıdır.
- `cgroup.controllers`, üst öğeden hangi controller'ların kullanılabildiğini ve dolayısıyla mevcut alt ağacın alt öğelere hangi controller'ları aktarabileceğini gösterir.
- `cgroup.subtree_control`, alt öğeler için hangi controller'ların gerçekten etkin olduğunu gösterir.
- `cgroup.events`, `populated=0/1` bilgisini sunar. Bu, bir alt ağacın boş hale gelip gelmediğini izlemek için kullanışlıdır; ancak v1 `release_agent` gibi bir host üzerinde code execution primitive değildir.

Başka bir process namespace'ini doğrudan incelemek için zaten yeterli ayrıcalığa sahipseniz görünümleri şu komutla karşılaştırın:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Tam Örnek: Paylaşılan cgroup Namespace + Yazılabilir cgroup v1

cgroup namespace tek başına genellikle escape için yeterli değildir. Pratik escalation, host'u açığa çıkaran cgroup path'lerinin yazılabilir cgroup v1 interface'leriyle birleştirilmesiyle gerçekleşir:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Bu dosyalara erişilebiliyor ve yazılabiliyorsa, [cgroups.md](../cgroups.md) içindeki tam `release_agent` exploitation akışına hemen geçin. Etki, container içinden host üzerinde kod çalıştırmadır.

Yazılabilir cgroup arayüzleri yoksa etki genellikle reconnaissance ile sınırlıdır.

## Kontroller

Bu komutların amacı, process'in private bir cgroup namespace görünümüne sahip olup olmadığını veya host hiyerarşisi hakkında gerçekten ihtiyaç duyduğundan daha fazla bilgi edinip edinmediğini görmektir.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Burada ilginç olanlar:

- Namespace identifier önem verdiğiniz bir host process ile eşleşiyorsa cgroup namespace paylaşılmış olabilir.
- `/proc/self/cgroup` içindeki host'u açığa çıkaran path'ler veya `mountinfo` içindeki ancestor-rooted entry'ler, doğrudan exploit edilebilir olmasalar bile keşif için faydalıdır.
- `cgroup2fs` kullanımdaysa, eski v1 primitive'lerinin hâlâ mevcut olduğunu varsaymak yerine delegation, görünür controller'lar ve yazılabilir subtree'lere odaklanın.
- cgroup mount'ları da yazılabilirse görünürlük sorusu çok daha önemli hâle gelir.

cgroup namespace, birincil escape-prevention mekanizması olarak değil, görünürlük-hardening katmanı olarak ele alınmalıdır. Host cgroup yapısının gereksiz yere açığa çıkarılması, attacker için reconnaissance değerini artırır.

## Referanslar

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
