# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

cgroup namespace, cgroups'un yerini almaz ve kaynak sınırlarını kendisi uygulamaz. Bunun yerine, **cgroup hiyerarşisinin** işlem tarafından **nasıl göründüğünü** değiştirir. Başka bir deyişle, görünür cgroup path bilgilerini sanallaştırır; böylece workload, host hiyerarşisinin tamamı yerine container kapsamlı bir görünüm görür.

Bu temel olarak bir görünürlük ve bilgi azaltma özelliğidir. Ortamın kendi kendine yeterli görünmesine yardımcı olur ve host'un cgroup düzeni hakkında daha az bilgi açığa çıkarır. Bu önemsiz görünebilir; ancak host yapısına gereksiz görünürlük reconnaissance'a yardımcı olabileceği ve ortama bağlı exploit zincirlerini basitleştirebileceği için yine de önemlidir.

## Çalışma Şekli

Özel bir cgroup namespace olmadan bir işlem, makinenin hiyerarşisinin gereğinden daha büyük bir bölümünü açığa çıkaran host-relative cgroup path'lerini görebilir. Özel bir cgroup namespace ile `/proc/self/cgroup` ve ilgili gözlemler, container'ın kendi görünümüne daha yerel hale gelir. Bu, özellikle workload'un daha temiz ve host hakkında daha az bilgi açığa çıkaran bir ortam görmesini isteyen modern runtime stack'lerinde faydalıdır.

Sanallaştırma yalnızca `/proc/<pid>/cgroup`'u değil, `/proc/<pid>/mountinfo`'yu da etkiler. Farklı bir cgroup-namespace perspektifinden başka bir işlemi okuduğunuzda, namespace root'unuzun dışındaki path'ler başında `../` bileşenleriyle gösterilir. Bu, delegated subtree'nizin üst tarafını gördüğünüze dair kullanışlı bir ipucudur. Labs ve post-exploitation için önemli bir ayrıntı şudur: yeni oluşturulan bir cgroup namespace, `mountinfo`'nun yeni root'u düzgün şekilde yansıtabilmesi için çoğu zaman **bu namespace'in içinden bir cgroupfs remount** gerektirir. Aksi takdirde `/..` gibi bir mount root görmeye devam edebilirsiniz; bu da namespace'in kendisi zaten değişmiş olsa bile inherited mount'un hâlâ ancestor-rooted bir görünüm sunduğu anlamına gelir.<sup>[[1]](#references)</sup>

## Lab

Bir cgroup namespace'i şu şekilde inceleyebilirsiniz:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
`mountinfo`'nun yeni cgroup-namespace root'unu daha net göstermesini istiyorsanız, cgroup filesystem'ini yeni namespace'in içinden yeniden mount edin ve tekrar karşılaştırın:
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

cgroup namespace, en iyi **visibility-hardening layer** olarak anlaşılmalıdır. Tek başına, container'da writable cgroup mounts, broad capabilities veya tehlikeli bir cgroup v1 ortamı varsa breakout'u engellemez. Ancak host cgroup namespace'i paylaşılıyorsa process, sistemin nasıl organize edildiği hakkında daha fazla bilgi edinir ve host-relative cgroup path'lerini diğer gözlemlerle eşleştirmeyi daha kolay bulabilir.

**cgroup v2** üzerinde namespace biraz daha önemli hâle gelir; çünkü delegation kuralları daha sıkıdır. Hierarchy `nsdelegate` ile mount edilmişse kernel, cgroup namespace'lerini delegation sınırları olarak ele alır: ancestor control files'ın delegatee'nin erişim alanı dışında kalması beklenir ve namespace root'unda yapılan write işlemleri `cgroup.procs`, `cgroup.threads` ve `cgroup.subtree_control` gibi delegation-safe files ile sınırlandırılır.<sup>[[2]](#references)</sup> Bu yine namespace'i tek başına bir escape primitive hâline getirmez; ancak compromised workload'un neleri inceleyebileceğini ve güvenli şekilde nerede sub-cgroup'lar oluşturabileceğini değiştirir.

Dolayısıyla bu namespace genellikle container breakout writeup'larının başrolünde yer almasa da host information leakage'i en aza indirme ve cgroup delegation'ını kısıtlama yönündeki daha geniş hedefe katkıda bulunur.

## Abuse

Anlık abuse değeri çoğunlukla reconnaissance'tır. Host cgroup namespace'i paylaşılıyorsa görünür path'leri karşılaştırın ve host'u açığa çıkaran hierarchy ayrıntılarını arayın:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Yazılabilir cgroup yolları da açığa çıkıyorsa, bu görünürlüğü tehlikeli legacy arayüzler için yapılan bir aramayla birleştirin:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Namespace'in kendisi nadiren anında escape sağlar, ancak cgroup tabanlı abuse primitive'lerini test etmeden önce ortamı haritalamayı genellikle kolaylaştırır.

Hızlı bir runtime gerçeklik kontrolü, attack path'ini önceliklendirmeye de yardımcı olur. Docker, `--cgroupns=host|private` seçeneklerini sunarken Podman `host`, `private`, `container:<id>` ve `ns:<path>` seçeneklerini destekler. Özellikle Podman'da varsayılan değer genellikle **cgroup v1'de `host`**, **cgroup v2'de ise `private`** olduğundan, yalnızca cgroup sürümünü belirlemek bile tam OCI config'ini incelemeden önce hangi namespace durumunun daha olası olduğunu gösterir.

### Modern v2 Recon: Bu, Delegated Bir Subtree mi?

Modern host'larda ilgi çekici soru çoğu zaman `release_agent` değil; mevcut process'in, nested group'lar oluşturmak için yeterli görünürlüğe veya write access'e sahip delegated bir **cgroup v2** subtree içinde çalışıp çalışmadığıdır:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Faydalı yorum:

- `cgroup2fs`, unified v2 hierarchy içinde olduğunuz anlamına gelir; bu nedenle klasik, yalnızca v1'e özgü `release_agent` zincirleri ilk tahmininiz olmamalıdır.
- `cgroup.controllers`, parent'tan hangi controller'ların kullanılabildiğini ve dolayısıyla mevcut subtree'nin children'lara potansiyel olarak neleri aktarabileceğini gösterir.
- `cgroup.subtree_control`, descendants için hangi controller'ların gerçekten etkinleştirildiğini gösterir.
- `cgroup.events`, `populated=0/1` değerlerini sunar; bu, bir subtree'nin boş hale gelip gelmediğini izlemek için kullanışlıdır, ancak v1 `release_agent` gibi bir host-code-execution primitive değildir.

Başka bir process namespace'ini doğrudan incelemek için zaten yeterli privilege'a sahipseniz, görünümleri şununla karşılaştırın:
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
Bu dosyalara erişilebiliyor ve yazılabiliyorsa, [cgroups.md](../cgroups.md) içindeki tam `release_agent` exploitation flow'una hemen pivot edin. Etki, container içinden host üzerinde kod çalıştırılmasıdır.

Writable cgroup interfaces olmadan etki genellikle reconnaissance ile sınırlıdır.

## Kontroller

Bu komutların amacı, process'in private cgroup namespace view'e sahip olup olmadığını veya gerçekten ihtiyaç duyduğundan daha fazla host hiyerarşisi bilgisi öğrenip öğrenmediğini görmektir.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Burada ilginç olanlar:

- Namespace identifier, ilgilendiğiniz bir host process ile eşleşiyorsa cgroup namespace paylaşılmış olabilir.
- `/proc/self/cgroup` içindeki host'u açığa çıkaran path'ler veya `mountinfo` içindeki ancestor-rooted girdiler, doğrudan exploit edilebilir olmasalar bile faydalı reconnaissance bilgileridir.
- `cgroup2fs` kullanılıyorsa, eski v1 primitive'lerinin hâlâ mevcut olduğunu varsaymak yerine delegation, görünür controller'lar ve yazılabilir subtree'lere odaklanın.
- cgroup mount'ları da yazılabilirse görünürlük sorusu çok daha önemli hâle gelir.

Cgroup namespace, birincil escape-prevention mechanism'ı olarak değil, visibility-hardening layer olarak değerlendirilmelidir. Host cgroup yapısının gereksiz şekilde açığa çıkarılması, attacker için reconnaissance değerini artırır.

## References

- [1] [cgroup_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [2] [Control Group v2 — The Linux Kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
