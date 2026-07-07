# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

cgroup namespace, cgroups’un yerini almaz ve kendi başına resource limits uygulamaz. Bunun yerine, process’e **cgroup hierarchy’nin nasıl göründüğünü** değiştirir. Başka bir deyişle, görünür cgroup path bilgisini virtualize eder; böylece workload, tam host hierarchy yerine container-kapsamlı bir görünüm görür.

Bu, esasen bir visibility ve information-reduction özelliğidir. Environment’ın self-contained görünmesine yardımcı olur ve host’un cgroup layout’u hakkında daha az bilgi açığa çıkarır. Bu mütevazı görünebilir, ancak yine de önemlidir; çünkü host yapısına gereksiz visibility, reconnaissance’a yardımcı olabilir ve environment-dependent exploit chain’leri kolaylaştırabilir.

## Operation

Private bir cgroup namespace olmadan, bir process host-relative cgroup path’leri görebilir ve bu da makinenin hierarchy’sinin faydalı olandan daha fazlasını açığa çıkarır. Private bir cgroup namespace ile `/proc/self/cgroup` ve ilgili gözlemler container’ın kendi görünümüne daha yerel hale gelir. Bu, workload’un daha temiz, host’u daha az ifşa eden bir environment görmesini isteyen modern runtime stack’lerde özellikle faydalıdır.

Virtualization ayrıca yalnızca `/proc/<pid>/mountinfo` üzerinde değil, `/proc/<pid>/cgroup` üzerinde de etkili olur. Farklı bir cgroup-namespace perspektifinden başka bir process’i okuduğunuzda, namespace root’unuzun dışındaki path’ler başında `../` bileşenleriyle gösterilir; bu, delegated subtree’nizin üstüne baktığınıza dair kullanışlı bir ipucudur. Lab’ler ve post-exploitation için faydalı bir nüans da şudur: Yeni oluşturulmuş bir cgroup namespace, `mountinfo` yeni root’u düzgün şekilde yansıtmadan önce çoğu zaman **o namespace içinden bir cgroupfs remount** gerektirir. Aksi halde yine de `/..` gibi bir mount root görebilirsiniz; bu, devralınan mount’un, namespace’in kendisi zaten değişmiş olsa bile, hâlâ ancestor-rooted bir görünüm sunduğu anlamına gelir.

## Lab

Aşağıdaki komutla bir cgroup namespace inceleyebilirsiniz:
```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```
Eğer `mountinfo`’nun yeni cgroup-namespace root’unu daha net göstermesini istiyorsanız, cgroup filesystem’ini yeni namespace’in içinden yeniden mount edin ve tekrar karşılaştırın:
```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Ve çalışma zamanı davranışını şunla karşılaştırın:
```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```
Değişiklik çoğunlukla process'in neyi görebildiğiyle ilgilidir, cgroup enforcement'ın olup olmadığıyla değil.

## Security Impact

cgroup namespace en iyi şekilde bir **visibility-hardening layer** olarak anlaşılır. Tek başına, container writable cgroup mounts, geniş capabilities veya tehlikeli bir cgroup v1 ortamına sahipse bir breakout'u durdurmaz. Ancak, host cgroup namespace paylaşılıyorsa, process sistemin nasıl organize edildiği hakkında daha fazla şey öğrenir ve host-relative cgroup yollarını diğer gözlemlerle eşleştirmesi daha kolay olabilir.

**cgroup v2** üzerinde, namespace biraz daha önemli hale gelir çünkü delegation kuralları daha sıkıdır. Hierarchy `nsdelegate` ile mount edilmişse, kernel cgroup namespaces'i delegation boundary olarak ele alır: ancestor control files, delegatee'nin erişiminin dışında kalmalıdır ve namespace root'undaki writes yalnızca `cgroup.procs`, `cgroup.threads` ve `cgroup.subtree_control` gibi delegation-safe dosyalarla sınırlıdır. Bu, namespace'i tek başına bir escape primitive yapmaz, ancak compromised workload'un neleri inspect edebileceğini ve nerede güvenli şekilde sub-cgroups oluşturabileceğini değiştirir.

Bu nedenle bu namespace genellikle container breakout writeups'ında başrolü oynamaz, fakat host information leakage'i azaltma ve cgroup delegation'ı kısıtlama gibi daha geniş hedefe yine de katkıda bulunur.

## Abuse

Doğrudan abuse değeri çoğunlukla reconnaissance'dır. Host cgroup namespace paylaşılıyorsa, görünen yolları karşılaştırın ve host'u ele veren hierarchy ayrıntılarını arayın:
```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```
Eğer yazılabilir cgroup yolları da ifşa ediliyorsa, bu görünürlüğü tehlikeli legacy arayüzler için bir aramayla birleştirin:
```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```
Namespace'in kendisi nadiren anında escape sağlar, ancak cgroup tabanlı abuse primitive'lerini test etmeden önce ortamı haritalamayı çoğu zaman kolaylaştırır.

Hızlı bir runtime gerçeklik kontrolü de attack path'i önceliklendirmeye yardımcı olur. Docker `--cgroupns=host|private` sunar, Podman ise `host`, `private`, `container:<id>`, ve `ns:<path>` destekler. Özellikle Podman'da varsayılan genellikle cgroup v1 üzerinde **`host`** ve cgroup v2 üzerinde **`private`** olur; bu yüzden sadece cgroup versiyonunu belirlemek bile, tam OCI config'i incelemeden önce hangi namespace durumunun daha olası olduğunu söyler.

### Modern v2 Recon: Is This A Delegated Subtree?

Modern host'larda ilginç soru çoğu zaman `release_agent` değildir; bunun yerine mevcut process'in, nested group'lar oluşturmak için yeterli görünürlük veya write access ile delegated bir **cgroup v2** subtree içinde olup olmadığıdır:
```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```
Faydalı yorum:

- `cgroup2fs`, birleşik v2 hiyerarşisinde olduğun anlamına gelir; bu yüzden klasik v1-only `release_agent` zincirleri ilk tahminin olmamalı.
- `cgroup.controllers`, üst öğeden hangi controller’ların kullanılabilir olduğunu gösterir ve dolayısıyla mevcut alt ağacın potansiyel olarak çocuklara neyi yayabileceğini belirtir.
- `cgroup.subtree_control`, hangi controller’ların aslında descendants için etkinleştirildiğini gösterir.
- `cgroup.events`, `populated=0/1` değerini açığa çıkarır; bu, bir alt ağacın boşalıp boşalmadığını izlemek için kullanışlıdır, ancak v1 `release_agent` gibi bir host-code-execution primitive değildir.

Başka bir process namespace’ini doğrudan inceleyecek kadar yetkin varsa, görünümleri şununla karşılaştır:
```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```
### Tam Örnek: Shared cgroup Namespace + Writable cgroup v1

cgroup namespace tek başına genellikle escape için yeterli değildir. Pratik escalation, host-revealing cgroup paths writable cgroup v1 arayüzleriyle birleştirildiğinde gerçekleşir:
```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```
Eğer bu dosyalar erişilebilir ve yazılabilirse, hemen [cgroups.md](../cgroups.md) içindeki tam `release_agent` exploitation flow’a pivot edin. Etki, container içinden host code execution’dır.

Yazılabilir cgroup arayüzleri olmadan, etki genellikle reconnaissance ile sınırlıdır.

## Checks

Bu komutların amacı, process’in private bir cgroup namespace görünümüne sahip olup olmadığını ya da host hierarchy hakkında gerçekten ihtiyaç duyduğundan fazlasını öğrenip öğrenmediğini görmek içindir.
```bash
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```
Burada ilginç olan:

- Namespace identifier, önem verdiğiniz bir host process ile eşleşiyorsa, cgroup namespace shared olabilir.
- `/proc/self/cgroup` içindeki host-revealing paths veya `mountinfo` içindeki ancestor-rooted entries, doğrudan exploitable olmasalar bile useful reconnaissance sağlar.
- `cgroup2fs` kullanılıyorsa, eski v1 primitives hâlâ varmış gibi varsaymak yerine delegation, visible controllers ve writable subtrees üzerine odaklanın.
- cgroup mounts da writable ise, visibility sorusu çok daha önemli hale gelir.

cgroup namespace, primary escape-prevention mechanism olmaktan ziyade bir visibility-hardening layer olarak ele alınmalıdır. Host cgroup structure’ının gereksiz yere exposed edilmesi, saldırgan için reconnaissance değerini artırır.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
